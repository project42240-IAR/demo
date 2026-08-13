"""
blockchain_logger.py
====================
Immutable proof-of-evidence logging module for the Fake Social Media Account
Detection platform.

Every time a case status transitions to "Escalated to Platform" or
"Account Suspended" this module:

  1. Sanitises the case payload (strips encrypted Fernet blobs; only
     plaintext, non-PII fields travel on-chain).
  2. Computes a deterministic SHA-256 hash of that sanitised payload.
  3. Signs and submits a transaction that calls EvidenceLog.logEvidence()
     on a locally deployed Solidity contract (Ganache / Anvil testnet).
  4. Waits for 1-block confirmation and returns a ChainReceipt dataclass.

The module NEVER raises an unhandled exception.  If the node is unreachable
or the transaction fails, it logs CRITICAL and returns ChainReceipt(ok=False).
The Flask HTTP response is never blocked.

Dry-run mode
------------
Set CHAIN_DRY_RUN=true in .env to skip real transactions.  A synthetic
receipt is returned so the rest of the stack (app.py, tests) behaves
identically without a running testnet.  Useful in CI and on developer
machines that haven't deployed the contract yet.

One-time setup
--------------
1. Start Ganache or Anvil:
       npx ganache --deterministic --accounts 10
       -- or --
       anvil --accounts 10 --block-time 1

2. Deploy the contract (downloads solc automatically via py-solc-x):
       python blockchain_logger.py --deploy

   This prints and saves the contract address to .env as
   CHAIN_CONTRACT_ADDRESS.

3. Optionally run the smoke test against the live node:
       python blockchain_logger.py --smoke

Environment variables (.env)
-----------------------------
  WEB3_PROVIDER_URI        RPC endpoint  (default: http://127.0.0.1:8545)
  CHAIN_CONTRACT_ADDRESS   Deployed EvidenceLog address (set after --deploy)
  CHAIN_PRIVATE_KEY        Hex private key for signing (optional;
                           if absent uses the node's first unlocked account)
  CHAIN_DRY_RUN            "true" / "1" → skip real tx, return synthetic receipt
  CHAIN_GAS_BUFFER         Float multiplier on estimated gas (default: 1.25)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv, set_key

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Bootstrap .env
# --------------------------------------------------------------------------- #

BASE_DIR = Path(__file__).parent.resolve()
ENV_PATH  = BASE_DIR / ".env"
ABI_PATH  = BASE_DIR / "contracts" / "EvidenceLog_abi.json"
SOL_PATH  = BASE_DIR / "contracts" / "EvidenceLog.sol"

load_dotenv(ENV_PATH)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

#: Status values that trigger an on-chain evidence log entry.
BLOCKCHAIN_TRIGGER_STATUSES: frozenset[str] = frozenset({
    "Escalated to Platform",
    "Account Suspended",
})

#: Case fields included in the hash payload (plaintext, non-PII).
#: Encrypted Fernet blobs (username, reasons, etc.) are intentionally excluded
#: so no private data ever reaches the blockchain.
_HASH_FIELDS: tuple[str, ...] = (
    "case_id",
    "platform",
    "verdict",
    "confidence",
    "rule_score",
    "model_score",
    "final_score",
    "status",
    "reported_at",
)

_DEFAULT_PROVIDER = "http://127.0.0.1:8545"
_CONFIRMATION_TIMEOUT = 120  # seconds to wait for tx receipt
_DEFAULT_GAS_BUFFER   = 1.25


def _is_dry_run() -> bool:
    return os.environ.get("CHAIN_DRY_RUN", "false").lower() in ("true", "1", "yes")


# --------------------------------------------------------------------------- #
# Output dataclass
# --------------------------------------------------------------------------- #

@dataclass
class ChainReceipt:
    """
    Result of a blockchain evidence log attempt.

    Attributes
    ----------
    ok           : True if the transaction was mined successfully.
    tx_hash      : "0x..." transaction hash, or "" on failure / dry-run.
    block_number : Block in which the tx was mined; 0 on failure.
    gas_used     : Gas consumed by the transaction; 0 on failure.
    payload_hash : "0x..." hex SHA-256 of the sanitised case payload.
    entry_index  : Position in the on-chain EvidenceEntry[] array; -1 on failure.
    dry_run      : True when CHAIN_DRY_RUN is active (no real tx submitted).
    error        : Human-readable error description, "" on success.
    """
    ok:           bool
    tx_hash:      str   = ""
    block_number: int   = 0
    gas_used:     int   = 0
    payload_hash: str   = ""
    entry_index:  int   = -1
    dry_run:      bool  = False
    error:        str   = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok":           self.ok,
            "tx_hash":      self.tx_hash,
            "block_number": self.block_number,
            "gas_used":     self.gas_used,
            "payload_hash": self.payload_hash,
            "entry_index":  self.entry_index,
            "dry_run":      self.dry_run,
            "error":        self.error,
        }


# --------------------------------------------------------------------------- #
# Hash computation
# --------------------------------------------------------------------------- #

def build_payload_hash(case: dict) -> bytes:
    """
    Compute a deterministic SHA-256 hash of the sanitised case payload.

    Only plaintext, non-PII fields listed in _HASH_FIELDS are included.
    Encrypted Fernet blobs (username, reasons, top_model_factors, etc.)
    are stripped so they never appear on the blockchain.

    The payload is serialised as compact, sorted-key JSON (no whitespace)
    to guarantee byte-for-byte reproducibility across Python versions,
    operating systems, and runtimes.

    Returns
    -------
    bytes
        Raw 32-byte SHA-256 digest, ready to be passed as ``bytes32`` to
        the Solidity contract.
    """
    sanitised = {k: case[k] for k in _HASH_FIELDS if k in case}
    canonical = json.dumps(sanitised, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def payload_hash_hex(case: dict) -> str:
    """Return the SHA-256 hash as a '0x'-prefixed hex string."""
    return "0x" + build_payload_hash(case).hex()


# --------------------------------------------------------------------------- #
# Web3 connection helpers
# --------------------------------------------------------------------------- #

def _load_abi() -> list[dict]:
    """Load the EvidenceLog ABI from the bundled JSON file."""
    if not ABI_PATH.exists():
        raise FileNotFoundError(
            f"ABI file not found: {ABI_PATH}\n"
            "Run 'python blockchain_logger.py --deploy' to compile and deploy the contract."
        )
    with ABI_PATH.open() as fh:
        return json.load(fh)


_w3_singleton = None
_contract_singleton = None


def _get_web3():
    """
    Return a connected Web3 instance (lazy singleton).
    Raises ConnectionError if the node is not reachable.
    """
    global _w3_singleton
    if _w3_singleton is not None:
        return _w3_singleton

    # Deferred import so the module loads even if web3 is not installed
    try:
        from web3 import Web3
        from web3.middleware import ExtraDataToPOAMiddleware
    except ImportError as exc:
        raise ImportError(
            "web3 is not installed. Run: pip install web3"
        ) from exc

    uri = os.environ.get("WEB3_PROVIDER_URI", _DEFAULT_PROVIDER)
    w3 = Web3(Web3.HTTPProvider(uri, request_kwargs={"timeout": 30}))

    # Inject PoA middleware — required for Ganache and some Polygon testnets
    # that use a PoA consensus layer (clique / IBFT).
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        raise ConnectionError(
            f"Cannot connect to Ethereum node at {uri!r}.\n"
            "Start Ganache:  npx ganache --deterministic --accounts 10\n"
            "Start Anvil:    anvil --accounts 10 --block-time 1\n"
            "Or set WEB3_PROVIDER_URI in .env to your Atlas/Alchemy endpoint."
        )

    logger.info("Web3 connected: %s  chain_id=%s", uri, w3.eth.chain_id)
    _w3_singleton = w3
    return w3


def _get_signing_account(w3) -> tuple[str, str | None]:
    """
    Return (address, private_key_or_None).

    Priority:
      1. CHAIN_PRIVATE_KEY env var  →  sign locally (production-grade)
      2. First unlocked node account  →  delegate signing to node (dev only)
    """
    raw_key = os.environ.get("CHAIN_PRIVATE_KEY", "").strip()
    if raw_key:
        if not raw_key.startswith("0x"):
            raw_key = "0x" + raw_key
        from eth_account import Account
        acct = Account.from_key(raw_key)
        return acct.address, raw_key

    # Fall back to first unlocked node account (Ganache / Anvil dev mode)
    accounts = w3.eth.accounts
    if not accounts:
        raise RuntimeError(
            "No CHAIN_PRIVATE_KEY set and the node has no unlocked accounts.\n"
            "Set CHAIN_PRIVATE_KEY=<hex> in .env, or start Ganache/Anvil "
            "with --deterministic."
        )
    logger.warning(
        "CHAIN_PRIVATE_KEY not set — using node account %s (dev mode only).",
        accounts[0],
    )
    return accounts[0], None


def _get_contract(w3):
    """Return the deployed EvidenceLog contract instance (lazy singleton)."""
    global _contract_singleton
    if _contract_singleton is not None:
        return _contract_singleton

    address = os.environ.get("CHAIN_CONTRACT_ADDRESS", "").strip()
    if not address:
        raise RuntimeError(
            "CHAIN_CONTRACT_ADDRESS is not set in .env.\n"
            "Run: python blockchain_logger.py --deploy\n"
            "Then copy the printed address into .env."
        )

    from web3 import Web3
    checksummed = Web3.to_checksum_address(address)
    abi = _load_abi()
    _contract_singleton = w3.eth.contract(address=checksummed, abi=abi)
    logger.info("EvidenceLog contract loaded at %s", checksummed)
    return _contract_singleton


# --------------------------------------------------------------------------- #
# Transaction helper
# --------------------------------------------------------------------------- #

def _send_tx(w3, contract_fn, from_address: str, private_key: str | None) -> dict:
    """
    Estimate gas, build, sign (if private_key given), and submit a transaction.
    Waits for 1-block confirmation.

    Returns the transaction receipt dict.
    Raises on timeout or revert.
    """
    gas_buffer = float(os.environ.get("CHAIN_GAS_BUFFER", _DEFAULT_GAS_BUFFER))

    estimated_gas = contract_fn.estimate_gas({"from": from_address})
    gas_limit = int(estimated_gas * gas_buffer)

    if private_key:
        # Local signing — preferred; works on any node including public RPCs
        nonce = w3.eth.get_transaction_count(from_address, "pending")
        tx = contract_fn.build_transaction({
            "from":     from_address,
            "gas":      gas_limit,
            "nonce":    nonce,
            "chainId":  w3.eth.chain_id,
        })
        signed = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        # Unlocked node account (dev-only, Ganache / Anvil)
        tx_hash = contract_fn.transact({
            "from": from_address,
            "gas":  gas_limit,
        })

    logger.info("TX submitted: %s  (gas_limit=%d)", tx_hash.hex(), gas_limit)
    receipt = w3.eth.wait_for_transaction_receipt(
        tx_hash, timeout=_CONFIRMATION_TIMEOUT
    )
    return receipt


# --------------------------------------------------------------------------- #
# Public API — log_evidence_event
# --------------------------------------------------------------------------- #

def log_evidence_event(case: dict, reviewer: str = "system") -> ChainReceipt:
    """
    Hash the case payload and commit it to the EvidenceLog smart contract.

    This is the single entry point called by app.py.

    Parameters
    ----------
    case     : Decrypted case dict as returned by database.py (e.g. from
               ``update_case_status()``).  Encrypted blobs are acceptable —
               they are stripped before hashing.
    reviewer : Reviewer identity from the X-Reviewer HTTP header.

    Returns
    -------
    ChainReceipt
        Always returns (never raises).  Check ``receipt.ok`` to determine
        whether the on-chain commit succeeded.
    """
    # ── Compute hash before any network calls ──────────────────────────── #
    raw_hash_bytes = build_payload_hash(case)
    hash_hex       = "0x" + raw_hash_bytes.hex()

    # ── Dry-run mode — return a synthetic receipt immediately ──────────── #
    if _is_dry_run():
        logger.info(
            "[DRY-RUN] Skipping real transaction for case_id=%s  hash=%s",
            case.get("case_id"), hash_hex,
        )
        return ChainReceipt(
            ok=True,
            tx_hash="0x" + "0" * 64,
            block_number=0,
            gas_used=0,
            payload_hash=hash_hex,
            entry_index=0,
            dry_run=True,
            error="",
        )

    try:
        w3 = _get_web3()
        contract = _get_contract(w3)
        from_address, private_key = _get_signing_account(w3)

        # Build the contract function call
        # bytes32 argument must be passed as a 32-byte bytes object
        fn = contract.functions.logEvidence(
            raw_hash_bytes,                        # bytes32 payloadHash
            str(case.get("case_id",   "")),        # string  caseId
            str(case.get("platform",  "Unknown")), # string  platform
            str(case.get("verdict",   "Unknown")), # string  verdict
            str(case.get("status",    "")),        # string  newStatus
            str(reviewer),                         # string  reviewer
        )

        receipt = _send_tx(w3, fn, from_address, private_key)

        if receipt["status"] != 1:
            raise RuntimeError(
                f"Transaction reverted. Receipt: {dict(receipt)}"
            )

        # Extract entry_index from the EvidenceLogged event logs
        entry_index = -1
        try:
            logs = contract.events.EvidenceLogged().process_receipt(receipt)
            if logs:
                entry_index = int(logs[0]["args"]["entryIndex"])
        except Exception:
            pass  # non-fatal: entry_index stays -1

        logger.info(
            "On-chain evidence logged: case_id=%s  entry_index=%d  "
            "tx=%s  block=%d  gas=%d",
            case.get("case_id"), entry_index,
            receipt["transactionHash"].hex(),
            receipt["blockNumber"],
            receipt["gasUsed"],
        )

        return ChainReceipt(
            ok=True,
            tx_hash="0x" + receipt["transactionHash"].hex(),
            block_number=int(receipt["blockNumber"]),
            gas_used=int(receipt["gasUsed"]),
            payload_hash=hash_hex,
            entry_index=entry_index,
            dry_run=False,
            error="",
        )

    except Exception as exc:  # pylint: disable=broad-except
        msg = f"{type(exc).__name__}: {exc}"
        logger.critical(
            "Blockchain evidence log FAILED for case_id=%s: %s",
            case.get("case_id"), msg,
        )
        return ChainReceipt(
            ok=False,
            payload_hash=hash_hex,
            error=msg,
        )


# --------------------------------------------------------------------------- #
# verify_entry — off-chain verification helper
# --------------------------------------------------------------------------- #

def verify_entry(entry_index: int, expected_case: dict) -> bool:
    """
    Retrieve entry *entry_index* from the contract and verify the stored
    ``payloadHash`` matches a freshly computed hash of *expected_case*.

    Returns True if the hashes match, False otherwise.
    Useful for forensic verification without trusting any database record.
    """
    try:
        w3       = _get_web3()
        contract = _get_contract(w3)
        entry    = contract.functions.getEntry(entry_index).call()
        # entry is a tuple: (payloadHash, caseId, platform, verdict, newStatus, reviewer, timestamp)
        on_chain_hash = entry[0]  # bytes32
        local_hash    = build_payload_hash(expected_case)
        match = on_chain_hash == local_hash
        if match:
            logger.info("Verification PASSED for entry_index=%d", entry_index)
        else:
            logger.warning(
                "Verification FAILED for entry_index=%d  "
                "on_chain=%s  local=%s",
                entry_index, on_chain_hash.hex(), local_hash.hex(),
            )
        return match
    except Exception as exc:
        logger.error("verify_entry(%d) failed: %s", entry_index, exc)
        return False


# --------------------------------------------------------------------------- #
# Contract deployment helper (python blockchain_logger.py --deploy)
# --------------------------------------------------------------------------- #

def deploy_contract() -> str:
    """
    Compile EvidenceLog.sol with py-solc-x and deploy it to the connected
    testnet.  Saves CHAIN_CONTRACT_ADDRESS to .env.

    Returns the deployed contract address.
    """
    try:
        import solcx  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "py-solc-x is not installed. Run: pip install py-solc-x"
        ) from exc

    # Ensure a compatible compiler version is available
    SOLC_VERSION = "0.8.20"
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if SOLC_VERSION not in installed:
        print(f"Downloading solc {SOLC_VERSION} (one-time, ~50 MB) ...")
        solcx.install_solc(SOLC_VERSION, show_progress=True)

    print(f"Compiling {SOL_PATH.name} ...")
    solcx.set_solc_version(SOLC_VERSION)
    compiled = solcx.compile_files(
        [str(SOL_PATH)],
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
    )

    # The key is "<path>:<ContractName>"
    contract_key = next(k for k in compiled if "EvidenceLog" in k)
    abi      = compiled[contract_key]["abi"]
    bytecode = compiled[contract_key]["bin"]

    # Save refreshed ABI back to file
    ABI_PATH.write_text(json.dumps(abi, indent=2))
    print(f"ABI saved to {ABI_PATH}")

    w3 = _get_web3()
    from_address, private_key = _get_signing_account(w3)

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    if private_key:
        nonce = w3.eth.get_transaction_count(from_address, "pending")
        deploy_tx = Contract.constructor().build_transaction({
            "from":    from_address,
            "nonce":   nonce,
            "chainId": w3.eth.chain_id,
        })
        signed = w3.eth.account.sign_transaction(deploy_tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        tx_hash = Contract.constructor().transact({"from": from_address})

    print(f"Deploying ... tx={tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt["status"] != 1:
        raise RuntimeError("Deployment transaction reverted!")

    address = receipt["contractAddress"]
    print(f"\nContract deployed at: {address}")

    # Persist to .env
    set_key(str(ENV_PATH), "CHAIN_CONTRACT_ADDRESS", address)
    os.environ["CHAIN_CONTRACT_ADDRESS"] = address
    print(f"CHAIN_CONTRACT_ADDRESS written to {ENV_PATH}")

    return address


# --------------------------------------------------------------------------- #
# CLI entry-point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="EvidenceLog blockchain utilities"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--deploy",
        action="store_true",
        help="Compile EvidenceLog.sol and deploy to the local testnet.",
    )
    group.add_argument(
        "--smoke",
        action="store_true",
        help="Log a synthetic evidence entry and verify it on-chain.",
    )
    group.add_argument(
        "--verify",
        metavar="ENTRY_INDEX",
        type=int,
        help="Re-hash a sample payload and verify it matches entry N on-chain.",
    )
    group.add_argument(
        "--hash",
        action="store_true",
        help="Print the SHA-256 hash of a sample payload (no network call).",
    )
    args = parser.parse_args()

    SAMPLE_CASE = {
        "case_id":     "ab12cd34",
        "platform":    "Instagram",
        "verdict":     "Likely Fake",
        "confidence":  "High",
        "rule_score":  72,
        "model_score": 81.5,
        "final_score": 77.3,
        "status":      "Escalated to Platform",
        "reported_at": "2026-08-11T05:00:00+00:00",
    }

    if args.deploy:
        addr = deploy_contract()
        print(f"\n[OK] Add this to .env:\n    CHAIN_CONTRACT_ADDRESS={addr}\n")

    elif args.hash:
        h = payload_hash_hex(SAMPLE_CASE)
        print(f"\nSample payload fields:\n{json.dumps(SAMPLE_CASE, indent=2)}")
        print(f"\nSHA-256 (hex): {h}\n")

    elif args.smoke:
        print("\n-- Smoke test (live node) --")
        if _is_dry_run():
            print("CHAIN_DRY_RUN=true; switching to real mode for smoke test.")
            os.environ["CHAIN_DRY_RUN"] = "false"

        receipt = log_evidence_event(SAMPLE_CASE, reviewer="smoke-tester")
        if not receipt.ok:
            print(f"\n[FAIL] {receipt.error}")
            sys.exit(1)

        print(f"  tx_hash      : {receipt.tx_hash}")
        print(f"  block_number : {receipt.block_number}")
        print(f"  gas_used     : {receipt.gas_used}")
        print(f"  payload_hash : {receipt.payload_hash}")
        print(f"  entry_index  : {receipt.entry_index}")

        print("\n-- Verifying on-chain entry --")
        ok = verify_entry(receipt.entry_index, SAMPLE_CASE)
        if ok:
            print("[OK]  Hash verification passed.\n")
        else:
            print("[FAIL]  Hash mismatch!\n")
            sys.exit(1)

    elif args.verify is not None:
        ok = verify_entry(args.verify, SAMPLE_CASE)
        print("[OK]  Match." if ok else "[FAIL]  Mismatch.")
