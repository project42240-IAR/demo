# Blockchain Proof-of-Evidence Logger

Attach an immutable, legally-defensible on-chain audit trail to the two
highest-severity case status transitions: **"Escalated to Platform"** and
**"Account Suspended"**. Every such transition produces a SHA-256 hash of
the sanitised case payload that is committed to a Solidity smart contract
running on a local Ethereum testnet (Ganache / Anvil).

---

## Architecture Overview

```
app.py  ──status_update──▶  database.py (MongoDB)
           │                     │
           └──(if high-severity)─▶  blockchain_logger.py
                                         │
                               web3.py + ABI
                                         │
                               EvidenceLog.sol (deployed on testnet)
                                         │
                               on-chain: sha256_hash, case_id,
                                         platform, verdict,
                                         reviewer, timestamp
```

---

## Proposed Changes

### [NEW] `contracts/EvidenceLog.sol` — Solidity Smart Contract

A minimal, gas-efficient contract that stores immutable evidence entries.

**Storage:** A mapping + public array of `EvidenceEntry` structs:
```solidity
struct EvidenceEntry {
    bytes32 payloadHash;   // SHA-256 of the case payload
    string  caseId;        // human-readable case reference
    string  platform;      // e.g. "Instagram"
    string  verdict;       // "Likely Fake" | "Suspicious"
    string  newStatus;     // "Escalated to Platform" | "Account Suspended"
    string  reviewer;      // who triggered the transition
    uint256 timestamp;     // block.timestamp (Unix epoch)
}
```

- `logEvidence(...)` — callable by any authorised address; emits `EvidenceLogged` event
- `getEntry(uint256 index)` — public view for forensic retrieval
- `getCount()` — total number of logged entries
- No admin keys, no upgradability, no `selfdestruct` — deliberately immutable

---

### [NEW] `contracts/EvidenceLog_abi.json` — Contract ABI

The compiled ABI extracted from the Solidity contract.
Pre-computed so the project has **zero Solidity compilation toolchain dependency** at runtime.

---

### [NEW] `blockchain_logger.py` — Python Integration

#### Key responsibilities

| Concern | Detail |
|---|---|
| **Connection** | Connects to `WEB3_PROVIDER_URI` (default: `http://127.0.0.1:8545`) via `web3.py` |
| **Signing account** | Loads private key from `CHAIN_PRIVATE_KEY` in `.env`; auto-uses Ganache/Anvil account[0] if absent |
| **Hash computation** | Deterministic `json.dumps` (sorted keys, no whitespace) → SHA-256 → `bytes32` |
| **Sanitisation** | Strips encrypted Fernet blobs before hashing (only plaintext fields go on-chain) |
| **Transaction** | `logEvidence(...)` call, signed locally, submitted with gas estimation + 20% buffer |
| **Receipt** | Waits for 1-block confirmation; returns `ChainReceipt` dataclass |
| **Fallback** | If the node is unreachable or the tx fails, logs a `CRITICAL` warning and returns a `ChainReceipt(ok=False, ...)` — never raises, so app.py never breaks |
| **Dry-run mode** | `CHAIN_DRY_RUN=true` in `.env` → skips tx, returns a synthetic receipt (useful in CI / no testnet) |

#### `ChainReceipt` dataclass returned to `app.py`
```python
@dataclass
class ChainReceipt:
    ok: bool
    tx_hash: str        # "0x..." or "" on failure
    block_number: int   # 0 on failure
    gas_used: int       # 0 on failure
    payload_hash: str   # "0x..." hex SHA-256
    error: str          # "" on success
```

---

### [MODIFY] `app.py` — Hook into `update_status`

In the `update_status` route, **after** a successful MongoDB write, check if
the new status is a high-severity transition and call:

```python
from blockchain_logger import log_evidence_event, BLOCKCHAIN_TRIGGER_STATUSES

if new_status in BLOCKCHAIN_TRIGGER_STATUSES:
    receipt = log_evidence_event(updated, reviewer=reviewer)
    # Receipt stored on the response but never blocks the HTTP response
```

The `tx_hash` and `block_number` are appended to the API response body so the
caller has immediate proof of the on-chain commitment.

---

### [MODIFY] `requirements.txt`

Add:
```
web3>=6.15
```

---

## `.env` Variables Added

| Variable | Default | Purpose |
|---|---|---|
| `WEB3_PROVIDER_URI` | `http://127.0.0.1:8545` | Ganache / Anvil RPC endpoint |
| `CHAIN_CONTRACT_ADDRESS` | *(must be set after first deploy)* | Deployed `EvidenceLog` address |
| `CHAIN_PRIVATE_KEY` | *(auto-uses account[0] on Ganache)* | Signing key; never commit this |
| `CHAIN_DRY_RUN` | `false` | Skip real tx — useful in CI |

---

## Testnet Setup (one-time)

**Ganache (GUI or CLI):**
```bash
npx ganache --deterministic --accounts 10
```

**Anvil (Foundry):**
```bash
anvil --accounts 10 --block-time 1
```

After the node is running, `python blockchain_logger.py --deploy` deploys the contract
and prints the address to paste into `.env`.

---

## Verification Plan

### Automated
```bash
python blockchain_logger.py --deploy   # deploy contract, print address
python blockchain_logger.py --smoke    # end-to-end: hash → sign → mine → verify
```

### Manual
- Start Ganache, set `CHAIN_CONTRACT_ADDRESS` in `.env`
- `POST /api/reports/<id>/status` with `{"status": "Escalated to Platform"}`
- Response body will contain `chain_receipt.tx_hash` — paste it into Ganache UI to verify
