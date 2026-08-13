"""
database.py
===========
Supabase database layer for the Fake Social Media Account Detection platform.

Tables
------
  cases       – one row per reported flagged account
  audit_logs  – append-only log of every reviewer action

Encryption
----------
  Field-level Fernet (AES-128-CBC + HMAC-SHA256) encryption via the
  `cryptography` library.  Sensitive fields are encrypted before they reach the
  wire; the database server never sees plaintext for those fields.

  Encrypted fields
    cases      : username, reasons, top_model_factors, status_history
    audit_logs : reviewer, old_value, new_value

  Non-sensitive indexable fields (case_id, platform, verdict, final_score,
  status, reported_at) are stored as plaintext so queries and sorts work
  efficiently without loading the full document.

  The symmetric key is read from env var DB_ENCRYPTION_KEY (URL-safe base64,
  32 raw bytes → 44 base64 chars).  If the variable is absent a fresh key is
  generated, written to .env in the project root, and a warning is printed.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv, set_key
from supabase import create_client, Client

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# .env bootstrap
# --------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

# Load existing .env (if any) before reading os.environ
load_dotenv(ENV_PATH)


def _bootstrap_env() -> None:
    """Ensure required env vars exist; generate key if missing."""
    if not os.environ.get("DB_ENCRYPTION_KEY"):
        new_key = Fernet.generate_key().decode()  # 44-char URL-safe base64
        set_key(ENV_PATH, "DB_ENCRYPTION_KEY", new_key)
        os.environ["DB_ENCRYPTION_KEY"] = new_key
        logger.warning(
            "No DB_ENCRYPTION_KEY found – generated a new key and saved it to %s. "
            "Back this up immediately; losing it means losing access to all "
            "encrypted database fields.",
            ENV_PATH,
        )


_bootstrap_env()

# --------------------------------------------------------------------------- #
# Fernet cipher — field-level encryption
# --------------------------------------------------------------------------- #

_raw_key = os.environ["DB_ENCRYPTION_KEY"].encode()
_cipher: Fernet = Fernet(_raw_key)


def _encrypt(value: Any) -> str | None:
    """
    Serialize *value* to JSON, then return a Fernet-encrypted base64 string.
    Returns None if value is None.
    """
    if value is None:
        return None
    plaintext = json.dumps(value, ensure_ascii=False).encode()
    return _cipher.encrypt(plaintext).decode()


def _decrypt(token: str | None) -> Any:
    """
    Decrypt a Fernet token and deserialize from JSON.
    Returns None if token is None or decryption fails (key mismatch).
    """
    if token is None:
        return None
    try:
        plaintext = _cipher.decrypt(token.encode())
        return json.loads(plaintext)
    except (InvalidToken, json.JSONDecodeError) as exc:
        logger.error("Decryption failed: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Supabase connection
# --------------------------------------------------------------------------- #

_client: Client | None = None


def get_client() -> Client:
    """Return the Supabase Client instance (lazy singleton)."""
    global _client
    if _client is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_PUBLISHABLE_KEY")
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SECRET_KEY (or SUPABASE_PUBLISHABLE_KEY) must be set in .env"
            )
        _client = create_client(url, key)
        logger.info("Supabase client connected: %s", url)
    return _client


def get_db():
    """Backwards compatibility alias for backend.py health check."""
    return get_client()


def get_rest_url(endpoint: str = "") -> str:
    """Return direct REST API URL for Supabase (e.g., https://brwibpgkzlvunyxejhrh.supabase.co/rest/v1/)."""
    base_url = os.environ.get("SUPABASE_REST_URL") or f"{os.environ.get('SUPABASE_URL', 'https://brwibpgkzlvunyxejhrh.supabase.co').rstrip('/')}/rest/v1/"
    path = endpoint.lstrip("/")
    return f"{base_url.rstrip('/')}/{path}" if path else base_url


def execute_rest_query(endpoint: str, method: str = "GET", params: dict | None = None, json_payload: dict | None = None) -> Any:
    """
    Perform direct HTTP REST query against Supabase PostgREST API (e.g. /rest/v1/cases).
    """
    import requests
    url = get_rest_url(endpoint)
    key = os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_PUBLISHABLE_KEY")
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    response = requests.request(method, url, headers=headers, params=params, json=json_payload)
    response.raise_for_status()
    return response.json() if response.text else {}


# --------------------------------------------------------------------------- #
# Index / Connection initialisation
# --------------------------------------------------------------------------- #

def init_indexes() -> None:
    """
    Verify Supabase database connectivity and tables.
    Called once from app.py inside the Flask app context.
    """
    client = get_client()
    try:
        # Perform a lightweight query on cases table to verify reachability
        client.table("cases").select("case_id").limit(1).execute()
        logger.info("Supabase database connection and tables verified.")
    except Exception as exc:
        logger.warning(
            "Supabase table verification note: %s. "
            "Ensure setup_supabase.sql has been executed in the Supabase Dashboard SQL Editor.",
            exc,
        )


# --------------------------------------------------------------------------- #
# Serialisation helpers
# --------------------------------------------------------------------------- #

_PLAINTEXT_CASE_FIELDS = {
    "case_id", "platform", "verdict", "confidence",
    "rule_score", "model_score", "final_score",
    "status", "reported_at",
}

_ENCRYPTED_CASE_FIELDS = {
    "username", "reasons", "top_model_factors", "status_history",
}


def _case_to_record(case: dict) -> dict:
    """Convert an application-level case dict to a Supabase database row."""
    record: dict[str, Any] = {}
    for key, val in case.items():
        if key in _ENCRYPTED_CASE_FIELDS:
            record[key] = _encrypt(val)
        elif key in _PLAINTEXT_CASE_FIELDS:
            record[key] = val
        else:
            # Extra fields stored as encrypted json payload string
            record[key] = _encrypt(val) if isinstance(val, (dict, list)) else val
    return record


def _record_to_case(record: dict) -> dict:
    """Convert a Supabase database row back to an application-level case dict."""
    if not record:
        return {}
    case: dict[str, Any] = {}
    for key, val in record.items():
        if key in ("created_at", "id"):
            continue  # strip DB internal column
        if key in _ENCRYPTED_CASE_FIELDS:
            case[key] = _decrypt(val)
        else:
            # Attempt decryption if stored as encrypted token string
            if isinstance(val, str) and val.startswith("gAAAAA"):
                decrypted = _decrypt(val)
                case[key] = decrypted if decrypted is not None else val
            else:
                case[key] = val
    return case


# --------------------------------------------------------------------------- #
# Public API – Cases
# --------------------------------------------------------------------------- #

VALID_STATUSES = frozenset({
    "Pending Agency Review",
    "Escalated to Platform",
    "Account Suspended",
    "Dismissed - False Positive",
})


def insert_case(case: dict) -> dict:
    """
    Insert a new case document into Supabase.
    """
    if "status_history" not in case:
        case["status_history"] = [
            {
                "status": case.get("status", "Pending Agency Review"),
                "changed_at": case.get("reported_at", datetime.now(timezone.utc).isoformat()),
                "changed_by": "system",
            }
        ]

    record = _case_to_record(case)
    try:
        get_client().table("cases").insert(record).execute()
    except Exception as exc:
        logger.error("insert_case failed: %s", exc)
        raise

    # Log audit entry for case creation
    _write_audit(
        case_id=case["case_id"],
        reviewer="system",
        action="report_created",
        old_value=None,
        new_value=case,
    )
    return case


def list_cases() -> list[dict]:
    """
    Return all cases sorted by reported_at descending.
    Decrypts sensitive fields before returning.
    """
    try:
        res = get_client().table("cases").select("*").order("reported_at", desc=True).execute()
        return [_record_to_case(r) for r in res.data]
    except Exception as exc:
        logger.error("list_cases failed: %s", exc)
        return []


def get_case(case_id: str) -> dict | None:
    """Fetch a single case by case_id."""
    try:
        res = get_client().table("cases").select("*").eq("case_id", case_id).execute()
        if res.data:
            return _record_to_case(res.data[0])
        return None
    except Exception as exc:
        logger.error("get_case(%s) failed: %s", case_id, exc)
        return None


def update_case_status(
    case_id: str,
    new_status: str,
    reviewer: str = "system",
) -> dict | None:
    """
    Atomically update the case status and append a history entry in Supabase.
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status!r}")

    current = get_case(case_id)
    if current is None:
        return None

    old_status = current.get("status")
    history = current.get("status_history") or []
    if not isinstance(history, list):
        history = [history]

    now_iso = datetime.now(timezone.utc).isoformat()
    history.append({
        "status": new_status,
        "changed_at": now_iso,
        "changed_by": reviewer,
    })

    update_payload = {
        "status": new_status,
        "status_history": _encrypt(history),
    }

    try:
        res = get_client().table("cases").update(update_payload).eq("case_id", case_id).execute()
        if not res.data:
            return None
    except Exception as exc:
        logger.error("update_case_status(%s) failed: %s", case_id, exc)
        raise

    _write_audit(
        case_id=case_id,
        reviewer=reviewer,
        action="status_update",
        old_value={"status": old_status},
        new_value={"status": new_status},
    )
    return get_case(case_id)


# --------------------------------------------------------------------------- #
# Public API – Audit Logs
# --------------------------------------------------------------------------- #

def _write_audit(
    case_id: str,
    reviewer: str,
    action: str,
    old_value: Any,
    new_value: Any,
) -> None:
    """Insert an audit log entry in Supabase."""
    entry = {
        "case_id": case_id,
        "reviewer": _encrypt(reviewer),
        "action": action,
        "old_value": _encrypt(old_value),
        "new_value": _encrypt(new_value),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        get_client().table("audit_logs").insert(entry).execute()
    except Exception as exc:
        logger.error("_write_audit failed (non-fatal): %s", exc)


def list_audit_logs(case_id: str | None = None) -> list[dict]:
    """
    Return audit log entries, optionally filtered by case_id.
    Sorted newest-first.
    """
    try:
        query = get_client().table("audit_logs").select("*")
        if case_id:
            query = query.eq("case_id", case_id)
        res = query.order("timestamp", desc=True).execute()
        logs = []
        for d in res.data:
            logs.append({
                "case_id": d.get("case_id"),
                "action": d.get("action"),
                "timestamp": d.get("timestamp"),
                "reviewer": _decrypt(d.get("reviewer")),
                "old_value": _decrypt(d.get("old_value")),
                "new_value": _decrypt(d.get("new_value")),
            })
        return logs
    except Exception as exc:
        logger.error("list_audit_logs failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Migration helper — import existing case_log.json into Supabase
# --------------------------------------------------------------------------- #

def migrate_from_json(json_path: str) -> int:
    """
    One-shot migration of an existing case_log.json into Supabase.
    """
    if not os.path.exists(json_path):
        logger.info("migrate_from_json: %s not found – nothing to migrate.", json_path)
        return 0

    with open(json_path, "r", encoding="utf-8") as fh:
        cases: list[dict] = json.load(fh)

    inserted = 0
    for case in cases:
        case_id = case.get("case_id")
        if not case_id:
            continue
        existing = get_case(case_id)
        if existing:
            logger.debug("migrate_from_json: skipping existing case_id=%s", case_id)
            continue
        try:
            insert_case(case)
            inserted += 1
        except Exception as exc:
            logger.warning("migrate_from_json: skipped case %s – %s", case_id, exc)

    logger.info("migrate_from_json: inserted %d / %d cases.", inserted, len(cases))
    return inserted


# --------------------------------------------------------------------------- #
# Built-in smoke test (python database.py)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uuid

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    print("\n-- Connecting to Supabase ...")
    client = get_client()

    print("\n-- Verifying database tables ...")
    init_indexes()

    test_case_id = str(uuid.uuid4())[:8]
    test_case = {
        "case_id": test_case_id,
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "status": "Pending Agency Review",
        "username": "smoke_test_user",
        "platform": "X",
        "verdict": "Suspicious",
        "confidence": "Medium",
        "rule_score": 44,
        "model_score": 55.0,
        "final_score": 50.2,
        "reasons": ["Bio is empty", "No profile photo set"],
        "top_model_factors": ["Account age", "Posting frequency"],
    }

    print(f"\n-- Inserting test case (case_id={test_case_id}) ...")
    insert_case(test_case)

    print("\n-- Fetching it back ...")
    fetched = get_case(test_case_id)
    assert fetched is not None, "Case not found after insert!"
    assert fetched["username"] == "smoke_test_user", "Username decryption mismatch!"
    assert fetched["reasons"] == ["Bio is empty", "No profile photo set"], "Reasons mismatch!"
    print(f"   username  : {fetched['username']}")
    print(f"   reasons   : {fetched['reasons']}")
    print(f"   verdict   : {fetched['verdict']}")

    print("\n-- Updating status ...")
    updated = update_case_status(test_case_id, "Escalated to Platform", reviewer="admin")
    assert updated["status"] == "Escalated to Platform", "Status update failed!"
    print(f"   new status: {updated['status']}")

    print("\n-- Checking audit log ...")
    logs = list_audit_logs(case_id=test_case_id)
    assert len(logs) >= 2, f"Expected >=2 audit entries, got {len(logs)}"
    for log in logs:
        print(f"   [{log['timestamp']}] {log['action']}  reviewer={log['reviewer']}")

    print("\n-- Cleaning up test document ...")
    get_client().table("cases").delete().eq("case_id", test_case_id).execute()
    get_client().table("audit_logs").delete().eq("case_id", test_case_id).execute()

    print("\n[OK]  Smoke test passed -- Supabase database layer is healthy.\n")
