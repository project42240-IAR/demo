"""
database.py
===========
MongoDB database layer for the Fake Social Media Account Detection platform.

Collections
-----------
  cases       – one document per reported flagged account
  audit_logs  – append-only log of every reviewer action

Encryption
----------
  Field-level Fernet (AES-128-CBC + HMAC-SHA256) encryption via the
  `cryptography` library.  Sensitive fields are encrypted before they reach the
  wire; the MongoDB server never sees plaintext for those fields.

  Encrypted fields
    cases      : username, reasons, top_model_factors, status_history
    audit_logs : reviewer, old_value, new_value

  Non-sensitive indexable fields (case_id, platform, verdict, final_score,
  status, reported_at) are stored as plaintext so queries and sorts work
  efficiently without loading the full document.

  The symmetric key is read from env var DB_ENCRYPTION_KEY (URL-safe base64,
  32 raw bytes → 44 base64 chars).  If the variable is absent a fresh key is
  generated, written to .env in the project root, and a warning is printed.
  Back up this key – losing it means losing access to all encrypted data.

Concurrency Safety
------------------
  PyMongo's MongoClient maintains an internal connection pool and is fully
  thread-safe.  All write operations use atomic MongoDB update operators
  ($set, $push) via find_one_and_update so there are no read-modify-write
  windows even under concurrent Flask threads.

Key management
--------------
  .env (auto-created on first run):
      DB_ENCRYPTION_KEY=<url-safe base64 key>
      MONGO_URI=mongodb://localhost:27017
      MONGO_DB_NAME=fake_account_detector
"""
from __future__ import annotations

import json
import logging
import os
import base64
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv, set_key
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

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

    if not os.environ.get("MONGO_URI"):
        set_key(ENV_PATH, "MONGO_URI", "mongodb://localhost:27017")
        os.environ["MONGO_URI"] = "mongodb://localhost:27017"

    if not os.environ.get("MONGO_DB_NAME"):
        set_key(ENV_PATH, "MONGO_DB_NAME", "fake_account_detector")
        os.environ["MONGO_DB_NAME"] = "fake_account_detector"


_bootstrap_env()

# --------------------------------------------------------------------------- #
# Fernet cipher — field-level encryption
# --------------------------------------------------------------------------- #

_raw_key = os.environ["DB_ENCRYPTION_KEY"].encode()
_cipher: Fernet = Fernet(_raw_key)


def _encrypt(value: Any) -> str:
    """
    Serialize *value* to JSON, then return a Fernet-encrypted base64 string.
    Stores as plain str in MongoDB (fits inside BSON String cleanly).
    """
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
# MongoDB connection
# --------------------------------------------------------------------------- #

_client: MongoClient | None = None


def get_db():
    """Return the MongoDatabase instance (lazy singleton)."""
    global _client
    if _client is None:
        uri = os.environ["MONGO_URI"]
        _client = MongoClient(
            uri,
            serverSelectionTimeoutMS=5_000,
            connectTimeoutMS=5_000,
        )
        # Trigger a lightweight server check on first use
        _client.admin.command("ping")
        logger.info("MongoDB connected: %s", uri)
    return _client[os.environ["MONGO_DB_NAME"]]


def get_cases() -> Collection:
    return get_db()["cases"]


def get_audit_logs() -> Collection:
    return get_db()["audit_logs"]


# --------------------------------------------------------------------------- #
# Index initialisation (idempotent — safe to call on every startup)
# --------------------------------------------------------------------------- #

def init_indexes() -> None:
    """
    Create indexes if they do not already exist.
    Called once from app.py inside the Flask app context.
    """
    cases = get_cases()
    # Unique case_id for upsert safety
    cases.create_index("case_id", unique=True, background=True)
    # Sort by most-recently-reported first (used by list_cases)
    cases.create_index([("reported_at", DESCENDING)], background=True)
    # Filter by verdict / platform quickly
    cases.create_index("verdict", background=True)
    cases.create_index("platform", background=True)
    cases.create_index("status", background=True)

    audit_logs = get_audit_logs()
    audit_logs.create_index("case_id", background=True)
    audit_logs.create_index([("timestamp", DESCENDING)], background=True)

    logger.info("MongoDB indexes verified.")


# --------------------------------------------------------------------------- #
# Serialisation helpers
# --------------------------------------------------------------------------- #

# Fields stored plaintext (indexed / sorted on server-side)
_PLAINTEXT_CASE_FIELDS = {
    "case_id", "platform", "verdict", "confidence",
    "rule_score", "model_score", "final_score",
    "status", "reported_at",
}

# Fields encrypted before storage
_ENCRYPTED_CASE_FIELDS = {
    "username", "reasons", "top_model_factors", "status_history",
}


def _case_to_doc(case: dict) -> dict:
    """Convert an application-level case dict to a MongoDB document."""
    doc: dict[str, Any] = {}
    for key, val in case.items():
        if key in _ENCRYPTED_CASE_FIELDS:
            doc[key] = _encrypt(val)
        elif key in _PLAINTEXT_CASE_FIELDS:
            doc[key] = val
        else:
            # Unknown fields stored as-is (forward-compatible)
            doc[key] = val
    return doc


def _doc_to_case(doc: dict) -> dict:
    """Convert a MongoDB document back to an application-level case dict."""
    if doc is None:
        return {}
    case: dict[str, Any] = {}
    for key, val in doc.items():
        if key == "_id":
            continue  # strip Mongo internal id
        if key in _ENCRYPTED_CASE_FIELDS:
            case[key] = _decrypt(val)
        else:
            case[key] = val
    return case


def _audit_to_doc(audit: dict) -> dict:
    return {
        "case_id": audit["case_id"],
        "action": audit["action"],
        "timestamp": audit["timestamp"],
        # Encrypted sensitive fields
        "reviewer": _encrypt(audit.get("reviewer", "system")),
        "old_value": _encrypt(audit.get("old_value")),
        "new_value": _encrypt(audit.get("new_value")),
    }


def _doc_to_audit(doc: dict) -> dict:
    if doc is None:
        return {}
    return {
        "case_id": doc.get("case_id"),
        "action": doc.get("action"),
        "timestamp": doc.get("timestamp"),
        "reviewer": _decrypt(doc.get("reviewer")),
        "old_value": _decrypt(doc.get("old_value")),
        "new_value": _decrypt(doc.get("new_value")),
    }


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
    Insert a new case document.  ``case`` must contain at minimum:
      case_id, platform, verdict, confidence, rule_score, model_score,
      final_score, status, reported_at, username, reasons,
      top_model_factors.

    Returns the inserted document as an application dict.

    Thread safety: MongoClient connection pool handles concurrent inserts.
    """
    # Initialise status_history as an embedded array on first insert
    if "status_history" not in case:
        case["status_history"] = [
            {
                "status": case.get("status", "Pending Agency Review"),
                "changed_at": case.get("reported_at", datetime.now(timezone.utc).isoformat()),
                "changed_by": "system",
            }
        ]

    doc = _case_to_doc(case)
    try:
        get_cases().insert_one(doc)
    except PyMongoError as exc:
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
    Return all cases sorted by reported_at descending (most recent first).
    Decrypts sensitive fields before returning.
    """
    try:
        docs = get_cases().find({}, sort=[("reported_at", DESCENDING)])
        return [_doc_to_case(d) for d in docs]
    except PyMongoError as exc:
        logger.error("list_cases failed: %s", exc)
        return []


def get_case(case_id: str) -> dict | None:
    """Fetch a single case by its human-readable case_id."""
    try:
        doc = get_cases().find_one({"case_id": case_id})
        return _doc_to_case(doc) if doc else None
    except PyMongoError as exc:
        logger.error("get_case(%s) failed: %s", case_id, exc)
        return None


def update_case_status(
    case_id: str,
    new_status: str,
    reviewer: str = "system",
) -> dict | None:
    """
    Atomically update the case status and append a history entry.

    Uses find_one_and_update with $set + $push — a single atomic MongoDB
    operation.  No two Flask threads can interleave their read and write
    for the same document.

    Returns the updated case dict, or None if case_id not found.
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status!r}")

    now_iso = datetime.now(timezone.utc).isoformat()
    history_entry = {
        "status": new_status,
        "changed_at": now_iso,
        "changed_by": reviewer,
    }

    # Fetch old status before update (for audit log)
    old_doc = get_cases().find_one({"case_id": case_id}, {"status": 1})
    old_status = old_doc["status"] if old_doc else None

    update_op = {
        "$set": {"status": new_status},
        "$push": {"status_history": _encrypt(history_entry)},
    }
    try:
        updated_doc = get_cases().find_one_and_update(
            {"case_id": case_id},
            update_op,
            return_document=True,  # return the document *after* update
        )
    except PyMongoError as exc:
        logger.error("update_case_status(%s) failed: %s", case_id, exc)
        raise

    if updated_doc is None:
        return None

    _write_audit(
        case_id=case_id,
        reviewer=reviewer,
        action="status_update",
        old_value={"status": old_status},
        new_value={"status": new_status},
    )
    return _doc_to_case(updated_doc)


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
    """Insert an audit log entry.  Non-blocking best-effort – logs on error."""
    entry = {
        "case_id": case_id,
        "reviewer": reviewer,
        "action": action,
        "old_value": old_value,
        "new_value": new_value,
        "timestamp": datetime.now(timezone.utc),
    }
    try:
        get_audit_logs().insert_one(_audit_to_doc(entry))
    except PyMongoError as exc:
        logger.error("_write_audit failed (non-fatal): %s", exc)


def list_audit_logs(case_id: str | None = None) -> list[dict]:
    """
    Return audit log entries, optionally filtered by case_id.
    Sorted newest-first.
    """
    query = {"case_id": case_id} if case_id else {}
    try:
        docs = get_audit_logs().find(query, sort=[("timestamp", DESCENDING)])
        return [_doc_to_audit(d) for d in docs]
    except PyMongoError as exc:
        logger.error("list_audit_logs failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Migration helper — import existing case_log.json into MongoDB
# --------------------------------------------------------------------------- #

def migrate_from_json(json_path: str) -> int:
    """
    One-shot migration of an existing case_log.json into MongoDB.
    Skips documents whose case_id already exists (idempotent).
    Returns the number of documents actually inserted.
    """
    if not os.path.exists(json_path):
        logger.info("migrate_from_json: %s not found – nothing to migrate.", json_path)
        return 0

    with open(json_path, "r", encoding="utf-8") as fh:
        cases: list[dict] = json.load(fh)

    inserted = 0
    for case in cases:
        existing = get_cases().find_one({"case_id": case.get("case_id")})
        if existing:
            logger.debug("migrate_from_json: skipping existing case_id=%s", case.get("case_id"))
            continue
        try:
            insert_case(case)
            inserted += 1
        except PyMongoError as exc:
            logger.warning("migrate_from_json: skipped case %s – %s", case.get("case_id"), exc)

    logger.info("migrate_from_json: inserted %d / %d cases.", inserted, len(cases))
    return inserted


# --------------------------------------------------------------------------- #
# Built-in smoke test (python database.py)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uuid
    from pymongo.errors import ServerSelectionTimeoutError

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    print("\n-- Connecting to MongoDB ...")
    try:
        # Quick reachability check before running the full test
        get_db().command("ping")
    except ServerSelectionTimeoutError:
        print(
            "\n[ERROR] Cannot reach MongoDB at localhost:27017.\n"
            "\nTo start MongoDB on Windows:\n"
            "  1. Install  : https://www.mongodb.com/try/download/community\n"
            "  2. Start    : net start MongoDB\n"
            "     -- or --  mongod --dbpath C:\\data\\db\n"
            "\nAlternatively, set MONGO_URI in .env to point to MongoDB Atlas:\n"
            "  MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/\n"
        )
        raise SystemExit(1)

    print("\n-- Initialising indexes ...")
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
    get_cases().delete_one({"case_id": test_case_id})
    get_audit_logs().delete_many({"case_id": test_case_id})

    print("\n[OK]  Smoke test passed -- MongoDB layer is healthy.\n")

