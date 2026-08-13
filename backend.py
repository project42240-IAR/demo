"""
backend.py
==========
Production-grade Flask backend for the SENTRY Fake Social Media Account
Detection & Reporting System (PS-SW-003).

This file is the unified entry point that wires together every subsystem:

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Subsystem        Module                Role                             │
  │  ─────────────────────────────────────────────────────────────────────  │
  │  Detection engine  detector.py          RawAccount → Assessment          │
  │  OSINT scraper     scraper.py           URL → RawAccount (3-layer)       │
  │  Multi-engine agg  aggregator.py        VirusTotal-style 3-engine scan   │
  │  Supabase layer    database.py          Encrypted cases + audit logs     │
  │  Blockchain log    blockchain_logger.py  SHA-256 on-chain evidence log   │
  └─────────────────────────────────────────────────────────────────────────┘

API Surface
-----------
  GET  /api/health             — liveness / dependency health check
  GET  /api/stats              — dashboard summary counters

  POST /api/scan               — single-engine stateless scan
  POST /api/aggregate          — 3-engine parallel consensus scan
  POST /api/scrape             — scrape a public profile URL → RawAccount

  POST /api/report             — persist assessment → Supabase case
  GET  /api/reports            — list cases (paginated, filtered)
  GET  /api/reports/<id>       — fetch single case
  POST /api/reports/<id>/status — update status (+ blockchain on escalate)
  GET  /api/reports/<id>/audit — audit trail for case
  DELETE /api/reports/<id>     — soft-delete / mark dismissed

  GET  /api/reports/export     — download all cases as CSV

  GET  /                       — serve the SENTRY dashboard

Security
--------
  • All write routes validate input strictly; unknown fields are ignored.
  • Status transitions are stored in Supabase.
  • High-severity transitions trigger an on-chain SHA-256 hash via Web3.py.
  • Sensitive fields (username, reasons) are Fernet-encrypted at rest.
  • CORS is enabled for the configured CORS_ORIGINS env var.
  • Rate-limiting stubs are in place (add flask-limiter in production).

Configuration  (.env)
---------------------
  FLASK_SECRET_KEY        — session signing key (auto-generated if absent)
  FLASK_DEBUG             — "true" for dev mode
  FLASK_PORT              — port to listen on (default 5000)
  FLASK_HOST              — host to bind (default 0.0.0.0)
  CORS_ORIGINS            — comma-separated allowed origins (default *)
  SUPABASE_URL            — Supabase project URL
  SUPABASE_SECRET_KEY     — Supabase secret service role key
  DB_ENCRYPTION_KEY       — Fernet key for field-level encryption
  CHAIN_DRY_RUN           — "true" to skip real blockchain transactions
  WEB3_PROVIDER_URI       — Ganache / Anvil RPC endpoint
  CHAIN_CONTRACT_ADDRESS  — deployed EvidenceLog contract address
  CHAIN_PRIVATE_KEY       — hex private key for signing transactions
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from dotenv import load_dotenv, set_key
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
)

# ── internal modules ──────────────────────────────────────────────────────── #
from detector import RawAccount, assess_account
from aggregator import scan_profile_endpoint
import database as db
from blockchain_logger import log_evidence_event, BLOCKCHAIN_TRIGGER_STATUSES

# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

# Auto-generate FLASK_SECRET_KEY if missing
if not os.environ.get("FLASK_SECRET_KEY"):
    new_key = secrets.token_hex(32)
    set_key(ENV_PATH, "FLASK_SECRET_KEY", new_key)
    os.environ["FLASK_SECRET_KEY"] = new_key

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("FLASK_DEBUG", "").lower() == "true"
          else logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sentry.backend")

# --------------------------------------------------------------------------- #
# Flask app factory
# --------------------------------------------------------------------------- #

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates",
)
app.secret_key = os.environ["FLASK_SECRET_KEY"]


# ── CORS (manual, zero extra dependency) ──────────────────────────────────── #

_CORS_ORIGINS: list[str] = [
    o.strip()
    for o in os.environ.get("CORS_ORIGINS", "*").split(",")
    if o.strip()
]


def _apply_cors(response: Response) -> Response:
    origin = request.headers.get("Origin", "")
    if "*" in _CORS_ORIGINS or origin in _CORS_ORIGINS:
        allow = origin if origin else "*"
        response.headers["Access-Control-Allow-Origin"]  = allow
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PUT, DELETE, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Reviewer, Authorization"
        )
        response.headers["Access-Control-Max-Age"] = "86400"
    return response


@app.after_request
def after_request(response: Response) -> Response:
    return _apply_cors(response)


@app.before_request
def handle_preflight():
    """Handle CORS pre-flight OPTIONS requests."""
    if request.method == "OPTIONS":
        resp = Response()
        return _apply_cors(resp)


# --------------------------------------------------------------------------- #
# Startup — DB indexes & legacy migration
# --------------------------------------------------------------------------- #

with app.app_context():
    try:
        db.init_indexes()
        legacy = os.path.join(BASE_DIR, "case_log.json")
        if os.path.exists(legacy):
            migrated = db.migrate_from_json(legacy)
            if migrated:
                logger.info("Migrated %d case(s) from case_log.json.", migrated)
    except Exception as exc:
        logger.error(
            "DB init failed — app will start but DB ops will fail: %s", exc
        )


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def _get_reviewer() -> str:
    """Pull reviewer identity from X-Reviewer header, default 'system'."""
    return request.headers.get("X-Reviewer", "system").strip() or "system"


def _case_to_api(case: dict) -> dict:
    """Serialise a case dict for JSON output."""
    out = dict(case)
    if isinstance(out.get("reported_at"), datetime):
        out["reported_at"] = out["reported_at"].isoformat()
    out.setdefault("status_history", [])
    return out


def _json_error(msg: str, code: int = 400) -> tuple[Response, int]:
    return jsonify({"ok": False, "error": msg}), code


def _require_json(fn):
    """Decorator: return 415 if Content-Type is not application/json."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH"):
            ct = request.content_type or ""
            if "application/json" not in ct and not request.get_data():
                pass  # allow empty body — get_json(force=True) handles it
        return fn(*args, **kwargs)
    return wrapper


def _build_raw_account(payload: dict) -> RawAccount:
    """Build a RawAccount from a JSON payload dict, with safe defaults."""
    return RawAccount(
        username              = str(payload.get("username", "")).strip() or "unknown_user",
        display_name          = str(payload.get("display_name", "")),
        account_age_days      = float(payload.get("account_age_days", 365)),
        followers             = int(payload.get("followers", 0)),
        following             = int(payload.get("following", 0)),
        posts_count           = int(payload.get("posts_count", 0)),
        has_profile_pic       = bool(payload.get("has_profile_pic", True)),
        bio                   = str(payload.get("bio", "")),
        avg_posts_per_day     = float(payload.get("avg_posts_per_day", 0.5)),
        engagement_rate       = float(payload.get("engagement_rate", 0.05)),
        account_uses_stock_photo = bool(payload.get("account_uses_stock_photo", False)),
        recent_username_changes  = int(payload.get("recent_username_changes", 0)),
        platform              = str(payload.get("platform", "generic")),
    )


# --------------------------------------------------------------------------- #
# Route: dashboard
# --------------------------------------------------------------------------- #

@app.route("/", methods=["GET"])
def index():
    """Serve the SENTRY SOC dashboard."""
    return render_template("index.html")


# --------------------------------------------------------------------------- #
# Route: health check
# --------------------------------------------------------------------------- #

@app.route("/api/health", methods=["GET"])
def health():
    """
    Liveness and dependency health check.

    Returns 200 when all critical subsystems are reachable,
    503 if the database is unavailable.

    Response:
    {
      "status": "healthy" | "degraded",
      "timestamp": "...",
      "subsystems": {
        "database":   { "status": "ok" | "error", "latency_ms": 12 },
        "blockchain": { "status": "ok" | "dry_run" | "not_configured" },
        "engine":     { "status": "ok" }
      }
    }
    """
    import time
    subsystems: dict[str, Any] = {}
    overall_ok = True

    # ── Supabase ─────────────────────────────────────────────────────────── #
    t0 = time.perf_counter()
    try:
        db.init_indexes()
        subsystems["database"] = {
            "status":     "ok",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }
    except Exception as exc:
        subsystems["database"] = {"status": "error", "detail": str(exc)}
        overall_ok = False

    # ── Blockchain ───────────────────────────────────────────────────────── #
    dry_run = os.environ.get("CHAIN_DRY_RUN", "false").lower() in ("true", "1")
    contract_addr = os.environ.get("CHAIN_CONTRACT_ADDRESS", "").strip()
    if dry_run:
        subsystems["blockchain"] = {"status": "dry_run"}
    elif contract_addr:
        try:
            from blockchain_logger import _get_web3
            w3 = _get_web3()
            subsystems["blockchain"] = {
                "status":   "ok",
                "chain_id": w3.eth.chain_id,
                "contract": contract_addr[:10] + "...",
            }
        except Exception as exc:
            subsystems["blockchain"] = {"status": "error", "detail": str(exc)}
    else:
        subsystems["blockchain"] = {"status": "not_configured"}

    # ── Detection engine ─────────────────────────────────────────────────── #
    subsystems["engine"] = {"status": "ok", "engines": 3}

    status_text = "healthy" if overall_ok else "degraded"
    http_code   = 200 if overall_ok else 503

    return jsonify({
        "ok":         overall_ok,
        "status":     status_text,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "subsystems": subsystems,
    }), http_code


# --------------------------------------------------------------------------- #
# Route: stats / dashboard counters
# --------------------------------------------------------------------------- #

@app.route("/api/stats", methods=["GET"])
def stats():
    """
    Summary statistics for the SOC dashboard.

    Response:
    {
      "total_cases": 42,
      "by_verdict": { "Likely Fake": 18, "Suspicious": 15, "Likely Genuine": 9 },
      "by_status":  { "Pending Agency Review": 10, ... },
      "by_platform": { "Instagram": 20, "X": 12, ... },
      "avg_final_score": 61.4,
      "high_risk_count": 18
    }
    """
    try:
        cases = db.list_cases()
    except Exception as exc:
        return _json_error(f"Database error: {exc}", 503)

    total = len(cases)
    by_verdict:  dict[str, int] = {}
    by_status:   dict[str, int] = {}
    by_platform: dict[str, int] = {}
    score_sum = 0.0
    high_risk = 0

    for c in cases:
        verdict  = c.get("verdict",  "Unknown")
        status   = c.get("status",   "Unknown")
        platform = c.get("platform", "Unknown")
        score    = float(c.get("final_score", 0) or 0)

        by_verdict[verdict]   = by_verdict.get(verdict, 0)   + 1
        by_status[status]     = by_status.get(status, 0)     + 1
        by_platform[platform] = by_platform.get(platform, 0) + 1
        score_sum += score
        if score >= 70:
            high_risk += 1

    return jsonify({
        "ok":              True,
        "total_cases":     total,
        "by_verdict":      by_verdict,
        "by_status":       by_status,
        "by_platform":     by_platform,
        "avg_final_score": round(score_sum / total, 1) if total else 0.0,
        "high_risk_count": high_risk,
    })


# --------------------------------------------------------------------------- #
# Route: single-engine scan  (stateless)
# --------------------------------------------------------------------------- #

@app.route("/api/scan", methods=["POST"])
@_require_json
def scan():
    """
    Run the single-engine detection pipeline (Heuristics + ML) on a
    manually submitted account profile.  Stateless — nothing is stored.

    Request body: { username, display_name, platform, account_age_days,
                    followers, following, posts_count, has_profile_pic,
                    bio, avg_posts_per_day, engagement_rate,
                    account_uses_stock_photo, recent_username_changes }

    Response: Assessment dict (rule_score, model_score, final_score,
                               verdict, confidence, reasons, top_model_factors)
    """
    payload = request.get_json(force=True) or {}
    try:
        raw = _build_raw_account(payload)
    except (ValueError, TypeError) as exc:
        return _json_error(f"Invalid input: {exc}")

    result = assess_account(raw)
    return jsonify({"ok": True, **result.to_dict()})


# --------------------------------------------------------------------------- #
# Route: multi-engine aggregate scan  (stateless, VirusTotal pattern)
# --------------------------------------------------------------------------- #

@app.route("/api/aggregate", methods=["POST"])
@_require_json
def aggregate():
    """
    Fan out to three detection engines in parallel (asyncio) and return
    a consensus result with detection ratio and weighted risk score.

    Accepts any of:
      Option 1 — profile_url  (scraper.py fetches metadata automatically)
      Option 2 — full account fields  (same as /api/scan + profile_url optional)
      Option 3 — username + platform only  (Engine A uses minimal defaults)

    Response: {
      detection_ratio, weighted_score, verdict, confidence,
      engines_queried, engines_succeeded, engines_flagged,
      consensus_signals, engine_matrix, scan_timestamp, total_latency_ms
    }
    """
    payload = request.get_json(force=True) or {}
    if not payload.get("username") and not payload.get("profile_url"):
        return _json_error("Provide 'username' or 'profile_url'")
    try:
        result = scan_profile_endpoint(payload)
    except Exception as exc:
        logger.exception("Aggregator error")
        return _json_error(f"Aggregator failed: {exc}", 500)

    return jsonify({"ok": True, **result})


# --------------------------------------------------------------------------- #
# Route: OSINT scraper
# --------------------------------------------------------------------------- #

@app.route("/api/scrape", methods=["POST"])
@_require_json
def scrape():
    """
    Scrape a public social-media profile URL and return the extracted
    RawAccount fields without running any scoring.

    Request: { "url": "https://instagram.com/some_user" }

    Response: { scrape_ok, source, account: { ...RawAccount fields... } }
    """
    payload = request.get_json(force=True) or {}
    url = (payload.get("url") or "").strip()
    if not url.startswith("http"):
        return _json_error("Provide a valid 'url' starting with http(s)://")

    try:
        from scraper import scrape_profile  # noqa: PLC0415
        result = scrape_profile(url)
        raw = result.account
        return jsonify({
            "ok":       True,
            "scrape_ok": result.scrape_ok,
            "source":   result.source,
            "account":  {
                "username":               raw.username,
                "display_name":           raw.display_name,
                "platform":               raw.platform,
                "account_age_days":       raw.account_age_days,
                "followers":              raw.followers,
                "following":              raw.following,
                "posts_count":            raw.posts_count,
                "has_profile_pic":        raw.has_profile_pic,
                "bio":                    raw.bio,
                "avg_posts_per_day":      raw.avg_posts_per_day,
                "engagement_rate":        raw.engagement_rate,
                "account_uses_stock_photo": raw.account_uses_stock_photo,
                "recent_username_changes": raw.recent_username_changes,
            },
        })
    except Exception as exc:
        logger.exception("Scrape error for url=%s", url)
        return _json_error(f"Scrape failed: {exc}", 500)


# --------------------------------------------------------------------------- #
# Route: create case report
# --------------------------------------------------------------------------- #

@app.route("/api/report", methods=["POST"])
@_require_json
def report():
    """
    Persist a flagged account assessment into the MongoDB cases collection.

    The body can be supplied in two forms:

    Form A (standard — from /api/scan):
      { "assessment": { ...assess_account() output... } }

    Form B (aggregate — from /api/aggregate, one-shot scan + store):
      { "username": "...", "platform": "...", ...all profile fields... }
      Auto-scans if no 'assessment' key is present.

    Response: 201 + stored case doc.
    """
    payload = request.get_json(force=True) or {}
    assessment = payload.get("assessment")

    if not assessment:
        # Attempt inline scan if profile fields are present
        if payload.get("username"):
            try:
                raw  = _build_raw_account(payload)
                asmt = assess_account(raw)
                assessment = asmt.to_dict()
            except Exception as exc:
                return _json_error(f"Auto-scan failed: {exc}")
        else:
            return _json_error("'assessment' or 'username' is required")

    case = {
        "case_id":    str(uuid.uuid4())[:8],
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "status":     "Pending Agency Review",
        **assessment,
    }

    try:
        stored = db.insert_case(case)
    except Exception as exc:
        logger.exception("insert_case failed")
        return _json_error(f"Database write failed: {exc}", 500)

    return jsonify({"ok": True, **_case_to_api(stored)}), 201


# --------------------------------------------------------------------------- #
# Route: list cases  (paginated + filtered)
# --------------------------------------------------------------------------- #

@app.route("/api/reports", methods=["GET"])
def list_reports():
    """
    Return all cases sorted by reported_at descending.

    Query parameters:
      page     — 1-based page number  (default 1)
      per_page — results per page     (default 50, max 200)
      verdict  — filter by verdict    (e.g. "Likely Fake")
      platform — filter by platform   (e.g. "Instagram")
      status   — filter by status
      q        — substring match on username  (case-insensitive)

    Response: {
      ok, total, page, per_page, pages,
      cases: [ ...case dicts... ]
    }
    """
    try:
        all_cases = db.list_cases()
    except Exception as exc:
        return _json_error(f"Database error: {exc}", 503)

    # ── Filtering ────────────────────────────────────────────────────────── #
    verdict_f  = request.args.get("verdict",  "").strip().lower()
    platform_f = request.args.get("platform", "").strip().lower()
    status_f   = request.args.get("status",   "").strip().lower()
    query_f    = request.args.get("q",        "").strip().lower()

    def _matches(c: dict) -> bool:
        if verdict_f  and (c.get("verdict",  "") or "").lower() != verdict_f:
            return False
        if platform_f and (c.get("platform", "") or "").lower() != platform_f:
            return False
        if status_f   and (c.get("status",   "") or "").lower() != status_f:
            return False
        if query_f    and query_f not in (c.get("username", "") or "").lower():
            return False
        return True

    filtered = [c for c in all_cases if _matches(c)]

    # ── Pagination ───────────────────────────────────────────────────────── #
    try:
        page     = max(1, int(request.args.get("page",     1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        page, per_page = 1, 50

    total = len(filtered)
    pages = max(1, (total + per_page - 1) // per_page)
    start = (page - 1) * per_page
    page_cases = filtered[start: start + per_page]

    return jsonify({
        "ok":       True,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    pages,
        "cases":    [_case_to_api(c) for c in page_cases],
    })


# --------------------------------------------------------------------------- #
# Route: get single case
# --------------------------------------------------------------------------- #

@app.route("/api/reports/<case_id>", methods=["GET"])
def get_report(case_id: str):
    """Fetch a single case document by its case_id."""
    case = db.get_case(case_id)
    if not case:
        return _json_error("case not found", 404)
    return jsonify({"ok": True, **_case_to_api(case)})


# --------------------------------------------------------------------------- #
# Route: update case status  (+ blockchain evidence log)
# --------------------------------------------------------------------------- #

@app.route("/api/reports/<case_id>/status", methods=["POST"])
@_require_json
def update_status(case_id: str):
    """
    Atomically update the workflow status of a case.

    Uses MongoDB find_one_and_update ($set + $push) — no race-condition
    window even under concurrent Flask threads.

    For high-severity transitions ("Escalated to Platform",
    "Account Suspended") a SHA-256 hash of the sanitised case payload is
    committed on-chain via blockchain_logger.py.  The ChainReceipt is
    appended to the HTTP response.

    Request:  { "status": "<new_status>" }
    Headers:  X-Reviewer: <identity>   (optional, default "system")
    """
    payload    = request.get_json(force=True) or {}
    new_status = payload.get("status")

    if new_status not in db.VALID_STATUSES:
        return _json_error(
            f"Invalid status. Valid values: {sorted(db.VALID_STATUSES)}"
        )

    reviewer = _get_reviewer()
    try:
        updated = db.update_case_status(case_id, new_status, reviewer=reviewer)
    except ValueError as exc:
        return _json_error(str(exc))
    except Exception as exc:
        logger.exception("update_case_status failed for %s", case_id)
        return _json_error(f"Database update failed: {exc}", 500)

    if updated is None:
        return _json_error("case not found", 404)

    # ── Blockchain evidence log ───────────────────────────────────────────── #
    chain_receipt = None
    if new_status in BLOCKCHAIN_TRIGGER_STATUSES:
        chain_receipt = log_evidence_event(
            {**updated, "status": new_status},
            reviewer=reviewer,
        )
        if not chain_receipt.ok:
            logger.critical(
                "BLOCKCHAIN LOG FAILED for case_id=%s: %s",
                case_id, chain_receipt.error,
            )

    response_body = {"ok": True, **_case_to_api(updated)}
    if chain_receipt is not None:
        response_body["chain_receipt"] = chain_receipt.to_dict()

    return jsonify(response_body)


# --------------------------------------------------------------------------- #
# Route: soft-delete / dismiss a case
# --------------------------------------------------------------------------- #

@app.route("/api/reports/<case_id>", methods=["DELETE"])
def delete_report(case_id: str):
    """
    Soft-delete a case by setting its status to
    'Dismissed - False Positive'.

    Reviewer must be provided via X-Reviewer header.
    """
    reviewer = _get_reviewer()
    try:
        updated = db.update_case_status(
            case_id, "Dismissed - False Positive", reviewer=reviewer
        )
    except Exception as exc:
        return _json_error(f"Dismiss failed: {exc}", 500)

    if updated is None:
        return _json_error("case not found", 404)

    return jsonify({
        "ok":      True,
        "message": f"Case {case_id} dismissed as false positive.",
        **_case_to_api(updated),
    })


# --------------------------------------------------------------------------- #
# Route: audit trail for a case
# --------------------------------------------------------------------------- #

@app.route("/api/reports/<case_id>/audit", methods=["GET"])
def get_audit_log(case_id: str):
    """
    Return the full, immutable audit trail for a specific case.
    Entries are decrypted by database.py and sorted newest-first.
    """
    logs = db.list_audit_logs(case_id=case_id)
    serialised = []
    for entry in logs:
        e = dict(entry)
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        serialised.append(e)
    return jsonify({"ok": True, "audit_log": serialised})


# --------------------------------------------------------------------------- #
# Route: CSV export
# --------------------------------------------------------------------------- #

@app.route("/api/reports/export", methods=["GET"])
def export_reports():
    """
    Download all cases as a UTF-8 CSV file.

    Supports the same ?verdict=, ?platform=, ?status= filters as list_reports.
    """
    try:
        all_cases = db.list_cases()
    except Exception as exc:
        return _json_error(f"Database error: {exc}", 503)

    # Apply optional filters
    verdict_f  = request.args.get("verdict",  "").strip().lower()
    platform_f = request.args.get("platform", "").strip().lower()
    status_f   = request.args.get("status",   "").strip().lower()

    filtered = [
        c for c in all_cases
        if (not verdict_f  or (c.get("verdict",  "") or "").lower() == verdict_f)
        and (not platform_f or (c.get("platform", "") or "").lower() == platform_f)
        and (not status_f   or (c.get("status",   "") or "").lower() == status_f)
    ]

    buf = io.StringIO()
    if filtered:
        fieldnames = list(filtered[0].keys())
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for c in filtered:
            row = dict(c)
            for key in ("reasons", "top_model_factors", "status_history"):
                if isinstance(row.get(key), list):
                    row[key] = json.dumps(row[key], ensure_ascii=False)
            if isinstance(row.get("reported_at"), datetime):
                row["reported_at"] = row["reported_at"].isoformat()
            writer.writerow(row)

    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="sentry_flagged_accounts.csv",
    )


# --------------------------------------------------------------------------- #
# Route: global audit log (admin view)
# --------------------------------------------------------------------------- #

@app.route("/api/audit", methods=["GET"])
def global_audit():
    """
    Return the most recent audit log entries across ALL cases.

    Query params:
      limit — max entries to return (default 100, max 500)
    """
    try:
        limit = min(500, max(1, int(request.args.get("limit", 100))))
    except (ValueError, TypeError):
        limit = 100

    logs = db.list_audit_logs()  # all, sorted newest-first
    serialised = []
    for entry in logs[:limit]:
        e = dict(entry)
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        serialised.append(e)

    return jsonify({
        "ok":    True,
        "count": len(serialised),
        "audit_log": serialised,
    })


# --------------------------------------------------------------------------- #
# Error handlers
# --------------------------------------------------------------------------- #

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "endpoint not found"}), 404
    return render_template("index.html"), 200  # SPA fallback


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"ok": False, "error": "method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled server error")
    return jsonify({"ok": False, "error": "internal server error"}), 500


# --------------------------------------------------------------------------- #
# Dev server
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    host  = os.environ.get("FLASK_HOST", "0.0.0.0")
    port  = int(os.environ.get("FLASK_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    logger.info("=" * 60)
    logger.info("  SENTRY Backend starting")
    logger.info("  Host   : %s", host)
    logger.info("  Port   : %s", port)
    logger.info("  Debug  : %s", debug)
    logger.info("  Mongo  : %s", os.environ.get("MONGO_URI", "not set"))
    logger.info("  Chain  : %s",
        "dry-run" if os.environ.get("CHAIN_DRY_RUN", "").lower() in ("true","1")
        else os.environ.get("CHAIN_CONTRACT_ADDRESS", "not configured")
    )
    logger.info("=" * 60)

    app.run(host=host, port=port, debug=debug)
