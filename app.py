"""
app.py
Flask application exposing the detection engine as a small SOC-style
dashboard, plus the "report to central agency" workflow described in the
problem statement (PS-SW-003): once a tool flags an account, a designated
central agency needs a record it can act on (approach the platform for
suspension / pursue legal action).

Database backend: Supabase (via database.py)
  - cases table      : full case row with encrypted sensitive fields
  - audit_logs table : append-only reviewer action trail

All case reads/writes go through database.py which guarantees:
  - Field-level Fernet (AES-128) encryption for sensitive fields
  - Atomic find_one_and_update for status changes (no race conditions)
  - Per-request audit log entries

Blockchain backend: Ethereum/Polygon testnet (via blockchain_logger.py)
  - Status transitions to "Escalated to Platform" or "Account Suspended"
    trigger an immutable on-chain SHA-256 evidence log via Web3.py.
  - Set CHAIN_DRY_RUN=true in .env to skip real txs during development.
  - ChainReceipt (tx_hash, block_number, payload_hash) is returned on
    the HTTP response for immediate client-side verification.
"""
import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file, render_template, session, redirect, url_for

from detector import RawAccount, assess_account, FEATURE_COLUMNS  # noqa: F401
import database as db
from blockchain_logger import (
    log_evidence_event,
    BLOCKCHAIN_TRIGGER_STATUSES,
)
from aggregator import scan_profile_endpoint


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "sentry_super_secret_key_2026_sih")


# --------------------------------------------------------------------------- #
# Startup – initialise indexes once the Flask app context is available
# --------------------------------------------------------------------------- #

with app.app_context():
    try:
        db.init_indexes()
        # One-shot migration: import existing case_log.json if present
        legacy_path = os.path.join(BASE_DIR, "case_log.json")
        if os.path.exists(legacy_path):
            migrated = db.migrate_from_json(legacy_path)
            if migrated:
                app.logger.info(
                    "Migrated %d case(s) from case_log.json into Supabase.", migrated
                )
    except Exception as exc:  # pragma: no cover
        app.logger.error(
            "Database initialisation failed: %s — the app will start but "
            "all database operations will fail until Supabase is reachable.",
            exc,
        )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #

def _get_reviewer() -> str:
    """
    Extract reviewer identity from request headers.
    Clients should send:  X-Reviewer: alice@agency.gov
    Falls back to "system" if the header is absent.
    """
    return request.headers.get("X-Reviewer", "system").strip() or "system"


def _case_to_api_response(case: dict) -> dict:
    """
    Serialise a case dict for JSON output.
    Converts datetime objects to ISO strings and coerces list fields.
    """
    out = dict(case)
    if isinstance(out.get("reported_at"), datetime):
        out["reported_at"] = out["reported_at"].isoformat()
    # status_history may be a list of dicts or encrypted items — include as-is
    # (already decrypted by database.py)
    if "status_history" not in out:
        out["status_history"] = []
    return out


# --------------------------------------------------------------------------- #
# Routes & Authentication
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login_page"))
    return render_template("index.html", current_user=session["user"])


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if "user" in session:
            return redirect(url_for("index"))
        return render_template("login.html")

    payload = request.get_json(silent=True) or request.form or {}
    email = payload.get("email", "").strip()
    password = payload.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400

    user = db.verify_user_credentials(email, password)
    if not user:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    session["user"] = user
    return jsonify({"success": True, "redirect": "/", "user": user})


@app.route("/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or request.form or {}
    email = payload.get("email", "").strip()
    password = payload.get("password", "")
    full_name = payload.get("full_name", "").strip()
    role = payload.get("role", "analyst").strip()

    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400

    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters long."}), 400

    try:
        new_user = db.create_user(
            email=email,
            password=password,
            full_name=full_name or "Security Analyst",
            role=role,
        )
        session["user"] = new_user
        return jsonify({"success": True, "redirect": "/", "user": new_user}), 201
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        app.logger.error("Registration error: %s", exc)
        return jsonify({"success": False, "error": f"Registration failed: {exc}"}), 500


@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    payload = request.get_json(silent=True) or request.form or {}
    email = payload.get("email", "").strip()
    if not email:
        return jsonify({"success": False, "error": "Email address is required."}), 400

    # Simulate/record password reset audit event
    db._write_audit(
        case_id="AUTH-SYS",
        reviewer=email,
        action="password_reset_requested",
        old_value=None,
        new_value="Password reset token issued",
    )
    return jsonify({
        "success": True,
        "message": f"Password reset instructions have been dispatched to {email}. Check your inbox.",
    })


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    if request.is_json:
        return jsonify({"success": True, "redirect": "/login"})
    return redirect(url_for("login_page"))


@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Return live SOC Dashboard Overview KPI metrics, risk distribution, and recent cases."""
    stats = db.get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Run the detection engine on a manually submitted account profile.
    Does NOT store anything — pure stateless analysis.
    """
    payload = request.get_json(force=True) or {}
    try:
        raw = RawAccount(
            username=payload.get("username", "").strip() or "unknown_user",
            display_name=payload.get("display_name", ""),
            account_age_days=float(payload.get("account_age_days", 365)),
            followers=int(payload.get("followers", 0)),
            following=int(payload.get("following", 0)),
            posts_count=int(payload.get("posts_count", 0)),
            has_profile_pic=bool(payload.get("has_profile_pic", True)),
            bio=payload.get("bio", ""),
            avg_posts_per_day=float(payload.get("avg_posts_per_day", 0.5)),
            engagement_rate=float(payload.get("engagement_rate", 0.05)),
            account_uses_stock_photo=bool(payload.get("account_uses_stock_photo", False)),
            recent_username_changes=int(payload.get("recent_username_changes", 0)),
            platform=payload.get("platform", "generic"),
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": f"Invalid input: {exc}"}), 400

    result = assess_account(raw)
    return jsonify(result.to_dict())


@app.route("/api/aggregate", methods=["POST"])
def aggregate():
    """
    Multi-engine signal aggregator — VirusTotal-style consensus scan.

    Fans out to three detection engines in parallel:
      Engine A — Internal Heuristics + ML (detector.assess_account)
      Engine B — Metadata Anomaly Check (entropy, link-shorteners, engagement)
      Engine C — External API Proxy (HIBP, blocklists, OSINT)

    Accepts either a profile URL or a full account data payload:

    Option 1 — URL scrape (scraper.py fetches metadata automatically):
      { "profile_url": "https://instagram.com/some_user" }

    Option 2 — Manual profile data (same fields as /api/scan):
      { "username": "bot_x99", "platform": "X", "followers": 5,
        "following": 7800, "bio": "Buy followers http://bit.ly/xyz", ... }

    Option 3 — Username-only (Engine A uses minimal defaults):
      { "username": "bot_x99", "platform": "X" }

    Returns
    -------
    {
      "username":          "bot_x99",
      "platform":          "X",
      "detection_ratio":   "2/3",
      "weighted_score":    74.2,
      "verdict":           "Likely Fake",
      "confidence":        "High",
      "engines_queried":   3,
      "engines_succeeded": 3,
      "engines_flagged":   2,
      "consensus_signals": [...],
      "engine_matrix":     [ { engine_id, status, risk_score, signals, ... }, ... ],
      "scan_timestamp":    "2026-08-11T05:00:00+00:00",
      "total_latency_ms":  312.4
    }
    """
    payload = request.get_json(force=True) or {}
    try:
        result = scan_profile_endpoint(payload)
    except Exception as exc:
        return jsonify({"error": f"Aggregator failed: {exc}"}), 500

    return jsonify(result)


@app.route("/api/report", methods=["POST"])
def report():
    """
    Push a flagged account assessment into the MongoDB cases collection.

    Expected body:
      { "assessment": { ...assess_account() output... } }

    Writes an AuditLog entry ("report_created") automatically.
    """
    payload = request.get_json(force=True) or {}
    assessment = payload.get("assessment")
    if not assessment:
        return jsonify({"error": "assessment payload is required"}), 400

    case = {
        "case_id": str(uuid.uuid4())[:8],
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "status": "Pending Agency Review",
        **assessment,
    }

    try:
        stored = db.insert_case(case)
    except Exception as exc:
        return jsonify({"error": f"Database write failed: {exc}"}), 500

    return jsonify(_case_to_api_response(stored)), 201


@app.route("/api/reports", methods=["GET"])
def list_reports():
    """
    Return all cases sorted by reported_at descending.
    Sensitive fields are decrypted by database.py before serialisation.
    """
    cases = db.list_cases()
    return jsonify([_case_to_api_response(c) for c in cases])


@app.route("/api/reports/<case_id>", methods=["GET"])
def get_report(case_id):
    """Fetch a single case by case_id."""
    case = db.get_case(case_id)
    if not case:
        return jsonify({"error": "case not found"}), 404
    return jsonify(_case_to_api_response(case))


@app.route("/api/reports/<case_id>/status", methods=["POST"])
def update_status(case_id):
    """
    Update the workflow status of a case.

    Atomic $set + $push via find_one_and_update — safe under concurrent
    scanning sessions with no read-modify-write race window.

    Appends to status_history and writes an AuditLog entry.

    For high-severity transitions ("Escalated to Platform", "Account Suspended")
    a SHA-256 hash of the sanitised case payload is committed on-chain via
    blockchain_logger.py.  The ChainReceipt is included in the response body.

    Headers:
      X-Reviewer: <reviewer name or email>   (optional, defaults to "system")
    """
    payload = request.get_json(force=True) or {}
    new_status = payload.get("status")
    if new_status not in db.VALID_STATUSES:
        return jsonify({"error": "invalid status", "valid": list(db.VALID_STATUSES)}), 400

    reviewer = _get_reviewer()
    try:
        updated = db.update_case_status(case_id, new_status, reviewer=reviewer)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Database update failed: {exc}"}), 500

    if updated is None:
        return jsonify({"error": "case not found"}), 404

    # ── Blockchain evidence log for high-severity transitions ──────────── #
    chain_receipt = None
    if new_status in BLOCKCHAIN_TRIGGER_STATUSES:
        # Inject reviewer into the case dict so it's accessible inside
        # blockchain_logger without modifying the DB document.
        chain_receipt = log_evidence_event(
            {**updated, "status": new_status},
            reviewer=reviewer,
        )
        if not chain_receipt.ok:
            # Non-fatal: the DB update already succeeded.  Log the failure
            # prominently so an operator can re-submit manually if needed.
            app.logger.critical(
                "BLOCKCHAIN LOG FAILED for case_id=%s: %s",
                case_id, chain_receipt.error,
            )

    response = _case_to_api_response(updated)
    if chain_receipt is not None:
        response["chain_receipt"] = chain_receipt.to_dict()

    return jsonify(response)


@app.route("/api/reports/<case_id>/audit", methods=["GET"])
def get_audit_log(case_id):
    """Return the full audit trail for a specific case."""
    logs = db.list_audit_logs(case_id=case_id)
    # Serialise datetime objects
    serialised = []
    for entry in logs:
        e = dict(entry)
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].isoformat()
        serialised.append(e)
    return jsonify(serialised)


@app.route("/api/reports/export", methods=["GET"])
def export_reports():
    """
    Export all cases as a UTF-8 CSV download.
    status_history is serialised as a JSON string in the CSV.
    """
    cases = db.list_cases()
    buf = io.StringIO()

    if cases:
        # Build a flat fieldname list from the first document
        fieldnames = list(cases[0].keys())
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for c in cases:
            row = dict(c)
            # Flatten list / dict fields to strings for CSV
            for key in ("reasons", "top_model_factors", "status_history"):
                val = row.get(key)
                if isinstance(val, list):
                    row[key] = json.dumps(val, ensure_ascii=False)
            writer.writerow(row)

    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="flagged_accounts_report.csv",
    )


# --------------------------------------------------------------------------- #
# Dev server
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    app.run(debug=True, port=5000)
