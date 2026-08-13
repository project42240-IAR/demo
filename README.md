# SENTRY — Fake Social Media Account Detection & Reporting System

Prototype for **PS-SW-003 · Software · Blockchain & Cybersecurity** (SIH Sprint 2026).

Detects likely-fake profiles on social platforms from observable account signals,
explains *why* an account was flagged, and routes flagged accounts into a case log
that stands in for the "designated central agency" the problem statement calls for
— the body that would approach the platform for suspension or pursue legal action.

## How it addresses the brief

| Requirement from PS-SW-003 | How this prototype covers it |
|---|---|
| Tool to identify fake profiles on popular social platforms | `detector.py` — rule engine + trained classifier scoring any profile 0–100 |
| Explainable identification, not a black box | Every score comes with the specific signals that triggered it (empty bio, stock photo, bot-like posting cadence, etc.) |
| Central agency informed of identified fake accounts | `/api/report` files a case into `case_log.json`, viewable in the **Case Log** panel |
| Time-bound handling until suspension | Case log has a status pipeline: `Pending Agency Review → Escalated to Platform → Account Suspended` (or `Dismissed – False Positive`) |
| Works across platforms (Facebook, Instagram, Twitter, etc.) | Detection is platform-agnostic — a `platform` tag is attached per scan/report rather than hard-coded logic per site |

## Architecture

```
Browser (dashboard)
   │  fetch()
   ▼
Flask app (app.py)
   │
   ├── /api/scan     → detector.py: feature engineering → rule score + ML score → blended verdict
   ├── /api/report    → appends a case to case_log.json (stand-in for the central agency's queue)
   ├── /api/reports    → lists filed cases for the dashboard table
   └── /api/reports/export → CSV download for handing off to the agency / compliance team
```

**Detection engine (`detector.py`)** — two layers, blended 45/55:
1. **Rule-based heuristics** (transparent, auditable): account age, missing/stock
   profile photo, empty bio, digit-heavy usernames, extreme follower/following
   imbalance, abnormal posting frequency, near-zero engagement despite a large
   following, frequent username changes, zero posts on an old account.
2. **Trained classifier** (`RandomForestClassifier`, scikit-learn): catches
   non-obvious combinations of the same underlying features that hand-written
   rules would miss. Trained on `data/synthetic_accounts.csv`, a synthetic
   dataset built to mirror realistic genuine vs. fake account distributions.

> **Production note:** real platform API access (Meta Graph API, X API, etc.) and
> genuine labeled takedown data were out of scope for a sprint prototype. Swap
> `data/generate_synthetic_data.py`'s output for real historical data and the
> same pipeline (`engineer_features` → `RandomForestClassifier`) retrains as-is.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`. Use **Load suspicious example** / **Load
genuine example** on the dashboard for a quick demo without typing data by hand.

The classifier trains itself automatically on first run (a few seconds) and
caches to `model/rf_model.joblib`. Delete that file to force a retrain.

## Project layout

```
fake-account-detector/
├── app.py                    Flask routes (scan, report, case log, CSV export)
├── detector.py                Feature engineering, rule engine, ML classifier
├── requirements.txt
├── data/
│   ├── generate_synthetic_data.py   Synthetic training-data generator
│   └── synthetic_accounts.csv       Generated training set (1,200 rows)
├── model/                     Trained model cache (created on first run)
├── templates/index.html       Dashboard UI
└── static/
    ├── style.css
    └── script.js
```

## Suggested next steps for the full submission

- Replace synthetic training data with a real, labeled dataset (platform
  takedown records, or a public fake-account benchmark dataset).
- Add platform API connectors (subject to each platform's developer terms) so
  scans can be run directly from a username instead of manual field entry.
- Give the central-agency case log persistent storage (a real database) and
  role-based access instead of the local JSON file used for this prototype.
- Add an audit trail per case (who reviewed it, when, and why) for legal
  defensibility if a flagged account disputes the takedown.
# devlop-repo
# demo
