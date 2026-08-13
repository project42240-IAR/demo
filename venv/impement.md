Architecture
aggregate_profile()  ── asyncio.gather() ──┬── Engine A (50% weight)
                                           │   assess_account() via run_in_executor
                                           │
                                           ├── Engine B (30% weight)
                                           │   Local rules: entropy, shorteners,
                                           │   engagement anomaly, emoji density
                                           │
                                           └── Engine C (20% weight)
                                               HIBP mock, blocklist, OSINT,
                                               disposable-account pattern
Each engine wrapped in _run_engine_safe() → timeout + exception isolation
Engine-by-engine breakdown
Engine	Weight	Signals checked	Detection
A — ML + Heuristics	50%	12 RandomForest features, 12 rule checks	bot_spam9927 → 32.2
B — Metadata Anomaly	30%	Shannon entropy, digit ratio, link-shortener regex, engagement anomaly, emoji density, display-name overlap	bit.ly in bio → flagged
C — External API Proxy	20%	HIBP breach count, spam blocklist, trailing-digit OSINT pattern, disposable-account suffix check	12 breaches → 94/100
Key resilience properties
Scenario	Behaviour
Engine raises RuntimeError	Logged at ERROR, status="timeout/failed", pipeline continues
Engine exceeds timeout	asyncio.TimeoutError caught, same graceful degradation
All engines fail	Returns weighted_score=0, verdict="Likely Genuine" (safe default), 0/3 ratio
2-of-3 fail	Remaining engine's weight re-normalised to 100% automatically
New API endpoint in app.py
POST /api/aggregate
{ "profile_url": "https://x.com/bot_spam9927" }
   -- or --
{ "username": "bot_spam9927", "platform": "X",
  "followers": 23, "following": 4800, "bio": "" }
Returns detection_ratio, weighted_score, verdict, and full engine_matrix with per-engine risk_score, signals, latency_ms, and status.

