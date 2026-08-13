"""
aggregator.py
=============
Multi-engine signal aggregator for the Fake Social Media Account Detection
platform — modelled after the VirusTotal consensus pattern.

Architecture
------------
  Given a profile URL *or* a (username, platform) pair the orchestrator fans
  out to three independent detection engines in parallel using asyncio, collects
  their individual results into a structured ``AggregatorResult``, and computes:

    • A detection ratio   ("2/3 engines flagged this profile")
    • A weighted final risk score  (0–100)
    • A consensus verdict  ("Likely Fake" / "Suspicious" / "Likely Genuine")

  Each engine runs inside its own asyncio Task with a configurable timeout.
  Any engine that raises, times out, or returns an error is captured, logged as
  ``status="timeout/failed"``, and excluded from the weighted average — the
  remaining engines still produce a valid result.

Engines
-------
  Engine A – Internal Heuristics + ML
    Wraps detector.assess_account() (RandomForest + explainable rules).
    Weight: 0.50  (highest trust — trained on platform-specific data)

  Engine B – Metadata Anomaly Check
    Local rule checker that operates purely on profile metadata fields:
      • Shannon entropy of the username (high entropy → random-looking → bot risk)
      • Username character class composition (digit ratio, special char ratio)
      • Profile-image existence and stock-photo flag
      • Link-shortener URL detection in the bio (bit.ly, tinyurl, t.co, etc.)
      • Display-name / username token-overlap score
      • Bio word count and presence of emoji clusters
      • Engagement anomaly index
    Weight: 0.30

  Engine C – External API Proxy (pluggable mock)
    Simulates queries to external threat-intelligence sources:
      • HaveIBeenPwned-style breach DB lookup
      • Platform-specific spam registry blocklist
      • Public OSINT username reputation databases
      • Disposable-email / temporary-phone association check
    Returns a structured hit count and a normalised risk contribution.
    Weight: 0.20

Usage
-----
  # Async (recommended — call from within an asyncio event loop)
  from aggregator import aggregate_profile
  result = await aggregate_profile(
      url="https://instagram.com/some_account",
      timeout=15.0,
  )
  print(result.to_dict())

  # Sync convenience wrapper
  from aggregator import aggregate_profile_sync
  result = aggregate_profile_sync(
      username="some_account",
      platform="Instagram",
      timeout=15.0,
  )

  # CLI
  python aggregator.py https://instagram.com/some_account
  python aggregator.py --username bot_spam9927 --platform X
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from detector import RawAccount, assess_account

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

#: Per-engine timeout in seconds.  Can be overridden per call.
DEFAULT_ENGINE_TIMEOUT: float = 12.0

#: Engine weights must sum to 1.0.
ENGINE_WEIGHTS: dict[str, float] = {
    "engine_a": 0.50,   # Internal Heuristics + ML
    "engine_b": 0.30,   # Metadata Anomaly Check
    "engine_c": 0.20,   # External API Proxy
}

#: Risk-score thresholds (shared with detector.py conventions).
_THRESHOLD_HIGH       = 70.0
_THRESHOLD_SUSPICIOUS = 40.0

#: Short URL / link-shortener pattern — Engine B.
_SHORTENER_RE = re.compile(
    r"https?://(?:"
    r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|"
    r"rb\.gy|short\.io|cutt\.ly|is\.gd|v\.gd|tiny\.cc|"
    r"shorte\.st|adf\.ly|bc\.vc|sh\.st"
    r")/",
    re.IGNORECASE,
)

#: Engine C — simulated blocklist entries  (username → risk_score 0–100).
_MOCK_BLOCKLIST: dict[str, float] = {
    "bot_spam9927":    95.0,
    "insta_bot_xyz9":  88.0,
    "fakemedia2024":   91.0,
    "spam_promo_99":   87.0,
    "sell_follow_xx":  82.0,
}

#: Engine C — simulated HIBP breach associations  (username → breach_count).
_MOCK_BREACH_DB: dict[str, int] = {
    "bot_spam9927":  12,
    "leaked_acc01":   7,
    "hacked_user88":  5,
}

# --------------------------------------------------------------------------- #
# Shared data structures
# --------------------------------------------------------------------------- #

class EngineStatus(str, Enum):
    OK      = "ok"
    FAILED  = "timeout/failed"
    SKIPPED = "skipped"


@dataclass
class EngineResult:
    """
    Standardised output from a single detection engine.

    Attributes
    ----------
    engine_id    : "engine_a" | "engine_b" | "engine_c"
    engine_name  : Human-readable label.
    status       : ok | timeout/failed | skipped
    risk_score   : 0–100 normalised risk contribution (0 on failure).
    flagged      : True when this engine considers the profile suspicious.
    signals      : List of human-readable detection signals / reasons.
    raw          : Unstructured engine-specific output dict (for debugging).
    latency_ms   : Wall-clock time spent in this engine (milliseconds).
    error        : Exception message on failure, "" on success.
    weight       : Engine weight used in the aggregated score calculation.
    """
    engine_id:   str
    engine_name: str
    status:      EngineStatus  = EngineStatus.OK
    risk_score:  float         = 0.0
    flagged:     bool          = False
    signals:     list[str]     = field(default_factory=list)
    raw:         dict[str, Any]= field(default_factory=dict)
    latency_ms:  float         = 0.0
    error:       str           = ""
    weight:      float         = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_id":   self.engine_id,
            "engine_name": self.engine_name,
            "status":      self.status.value,
            "risk_score":  round(self.risk_score, 1),
            "flagged":     self.flagged,
            "signals":     self.signals,
            "latency_ms":  round(self.latency_ms, 1),
            "error":       self.error,
            "weight":      self.weight,
        }


@dataclass
class AggregatorResult:
    """
    Final aggregated response combining all engine outputs.

    Attributes
    ----------
    username          : Profile username extracted from URL or passed directly.
    platform          : Detected or supplied platform name.
    profile_url       : Original URL (empty if username-only input).
    engines           : Ordered list of EngineResult objects.
    engines_queried   : Total engines attempted.
    engines_succeeded : Engines that returned a valid result.
    engines_flagged   : Engines that flagged the profile as suspicious.
    detection_ratio   : Human-readable ratio string, e.g. "2/3".
    weighted_score    : Final weighted risk score (0–100).
    verdict           : "Likely Fake" | "Suspicious" | "Likely Genuine".
    confidence        : "High" | "Medium" | "Low".
    consensus_signals : Union of all engine signals (de-duplicated).
    scan_timestamp    : UTC ISO-8601 timestamp of the scan.
    total_latency_ms  : Wall-clock time for the full parallel scan.
    """
    username:           str
    platform:           str
    profile_url:        str
    engines:            list[EngineResult] = field(default_factory=list)
    engines_queried:    int   = 0
    engines_succeeded:  int   = 0
    engines_flagged:    int   = 0
    detection_ratio:    str   = "0/0"
    weighted_score:     float = 0.0
    verdict:            str   = "Likely Genuine"
    confidence:         str   = "Low"
    consensus_signals:  list[str] = field(default_factory=list)
    scan_timestamp:     str   = ""
    total_latency_ms:   float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "username":           self.username,
            "platform":           self.platform,
            "profile_url":        self.profile_url,
            "scan_timestamp":     self.scan_timestamp,
            "total_latency_ms":   round(self.total_latency_ms, 1),
            "engines_queried":    self.engines_queried,
            "engines_succeeded":  self.engines_succeeded,
            "engines_flagged":    self.engines_flagged,
            "detection_ratio":    self.detection_ratio,
            "weighted_score":     round(self.weighted_score, 1),
            "verdict":            self.verdict,
            "confidence":         self.confidence,
            "consensus_signals":  self.consensus_signals,
            "engine_matrix":      [e.to_dict() for e in self.engines],
        }


# --------------------------------------------------------------------------- #
# Utility helpers
# --------------------------------------------------------------------------- #

def _shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of *text*.
    Range: 0 (all same character) → log2(len(charset)) (perfectly random).
    """
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isdigit() for ch in text) / len(text)


def _special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(not ch.isalnum() and ch not in ("_", ".") for ch in text) / len(text)


def _verdict_from_score(score: float) -> tuple[str, str]:
    if score >= _THRESHOLD_HIGH:
        return "Likely Fake", "High"
    if score >= _THRESHOLD_SUSPICIOUS:
        return "Suspicious", "Medium"
    return "Likely Genuine", "Low"


def _url_to_username_platform(url_or_username: str) -> tuple[str, str, str]:
    """
    Accept either a full URL or a bare username.
    Returns (username, platform, canonical_url).
    """
    url = url_or_username.strip()
    if url.startswith("http://") or url.startswith("https://"):
        parsed   = urllib.parse.urlparse(url)
        host     = parsed.netloc.lower().lstrip("www.")
        path     = parsed.path.rstrip("/")
        segments = [s for s in path.split("/") if s]
        # Platform detection
        platform_map = {
            "twitter.com": "X",  "x.com": "X",
            "instagram.com": "Instagram",
            "facebook.com": "Facebook",
            "tiktok.com": "TikTok",
            "linkedin.com": "LinkedIn",
            "github.com": "GitHub",
            "reddit.com": "Reddit",
        }
        platform = next((v for k, v in platform_map.items() if k in host), "Generic")
        skip = {"user", "users", "profile", "u", "in", "channel", "c"}
        username = ""
        for seg in segments:
            if seg.lower() not in skip:
                username = seg.lstrip("@")
                break
        return username or "unknown", platform, url
    # Bare username — no URL
    return url.lstrip("@"), "Generic", ""


# --------------------------------------------------------------------------- #
# Engine A — Internal Heuristics + ML  (wraps detector.assess_account)
# --------------------------------------------------------------------------- #

async def _run_engine_a(raw: RawAccount) -> EngineResult:
    """
    Wrap the synchronous assess_account() call in a thread executor so it
    does not block the asyncio event loop.
    """
    t0 = time.perf_counter()
    loop = asyncio.get_event_loop()

    result_obj = await loop.run_in_executor(None, assess_account, raw)
    latency = (time.perf_counter() - t0) * 1000

    score   = result_obj.final_score
    flagged = score >= _THRESHOLD_SUSPICIOUS

    return EngineResult(
        engine_id   = "engine_a",
        engine_name = "Internal Heuristics + ML (RandomForest)",
        status      = EngineStatus.OK,
        risk_score  = score,
        flagged     = flagged,
        signals     = result_obj.reasons + [
            f"Top ML factor: {f}" for f in result_obj.top_model_factors
        ],
        raw         = result_obj.to_dict(),
        latency_ms  = latency,
        weight      = ENGINE_WEIGHTS["engine_a"],
    )


# --------------------------------------------------------------------------- #
# Engine B — Metadata Anomaly Check  (local rule-based, no external calls)
# --------------------------------------------------------------------------- #

def _engine_b_sync(raw: RawAccount) -> EngineResult:
    """
    Pure local rule checker — no I/O, so called directly (not via executor).

    Rules evaluated (each contributes up to a defined risk budget):
      1.  Username entropy > 3.8 (random-looking)        → +20
      2.  Username digit ratio > 0.35                     → +15
      3.  Username special-char ratio > 0.15              → +10
      4.  Display-name / username zero token overlap      → +10
      5.  No profile picture                              → +12
      6.  Profile picture is a stock/stolen image         → +18
      7.  Bio contains a link-shortener URL               → +22
      8.  Bio word count ≤ 2 but account > 30 days old   → +8
      9.  Emoji cluster density > 0.25 of bio tokens     → +6
     10.  Engagement anomaly  (>500 followers, <0.3% ER)  → +12
     11.  Follower/following ratio extreme                 → +15
    """
    t0 = time.perf_counter()
    signals: list[str] = []
    score = 0.0
    username   = raw.username or ""
    bio        = raw.bio or ""
    display    = raw.display_name or ""

    # ── 1. Username entropy ──────────────────────────────────────────────── #
    entropy = _shannon_entropy(username)
    if entropy > 3.8:
        score += 20
        signals.append(f"Username entropy {entropy:.2f} > 3.8 (random-looking)")
    elif entropy > 3.2:
        score += 8
        signals.append(f"Username entropy {entropy:.2f} moderately elevated")

    # ── 2. Username digit ratio ───────────────────────────────────────────── #
    dr = _digit_ratio(username)
    if dr > 0.35:
        score += 15
        signals.append(f"Username digit ratio {dr:.0%} — dominated by numbers")
    elif dr > 0.20:
        score += 5
        signals.append(f"Username digit ratio {dr:.0%} — slightly elevated")

    # ── 3. Special character ratio ────────────────────────────────────────── #
    scr = _special_char_ratio(username)
    if scr > 0.15:
        score += 10
        signals.append(
            f"Username special-char ratio {scr:.0%} — unusual character pattern"
        )

    # ── 4. Display-name / username token overlap ──────────────────────────── #
    u_tokens = set(re.sub(r"[^a-z]", " ", username.lower()).split())
    d_tokens = set(re.sub(r"[^a-z]", " ", display.lower()).split())
    if u_tokens and d_tokens and not u_tokens & d_tokens:
        score += 10
        signals.append("Display name shares no tokens with username")

    # ── 5. Profile picture missing ────────────────────────────────────────── #
    if not raw.has_profile_pic:
        score += 12
        signals.append("No profile picture set")

    # ── 6. Stock / stolen photo ──────────────────────────────────────────── #
    if raw.account_uses_stock_photo:
        score += 18
        signals.append("Profile photo flagged as stock or stolen image")

    # ── 7. Link-shortener in bio ─────────────────────────────────────────── #
    if _SHORTENER_RE.search(bio):
        score += 22
        signals.append(
            "Bio contains a link-shortener URL — common in spam / phishing profiles"
        )

    # ── 8. Thin bio on established account ───────────────────────────────── #
    bio_words = len(bio.split()) if bio.strip() else 0
    if bio_words <= 2 and raw.account_age_days > 30:
        score += 8
        signals.append(
            f"Bio has only {bio_words} word(s) on an account older than 30 days"
        )

    # ── 9. Emoji cluster density ─────────────────────────────────────────── #
    # A rough emoji detector using Unicode ranges
    emoji_count = sum(
        1 for ch in bio
        if ord(ch) in range(0x1F300, 0x1FAFF) or ord(ch) in range(0x2600, 0x27BF)
    )
    bio_token_count = max(len(bio), 1)
    emoji_density = emoji_count / bio_token_count
    if emoji_density > 0.25:
        score += 6
        signals.append(
            f"High emoji density in bio ({emoji_count} emoji / {bio_token_count} chars)"
        )

    # ── 10. Engagement anomaly ────────────────────────────────────────────── #
    if raw.followers > 500 and raw.engagement_rate < 0.003:
        score += 12
        signals.append(
            f"Engagement rate {raw.engagement_rate:.2%} extremely low for "
            f"{raw.followers:,} followers (likely purchased)"
        )

    # ── 11. Follower / following imbalance ────────────────────────────────── #
    if raw.following > 300 and raw.followers / max(raw.following, 1) < 0.02:
        score += 15
        signals.append(
            f"Follows {raw.following:,} but only {raw.followers:,} followers "
            "(mass-following bot behaviour)"
        )

    score = min(score, 100.0)
    flagged = score >= _THRESHOLD_SUSPICIOUS
    latency = (time.perf_counter() - t0) * 1000

    return EngineResult(
        engine_id   = "engine_b",
        engine_name = "Metadata Anomaly Check (local rule-based)",
        status      = EngineStatus.OK,
        risk_score  = score,
        flagged     = flagged,
        signals     = signals,
        raw         = {
            "username_entropy":     round(entropy, 3),
            "digit_ratio":          round(dr, 3),
            "special_char_ratio":   round(scr, 3),
            "bio_word_count":       bio_words,
            "emoji_density":        round(emoji_density, 3),
            "shortener_in_bio":     bool(_SHORTENER_RE.search(bio)),
        },
        latency_ms  = latency,
        weight      = ENGINE_WEIGHTS["engine_b"],
    )


async def _run_engine_b(raw: RawAccount) -> EngineResult:
    """Async wrapper — Engine B is pure CPU so no executor needed."""
    return _engine_b_sync(raw)


# --------------------------------------------------------------------------- #
# Engine C — External API Proxy (pluggable mock)
# --------------------------------------------------------------------------- #

async def _run_engine_c(username: str, platform: str) -> EngineResult:
    """
    Simulates parallel queries to external threat-intelligence sources:
      • HaveIBeenPwned-style breach database
      • Platform blocklist / spam registry
      • OSINT username reputation score
      • Disposable phone/email association check

    In production replace each ``await asyncio.sleep(...)`` stub with a real
    aiohttp call to the respective API endpoint.  The result contract
    (EngineResult) is identical so no downstream changes are required.
    """
    t0 = time.perf_counter()
    signals: list[str] = []
    score   = 0.0

    key = username.lower()

    # ── Sub-query 1: HIBP-style breach DB lookup ─────────────────────────── #
    await asyncio.sleep(0.05)   # simulate I/O latency
    breach_count = _MOCK_BREACH_DB.get(key, 0)
    if breach_count > 0:
        breach_score = min(breach_count * 8, 40)
        score += breach_score
        signals.append(
            f"Username associated with {breach_count} known data breach(es) "
            f"[HIBP-style registry]"
        )

    # ── Sub-query 2: Platform-specific spam blocklist ─────────────────────── #
    await asyncio.sleep(0.04)
    blocklist_score = _MOCK_BLOCKLIST.get(key, 0.0)
    if blocklist_score > 0:
        contribution = blocklist_score * 0.40   # 40% weight in this engine
        score += contribution
        signals.append(
            f"Username found in platform spam blocklist "
            f"(blocklist risk {blocklist_score:.0f}/100)"
        )

    # ── Sub-query 3: OSINT reputation score ──────────────────────────────── #
    await asyncio.sleep(0.03)
    # Heuristic simulation: usernames with >3 digits at end → elevated OSINT risk
    trailing_digits = len(re.search(r"\d*$", username).group())
    if trailing_digits >= 4:
        osint_score = min(trailing_digits * 4, 20)
        score += osint_score
        signals.append(
            f"Username ends with {trailing_digits} sequential digits "
            f"(OSINT pattern: common in auto-generated bot accounts)"
        )

    # ── Sub-query 4: Disposable-phone / temp-email association ───────────── #
    await asyncio.sleep(0.02)
    # Simulation: profiles on certain platforms with zero posts → check flag
    # In production: call an email/phone reputation API here
    if platform.lower() in ("x", "twitter") and key.endswith("9"):
        score += 5
        signals.append(
            "Username suffix pattern matches disposable-account naming convention"
        )

    score = min(score, 100.0)
    flagged = score >= _THRESHOLD_SUSPICIOUS
    latency = (time.perf_counter() - t0) * 1000

    return EngineResult(
        engine_id   = "engine_c",
        engine_name = "External API Proxy (HaveIBeenPwned / blocklists / OSINT)",
        status      = EngineStatus.OK,
        risk_score  = score,
        flagged     = flagged,
        signals     = signals,
        raw         = {
            "breach_count":       breach_count,
            "blocklist_score":    blocklist_score,
            "trailing_digits":    trailing_digits,
        },
        latency_ms  = latency,
        weight      = ENGINE_WEIGHTS["engine_c"],
    )


# --------------------------------------------------------------------------- #
# Engine wrapper — timeout + exception isolation
# --------------------------------------------------------------------------- #

async def _run_engine_safe(
    engine_id:   str,
    engine_name: str,
    coro,
    timeout:     float,
) -> EngineResult:
    """
    Execute *coro* with a hard timeout.  On any exception (including
    asyncio.TimeoutError) returns a failed EngineResult so the aggregator
    pipeline never crashes.
    """
    t0 = time.perf_counter()
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        msg = f"Engine timed out after {timeout:.1f}s"
        logger.warning("[%s] %s", engine_id, msg)
        return EngineResult(
            engine_id   = engine_id,
            engine_name = engine_name,
            status      = EngineStatus.FAILED,
            error       = msg,
            latency_ms  = (time.perf_counter() - t0) * 1000,
            weight      = ENGINE_WEIGHTS.get(engine_id, 0.0),
        )
    except Exception as exc:  # pylint: disable=broad-except
        msg = f"{type(exc).__name__}: {exc}"
        logger.error("[%s] Exception: %s", engine_id, msg, exc_info=True)
        return EngineResult(
            engine_id   = engine_id,
            engine_name = engine_name,
            status      = EngineStatus.FAILED,
            error       = msg,
            latency_ms  = (time.perf_counter() - t0) * 1000,
            weight      = ENGINE_WEIGHTS.get(engine_id, 0.0),
        )


# --------------------------------------------------------------------------- #
# Score aggregation
# --------------------------------------------------------------------------- #

def _aggregate_scores(results: list[EngineResult]) -> tuple[float, int, int]:
    """
    Compute the weighted average risk score from all *successful* engines.

    Failed engines are excluded from both the numerator and the denominator
    so the remaining engines' weights are re-normalised automatically.

    Returns (weighted_score, engines_succeeded, engines_flagged).
    """
    ok_results = [r for r in results if r.status == EngineStatus.OK]
    if not ok_results:
        return 0.0, 0, 0

    total_weight  = sum(r.weight for r in ok_results)
    weighted_sum  = sum(r.risk_score * r.weight for r in ok_results)
    weighted_score = weighted_sum / total_weight if total_weight > 0 else 0.0

    engines_flagged = sum(1 for r in ok_results if r.flagged)
    return round(weighted_score, 2), len(ok_results), engines_flagged


# --------------------------------------------------------------------------- #
# Public API — async entry point
# --------------------------------------------------------------------------- #

async def aggregate_profile(
    url:      str | None = None,
    username: str | None = None,
    platform: str        = "Generic",
    raw:      RawAccount | None = None,
    timeout:  float      = DEFAULT_ENGINE_TIMEOUT,
) -> AggregatorResult:
    """
    Fan out to all three detection engines in parallel and aggregate results.

    Parameters
    ----------
    url      : Full public profile URL (e.g. "https://x.com/some_user").
               If supplied, username and platform are extracted automatically.
    username : Profile username.  Used when *url* is not available.
    platform : Platform name.  Used together with *username*.
    raw      : Pre-built RawAccount.  Bypasses scraping when supplied.
               If None and no *url* is given, a minimal RawAccount is
               constructed from username + platform for Engine A.
    timeout  : Per-engine timeout in seconds.

    Returns
    -------
    AggregatorResult
        Always returns (never raises).  Check ``result.engines`` for
        individual engine statuses when debugging partial failures.
    """
    wall_start = time.perf_counter()

    # ── Resolve username / platform / url ──────────────────────────────── #
    if url:
        _username, _platform, _canonical_url = _url_to_username_platform(url)
        username = username or _username
        platform = platform if platform != "Generic" else _platform
        profile_url = _canonical_url
    else:
        profile_url = ""
        username = username or "unknown"

    # ── Build RawAccount for Engine A if not provided ─────────────────── #
    if raw is None:
        if url:
            # Use scraper if URL is available; fall back gracefully
            try:
                from scraper import scrape_profile  # noqa: PLC0415
                loop = asyncio.get_event_loop()
                scrape_result = await loop.run_in_executor(
                    None, scrape_profile, url
                )
                raw = scrape_result.account
                logger.info(
                    "Scraper: source=%s  scrape_ok=%s",
                    scrape_result.source, scrape_result.scrape_ok,
                )
            except Exception as exc:
                logger.warning("Scraper failed, using minimal RawAccount: %s", exc)
                raw = RawAccount(username=username, platform=platform)
        else:
            raw = RawAccount(username=username, platform=platform)

    logger.info(
        "Aggregator starting scan: username=%r  platform=%r  timeout=%.1fs",
        username, platform, timeout,
    )

    # ── Launch all three engines concurrently ─────────────────────────── #
    engine_tasks = [
        _run_engine_safe("engine_a", "Internal Heuristics + ML",
                         _run_engine_a(raw), timeout),
        _run_engine_safe("engine_b", "Metadata Anomaly Check",
                         _run_engine_b(raw), timeout),
        _run_engine_safe("engine_c", "External API Proxy",
                         _run_engine_c(username, platform), timeout),
    ]

    engine_results: list[EngineResult] = list(
        await asyncio.gather(*engine_tasks)
    )

    # ── Aggregate ─────────────────────────────────────────────────────── #
    weighted_score, succeeded, flagged = _aggregate_scores(engine_results)
    verdict, confidence = _verdict_from_score(weighted_score)
    total = len(engine_results)

    # Consensus signals: union of all engine signals, de-duplicated, ordered
    seen: set[str] = set()
    consensus: list[str] = []
    for er in engine_results:
        if er.status == EngineStatus.OK:
            for sig in er.signals:
                if sig not in seen:
                    seen.add(sig)
                    consensus.append(sig)

    wall_ms = (time.perf_counter() - wall_start) * 1000

    result = AggregatorResult(
        username          = username,
        platform          = platform,
        profile_url       = profile_url,
        engines           = engine_results,
        engines_queried   = total,
        engines_succeeded = succeeded,
        engines_flagged   = flagged,
        detection_ratio   = f"{flagged}/{total}",
        weighted_score    = weighted_score,
        verdict           = verdict,
        confidence        = confidence,
        consensus_signals = consensus,
        scan_timestamp    = datetime.now(timezone.utc).isoformat(),
        total_latency_ms  = round(wall_ms, 1),
    )

    logger.info(
        "Aggregator complete: %s  score=%.1f  verdict=%s  ratio=%s  "
        "total_ms=%.0f",
        username, weighted_score, verdict,
        result.detection_ratio, wall_ms,
    )
    return result


# --------------------------------------------------------------------------- #
# Public API — synchronous convenience wrapper
# --------------------------------------------------------------------------- #

def aggregate_profile_sync(
    url:      str | None = None,
    username: str | None = None,
    platform: str        = "Generic",
    raw:      RawAccount | None = None,
    timeout:  float      = DEFAULT_ENGINE_TIMEOUT,
) -> AggregatorResult:
    """
    Synchronous wrapper around ``aggregate_profile()``.

    Creates (or reuses) an asyncio event loop.  Safe to call from any
    non-async context including Flask route handlers and unit tests.
    """
    try:
        loop = asyncio.get_running_loop()
        # Already inside a running loop (e.g. Jupyter / FastAPI).
        # Schedule as a coroutine and return the future.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                aggregate_profile(
                    url=url, username=username, platform=platform,
                    raw=raw, timeout=timeout,
                ),
            )
            return future.result()
    except RuntimeError:
        # No running loop — use asyncio.run() directly.
        return asyncio.run(
            aggregate_profile(
                url=url, username=username, platform=platform,
                raw=raw, timeout=timeout,
            )
        )


# --------------------------------------------------------------------------- #
# Flask route helper — drop-in for app.py integration
# --------------------------------------------------------------------------- #

def scan_profile_endpoint(payload: dict) -> dict:
    """
    Thin adapter for calling from a Flask route handler.

    Accepts the same JSON payload shape as /api/scan (username, platform, etc.)
    *plus* an optional ``profile_url`` field.  Returns result.to_dict().

    Example
    -------
    @app.route("/api/aggregate", methods=["POST"])
    def aggregate():
        from aggregator import scan_profile_endpoint
        return jsonify(scan_profile_endpoint(request.get_json(force=True) or {}))
    """
    url      = payload.get("profile_url", "").strip() or None
    username = payload.get("username",    "").strip() or None
    platform = payload.get("platform",    "Generic").strip()
    timeout  = float(payload.get("timeout", DEFAULT_ENGINE_TIMEOUT))

    # If full account fields are present, build a RawAccount directly
    raw: RawAccount | None = None
    if username and any(k in payload for k in ("followers", "bio", "posts_count")):
        try:
            raw = RawAccount(
                username=username,
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
                platform=platform,
            )
        except (ValueError, TypeError) as exc:
            logger.warning("Could not build RawAccount from payload: %s", exc)

    result = aggregate_profile_sync(
        url=url, username=username, platform=platform,
        raw=raw, timeout=timeout,
    )
    return result.to_dict()


# --------------------------------------------------------------------------- #
# CLI entry-point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="Multi-engine fake-profile aggregator (VirusTotal pattern)"
    )
    parser.add_argument(
        "url", nargs="?", default=None,
        help="Full public profile URL to scan (e.g. https://x.com/some_user)",
    )
    parser.add_argument("--username", "-u", default=None, help="Username")
    parser.add_argument("--platform", "-p", default="Generic", help="Platform name")
    parser.add_argument(
        "--timeout", "-t", type=float, default=DEFAULT_ENGINE_TIMEOUT,
        help=f"Per-engine timeout in seconds (default: {DEFAULT_ENGINE_TIMEOUT})",
    )
    parser.add_argument(
        "--json", "-j", action="store_true",
        help="Print full JSON result instead of the formatted summary",
    )
    args = parser.parse_args()

    if not args.url and not args.username:
        parser.error("Provide a profile URL or --username / --platform.")

    result = aggregate_profile_sync(
        url=args.url,
        username=args.username,
        platform=args.platform,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        # Formatted human-readable summary
        r = result
        bar = "=" * 60
        print(f"\n{bar}")
        print(f"  Fake Profile Aggregator — Scan Report")
        print(bar)
        print(f"  Username      : {r.username}")
        print(f"  Platform      : {r.platform}")
        print(f"  Scanned at    : {r.scan_timestamp}")
        print(f"  Total time    : {r.total_latency_ms:.0f} ms")
        print(bar)
        print(f"  Detection     : {r.detection_ratio} engines flagged this profile")
        print(f"  Weighted Score: {r.weighted_score:.1f} / 100")
        print(f"  Verdict       : {r.verdict}  [{r.confidence} confidence]")
        print(bar)

        for eng in r.engines:
            icon = "[OK]" if eng.status == EngineStatus.OK else "[!!]"
            flag = " (FLAGGED)" if eng.flagged else ""
            print(f"\n  {icon} {eng.engine_name}{flag}")
            print(f"       Status     : {eng.status.value}")
            print(f"       Risk Score : {eng.risk_score:.1f}  Weight: {eng.weight:.0%}")
            print(f"       Latency    : {eng.latency_ms:.0f} ms")
            if eng.error:
                print(f"       Error      : {eng.error}")
            for sig in eng.signals[:5]:
                print(f"       - {sig}")
            if len(eng.signals) > 5:
                print(f"       ... and {len(eng.signals) - 5} more signal(s)")

        print(f"\n{bar}")
        print("  Consensus Signals:")
        for sig in r.consensus_signals:
            print(f"    * {sig}")
        print(f"{bar}\n")
