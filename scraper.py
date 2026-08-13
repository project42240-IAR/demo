"""
scraper.py
==========
Lightweight OSINT scraper module for the Fake Social Media Account Detection platform.

Architecture
------------
  Layer 1  – BeautifulSoup-based HTTP scraper
               Fetches the public profile page with randomised headers + exponential
               back-off.  Extracts bio text, follower/following/post counts, and
               whether a profile-image element is present.

  Layer 2  – Playwright async scraper (optional)
               Falls back to a headless Chromium session when the page requires
               JavaScript to render (e.g. React/Next-JS SPAs).  Only imported when
               needed so the module stays usable even if playwright is not installed.

  Layer 3  – Mock fallback
               Activated when both live scrapers fail (rate-limit / hard block /
               CAPTCHA / network error).  Returns a realistic sample profile from the
               built-in MOCK_PROFILES dictionary so that downstream code keeps working
               during development, CI, or when the target site is temporarily down.

Output
------
  Every scrape path returns a ``RawAccount`` dataclass instance that is passed
  directly to ``assess_account()`` in detector.py without any transformation.

Security / Safety notes
-----------------------
  • No credentials are stored or transmitted.
  • Robots.txt is consulted before every live scrape; non-compliant paths are
    skipped and the mock profile is returned instead.
  • All HTTP calls are made through a dedicated requests.Session with a 10-second
    timeout and TLS verification enabled.
  • Rate-limit / 429 / 403 responses trigger immediate fallback to the mock layer;
    no retry-storm is possible.
  • No cookies are persisted to disk.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import time
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Any

import requests
from bs4 import BeautifulSoup

# RawAccount is defined in detector.py; import it to avoid duplication.
from detector import RawAccount

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Constants & helpers
# --------------------------------------------------------------------------- #

_TIMEOUT = 10          # seconds per HTTP request
_MAX_RETRIES = 2       # live-scrape attempts before falling back to mock
_BACKOFF_BASE = 1.5    # seconds, exponentially multiplied on each retry

# Rotate User-Agent strings to reduce trivial bot-detection fingerprinting.
_USER_AGENTS: list[str] = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4.1 Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
]

# Platform detection by hostname keyword
_PLATFORM_MAP: dict[str, str] = {
    "twitter.com": "X",
    "x.com": "X",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "linkedin.com": "LinkedIn",
    "tiktok.com": "TikTok",
    "github.com": "GitHub",
    "reddit.com": "Reddit",
}


def _detect_platform(url: str) -> str:
    """Return a human-readable platform name derived from the URL hostname."""
    host = urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
    for keyword, name in _PLATFORM_MAP.items():
        if keyword in host:
            return name
    return "Generic"


def _extract_username(url: str) -> str:
    """Best-effort username extraction from common profile URL patterns."""
    path = urllib.parse.urlparse(url).path.rstrip("/")
    segments = [s for s in path.split("/") if s]
    # Remove common non-user path prefixes
    skip = {"user", "users", "profile", "u", "in", "channel", "c"}
    for seg in segments:
        if seg.lower() not in skip and not seg.startswith("@"):
            return seg.lstrip("@")
    return segments[-1].lstrip("@") if segments else "unknown"


def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    return session


# --------------------------------------------------------------------------- #
# Robots.txt compliance helper
# --------------------------------------------------------------------------- #

_robots_cache: dict[str, urllib.robotparser.RobotFileParser] = {}


def _is_allowed(url: str, user_agent: str = "*") -> bool:
    """Return True if robots.txt permits fetching *url*."""
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    if robots_url not in _robots_cache:
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
        except Exception:
            # If robots.txt is unreachable assume allowed (conservative approach).
            _robots_cache[robots_url] = None  # type: ignore[assignment]
        else:
            _robots_cache[robots_url] = rp
    rp = _robots_cache.get(robots_url)
    if rp is None:
        return True
    return rp.can_fetch(user_agent, url)


# --------------------------------------------------------------------------- #
# Extraction helpers (platform-aware CSS/regex selectors)
# --------------------------------------------------------------------------- #

@dataclass
class _RawParsed:
    """Intermediate, unvalidated data container from HTML parsing."""
    bio: str = ""
    followers: int = 0
    following: int = 0
    posts_count: int = 0
    has_profile_pic: bool = False
    display_name: str = ""
    account_age_days: float = 365.0
    avg_posts_per_day: float = 0.5
    engagement_rate: float = 0.05
    account_uses_stock_photo: bool = False
    recent_username_changes: int = 0


def _parse_count(text: str | None) -> int:
    """Convert human-readable counts like '12.4K', '1.2M' → int."""
    if not text:
        return 0
    text = text.strip().replace(",", "")
    multipliers = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}
    match = re.match(r"([\d.]+)\s*([kmb]?)", text.lower())
    if not match:
        return 0
    value, suffix = match.groups()
    return int(float(value) * multipliers.get(suffix, 1))


def _parse_generic(soup: BeautifulSoup) -> _RawParsed:
    """
    Generic parser: tries common Open Graph / schema.org / heuristic selectors.
    Works reasonably well on many social platforms that embed metadata.
    """
    parsed = _RawParsed()

    # --- display name ---
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        parsed.display_name = str(og_title["content"]).split("|")[0].strip()

    # --- bio ---
    og_desc = soup.find("meta", property="og:description")
    if og_desc and og_desc.get("content"):
        parsed.bio = str(og_desc["content"]).strip()
    elif soup.find("meta", attrs={"name": "description"}):
        parsed.bio = str(
            soup.find("meta", attrs={"name": "description"})["content"]  # type: ignore[index]
        ).strip()

    # --- profile image ---
    og_image = soup.find("meta", property="og:image")
    parsed.has_profile_pic = bool(og_image and og_image.get("content"))

    # --- follower / following / post counts via text heuristics ---
    text = soup.get_text(" ", strip=True)
    for pattern, attr in [
        (r"([\d.,]+[kmb]?)\s*(?:followers?)", "followers"),
        (r"([\d.,]+[kmb]?)\s*(?:following)", "following"),
        (r"([\d.,]+[kmb]?)\s*(?:posts?|tweets?|videos?|photos?)", "posts_count"),
    ]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            setattr(parsed, attr, _parse_count(m.group(1)))

    return parsed


def _parse_x(soup: BeautifulSoup) -> _RawParsed:
    """
    X (Twitter) specific parser.
    X's public page embeds a JSON blob inside <script id="__NEXT_DATA__">
    which is accessible without JS execution on the legacy render path.
    """
    import json

    parsed = _parse_generic(soup)  # baseline

    script = soup.find("script", id="__NEXT_DATA__")
    if script and script.string:
        try:
            data = json.loads(script.string)
            props = (
                data.get("props", {})
                .get("pageProps", {})
                .get("timeline", {})
                .get("entries", [{}])[0]
                .get("content", {})
                .get("itemContent", {})
                .get("tweet_results", {})
                .get("result", {})
                .get("core", {})
                .get("user_results", {})
                .get("result", {})
                .get("legacy", {})
            )
            if props:
                parsed.followers = props.get("followers_count", parsed.followers)
                parsed.following = props.get("friends_count", parsed.following)
                parsed.posts_count = props.get("statuses_count", parsed.posts_count)
                parsed.bio = props.get("description", parsed.bio)
                parsed.display_name = props.get("name", parsed.display_name)
                parsed.has_profile_pic = bool(
                    props.get("profile_image_url_https", "")
                    and "default_profile" not in props.get("profile_image_url_https", "")
                )
                created_at = props.get("created_at", "")
                if created_at:
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.strptime(created_at, "%a %b %d %H:%M:%S +0000 %Y")
                        parsed.account_age_days = (
                            datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)
                        ).days
                    except ValueError:
                        pass
        except (json.JSONDecodeError, KeyError, IndexError):
            pass  # fall back to generic parse result

    return parsed


def _parse_instagram(soup: BeautifulSoup) -> _RawParsed:
    """
    Instagram specific parser using the og: tags Instagram still embeds
    in its server-rendered HTML.  The full follower count is encoded in
    the description meta tag as: "X Followers, Y Following, Z Posts".
    """
    parsed = _parse_generic(soup)  # baseline

    desc = ""
    og_desc = soup.find("meta", property="og:description")
    if og_desc and og_desc.get("content"):
        desc = str(og_desc["content"])

    m = re.match(
        r"([\d,]+[kmb]?)\s+Followers?,\s*([\d,]+[kmb]?)\s+Following,\s*([\d,]+[kmb]?)\s+Posts?",
        desc,
        re.IGNORECASE,
    )
    if m:
        parsed.followers = _parse_count(m.group(1))
        parsed.following = _parse_count(m.group(2))
        parsed.posts_count = _parse_count(m.group(3))

    return parsed


# Registry of platform-specific parsers
_PARSERS: dict[str, Any] = {
    "X": _parse_x,
    "Instagram": _parse_instagram,
}


def _html_to_raw_parsed(html: str, platform: str) -> _RawParsed:
    soup = BeautifulSoup(html, "html.parser")
    parser_fn = _PARSERS.get(platform, _parse_generic)
    return parser_fn(soup)


# --------------------------------------------------------------------------- #
# Layer 1 – BeautifulSoup HTTP scraper
# --------------------------------------------------------------------------- #

class ScraperError(Exception):
    """Raised when both live-scrape layers have been exhausted."""


class RateLimitError(ScraperError):
    """Raised on HTTP 429 / 403 so the caller can immediately fall back."""


def _fetch_html_requests(url: str) -> str:
    """
    Fetch *url* using requests, with retry logic and exponential back-off.

    Raises
    ------
    RateLimitError  – on 429 / 403 (signal to fall back to mock immediately)
    ScraperError    – on persistent failure after _MAX_RETRIES attempts
    """
    session = _make_session()
    last_exc: Exception | None = None

    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=_TIMEOUT, verify=True)
            if response.status_code in (429, 403):
                raise RateLimitError(
                    f"HTTP {response.status_code} received – rate-limited or blocked."
                )
            if response.status_code != 200:
                raise ScraperError(
                    f"Unexpected HTTP {response.status_code} from {url!r}"
                )
            return response.text

        except RateLimitError:
            raise  # propagate immediately – no retries for rate-limit
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            wait = _BACKOFF_BASE ** attempt + random.uniform(0, 0.5)
            logger.warning("Attempt %d failed: %s – retrying in %.1fs", attempt + 1, exc, wait)
            time.sleep(wait)

    raise ScraperError(
        f"All {_MAX_RETRIES + 1} HTTP attempts failed for {url!r}"
    ) from last_exc


# --------------------------------------------------------------------------- #
# Layer 2 – Playwright async scraper
# --------------------------------------------------------------------------- #

async def _fetch_html_playwright_async(url: str) -> str:
    """
    Headless Chromium rendering via Playwright.
    Only called when the BS4 layer returns an empty / unparse-able page.

    Raises
    ------
    ImportError   – if playwright is not installed
    ScraperError  – on navigation / timeout errors
    """
    try:
        from playwright.async_api import async_playwright, TimeoutError as PwTimeout
    except ImportError as exc:
        raise ImportError(
            "playwright is not installed. Run: pip install playwright && playwright install chromium"
        ) from exc

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=random.choice(_USER_AGENTS),
            locale="en-US",
            java_script_enabled=True,
            bypass_csp=False,
        )
        page = await context.new_page()
        try:
            await page.goto(url, timeout=_TIMEOUT * 1000, wait_until="domcontentloaded")
            # Wait a beat for any lazy-loaded metadata
            await page.wait_for_timeout(2000)
            return await page.content()
        except PwTimeout as exc:
            raise ScraperError(f"Playwright timed out on {url!r}") from exc
        finally:
            await browser.close()


def _fetch_html_playwright(url: str) -> str:
    """Synchronous wrapper around the async Playwright scraper."""
    return asyncio.run(_fetch_html_playwright_async(url))


# --------------------------------------------------------------------------- #
# Layer 3 – Mock / fallback profiles
# --------------------------------------------------------------------------- #

# Keyed by (platform_lower, username_lower).
# username "*" acts as a catch-all for that platform.
MOCK_PROFILES: dict[tuple[str, str], dict[str, Any]] = {
    # ── X / Twitter samples ────────────────────────────────────────────────
    ("x", "realuser123"): {
        "display_name": "Real User",
        "account_age_days": 1280,
        "followers": 840,
        "following": 312,
        "posts_count": 2100,
        "has_profile_pic": True,
        "bio": "Software dev | coffee addict | opinions are my own",
        "avg_posts_per_day": 1.6,
        "engagement_rate": 0.045,
        "account_uses_stock_photo": False,
        "recent_username_changes": 0,
    },
    ("x", "bot_spam9927"): {
        "display_name": "Bot Spammer",
        "account_age_days": 14,
        "followers": 23,
        "following": 4800,
        "posts_count": 0,
        "has_profile_pic": False,
        "bio": "",
        "avg_posts_per_day": 0.0,
        "engagement_rate": 0.001,
        "account_uses_stock_photo": False,
        "recent_username_changes": 3,
    },
    # X catch-all
    ("x", "*"): {
        "display_name": "Sample X User",
        "account_age_days": 420,
        "followers": 510,
        "following": 380,
        "posts_count": 740,
        "has_profile_pic": True,
        "bio": "Tweeting about things. Not affiliated with anyone.",
        "avg_posts_per_day": 1.8,
        "engagement_rate": 0.04,
        "account_uses_stock_photo": False,
        "recent_username_changes": 0,
    },
    # ── Instagram samples ──────────────────────────────────────────────────
    ("instagram", "travel.addict_real"): {
        "display_name": "Travel Addict",
        "account_age_days": 2100,
        "followers": 15_400,
        "following": 620,
        "posts_count": 310,
        "has_profile_pic": True,
        "bio": "Wanderer. Photographer. 50+ countries 🌍",
        "avg_posts_per_day": 0.15,
        "engagement_rate": 0.072,
        "account_uses_stock_photo": False,
        "recent_username_changes": 1,
    },
    ("instagram", "insta_bot_xyz9"): {
        "display_name": "insta_bot_xyz9",
        "account_age_days": 7,
        "followers": 5,
        "following": 7800,
        "posts_count": 0,
        "has_profile_pic": True,
        "bio": "",
        "avg_posts_per_day": 0.0,
        "engagement_rate": 0.0,
        "account_uses_stock_photo": True,
        "recent_username_changes": 0,
    },
    # Instagram catch-all
    ("instagram", "*"): {
        "display_name": "Sample Instagram User",
        "account_age_days": 730,
        "followers": 1_200,
        "following": 540,
        "posts_count": 88,
        "has_profile_pic": True,
        "bio": "Living life one post at a time 📸",
        "avg_posts_per_day": 0.12,
        "engagement_rate": 0.06,
        "account_uses_stock_photo": False,
        "recent_username_changes": 0,
    },
    # ── Generic / unknown platform catch-all ──────────────────────────────
    ("generic", "*"): {
        "display_name": "Demo User",
        "account_age_days": 180,
        "followers": 200,
        "following": 150,
        "posts_count": 30,
        "has_profile_pic": True,
        "bio": "Demo profile – live scrape was blocked or rate-limited.",
        "avg_posts_per_day": 0.17,
        "engagement_rate": 0.05,
        "account_uses_stock_photo": False,
        "recent_username_changes": 0,
    },
}


def _get_mock_profile(platform: str, username: str) -> dict[str, Any]:
    """
    Look up a mock profile, falling back to the platform wildcard,
    then the generic wildcard.
    """
    key_platform = platform.lower()
    key_user = username.lower()

    # Exact match
    if (key_platform, key_user) in MOCK_PROFILES:
        return dict(MOCK_PROFILES[(key_platform, key_user)])

    # Platform wildcard
    if (key_platform, "*") in MOCK_PROFILES:
        return dict(MOCK_PROFILES[(key_platform, "*")])

    # Generic wildcard
    return dict(MOCK_PROFILES[("generic", "*")])


def _mock_raw_account(url: str, reason: str) -> RawAccount:
    """
    Return a mock RawAccount when live scraping is unavailable.
    Logs a warning so the caller is always aware that mock data is in use.
    """
    platform = _detect_platform(url)
    username = _extract_username(url)
    logger.warning(
        "Live scrape failed for %r (%s). Returning MOCK profile for platform=%r, user=%r.",
        url, reason, platform, username,
    )
    profile = _get_mock_profile(platform, username)
    return RawAccount(
        username=username,
        platform=platform,
        display_name=profile.get("display_name", username),
        account_age_days=profile.get("account_age_days", 365.0),
        followers=profile.get("followers", 0),
        following=profile.get("following", 0),
        posts_count=profile.get("posts_count", 0),
        has_profile_pic=profile.get("has_profile_pic", True),
        bio=profile.get("bio", ""),
        avg_posts_per_day=profile.get("avg_posts_per_day", 0.5),
        engagement_rate=profile.get("engagement_rate", 0.05),
        account_uses_stock_photo=profile.get("account_uses_stock_photo", False),
        recent_username_changes=profile.get("recent_username_changes", 0),
    )


# --------------------------------------------------------------------------- #
# Result dataclass (wraps RawAccount + scrape metadata)
# --------------------------------------------------------------------------- #

@dataclass
class ScrapeResult:
    """
    Container returned by ``scrape_profile()``.

    Attributes
    ----------
    account   : RawAccount instance ready for ``assess_account()``
    source    : "live_bs4" | "live_playwright" | "mock"
    scrape_ok : True when live data was successfully retrieved
    error_msg : Human-readable reason for falling back to mock, or ""
    """
    account: RawAccount
    source: str
    scrape_ok: bool
    error_msg: str = ""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def scrape_profile(url: str, *, force_mock: bool = False) -> ScrapeResult:
    """
    Scrape a public social-media profile URL and return a ``ScrapeResult``.

    Parameters
    ----------
    url         : Fully qualified public profile URL.
    force_mock  : If True, skip live scraping entirely (useful in testing /
                  offline environments).

    Returns
    -------
    ScrapeResult – always returns a result; never raises an unhandled exception.

    Example
    -------
    >>> from scraper import scrape_profile
    >>> from detector import assess_account
    >>> result = scrape_profile("https://x.com/realuser123")
    >>> assessment = assess_account(result.account)
    """
    url = url.strip()
    platform = _detect_platform(url)
    username = _extract_username(url)

    # ── Offline / forced mock mode ──────────────────────────────────────────
    if force_mock:
        account = _mock_raw_account(url, "force_mock=True")
        return ScrapeResult(account=account, source="mock", scrape_ok=False,
                            error_msg="force_mock requested by caller")

    # ── Robots.txt compliance check ─────────────────────────────────────────
    if not _is_allowed(url):
        account = _mock_raw_account(url, "robots.txt disallows scraping this path")
        return ScrapeResult(account=account, source="mock", scrape_ok=False,
                            error_msg="robots.txt disallows this URL")

    # ── Layer 1: BeautifulSoup via requests ─────────────────────────────────
    html: str | None = None
    try:
        html = _fetch_html_requests(url)
    except RateLimitError as exc:
        # Hard block / rate-limit → skip to mock immediately
        account = _mock_raw_account(url, str(exc))
        return ScrapeResult(account=account, source="mock", scrape_ok=False,
                            error_msg=str(exc))
    except ScraperError as exc:
        logger.warning("BS4 scrape failed: %s – trying Playwright.", exc)

    # ── Layer 2: Playwright (if BS4 failed or returned empty content) ────────
    if html is None or len(html.strip()) < 200:
        try:
            html = _fetch_html_playwright(url)
        except (ImportError, ScraperError, Exception) as exc:
            account = _mock_raw_account(url, f"All scrapers failed: {exc}")
            return ScrapeResult(account=account, source="mock", scrape_ok=False,
                                error_msg=str(exc))

    # ── Parse HTML → _RawParsed ─────────────────────────────────────────────
    try:
        raw_parsed = _html_to_raw_parsed(html, platform)
    except Exception as exc:
        account = _mock_raw_account(url, f"HTML parse error: {exc}")
        return ScrapeResult(account=account, source="mock", scrape_ok=False,
                            error_msg=str(exc))

    # Determine whether we actually got meaningful data
    scrape_source = "live_bs4" if html else "live_playwright"
    got_meaningful_data = (
        raw_parsed.followers > 0
        or raw_parsed.posts_count > 0
        or len(raw_parsed.bio) > 0
        or raw_parsed.display_name
    )

    if not got_meaningful_data:
        account = _mock_raw_account(url, "Live HTML parse returned no usable fields")
        return ScrapeResult(account=account, source="mock", scrape_ok=False,
                            error_msg="No profile metadata found in page HTML")

    account = RawAccount(
        username=username,
        display_name=raw_parsed.display_name or username,
        account_age_days=raw_parsed.account_age_days,
        followers=raw_parsed.followers,
        following=raw_parsed.following,
        posts_count=raw_parsed.posts_count,
        has_profile_pic=raw_parsed.has_profile_pic,
        bio=raw_parsed.bio,
        avg_posts_per_day=raw_parsed.avg_posts_per_day,
        engagement_rate=raw_parsed.engagement_rate,
        account_uses_stock_photo=raw_parsed.account_uses_stock_photo,
        recent_username_changes=raw_parsed.recent_username_changes,
        platform=platform,
    )
    return ScrapeResult(account=account, source=scrape_source, scrape_ok=True)


def scrape_and_assess(url: str, *, force_mock: bool = False):
    """
    Convenience wrapper: scrape a profile and immediately run it through
    the detection engine.

    Returns
    -------
    tuple[ScrapeResult, Assessment]

    Example
    -------
    >>> result, assessment = scrape_and_assess("https://instagram.com/travel.addict_real")
    >>> print(assessment.verdict, assessment.confidence)
    """
    # Late import to avoid circular imports at module load time
    from detector import assess_account  # noqa: PLC0415

    scrape_result = scrape_profile(url, force_mock=force_mock)
    assessment = assess_account(scrape_result.account)
    return scrape_result, assessment


# --------------------------------------------------------------------------- #
# CLI entry-point (python scraper.py <url> [--mock])
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(
        description="OSINT scraper – extract public metadata from a profile URL"
    )
    parser.add_argument("url", help="Public profile URL to scrape")
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Skip live scraping and use mock profile data",
    )
    args = parser.parse_args()

    scrape_res, assessment = scrape_and_assess(args.url, force_mock=args.mock)

    output = {
        "scrape_meta": {
            "url": args.url,
            "source": scrape_res.source,
            "scrape_ok": scrape_res.scrape_ok,
            "error_msg": scrape_res.error_msg,
        },
        "raw_account": {
            "username": scrape_res.account.username,
            "display_name": scrape_res.account.display_name,
            "platform": scrape_res.account.platform,
            "followers": scrape_res.account.followers,
            "following": scrape_res.account.following,
            "posts_count": scrape_res.account.posts_count,
            "has_profile_pic": scrape_res.account.has_profile_pic,
            "bio": scrape_res.account.bio,
            "account_age_days": scrape_res.account.account_age_days,
            "avg_posts_per_day": scrape_res.account.avg_posts_per_day,
            "engagement_rate": scrape_res.account.engagement_rate,
            "account_uses_stock_photo": scrape_res.account.account_uses_stock_photo,
            "recent_username_changes": scrape_res.account.recent_username_changes,
        },
        "assessment": assessment.to_dict(),
    }
    print(json.dumps(output, indent=2))
