"""
platforms/detector.py
=====================
Reusable platform detector for social media URLs and usernames.
"""
import re
from typing import Dict, Any


class PlatformDetector:
    """
    Parses and detects the target social media platform and identifier.
    Supports Instagram, X (Twitter), TikTok, Facebook, and YouTube.
    """

    PATTERNS = [
        (
            "instagram",
            re.compile(
                r"^https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_\.]+)/?",
                re.IGNORECASE,
            ),
        ),
        (
            "x",
            re.compile(
                r"^https?://(?:www\.)?(?:x|twitter)\.com/([a-zA-Z0-9_]{1,15})/?",
                re.IGNORECASE,
            ),
        ),
        (
            "tiktok",
            re.compile(
                r"^https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9_\.]+)/?",
                re.IGNORECASE,
            ),
        ),
        (
            "facebook",
            re.compile(
                r"^https?://(?:www\.)?(?:facebook|fb)\.com/([a-zA-Z0-9_\.]+)/?",
                re.IGNORECASE,
            ),
        ),
        (
            "youtube",
            re.compile(
                r"^https?://(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)?([a-zA-Z0-9_\.-]+)/?",
                re.IGNORECASE,
            ),
        ),
    ]

    @classmethod
    def detect(cls, raw_input: str) -> Dict[str, Any]:
        if not raw_input or not isinstance(raw_input, str):
            raise ValueError("Input profile URL or username is required.")

        clean_input = raw_input.strip()

        # 1. URL pattern matching
        for platform_name, pattern in cls.PATTERNS:
            match = pattern.search(clean_input)
            if match:
                identifier = match.group(1).lstrip("@")
                return {
                    "platform": platform_name,
                    "identifier": identifier,
                    "inputType": "url",
                    "raw_input": clean_input,
                }

        # 2. Handle handle inputs starting with @
        if clean_input.startswith("@"):
            identifier = clean_input[1:].strip()
            if not identifier:
                raise ValueError("Invalid username handle.")
            return {
                "platform": "generic",
                "identifier": identifier,
                "inputType": "username",
                "raw_input": clean_input,
            }

        # 3. Direct username string (if formatted as a valid handle)
        if re.match(r"^[a-zA-Z0-9_\.]{1,30}$", clean_input):
            return {
                "platform": "generic",
                "identifier": clean_input,
                "inputType": "username",
                "raw_input": clean_input,
            }

        raise ValueError(
            f"Unable to detect a supported social media platform for input: '{clean_input}'. "
            "Supported platforms: Instagram, X (Twitter), TikTok, Facebook, YouTube."
        )
