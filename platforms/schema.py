"""
platforms/schema.py
===================
Normalized schemas for multi-platform profiles and structured evidence.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class NormalizedProfile:
    platform: str
    platform_user_id: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    profile_url: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    followers: Optional[int] = None
    following: Optional[int] = None
    posts_count: Optional[int] = None
    verified: Optional[bool] = None
    account_created_at: Optional[str] = None
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlatformEvidence:
    type: str
    value: Any
    source: str  # "official_api", "derived_signal", "system_note"
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_url: Optional[str] = None
    confidence: Optional[float] = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
