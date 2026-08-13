"""
platforms package
=================
Multi-platform detection, official API adapters, normalization schema, and Evidence Engine.
"""

from .schema import NormalizedProfile, PlatformEvidence
from .detector import PlatformDetector
from .base import PlatformAdapter
from .instagram import InstagramAdapter
from .x import XAdapter
from .tiktok import TikTokAdapter
from .facebook import FacebookAdapter
from .youtube import YouTubeAdapter
from .evidence import EvidenceEngine

__all__ = [
    "NormalizedProfile",
    "PlatformEvidence",
    "PlatformDetector",
    "PlatformAdapter",
    "InstagramAdapter",
    "XAdapter",
    "TikTokAdapter",
    "FacebookAdapter",
    "YouTubeAdapter",
    "EvidenceEngine",
]
