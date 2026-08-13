"""
platforms/base.py
=================
Abstract Base Class for social media platform adapters.
"""
from abc import ABC, abstractmethod
from typing import List
from .schema import NormalizedProfile, PlatformEvidence


class PlatformAdapter(ABC):
    """
    Interface for platform-specific official API connectors.
    Isolates platform-specific API calls, headers, and authentication.
    """

    @abstractmethod
    def get_profile(self, identifier: str) -> NormalizedProfile:
        """Fetch and normalize profile data from official platform API."""
        pass

    @abstractmethod
    def get_evidence(self, identifier: str) -> List[PlatformEvidence]:
        """Fetch platform-specific evidence items."""
        pass
