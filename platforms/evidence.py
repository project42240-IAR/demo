"""
platforms/evidence.py
=====================
Evidence Engine processing normalized platform data into structured evidence records.
"""
from typing import List, Dict, Any
from datetime import datetime, timezone

from .schema import NormalizedProfile, PlatformEvidence


class EvidenceEngine:
    """
    Evaluates a NormalizedProfile and generates structured evidence items with
    source tracking, timestamps, and confidence scores.
    """

    @classmethod
    def process(cls, profile: NormalizedProfile) -> List[PlatformEvidence]:
        evidence_items: List[PlatformEvidence] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Direct API Verified Identity
        evidence_items.append(
            PlatformEvidence(
                type="API_VERIFIED_IDENTITY",
                value={
                    "platform": profile.platform,
                    "platform_user_id": profile.platform_user_id,
                    "username": profile.username,
                    "display_name": profile.display_name,
                },
                source="official_api",
                source_url=profile.profile_url,
                confidence=1.0,
                observed_at=now_iso,
            )
        )

        # 2. Verification Badge Evidence
        if profile.verified is not None:
            evidence_items.append(
                PlatformEvidence(
                    type="OFFICIAL_VERIFICATION_STATUS",
                    value={"verified": profile.verified},
                    source="official_api",
                    source_url=profile.profile_url,
                    confidence=1.0,
                    observed_at=now_iso,
                )
            )

        # 3. Account Creation & Age Evidence
        if profile.account_created_at:
            evidence_items.append(
                PlatformEvidence(
                    type="ACCOUNT_CREATION_DATE",
                    value={"created_at": profile.account_created_at},
                    source="official_api",
                    source_url=profile.profile_url,
                    confidence=1.0,
                    observed_at=now_iso,
                )
            )

        # 4. Derived Metric: Follower/Following Ratio & Anomaly Check
        if profile.followers is not None and profile.following is not None:
            following_val = max(1, profile.following)
            ratio = round(profile.followers / following_val, 2)
            is_anomaly = (profile.following > 2000 and profile.followers < 50) or (ratio < 0.02)
            evidence_items.append(
                PlatformEvidence(
                    type="FOLLOWER_FOLLOWING_RATIO",
                    value={
                        "followers": profile.followers,
                        "following": profile.following,
                        "ratio": ratio,
                        "is_extreme_anomaly": is_anomaly,
                    },
                    source="derived_signal",
                    source_url=profile.profile_url,
                    confidence=0.95,
                    observed_at=now_iso,
                )
            )

        # 5. Derived Metric: Profile Completeness Score
        completeness = 0.0
        details = {}
        if profile.avatar_url:
            completeness += 0.35
            details["has_avatar"] = True
        else:
            details["has_avatar"] = False

        if profile.bio and len(profile.bio.strip()) > 0:
            completeness += 0.35
            details["has_bio"] = True
        else:
            details["has_bio"] = False

        if profile.posts_count is not None and profile.posts_count > 0:
            completeness += 0.30
            details["has_posts"] = True
        else:
            details["has_posts"] = False

        evidence_items.append(
            PlatformEvidence(
                type="PROFILE_COMPLETENESS_SCORE",
                value={
                    "completeness_score": round(completeness, 2),
                    "details": details,
                },
                source="derived_signal",
                source_url=profile.profile_url,
                confidence=0.90,
                observed_at=now_iso,
            )
        )

        # 6. System Notes on Missing API Fields
        missing_fields = []
        if profile.bio is None:
            missing_fields.append("bio")
        if profile.following is None:
            missing_fields.append("following")
        if profile.account_created_at is None:
            missing_fields.append("account_created_at")

        if missing_fields:
            evidence_items.append(
                PlatformEvidence(
                    type="UNAVAILABLE_FIELDS_NOTE",
                    value={"missing_fields": missing_fields},
                    source="system_note",
                    source_url=profile.profile_url,
                    confidence=1.0,
                    observed_at=now_iso,
                )
            )

        return evidence_items
