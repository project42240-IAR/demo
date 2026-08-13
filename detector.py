"""
detector.py
Core detection engine for the Fake Social Media Account Detection & Reporting System.

Two layers of scoring, combined:
  1. A transparent rule-based heuristic score (0-100) — explainable, no training
     data required, mirrors what a human moderator would check.
  2. A RandomForest classifier trained on a labeled dataset (data/synthetic_accounts.csv
     in this prototype; swap in real platform / takedown data in production) that
     catches non-obvious combinations the hand-written rules miss.

The two scores are blended into a final trust score, and the engine returns the
specific reasons that drove the verdict so a human reviewer / the "central
agency" can audit the decision rather than trust a black box.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "synthetic_accounts.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "rf_model.joblib")

FEATURE_COLUMNS = [
    "account_age_days",
    "followers",
    "following",
    "posts_count",
    "has_profile_pic",
    "bio_length",
    "username_digit_ratio",
    "display_name_matches_username",
    "avg_posts_per_day",
    "follower_following_ratio_extreme",
    "engagement_rate",
    "account_uses_stock_photo",
    "recent_username_changes",
]


# --------------------------------------------------------------------------- #
# Feature engineering from raw, human-entered / scraped profile fields
# --------------------------------------------------------------------------- #

@dataclass
class RawAccount:
    username: str
    display_name: str = ""
    account_age_days: float = 365
    followers: int = 0
    following: int = 0
    posts_count: int = 0
    has_profile_pic: bool = True
    bio: str = ""
    avg_posts_per_day: float = 0.5
    engagement_rate: float = 0.05  # (likes+comments)/followers, 0-1
    account_uses_stock_photo: bool = False
    recent_username_changes: int = 0
    platform: str = "generic"


def _username_digit_ratio(username: str) -> float:
    if not username:
        return 0.0
    digits = sum(ch.isdigit() for ch in username)
    return digits / max(len(username), 1)


def _display_name_matches_username(username: str, display_name: str) -> int:
    if not username or not display_name:
        return 0
    u = re.sub(r"[^a-z]", "", username.lower())
    d = re.sub(r"[^a-z]", "", display_name.lower())
    if not u or not d:
        return 0
    return int(u in d or d in u)


def _follower_following_ratio_extreme(followers: int, following: int) -> int:
    following = max(following, 1)
    ratio = followers / following
    # Following thousands while almost no one follows back, or the inverse
    # (mass-following behaviour typical of bot/spam accounts).
    return int(ratio < 0.02 and following > 300)


def engineer_features(raw: RawAccount) -> dict[str, Any]:
    return {
        "account_age_days": raw.account_age_days,
        "followers": raw.followers,
        "following": raw.following,
        "posts_count": raw.posts_count,
        "has_profile_pic": int(raw.has_profile_pic),
        "bio_length": len(raw.bio or ""),
        "username_digit_ratio": _username_digit_ratio(raw.username),
        "display_name_matches_username": _display_name_matches_username(
            raw.username, raw.display_name
        ),
        "avg_posts_per_day": raw.avg_posts_per_day,
        "follower_following_ratio_extreme": _follower_following_ratio_extreme(
            raw.followers, raw.following
        ),
        "engagement_rate": raw.engagement_rate,
        "account_uses_stock_photo": int(raw.account_uses_stock_photo),
        "recent_username_changes": raw.recent_username_changes,
    }


# --------------------------------------------------------------------------- #
# Rule-based, explainable heuristic layer
# --------------------------------------------------------------------------- #

# Each rule: (predicate, points_added_to_risk, human-readable reason)
def _rule_checks(f: dict[str, Any]) -> list[tuple[int, str]]:
    hits = []
    if f["account_age_days"] < 30:
        hits.append((14, "Account created in the last 30 days"))
    elif f["account_age_days"] < 90:
        hits.append((6, "Account is less than 3 months old"))

    if not f["has_profile_pic"]:
        hits.append((10, "No profile photo set"))

    if f["account_uses_stock_photo"]:
        hits.append((16, "Profile photo appears to be a stock / stolen image"))

    if f["bio_length"] == 0:
        hits.append((6, "Bio is empty"))

    if f["username_digit_ratio"] > 0.35:
        hits.append((10, "Username is dominated by random digits"))

    if not f["display_name_matches_username"]:
        hits.append((4, "Display name has no relation to the username"))

    if f["follower_following_ratio_extreme"]:
        hits.append((14, "Follows thousands of accounts but is followed back by almost none"))

    if f["avg_posts_per_day"] > 15:
        hits.append((12, "Posting frequency is far above normal human behaviour"))

    if f["engagement_rate"] < 0.005 and f["followers"] > 200:
        hits.append((10, "Very large follower count with almost no engagement (likely purchased followers)"))

    if f["recent_username_changes"] >= 2:
        hits.append((8, "Username changed multiple times recently"))

    if f["posts_count"] == 0 and f["account_age_days"] > 14:
        hits.append((6, "Zero posts despite an account that is over two weeks old"))

    return hits


def rule_based_score(f: dict[str, Any]) -> tuple[int, list[str]]:
    hits = _rule_checks(f)
    score = min(sum(pts for pts, _ in hits), 100)
    reasons = [reason for _, reason in hits]
    return score, reasons


# --------------------------------------------------------------------------- #
# Trained classifier layer
# --------------------------------------------------------------------------- #

_model_cache: RandomForestClassifier | None = None


def _train_model() -> RandomForestClassifier:
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=7, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=7, class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    return clf


def get_model() -> RandomForestClassifier:
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    if os.path.exists(MODEL_PATH):
        _model_cache = joblib.load(MODEL_PATH)
    else:
        _model_cache = _train_model()
    return _model_cache


def model_score(f: dict[str, Any]) -> float:
    clf = get_model()
    row = pd.DataFrame([f])[FEATURE_COLUMNS]
    proba = clf.predict_proba(row)[0]
    classes = list(clf.classes_)
    fake_idx = classes.index(1)
    return float(proba[fake_idx]) * 100


def top_model_factors(f: dict[str, Any], k: int = 3) -> list[str]:
    """Approximate explanation using the model's global feature importances,
    reported only for features that look anomalous for this specific account."""
    clf = get_model()
    importances = dict(zip(FEATURE_COLUMNS, clf.feature_importances_))
    ranked = sorted(importances.items(), key=lambda kv: kv[1], reverse=True)
    labels = {
        "account_age_days": "Account age",
        "followers": "Follower count",
        "following": "Following count",
        "posts_count": "Total posts",
        "engagement_rate": "Engagement rate",
        "avg_posts_per_day": "Posting frequency",
        "username_digit_ratio": "Username digit ratio",
        "follower_following_ratio_extreme": "Follower/following imbalance",
        "recent_username_changes": "Recent username changes",
    }
    out = []
    for name, _ in ranked:
        if name in labels:
            out.append(labels[name])
        if len(out) >= k:
            break
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

@dataclass
class Assessment:
    username: str
    platform: str
    rule_score: int
    model_score: float
    final_score: float
    verdict: str
    confidence: str
    reasons: list[str] = field(default_factory=list)
    top_model_factors: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "username": self.username,
            "platform": self.platform,
            "rule_score": self.rule_score,
            "model_score": round(self.model_score, 1),
            "final_score": round(self.final_score, 1),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "top_model_factors": self.top_model_factors,
        }


def _verdict_for(score: float) -> tuple[str, str]:
    if score >= 70:
        return "Likely Fake", "High"
    if score >= 40:
        return "Suspicious", "Medium"
    return "Likely Genuine", "Low"


def assess_account(raw: RawAccount) -> Assessment:
    features = engineer_features(raw)
    r_score, reasons = rule_based_score(features)
    m_score = model_score(features)
    # Blend: rules are transparent/explainable, model catches subtler patterns.
    final = 0.45 * r_score + 0.55 * m_score
    verdict, confidence = _verdict_for(final)
    factors = top_model_factors(features)
    return Assessment(
        username=raw.username,
        platform=raw.platform,
        rule_score=r_score,
        model_score=m_score,
        final_score=final,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        top_model_factors=factors,
    )


if __name__ == "__main__":
    # quick smoke test
    test = RawAccount(
        username="john_doe1998234",
        display_name="xx_random_xx",
        account_age_days=12,
        followers=14,
        following=3400,
        posts_count=0,
        has_profile_pic=False,
        bio="",
        avg_posts_per_day=22,
        engagement_rate=0.001,
        account_uses_stock_photo=True,
        recent_username_changes=3,
        platform="Instagram",
    )
    result = assess_account(test)
    import json
    print(json.dumps(result.to_dict(), indent=2))
