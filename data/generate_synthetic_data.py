"""
Generates a synthetic labeled dataset of social media accounts (genuine vs fake)
for training / demoing the detector. In a production deployment this would be
replaced by data pulled from platform APIs / verified takedown records, but for
a hackathon prototype we simulate realistic feature distributions.
"""
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)
N_GENUINE = 600
N_FAKE = 600


def _clip(arr, lo, hi):
    return np.clip(arr, lo, hi)


def make_genuine(n):
    return pd.DataFrame({
        "account_age_days": RNG.normal(900, 500, n).clip(30, 4000),
        "followers": RNG.lognormal(5.5, 1.2, n).clip(5, 500000),
        "following": RNG.lognormal(4.8, 0.8, n).clip(5, 8000),
        "posts_count": RNG.lognormal(3.8, 1.1, n).clip(0, 5000),
        "has_profile_pic": RNG.choice([1, 0], n, p=[0.94, 0.06]),
        "bio_length": RNG.normal(60, 35, n).clip(0, 250),
        "username_digit_ratio": RNG.beta(1.2, 8, n),
        "display_name_matches_username": RNG.choice([1, 0], n, p=[0.55, 0.45]),
        "avg_posts_per_day": RNG.gamma(1.2, 0.15, n).clip(0, 20),
        "follower_following_ratio_extreme": RNG.choice([1, 0], n, p=[0.05, 0.95]),
        "engagement_rate": RNG.beta(2, 8, n),
        "account_uses_stock_photo": RNG.choice([1, 0], n, p=[0.03, 0.97]),
        "recent_username_changes": RNG.poisson(0.15, n),
        "label": 0,
    })


def make_fake(n):
    return pd.DataFrame({
        "account_age_days": RNG.exponential(60, n).clip(0, 900),
        "followers": RNG.lognormal(3.0, 1.5, n).clip(0, 20000),
        "following": RNG.lognormal(6.0, 1.0, n).clip(50, 30000),
        "posts_count": RNG.exponential(6, n).clip(0, 200),
        "has_profile_pic": RNG.choice([1, 0], n, p=[0.4, 0.6]),
        "bio_length": RNG.exponential(15, n).clip(0, 250),
        "username_digit_ratio": RNG.beta(3, 3, n),
        "display_name_matches_username": RNG.choice([1, 0], n, p=[0.15, 0.85]),
        "avg_posts_per_day": RNG.gamma(2.5, 1.5, n).clip(0, 60),
        "follower_following_ratio_extreme": RNG.choice([1, 0], n, p=[0.65, 0.35]),
        "engagement_rate": RNG.beta(1, 20, n),
        "account_uses_stock_photo": RNG.choice([1, 0], n, p=[0.35, 0.65]),
        "recent_username_changes": RNG.poisson(1.4, n),
        "label": 1,
    })


def build_dataset():
    df = pd.concat([make_genuine(N_GENUINE), make_fake(N_FAKE)], ignore_index=True)
    df = df.sample(frac=1, random_state=7).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_dataset()
    df.to_csv("synthetic_accounts.csv", index=False)
    print(f"Wrote {len(df)} rows to synthetic_accounts.csv")
