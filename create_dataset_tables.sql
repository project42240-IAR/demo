-- create_dataset_tables.sql
-- Run this script in your Supabase Dashboard SQL Editor:
-- https://supabase.com/dashboard/project/cyupdbhmtpbtscycdtiq/sql/new

-- 1. Facebook Fake Account Dataset Table
CREATE TABLE IF NOT EXISTS public.facebook_dataset (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id TEXT,
    platform TEXT DEFAULT 'Facebook',
    username_length INT,
    username_digit_ratio DOUBLE PRECISION,
    has_profile_photo INT,
    has_cover_photo INT,
    bio_length INT,
    followers INT,
    friends_count INT,
    posts_count INT,
    account_age_days INT,
    groups_count INT,
    pages_liked INT,
    verified INT,
    external_url INT,
    friend_request_rate DOUBLE PRECISION,
    engagement_rate DOUBLE PRECISION,
    duplicate_content_score DOUBLE PRECISION,
    bot_behavior_score DOUBLE PRECISION,
    label INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Instagram Fake Account Dataset Table
CREATE TABLE IF NOT EXISTS public.instagram_dataset (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id TEXT,
    platform TEXT DEFAULT 'Instagram',
    username_length INT,
    username_digit_ratio DOUBLE PRECISION,
    has_profile_photo INT,
    bio_length INT,
    followers INT,
    following INT,
    posts INT,
    account_age_days INT,
    private_account INT,
    verified INT,
    external_url INT,
    name_username_match INT,
    followers_following_ratio DOUBLE PRECISION,
    engagement_rate DOUBLE PRECISION,
    posting_frequency_per_day DOUBLE PRECISION,
    duplicate_content_score DOUBLE PRECISION,
    bot_behavior_score DOUBLE PRECISION,
    label INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Synthetic Accounts Dataset Table
CREATE TABLE IF NOT EXISTS public.synthetic_accounts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_age_days DOUBLE PRECISION,
    followers DOUBLE PRECISION,
    following DOUBLE PRECISION,
    posts_count DOUBLE PRECISION,
    has_profile_pic INT,
    bio_length DOUBLE PRECISION,
    username_digit_ratio DOUBLE PRECISION,
    display_name_matches_username INT,
    avg_posts_per_day DOUBLE PRECISION,
    follower_following_ratio_extreme INT,
    engagement_rate DOUBLE PRECISION,
    account_uses_stock_photo INT,
    recent_username_changes INT,
    label INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS and Grant Policies
ALTER TABLE public.facebook_dataset ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.instagram_dataset ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.synthetic_accounts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow full access on facebook_dataset" ON public.facebook_dataset;
CREATE POLICY "Allow full access on facebook_dataset" ON public.facebook_dataset FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on instagram_dataset" ON public.instagram_dataset;
CREATE POLICY "Allow full access on instagram_dataset" ON public.instagram_dataset FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on synthetic_accounts" ON public.synthetic_accounts;
CREATE POLICY "Allow full access on synthetic_accounts" ON public.synthetic_accounts FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
