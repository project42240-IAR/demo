-- setup_supabase.sql
-- Run this script in your Supabase Dashboard SQL Editor:
-- https://supabase.com/dashboard/project/brwibpgkzlvunyxejhrh/sql/new

-- 1. Cases Table
CREATE TABLE IF NOT EXISTS public.cases (
    case_id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence TEXT,
    rule_score DOUBLE PRECISION,
    model_score DOUBLE PRECISION,
    final_score DOUBLE PRECISION,
    status TEXT NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username TEXT,
    reasons TEXT,
    top_model_factors TEXT,
    status_history TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_reported_at ON public.cases (reported_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_verdict ON public.cases (verdict);
CREATE INDEX IF NOT EXISTS idx_cases_platform ON public.cases (platform);
CREATE INDEX IF NOT EXISTS idx_cases_status ON public.cases (status);

-- 2. Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id TEXT NOT NULL,
    reviewer TEXT,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_case_id ON public.audit_logs (case_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.audit_logs (timestamp DESC);

-- 3. Users Table
CREATE TABLE IF NOT EXISTS public.users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email ON public.users (email);

-- 5. Social Profiles & Multi-Platform Analysis Tables
CREATE TABLE IF NOT EXISTS public.profiles (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.platform_accounts (
    id TEXT PRIMARY KEY,
    profile_id TEXT REFERENCES public.profiles(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    platform_user_id TEXT NOT NULL,
    username TEXT,
    profile_url TEXT,
    followers INT,
    following INT,
    posts_count INT,
    verified BOOLEAN DEFAULT FALSE,
    raw_data JSONB,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.evidence (
    id TEXT PRIMARY KEY,
    platform_account_id TEXT REFERENCES public.platform_accounts(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value JSONB,
    source TEXT NOT NULL,
    source_url TEXT,
    confidence DOUBLE PRECISION DEFAULT 1.0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.analyses (
    id TEXT PRIMARY KEY,
    platform_account_id TEXT REFERENCES public.platform_accounts(id) ON DELETE CASCADE,
    final_score DOUBLE PRECISION NOT NULL,
    verdict TEXT NOT NULL,
    confidence TEXT,
    rule_score DOUBLE PRECISION,
    model_score DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.analysis_runs (
    id TEXT PRIMARY KEY,
    analysis_id TEXT REFERENCES public.analyses(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    input_text TEXT NOT NULL,
    latency_ms DOUBLE PRECISION,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_platform_accounts_platform ON public.platform_accounts (platform);
CREATE INDEX IF NOT EXISTS idx_platform_accounts_platform_user_id ON public.platform_accounts (platform_user_id);
CREATE INDEX IF NOT EXISTS idx_platform_accounts_username ON public.platform_accounts (username);
CREATE INDEX IF NOT EXISTS idx_platform_accounts_created_at ON public.platform_accounts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_platform_account_id ON public.evidence (platform_account_id);
CREATE INDEX IF NOT EXISTS idx_analyses_platform_account_id ON public.analyses (platform_account_id);

-- Enable RLS and Grant Policies
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.platform_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analysis_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow full access on cases" ON public.cases;
CREATE POLICY "Allow full access on cases" ON public.cases FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on audit_logs" ON public.audit_logs;
CREATE POLICY "Allow full access on audit_logs" ON public.audit_logs FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on users" ON public.users;
CREATE POLICY "Allow full access on users" ON public.users FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on profiles" ON public.profiles;
CREATE POLICY "Allow full access on profiles" ON public.profiles FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on platform_accounts" ON public.platform_accounts;
CREATE POLICY "Allow full access on platform_accounts" ON public.platform_accounts FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on evidence" ON public.evidence;
CREATE POLICY "Allow full access on evidence" ON public.evidence FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on analyses" ON public.analyses;
CREATE POLICY "Allow full access on analyses" ON public.analyses FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on analysis_runs" ON public.analysis_runs;
CREATE POLICY "Allow full access on analysis_runs" ON public.analysis_runs FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
