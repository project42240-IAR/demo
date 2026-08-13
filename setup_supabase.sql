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

-- 3. Enable RLS and Grant Access Policies
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Allow full access for service_role / anon key in this application
DROP POLICY IF EXISTS "Allow full access on cases" ON public.cases;
CREATE POLICY "Allow full access on cases" ON public.cases FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow full access on audit_logs" ON public.audit_logs;
CREATE POLICY "Allow full access on audit_logs" ON public.audit_logs FOR ALL TO anon, authenticated, service_role USING (true) WITH CHECK (true);
