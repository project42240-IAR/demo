/**
 * supabaseClient.ts
 * =================
 * Supabase TypeScript Client for the Fake Social Media Account Detection platform.
 * 
 * Exports typed Supabase instances (`supabase` and `supabaseAdmin`),
 * TypeScript interfaces (`Case`, `AuditLog`, `Database`),
 * and helper data access methods.
 *
 * Reads configuration from environment variables (.env.local / process.env / import.meta.env):
 *   - NEXT_PUBLIC_SUPABASE_URL / VITE_SUPABASE_URL / SUPABASE_URL
 *   - NEXT_PUBLIC_SUPABASE_ANON_KEY / NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY / SUPABASE_SECRET_KEY
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

// --------------------------------------------------------------------------- //
// Database Type Definitions
// --------------------------------------------------------------------------- //

export interface StatusHistoryEntry {
  status: string;
  changed_at: string;
  changed_by: string;
}

export interface Case {
  case_id: string;
  platform: string;
  verdict: string;
  confidence?: string | null;
  rule_score?: number | null;
  model_score?: number | null;
  final_score?: number | null;
  status: string;
  reported_at: string;
  username?: string | null;
  reasons?: string[] | string | null;
  top_model_factors?: string[] | string | null;
  status_history?: StatusHistoryEntry[] | string | null;
  created_at?: string;
}

export interface AuditLog {
  id?: number;
  case_id: string;
  reviewer?: string | null;
  action: string;
  old_value?: any;
  new_value?: any;
  timestamp: string;
}

export interface Database {
  public: {
    Tables: {
      cases: {
        Row: Case;
        Insert: Omit<Case, 'created_at'>;
        Update: Partial<Omit<Case, 'case_id'>>;
      };
      audit_logs: {
        Row: AuditLog;
        Insert: Omit<AuditLog, 'id'>;
        Update: Partial<Omit<AuditLog, 'id'>>;
      };
    };
    Views: {};
    Functions: {};
  };
}

// --------------------------------------------------------------------------- //
// Environment Variable Resolution
// --------------------------------------------------------------------------- //

function getEnvVar(name: string): string {
  // Support Node / Next.js process.env
  if (typeof process !== 'undefined' && process.env) {
    if (process.env[name]) return process.env[name]!;
  }
  // Support Vite import.meta.env
  try {
    // @ts-ignore
    if (typeof import.meta !== 'undefined' && import.meta.env) {
      // @ts-ignore
      if (import.meta.env[name]) return import.meta.env[name];
    }
  } catch {
    // Ignore in non-Vite environments
  }
  return '';
}

const supabaseUrl =
  getEnvVar('NEXT_PUBLIC_SUPABASE_URL') ||
  getEnvVar('VITE_SUPABASE_URL') ||
  getEnvVar('SUPABASE_URL');

const supabaseAnonKey =
  getEnvVar('NEXT_PUBLIC_SUPABASE_ANON_KEY') ||
  getEnvVar('NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY') ||
  getEnvVar('VITE_SUPABASE_ANON_KEY') ||
  getEnvVar('SUPABASE_PUBLISHABLE_KEY');

const supabaseSecretKey = getEnvVar('SUPABASE_SECRET_KEY');

if (!supabaseUrl || !supabaseAnonKey) {
  console.warn(
    'Supabase Warning: Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY in environment (.env.local).'
  );
}

// --------------------------------------------------------------------------- //
// Direct REST API Access
// --------------------------------------------------------------------------- //

export const SUPABASE_REST_URL =
  getEnvVar('NEXT_PUBLIC_SUPABASE_REST_URL') ||
  getEnvVar('SUPABASE_REST_URL') ||
  `${supabaseUrl || 'https://brwibpgkzlvunyxejhrh.supabase.co'}/rest/v1`;

/**
 * Perform a direct HTTP request to Supabase PostgREST endpoints (e.g. fetchRest('cases'))
 */
export async function fetchRest<T = any>(
  endpoint: string = '',
  options: RequestInit = {}
): Promise<T> {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
  const url = cleanEndpoint ? `${SUPABASE_REST_URL.replace(/\/$/, '')}/${cleanEndpoint}` : SUPABASE_REST_URL;
  
  const headers = {
    apikey: supabaseAnonKey,
    Authorization: `Bearer ${supabaseSecretKey || supabaseAnonKey}`,
    'Content-Type': 'application/json',
    Prefer: 'return=representation',
    ...options.headers,
  };

  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Supabase REST Error (${response.status}): ${errorText}`);
  }
  return response.json();
}

// --------------------------------------------------------------------------- //
// Client Instances
// --------------------------------------------------------------------------- //

/**
 * Public client for client-side operations (uses publishable/anon key)
 */
export const supabase: SupabaseClient<Database> = createClient<Database>(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-anon-key'
);

/**
 * Admin client for server-side elevated operations (uses secret key)
 */
export const supabaseAdmin: SupabaseClient<Database> = createClient<Database>(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseSecretKey || supabaseAnonKey || 'placeholder-secret-key'
);

// --------------------------------------------------------------------------- //
// Helper Functions for All Data Access
// --------------------------------------------------------------------------- //

/**
 * Fetch all reported cases sorted newest-first
 */
export async function getCases(): Promise<Case[]> {
  const { data, error } = await supabase
    .from('cases')
    .select('*')
    .order('reported_at', { ascending: false });

  if (error) {
    console.error('Error fetching cases from Supabase:', error);
    throw error;
  }
  return (data || []) as Case[];
}

/**
 * Fetch a single case by case_id
 */
export async function getCaseById(caseId: string): Promise<Case | null> {
  const { data, error } = await supabase
    .from('cases')
    .select('*')
    .eq('case_id', caseId)
    .single();

  if (error) {
    if (error.code === 'PGRST116') return null; // row not found
    console.error(`Error fetching case ${caseId}:`, error);
    throw error;
  }
  return data as Case;
}

/**
 * Insert a new case document into Supabase
 */
export async function insertCase(caseData: Omit<Case, 'created_at'>): Promise<Case> {
  const { data, error } = await supabase
    .from('cases')
    .insert([caseData])
    .select()
    .single();

  if (error) {
    console.error('Error inserting case into Supabase:', error);
    throw error;
  }

  // Record audit log entry
  await insertAuditLog({
    case_id: caseData.case_id,
    action: 'report_created',
    reviewer: 'system',
    old_value: null,
    new_value: caseData,
    timestamp: new Date().toISOString(),
  });

  return data as Case;
}

/**
 * Update case workflow status
 */
export async function updateCaseStatus(
  caseId: string,
  newStatus: string,
  reviewer: string = 'system'
): Promise<Case | null> {
  const currentCase = await getCaseById(caseId);
  if (!currentCase) return null;

  const oldStatus = currentCase.status;
  const history: StatusHistoryEntry[] = Array.isArray(currentCase.status_history)
    ? currentCase.status_history
    : [];

  history.push({
    status: newStatus,
    changed_at: new Date().toISOString(),
    changed_by: reviewer,
  });

  const { data, error } = await supabase
    .from('cases')
    .update({
      status: newStatus,
      status_history: history,
    })
    .eq('case_id', caseId)
    .select()
    .single();

  if (error) {
    console.error(`Error updating status for case ${caseId}:`, error);
    throw error;
  }

  // Record audit log entry
  await insertAuditLog({
    case_id: caseId,
    action: 'status_update',
    reviewer: reviewer,
    old_value: { status: oldStatus },
    new_value: { status: newStatus },
    timestamp: new Date().toISOString(),
  });

  return data as Case;
}

/**
 * Fetch audit logs, optionally filtered by case_id
 */
export async function getAuditLogs(caseId?: string): Promise<AuditLog[]> {
  let query = supabase.from('audit_logs').select('*');
  if (caseId) {
    query = query.eq('case_id', caseId);
  }
  const { data, error } = await query.order('timestamp', { ascending: false });

  if (error) {
    console.error('Error fetching audit logs:', error);
    throw error;
  }
  return (data || []) as AuditLog[];
}

/**
 * Insert an audit log entry
 */
export async function insertAuditLog(auditData: Omit<AuditLog, 'id'>): Promise<AuditLog> {
  const { data, error } = await supabase
    .from('audit_logs')
    .insert([auditData])
    .select()
    .single();

  if (error) {
    console.error('Error inserting audit log:', error);
    throw error;
  }
  return data as AuditLog;
}

export default supabase;
