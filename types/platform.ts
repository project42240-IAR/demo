export type SupportedPlatform = 'instagram' | 'x' | 'tiktok' | 'facebook' | 'youtube' | 'generic';

export interface ProfileInput {
  input: string;
  force_refresh?: boolean;
}

export interface NormalizedProfile {
  platform: SupportedPlatform;
  platform_user_id: string;
  username?: string;
  display_name?: string;
  profile_url?: string;
  bio?: string;
  avatar_url?: string;
  followers?: number;
  following?: number;
  posts_count?: number;
  verified?: boolean;
  account_created_at?: string;
  fetched_at: string;
  raw_data?: Record<string, unknown>;
}

export interface PlatformEvidence {
  type: string;
  value: unknown;
  source: 'official_api' | 'derived_signal' | 'system_note';
  observed_at: string;
  source_url?: string;
  confidence?: number;
}

export interface RiskAnalysis {
  final_score: number;
  verdict: string;
  confidence: string;
  rule_score: number;
  model_score: number;
  reasons: string[];
}

export interface APIResponseSuccess {
  success: true;
  profile: NormalizedProfile;
  evidence: PlatformEvidence[];
  analysis: RiskAnalysis;
  metadata: {
    platform: SupportedPlatform;
    fetchedAt: string;
    cached?: boolean;
  };
}

export interface APIErrorDetail {
  code: 'INVALID_INPUT' | 'UNSUPPORTED_PLATFORM' | 'PROFILE_NOT_FOUND' | 'PLATFORM_API_ERROR' | 'RATE_LIMIT_EXCEEDED';
  message: string;
}

export interface APIResponseError {
  success: false;
  error: APIErrorDetail;
}

export type APIResponse = APIResponseSuccess | APIResponseError;
