import { NIVARA_API_BASE_URL, NIVARA_API_TIMEOUT_MS } from '../config';

export type ApiReason = {
  code: string;
  severity: string;
  source: string;
  message: string;
};

export type ProviderEvidence = {
  provider?: string | null;
  status?: string;
  checked?: boolean;
  matched?: boolean;
  category?: string | null;
};

export type EvidenceSummary = {
  ml?: {
    status?: string;
    predicted_class?: string | null;
    confidence?: number | null;
    model?: string | null;
  };
  url_security?: { status?: string; scheme?: string | null; indicators?: Record<string, unknown> };
  redirect?: { status?: string; indicators?: Record<string, unknown> };
  threat_intelligence?: {
    status?: string;
    providers?: ProviderEvidence[];
    matched_providers?: string[];
    categories?: string[];
  };
};

export type RiskDecision = {
  risk_level: string;
  action: string;
  decision_confidence: number;
  evidence_quality: string;
  reasons: ApiReason[];
  evidence_summary: EvidenceSummary;
  decision_policy_version: string;
};

export type UrlAnalysisResponse = {
  analysis_status?: string;
  url?: string | null;
  normalized_url?: string | null;
  ml?: {
    status?: string;
    prediction?: string | null;
    prediction_index?: number | null;
    confidence?: number | null;
    probabilities?: Record<string, number> | null;
    model?: string | null;
  };
  security_indicators?: Record<string, unknown> | null;
  redirect_analysis?: {
    resolution_status?: string;
    reason?: string | null;
    redirect_count?: number;
  };
  threat_intelligence?: {
    status?: string;
    providers?: ProviderEvidence[];
    matched_providers?: string[];
    categories?: string[];
  };
  risk_decision?: RiskDecision | null;
};

export class NivaraApiError extends Error {
  constructor(
    message: string,
    readonly kind: 'timeout' | 'network' | 'http' | 'response',
    readonly status?: number,
  ) {
    super(message);
    this.name = 'NivaraApiError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateResponse(value: unknown): UrlAnalysisResponse {
  if (!isRecord(value)) {
    throw new NivaraApiError('The backend returned an unreadable response.', 'response');
  }
  const decision = value.risk_decision;
  if (
    !isRecord(decision) ||
    typeof decision.risk_level !== 'string' ||
    typeof decision.action !== 'string' ||
    typeof decision.evidence_quality !== 'string' ||
    !Array.isArray(decision.reasons) ||
    !isRecord(decision.evidence_summary)
  ) {
    throw new NivaraApiError('The backend response did not include a usable risk decision.', 'response');
  }
  return value as unknown as UrlAnalysisResponse;
}

export type ApiRequestOptions = {
  baseUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
};

export async function analyzeUrl(
  url: string,
  followRedirects = true,
  options: ApiRequestOptions = {},
): Promise<UrlAnalysisResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? NIVARA_API_TIMEOUT_MS);
  const baseUrl = (options.baseUrl ?? NIVARA_API_BASE_URL).replace(/\/+$/, '');
  const fetchImpl = options.fetchImpl ?? fetch;

  try {
    const response = await fetchImpl(`${baseUrl}/api/v1/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ url, follow_redirects: followRedirects }),
      signal: controller.signal,
    });
    const responseText = await response.text();
    let payload: unknown;
    try {
      payload = responseText ? JSON.parse(responseText) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const detail = isRecord(payload) && typeof payload.detail === 'string' ? payload.detail : null;
      throw new NivaraApiError(
        detail || `The backend returned HTTP ${response.status}.`,
        'http',
        response.status,
      );
    }
    return validateResponse(payload);
  } catch (error) {
    if (error instanceof NivaraApiError) throw error;
    if (controller.signal.aborted) {
      throw new NivaraApiError('The security analysis timed out. Check the backend connection and try again.', 'timeout');
    }
    throw new NivaraApiError(
      `Could not complete a response from the NIVARA backend at ${baseUrl}. Check the backend address and network.`,
      'network',
    );
  } finally {
    clearTimeout(timeout);
  }
}
