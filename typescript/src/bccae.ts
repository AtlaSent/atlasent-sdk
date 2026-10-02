/**
 * BCCAE V1 — TypeScript client.
 *
 * BCCAEClient wraps the four BCCAE Phase 3 endpoints:
 *   evaluate  → POST /v1/bccae/evaluations   (bccae:evaluate scope)
 *   execute   → POST /v1/bccae/execute        (bccae:execute scope)
 *   revoke    → POST /v1/bccae/revocations    (bccae:revoke scope)
 *   getEvidence → GET /v1/bccae/evidence/:id  (bccae:audit scope)
 *
 * Spec: atlasent-internal/architecture/BCCAE-architecture.md
 * Phase 3 — Execution Assurance. Not a Deploy Gate V1 customer API.
 */

import { functionRegionHeaders } from "./functionRegion.js";
import { AtlaSentError } from "./errors.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type BccaeActorType = "HUMAN" | "AGENT" | "SERVICE" | "EXTERNAL";
export type BccaeTrustLevel = "L0" | "L1" | "L2" | "L3";
export type BccaeResourceClassification =
  | "PUBLIC"
  | "INTERNAL"
  | "CONFIDENTIAL"
  | "RESTRICTED";
export type BccaeDeploymentEnv = "PROD" | "STAGING" | "DEV" | "TEST";
export type BccaeSecurityPosture = "STANDARD" | "ELEVATED" | "LOCKED";
export type BccaeRequestSource =
  | "AGENT"
  | "API"
  | "INTERNAL"
  | "SCHEDULED"
  | "TRIGGERED";
export type BccaeRevocationTargetType =
  | "PERMIT"
  | "EVALUATION"
  | "ACTOR"
  | "RESOURCE";

export interface BccaeEvaluateInput {
  actor_id: string;
  actor_type: BccaeActorType;
  actor_trust_level: BccaeTrustLevel;
  actor_claims?: Record<string, unknown>;
  action_id: string;
  execution_intent: string;
  /** 64 lowercase hex characters (32 random bytes). */
  caller_nonce: string;
  resource_ref: string;
  resource_type: string;
  resource_classification: BccaeResourceClassification;
  organization_version?: number;
  deployment_env: BccaeDeploymentEnv;
  deployment_region: string;
  security_posture: BccaeSecurityPosture;
  external_signals?: unknown[];
  dependencies?: unknown[];
  policy_version_set?: unknown[];
  request_source?: BccaeRequestSource;
  request_chain_id?: string;
  parent_eval_id?: string;
}

export interface BccaeEvaluateResponse {
  evaluation_id: string;
  envelope_hash: string;
  permit_token: string;
  permit_id: string;
  expires_at: string;
  outcome: "PERMIT" | "PERMIT_WITH_CONDITIONS";
}

export interface BccaeExecuteInput {
  permit_token: string;
  action_id: string;
  resource_ref: string;
}

export interface BccaeExecuteResponse {
  authorized: boolean;
  outcome: "EXECUTION_AUTHORIZED" | "EXECUTION_DENIED";
  permit_id?: string;
  evaluation_id?: string;
  envelope_hash?: string;
  evidence_id?: string | null;
  /** Populated on denial — identifies which gate check failed. */
  check?: string;
  reason?: string;
}

export interface BccaeRevokeInput {
  target_type: BccaeRevocationTargetType;
  target_id: string;
  reason: string;
}

export interface BccaeRevokeResponse {
  revocation_id: string;
  target_type: BccaeRevocationTargetType;
  target_id: string;
  effective_at: string;
}

export interface BccaeEvidenceResponse {
  evidence_id: string;
  org_id: string;
  event_type: string;
  evaluation_id: string | null;
  permit_id: string | null;
  envelope_hash: string | null;
  actor_id: string;
  action_id: string | null;
  resource_ref: string | null;
  outcome: string;
  detail: Record<string, unknown>;
  previous_evidence_id: string | null;
  previous_hash: string | null;
  record_hash: string;
  sequence: number;
  recorded_at: string;
  chain_integrity: {
    hash_intact: boolean;
    expected_hash?: string;
  };
}

export interface BccaeClientOptions {
  /** API key with appropriate bccae:* scopes. */
  apiKey: string;
  /** Override base URL. Defaults to https://api.atlasent.io */
  baseUrl?: string;
  /** Request timeout in ms. Defaults to 10000. */
  timeoutMs?: number;
  /** Inject a custom fetch implementation (testing / edge runtimes). */
  fetch?: typeof globalThis.fetch;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const DEFAULT_BASE_URL = "https://api.atlasent.io";
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Validates the caller-supplied base URL and returns its normalized origin
 * (scheme://host[:port]). Using parsed.origin rather than the raw string
 * breaks the taint path from caller input to the outbound fetch call.
 */
function enforceTls(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AtlaSentError(
      "BCCAEClient baseUrl is not a valid URL",
      { code: "network" },
    );
  }
  if (parsed.protocol === "http:") {
    // Exact hostname comparison via parsed.hostname avoids
    // false positives from query strings containing 'localhost'.
    const h = parsed.hostname;
    if (h !== "localhost" && h !== "127.0.0.1" && h !== "[::1]") {
      throw new AtlaSentError(
        "BCCAEClient baseUrl must use https:// for non-local endpoints",
        { code: "network" },
      );
    }
  }
  // Return the URL's origin (scheme + host + port) — any path/query
  // component in the raw input is intentionally dropped here.
  return parsed.origin;
}

/** Generate a cryptographically random 64-char hex nonce (32 bytes). */
export function generateBccaeNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── BCCAEClient ──────────────────────────────────────────────────────────────

/**
 * Thin HTTP client for the BCCAE V1 Phase 3 endpoints.
 *
 * Each method maps 1:1 to an edge function:
 *   - {@link BCCAEClient.evaluate}    → v1-bccae-evaluate
 *   - {@link BCCAEClient.execute}     → v1-bccae-execute
 *   - {@link BCCAEClient.revoke}      → v1-bccae-revoke
 *   - {@link BCCAEClient.getEvidence} → v1-bccae-evidence
 *
 * Authorization denials are returned (not thrown). Network errors,
 * invalid API keys, and 5xx responses throw {@link AtlaSentError}.
 *
 * Use {@link generateBccaeNonce} to produce a valid `caller_nonce`.
 */
export class BCCAEClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: BccaeClientOptions) {
    if (!options.apiKey || typeof options.apiKey !== "string") {
      throw new AtlaSentError("BCCAEClient: apiKey is required", {
        code: "invalid_api_key",
      });
    }
    this.apiKey = options.apiKey;
    // enforceTls validates scheme/host and returns parsed.origin,
    // severing any taint from the raw options.baseUrl string.
    this.baseUrl = enforceTls(options.baseUrl ?? DEFAULT_BASE_URL);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async evaluate(input: BccaeEvaluateInput): Promise<BccaeEvaluateResponse> {
    const { body } = await this.post<BccaeEvaluateResponse>(
      "/v1/bccae/evaluations",
      input,
    );
    return body;
  }

  async execute(input: BccaeExecuteInput): Promise<BccaeExecuteResponse> {
    const { body } = await this.post<BccaeExecuteResponse>(
      "/v1/bccae/execute",
      input,
    );
    return body;
  }

  async revoke(input: BccaeRevokeInput): Promise<BccaeRevokeResponse> {
    const { body } = await this.post<BccaeRevokeResponse>(
      "/v1/bccae/revocations",
      input,
    );
    return body;
  }

  async getEvidence(evidenceId: string): Promise<BccaeEvidenceResponse> {
    if (!evidenceId || typeof evidenceId !== "string") {
      throw new AtlaSentError("BCCAEClient: evidenceId is required", {
        code: "bad_request",
      });
    }
    const { body } = await this.get<BccaeEvidenceResponse>(
      `/v1/bccae/evidence/${encodeURIComponent(evidenceId)}`,
    );
    return body;
  }

  // ── HTTP primitives ─────────────────────────────────────────────────────────

  private async post<T>(
    path: string,
    body: unknown,
  ): Promise<{ body: T }> {
    return this.request<T>(path, "POST", body);
  }

  private async get<T>(path: string): Promise<{ body: T }> {
    return this.request<T>(path, "GET", undefined);
  }

  private async request<T>(
    path: string,
    method: "GET" | "POST",
    body: unknown,
  ): Promise<{ body: T }> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": "atlasent-bccae-client/1.0",
      ...functionRegionHeaders(url),
    };
    if (method === "POST") headers["Content-Type"] = "application/json";

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
        ...(method === "POST" ? { body: JSON.stringify(body) } : {}),
      });
    } catch (err) {
      throw new AtlaSentError(
        `BCCAEClient: network error on ${method} ${path}: ${err instanceof Error ? err.message : String(err)}`,
        { code: "network" },
      );
    }

    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new AtlaSentError(
        `BCCAEClient: non-JSON response (status ${response.status}) from ${method} ${path}`,
        { code: "network" },
      );
    }

    if (!response.ok) {
      const err = responseBody as Record<string, unknown>;
      const message =
        typeof err?.message === "string"
          ? err.message
          : `BCCAE request failed with status ${response.status}`;
      const code =
        response.status === 401
          ? "invalid_api_key"
          : response.status === 403
            ? "forbidden"
            : response.status === 429
              ? "rate_limited"
              : response.status >= 500
                ? "server_error"
                : "network";
      throw new AtlaSentError(message, { code });
    }

    return { body: responseBody as T };
  }
}
