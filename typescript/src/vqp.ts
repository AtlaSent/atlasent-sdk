/**
 * Delta VQP — TypeScript client for the VQP re-derivation audit endpoints.
 *
 * VQPClient wraps two service-role-only edge functions:
 *   generate → POST /functions/v1/v1-generate-vqp  (creates snapshot + prompt_hash)
 *   verify   → POST /functions/v1/v1-verify-vqp    (re-derives prompt, hashes, audits)
 *
 * These endpoints require a Supabase service_role key — not a user API key.
 * This client is for server-side admin tooling only.
 *
 * Spec: atlasent-api/supabase/functions/v1-generate-vqp, v1-verify-vqp
 * Phase 3 — Deterministic re-derivation audit.
 */

import { functionRegionHeaders } from "./functionRegion.js";
import { AtlaSentError } from "./errors.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type VqpVerdict = "qualified" | "conditionally_qualified" | "not_qualified";

export interface VQPGenerateInput {
  bundle_id: string;
  org_id: string;
  /** Additional context embedded in the VQP prompt for this snapshot. */
  vqp_context?: Record<string, unknown>;
}

export interface VQPGenerateResponse {
  snapshot_id: string;
  bundle_id: string;
  bundle_version: string;
  overall_verdict: VqpVerdict;
  quality_score: number;
  /** SHA-256 hex of the deterministic VQP prompt used to produce this snapshot. */
  prompt_hash: string;
  generation_model: string;
  generated_at: string;
}

export interface VQPVerifyInput {
  snapshot_id: string;
  /**
   * Re-call the AI model with the re-derived prompt to detect score drift.
   * When false (default), only prompt hash integrity is checked.
   */
  rerun?: boolean;
}

export interface VQPVerifyResponse {
  snapshot_id: string;
  /** True when the re-derived prompt hash matches the stored snapshot.prompt_hash. */
  hash_match: boolean;
  original_prompt_hash: string;
  rerun_prompt_hash: string;
  /** Score from the re-run AI call. Null when rerun was not requested. */
  rerun_score: number | null;
  /** Verdict from the re-run AI call. Null when rerun was not requested. */
  rerun_verdict: VqpVerdict | null;
  /** rerun_score - original quality_score. Null when rerun was not requested. */
  score_delta: number | null;
  /** True when rerun_verdict differs from the stored overall_verdict. */
  verdict_changed: boolean;
  /** UUID of the written vqp_audit_log row. */
  audit_log_id: string;
}

export interface VQPClientOptions {
  /** Supabase service_role key. These endpoints are not accessible with user API keys. */
  serviceRoleKey: string;
  /** Supabase project URL, e.g. https://<ref>.supabase.co */
  supabaseUrl: string;
  /** Request timeout in ms. Defaults to 30000 (AI re-run calls can be slow). */
  timeoutMs?: number;
  /** Inject a custom fetch implementation (testing / edge runtimes). */
  fetch?: typeof globalThis.fetch;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 30_000;

function enforceHttps(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AtlaSentError("VQPClient supabaseUrl is not a valid URL", {
      code: "network",
    });
  }
  if (parsed.protocol === "http:") {
    const h = parsed.hostname;
    if (h !== "localhost" && h !== "127.0.0.1" && h !== "[::1]") {
      throw new AtlaSentError(
        "VQPClient supabaseUrl must use https:// for non-local endpoints",
        { code: "network" },
      );
    }
  }
  return parsed.origin;
}

// ─── VQPClient ────────────────────────────────────────────────────────────────

/**
 * Thin HTTP client for the Delta VQP Phase 3 service-role endpoints.
 *
 * Each method maps 1:1 to an edge function:
 *   - {@link VQPClient.generate} → v1-generate-vqp
 *   - {@link VQPClient.verify}   → v1-verify-vqp
 *
 * **Server-side only.** These endpoints require `SUPABASE_SERVICE_ROLE_KEY`.
 * Never expose a service_role key in browser or agent code.
 *
 * Network errors and 5xx responses throw {@link AtlaSentError}.
 */
export class VQPClient {
  private readonly serviceRoleKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: VQPClientOptions) {
    if (!options.serviceRoleKey || typeof options.serviceRoleKey !== "string") {
      throw new AtlaSentError("VQPClient: serviceRoleKey is required", {
        code: "invalid_api_key",
      });
    }
    this.serviceRoleKey = options.serviceRoleKey;
    this.baseUrl = enforceHttps(options.supabaseUrl);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async generate(input: VQPGenerateInput): Promise<VQPGenerateResponse> {
    const { body } = await this.post<VQPGenerateResponse>(
      "/functions/v1/v1-generate-vqp",
      input,
    );
    return body;
  }

  async verify(input: VQPVerifyInput): Promise<VQPVerifyResponse> {
    const { body } = await this.post<VQPVerifyResponse>(
      "/functions/v1/v1-verify-vqp",
      input,
    );
    return body;
  }

  // ── HTTP primitives ─────────────────────────────────────────────────────────

  private async post<T>(path: string, body: unknown): Promise<{ body: T }> {
    return this.request<T>(path, "POST", body);
  }

  private async request<T>(
    path: string,
    method: "GET" | "POST",
    body: unknown,
  ): Promise<{ body: T }> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.serviceRoleKey}`,
      "User-Agent": "atlasent-vqp-client/1.0",
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
        `VQPClient: network error on ${method} ${path}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { code: "network" },
      );
    }

    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      throw new AtlaSentError(
        `VQPClient: non-JSON response (status ${response.status}) from ${method} ${path}`,
        { code: "network" },
      );
    }

    if (!response.ok) {
      const err = responseBody as Record<string, unknown>;
      const message =
        typeof err?.message === "string"
          ? err.message
          : `VQP request failed with status ${response.status}`;
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
