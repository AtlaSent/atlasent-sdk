/**
 * The two runtime calls that resume an escalated refund after a person
 * decides it in the AtlaSent console. Same protocol as atlasent-action's
 * `waitForApprovalResolution` and the MCP server's `awaitApproval`:
 *
 *   GET  /v1-approvals/{id}              status poll; never carries a token
 *   POST /v1-approvals/{id}/claim-permit one-time atomic claim of the permit
 *
 * This code cannot approve anything. It reads the decision a person made and,
 * on approval, claims the single permit the runtime minted for it.
 *
 * The @atlasent/shopify package carries the same file; the two install
 * independently.
 */

/** Built-in base: the hosted runtime's functions root (same as @atlasent/sdk). */
export const DEFAULT_APPROVALS_BASE_URL = "https://api.atlasent.io/functions/v1";

/** Statuses on which a permit can be claimed. Everything else that is not "pending" is final and has no permit. */
/** Hosts of AtlaSent's hosted runtime, where functions live under /functions/v1. */
const HOSTED_RUNTIME_HOSTS: ReadonlySet<string> = new Set(["api.atlasent.io", "kttccumlnmdtupgbyfue.supabase.co", "lwnqpmnxpeyhpxvastku.supabase.co"]);

/**
 * The SDK's base-URL rule (typescript/src/baseUrl.ts `resolveBaseUrl`; keep in
 * step, a test compares them): strip trailing slashes, and give a hosted host
 * with no path `/functions/v1`, where the gateway serves functions. Any other
 * host or explicit path passes through.
 */
export function resolveRuntimeBaseUrl(baseUrl: string): string {
  let end = baseUrl.length;
  while (end > 0 && baseUrl.charCodeAt(end - 1) === 47) end--;
  const trimmed = baseUrl.slice(0, end);
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return trimmed;
  }
  const atRoot = parsed.pathname === "" || parsed.pathname === "/";
  if (atRoot && parsed.search === "" && parsed.hash === "" && HOSTED_RUNTIME_HOSTS.has(parsed.hostname.toLowerCase())) {
    return `${trimmed}/functions/v1`;
  }
  return trimmed;
}

export const CLAIMABLE_APPROVAL_STATUSES: ReadonlySet<string> = new Set(["approved", "approved_awaiting_claim"]);

export type ApprovalStatus = { found: false } | { found: true; status: string; reEvaluationDecision?: string };

export type ApprovalClaim =
  | { claimed: true; permitToken: string; executionHashExpected?: string }
  | { claimed: false; failure: string };

export interface ApprovalsApi {
  getStatus(approvalRequestId: string): Promise<ApprovalStatus>;
  claimPermit(approvalRequestId: string): Promise<ApprovalClaim>;
}

export class ApprovalsApiError extends Error {
  override name = "ApprovalsApiError";
}

export function assertApprovalRequestId(id: string): string {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new ApprovalsApiError(`not an approval request id: ${JSON.stringify(id)}`);
  return id;
}

export function createApprovalsClient(opts: { apiKey: string; baseUrl?: string; fetch?: typeof fetch; timeoutMs?: number }): ApprovalsApi {
  const doFetch = opts.fetch ?? fetch;
  const base = resolveRuntimeBaseUrl(opts.baseUrl ?? DEFAULT_APPROVALS_BASE_URL);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const headers = { authorization: `Bearer ${opts.apiKey}`, "content-type": "application/json" };

  async function call(method: "GET" | "POST", path: string): Promise<{ status: number; json: Record<string, unknown> | null }> {
    const res = await doFetch(`${base}${path}`, {
      method,
      headers,
      ...(method === "POST" ? { body: "{}" } : {}),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const json = (await res.json().catch(() => null)) as unknown;
    return { status: res.status, json: json && typeof json === "object" ? (json as Record<string, unknown>) : null };
  }

  /** "HTTP 403" alone sends people hunting; name the scope the runtime asked for. */
  function httpFailure(status: number, json: Record<string, unknown> | null): string {
    if (status === 403 && json?.error === "insufficient_scope") return "HTTP 403: this API key lacks approvals:read, which resuming an escalated refund needs";
    if (status === 403 && typeof json?.message === "string" && /originating API key/.test(json.message)) {
      return "HTTP 403: only the API key that asked for the refund may claim its permit";
    }
    return `HTTP ${status}`;
  }

  return {
    async getStatus(id) {
      const { status, json } = await call("GET", `/v1-approvals/${encodeURIComponent(assertApprovalRequestId(id))}`);
      if (status === 404) return { found: false };
      if (status !== 200 || json === null || typeof json.status !== "string") {
        throw new ApprovalsApiError(`approval status read failed: ${httpFailure(status, json)}`);
      }
      const re = json.re_evaluation_decision;
      return { found: true, status: json.status, ...(typeof re === "string" ? { reEvaluationDecision: re } : {}) };
    },
    async claimPermit(id) {
      const { status, json } = await call("POST", `/v1-approvals/${encodeURIComponent(assertApprovalRequestId(id))}/claim-permit`);
      if (status === 403) return { claimed: false, failure: httpFailure(status, json) };
      if (status !== 200) return { claimed: false, failure: typeof json?.error === "string" ? json.error : `HTTP ${status}` };
      const token = json?.permit_token;
      if (json?.claimed !== true || typeof token !== "string" || token.length === 0) return { claimed: false, failure: "not_claimed" };
      const hash = json.execution_hash_expected;
      return { claimed: true, permitToken: token, ...(typeof hash === "string" && hash.length > 0 ? { executionHashExpected: hash } : {}) };
    },
  };
}
