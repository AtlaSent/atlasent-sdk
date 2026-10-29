/**
 * Trusted-host adapter for the EXISTING v1-agent-actor-identity endpoint.
 * It attests the agent bound to a key, never human approval or refund authority.
 * Shape/binding checks here do not replace the runtime's signature verification.
 */
import { resolveRuntimeBaseUrl, DEFAULT_APPROVALS_BASE_URL } from "./approvals.js";
import type { RefundActorIdentityResolver } from "./guard.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BYTES = 64 * 1024;
const record = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const fail = (): never => { throw new Error("agent identity source unavailable or returned an invalid binding"); };

export interface AgentActorIdentityOptions {
  apiKey: string;
  /** Must be the actual enrolled key-bound agent: agent:<lowercase UUID>. */
  actor: string;
  /** Expected tenant from trusted host configuration, never model input. */
  tenantId: string;
  baseUrl?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  now?: () => Date;
}

async function readJson(res: Response): Promise<unknown> {
  if (!res.body) return fail();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) return fail();
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    // Do not wait for an untrusted producer's cancellation acknowledgement.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function createAgentActorIdentityResolver(options: AgentActorIdentityOptions): RefundActorIdentityResolver {
  const { apiKey, actor } = options;
  const tenant = options.tenantId.toLowerCase();
  if (!apiKey || !actor.startsWith("agent:") || !UUID.test(actor.slice(6)) || !UUID.test(tenant)) {
    throw new Error("configure the enrolled agent identity, tenant and API key");
  }
  const base = new URL(resolveRuntimeBaseUrl(options.baseUrl ?? DEFAULT_APPROVALS_BASE_URL));
  if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash) {
    throw new Error("agent identity source requires an HTTPS runtime base without credentials, query or fragment");
  }
  const url = `${base.href.replace(/\/$/, "")}/v1-agent-actor-identity`;
  const doFetch = options.fetch ?? fetch;
  const now = options.now ?? (() => new Date());
  const timeout = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 60_000) throw new Error("invalid identity source timeout");

  return async binding => {
    // A staff/session actor cannot silently become the key's agent.
    if (binding.actor !== actor) return fail();
    try {
      const response = await doFetch(url, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(timeout),
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
        // request_hash is deliberately omitted. The permit execution hash is
        // not the endpoint-specific identity commitment expected by all
        // consumers; inventing that equality would make valid claims fail.
        body: JSON.stringify({ action_type: binding.actionType, environment: binding.environment }),
      });
      if (response.status !== 200 || response.redirected) {
        void response.body?.cancel().catch(() => {});
        return fail();
      }
      const envelope = await readJson(response);
      if (!record(envelope) || envelope.kind !== "actor_identity.v1" || envelope.actor_id !== actor ||
          envelope.agent_identity_id !== actor.slice(6) || !record(envelope.assertion)) return fail();
      const a = envelope.assertion;
      if (a.version !== "actor_identity.v1" || !record(a.subject) || !record(a.binding) || !record(a.issuer)) return fail();
      if (a.subject.principal_id !== actor || a.subject.principal_kind !== "agent" || a.subject.role !== "agent" ||
          a.binding.tenant_id !== tenant || a.binding.action_type !== binding.actionType ||
          a.binding.environment !== binding.environment || a.binding.request_hash !== undefined ||
          a.issuer.type !== "oidc" || a.issuer.issuer_id !== "atlasent-agent-key-issuer" ||
          typeof a.issuer.kid !== "string" || !a.issuer.kid ||
          a.agent_runtime_identity !== undefined || a.entra_provenance !== undefined ||
          typeof a.signature !== "string" || !/^[0-9a-f]{128}$/.test(a.signature) ||
          typeof a.issued_at !== "string" || typeof a.expires_at !== "string" ||
          envelope.expires_at !== a.expires_at) return fail();
      const issued = Date.parse(a.issued_at), expires = Date.parse(a.expires_at), current = now().getTime();
      if (![issued, expires, current].every(Number.isFinite) || expires <= current ||
          issued > current + 60_000 || expires <= issued || expires - issued > 365_000) return fail();
      return a;
    } catch { return fail(); }
  };
}
