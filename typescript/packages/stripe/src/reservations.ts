import { DEFAULT_APPROVALS_BASE_URL, resolveRuntimeBaseUrl } from "./approvals.js";

/** Budget evidence only: neither a Permit nor a provider-outcome receipt. */
export interface RefundBudgetSubject {
  environment: string;
  provider_account: string;
  business_request_id: string;
  payment_ref: string;
  customer_ref: string | null;
  amount_minor: string;
  currency: string;
}
export interface RefundReservationsApi {
  reserve(subject: RefundBudgetSubject): Promise<{ reservationId: string }>;
  recheck(subject: RefundBudgetSubject, reservationId: string): Promise<void>;
}
export class RefundBudgetError extends Error { override name = "RefundBudgetError"; }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Uses the existing runtime function, authenticated independently of Stripe. */
export function createRefundReservationsClient(opts: {
  apiKey: string; baseUrl?: string; fetch?: typeof fetch; timeoutMs?: number;
}): RefundReservationsApi {
  const base = resolveRuntimeBaseUrl(opts.baseUrl ?? DEFAULT_APPROVALS_BASE_URL);
  const url = new URL(base);
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
    || url.username || url.password || url.search || url.hash || !opts.apiKey.trim()) {
    throw new RefundBudgetError("invalid refund reservation client configuration");
  }
  const doFetch = opts.fetch ?? fetch;
  const key = opts.apiKey;
  const timeout = opts.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeout) || timeout <= 0 || timeout > 60_000) throw new RefundBudgetError("invalid budget timeout");

  async function call(action: string, subject: RefundBudgetSubject, reservationId?: string): Promise<string> {
    // Snapshot before any asynchronous authorizer/transport can mutate input.
    const frozen = structuredClone(subject);
    const body = { ...frozen, ...(reservationId === undefined ? {} : { reservation_id: reservationId }) };
    try {
      const res = await doFetch(`${base}/v1-consequential-operations/${action}`, {
        method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
        body: JSON.stringify(body), redirect: "error", signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok || !res.body) throw new RefundBudgetError("refund budget refused or unavailable");
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          size += value.byteLength;
          if (size > 65536) { await reader.cancel(); throw new RefundBudgetError("invalid budget receipt"); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      const r: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (!r || typeof r !== "object" || Array.isArray(r)) throw new RefundBudgetError("invalid budget receipt");
      const receipt = r as Record<string, unknown>;
      const binding = receipt.binding as Record<string, unknown> | undefined;
      if (receipt.ok !== true || receipt.state !== "reserved" || receipt.budget_status !== "enforced"
        || receipt.authority_effect !== "none" || typeof receipt.reservation_id !== "string" || !UUID.test(receipt.reservation_id)
        || (reservationId !== undefined && receipt.reservation_id !== reservationId)
        || typeof receipt.budget_remaining_minor !== "string" || !/^[0-9]+$/.test(receipt.budget_remaining_minor)
        || !binding || binding.provider !== "stripe" || binding.reservation_id !== receipt.reservation_id
        || Object.entries(frozen).some(([k, v]) => binding[k] !== v)) {
        throw new RefundBudgetError("invalid budget receipt");
      }
      return receipt.reservation_id;
    } catch (err) {
      if (err instanceof RefundBudgetError) throw err;
      // A transport/body error may contain credentials; never copy its message.
      throw new RefundBudgetError("refund budget refused or unavailable");
    }
  }
  return {
    reserve: async (subject) => ({ reservationId: await call("refund-reserve", subject) }),
    recheck: async (subject, reservationId) => { await call("refund-recheck", subject, reservationId); },
  };
}
