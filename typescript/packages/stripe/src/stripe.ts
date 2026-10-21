/**
 * Minimal Stripe REST client: the two calls a gated refund needs.
 *
 *   GET  /v1/payment_intents/:id?expand[]=latest_charge
 *   POST /v1/refunds  (form-encoded, with an Idempotency-Key)
 *
 * No Stripe-Version header is sent, so the account's default API version
 * applies. Field names follow Stripe's PaymentIntent, Charge and Refund
 * objects. They have not been run against a live account from this package
 * yet; check them against the version your account is pinned to.
 */

export interface StripeCharge {
  id: string;
  status: string;
  currency: string;
  amount_captured: number;
  amount_refunded: number;
  disputed: boolean;
  created: number;
}

export interface StripePaymentIntent {
  id: string;
  status: string;
  currency: string;
  metadata: Record<string, string>;
  latest_charge: StripeCharge | null;
}

export interface StripeRefund {
  id: string;
  status: string;
  amount: number;
  currency: string;
  charge: string | null;
  payment_intent: string | null;
  metadata: Record<string, string>;
}

export interface CreateRefundInput {
  payment_intent: string;
  amount: number;
  reason: "requested_by_customer";
  metadata: Record<string, string>;
}

/** What the guard needs from Stripe. Tests substitute a fake. */
export interface StripeApi {
  getPaymentIntent(id: string): Promise<StripePaymentIntent | null>;
  /** `idempotencyKey` makes a retried call return the first refund instead of creating a second. */
  createRefund(input: CreateRefundInput, idempotencyKey: string): Promise<StripeRefund>;
}

export class StripeApiError extends Error {
  override name = "StripeApiError";
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export function assertPaymentIntentId(id: string): string {
  const s = id.trim();
  if (!/^pi_[A-Za-z0-9]{1,250}$/.test(s)) throw new StripeApiError(`not a Stripe PaymentIntent id: ${JSON.stringify(id)}`);
  return s;
}

/** Stripe's form encoding, including nested `metadata[key]`. */
export function formEncode(input: Record<string, unknown>): string {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(input)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "object") {
      for (const [mk, mv] of Object.entries(v as Record<string, unknown>)) out.append(`${k}[${mk}]`, String(mv));
    } else {
      out.append(k, String(v));
    }
  }
  return out.toString();
}

export interface StripeClientOptions {
  /** A restricted key with Charges/PaymentIntents read and Refunds write is enough. */
  secretKey: string;
  /** Connect: act on a connected account. */
  stripeAccount?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  baseUrl?: string;
}

export function createStripeClient(opts: StripeClientOptions): StripeApi {
  const doFetch = opts.fetch ?? fetch;
  const base = (opts.baseUrl ?? "https://api.stripe.com").replace(/\/$/, "");
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const headers = (extra: Record<string, string> = {}) => ({
    authorization: `Bearer ${opts.secretKey}`,
    ...(opts.stripeAccount ? { "stripe-account": opts.stripeAccount } : {}),
    ...extra,
  });

  async function parse<T>(res: Response): Promise<T> {
    const body = (await res.json().catch(() => null)) as (T & { error?: { message?: string } }) | null;
    if (!res.ok || body === null) {
      throw new StripeApiError(`Stripe API HTTP ${res.status}${body?.error?.message ? `: ${body.error.message}` : ""}`, res.status);
    }
    return body;
  }

  return {
    async getPaymentIntent(id) {
      const pi = assertPaymentIntentId(id);
      const res = await doFetch(`${base}/v1/payment_intents/${pi}?expand%5B%5D=latest_charge`, {
        headers: headers(),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 404) return null;
      return parse<StripePaymentIntent>(res);
    },
    async createRefund(input, idempotencyKey) {
      const res = await doFetch(`${base}/v1/refunds`, {
        method: "POST",
        headers: headers({ "content-type": "application/x-www-form-urlencoded", "idempotency-key": idempotencyKey }),
        body: formEncode(input as unknown as Record<string, unknown>),
        signal: AbortSignal.timeout(timeoutMs),
      });
      return parse<StripeRefund>(res);
    },
  };
}
