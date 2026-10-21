/**
 * The after-the-fact alarm for Stripe: every `refund.created` event is
 * checked against the permit ledger, and a refund the gate did not
 * authorize (for example one issued in the Stripe Dashboard, or with another
 * API key) is flagged.
 *
 * This DETECTS, it does not prevent. Stripe offers no hook to approve a
 * refund before it is created. Prevention is the gate plus making it the
 * only holder of refund rights: a restricted API key for the gate, and no
 * refund permission for Dashboard users (see README).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import type { LedgerEntry, PermitLedger } from "./ledger.js";
import type { StripeRefund } from "./stripe.js";

/**
 * Verifies `Stripe-Signature: t=<unix>,v1=<hex>[,v1=...]`: HMAC-SHA256 of
 * `${t}.${rawBody}` with the endpoint's signing secret, within `toleranceSeconds`.
 */
export function verifyStripeSignature(
  rawBody: Buffer | string,
  header: string | undefined,
  secret: string,
  opts: { now?: Date; toleranceSeconds?: number } = {},
): boolean {
  if (typeof header !== "string" || header.length === 0 || header.length > 4096 || secret.length === 0) return false;
  let t: number | undefined;
  const v1: string[] = [];
  for (const part of header.split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === "t" && /^\d{1,12}$/.test(v)) t = Number(v);
    else if (k === "v1" && /^[0-9a-f]{64}$/.test(v)) v1.push(v);
  }
  if (t === undefined || v1.length === 0) return false;
  const nowS = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (Math.abs(nowS - t) > (opts.toleranceSeconds ?? 300)) return false;
  const body = typeof rawBody === "string" ? rawBody : rawBody.toString("utf8");
  const expected = createHmac("sha256", secret).update(`${t}.${body}`).digest();
  return v1.some((sig) => {
    const presented = Buffer.from(sig, "hex");
    return presented.length === expected.length && timingSafeEqual(presented, expected);
  });
}

export type StripeRefundAuditVerdict =
  | { verdict: "authorized"; refundId: string; paymentIntent: string | null; amountCents: number; gateRef: string }
  | { verdict: "ignored"; refundId: string; reason: string }
  | {
      verdict: "unauthorized";
      refundId: string;
      paymentIntent: string | null;
      amountCents: number;
      gateRef?: string;
      reason: string;
    };

export async function auditStripeRefund(refund: StripeRefund, ledger: PermitLedger): Promise<StripeRefundAuditVerdict> {
  const refundId = refund.id;
  // A failed or canceled refund moved no money.
  if (refund.status === "failed" || refund.status === "canceled") {
    return { verdict: "ignored", refundId, reason: `refund status ${refund.status}` };
  }
  const unauthorized = (reason: string, gateRef?: string): StripeRefundAuditVerdict => ({
    verdict: "unauthorized",
    refundId,
    paymentIntent: refund.payment_intent,
    amountCents: refund.amount,
    ...(gateRef !== undefined ? { gateRef } : {}),
    reason,
  });

  const gateRef = refund.metadata?.atlasent_gate_ref;
  if (typeof gateRef !== "string" || gateRef.length === 0) return unauthorized("the refund carries no AtlaSent gate reference");
  let entry: LedgerEntry | undefined;
  try {
    entry = await ledger.get(gateRef);
  } catch (err) {
    // Fail closed: a ledger that cannot be read never vouches for a refund.
    return unauthorized(`the permit ledger is unavailable (${err instanceof Error ? err.message : String(err)})`, gateRef);
  }
  if (entry === undefined) return unauthorized("the gate reference is not in the permit ledger", gateRef);
  if (entry.aborted_reason !== undefined) {
    return unauthorized(`the gate stopped this refund before issuing it (${entry.aborted_reason})`, gateRef);
  }
  if (entry.payment_intent !== refund.payment_intent) return unauthorized("the permit was for a different payment", gateRef);
  if (entry.amount_cents !== refund.amount) {
    return unauthorized(`the permit was for ${entry.amount_cents} cents, the refund was ${refund.amount}`, gateRef);
  }
  if (entry.refund_id !== undefined && entry.refund_id !== refundId) return unauthorized("the permit was used by a different refund", gateRef);
  let claimed: boolean;
  try {
    claimed = await ledger.claim(gateRef, refundId);
  } catch (err) {
    // Includes LedgerLockError: the claim was not recorded, so it is not authorized.
    return unauthorized(`the permit ledger is unavailable (${err instanceof Error ? err.message : String(err)})`, gateRef);
  }
  if (!claimed) return unauthorized("the permit already accounts for another refund", gateRef);
  return { verdict: "authorized", refundId, paymentIntent: refund.payment_intent, amountCents: refund.amount, gateRef };
}

/** Parses a verified event body; returns the refund for `refund.created`, else null. */
export function refundFromEvent(rawBody: Buffer | string): StripeRefund | null {
  const event = JSON.parse(typeof rawBody === "string" ? rawBody : rawBody.toString("utf8")) as {
    type?: string;
    data?: { object?: StripeRefund };
  };
  if (event.type !== "refund.created") return null;
  const r = event.data?.object;
  return r && typeof r.id === "string" && typeof r.amount === "number" ? r : null;
}
