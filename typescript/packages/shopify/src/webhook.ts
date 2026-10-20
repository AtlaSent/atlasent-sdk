/**
 * The after-the-fact alarm: every `refunds/create` webhook is checked against
 * the permit ledger, and a refund the gate did not authorize is flagged.
 *
 * This DETECTS, it does not prevent. Shopify sends the webhook after the
 * refund has happened. Prevention is the gate itself plus removing the
 * refund permission from staff accounts (see README).
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { gateRefFromNote, type PermitLedger } from "./ledger.js";
import { moneyToCents } from "./facts.js";

/** `X-Shopify-Hmac-Sha256`: base64 HMAC-SHA256 of the raw body with the app's client secret. */
export function verifyShopifyWebhookHmac(rawBody: Buffer | string, hmacHeader: string | undefined, secret: string): boolean {
  if (typeof hmacHeader !== "string" || hmacHeader.length === 0 || secret.length === 0) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  let presented: Buffer;
  try {
    presented = Buffer.from(hmacHeader, "base64");
  } catch {
    return false;
  }
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/** The fields of the REST-shaped refunds/create payload this check reads. */
export interface RefundWebhookPayload {
  id: number | string;
  order_id: number | string;
  note?: string | null;
  transactions?: { kind?: string; status?: string; amount?: string }[];
}

export type RefundAuditVerdict =
  | { verdict: "authorized"; refundId: string; orderId: string; amountCents: number; gateRef: string }
  | { verdict: "unauthorized"; refundId: string; orderId: string; amountCents: number | null; gateRef?: string; reason: string };

const numericId = (id: string | number) => String(id).replace(/^gid:\/\/shopify\/\w+\//, "");

function refundedCents(payload: RefundWebhookPayload): number | null {
  try {
    return (payload.transactions ?? [])
      .filter((t) => t.kind?.toLowerCase() === "refund" && t.status?.toLowerCase() === "success")
      .reduce((n, t) => n + moneyToCents(String(t.amount)), 0);
  } catch {
    return null;
  }
}

export async function auditRefundWebhook(payload: RefundWebhookPayload, ledger: PermitLedger): Promise<RefundAuditVerdict> {
  const refundId = numericId(payload.id);
  const orderId = numericId(payload.order_id);
  const amountCents = refundedCents(payload);
  const unauthorized = (reason: string, gateRef?: string): RefundAuditVerdict => ({
    verdict: "unauthorized",
    refundId,
    orderId,
    amountCents,
    ...(gateRef !== undefined ? { gateRef } : {}),
    reason,
  });

  const gateRef = gateRefFromNote(payload.note);
  if (gateRef === undefined) return unauthorized("the refund note carries no AtlaSent gate reference");
  const entry = await ledger.get(gateRef);
  if (entry === undefined) return unauthorized("the gate reference in the note is not in the permit ledger", gateRef);
  if (numericId(entry.order_id) !== orderId) return unauthorized("the permit was for a different order", gateRef);
  if (amountCents === null || amountCents !== entry.amount_cents) {
    return unauthorized(`the permit was for ${entry.amount_cents} cents, the refund was ${amountCents ?? "unreadable"}`, gateRef);
  }
  if (entry.refund_id !== undefined && numericId(entry.refund_id) !== refundId) {
    return unauthorized("the permit was used by a different refund", gateRef);
  }
  if (!(await ledger.claim(gateRef, refundId))) {
    return unauthorized("the permit already accounts for another refund", gateRef);
  }
  return { verdict: "authorized", refundId, orderId, amountCents, gateRef };
}
