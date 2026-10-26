/**
 * Read-only post-purchase operations preview for the existing Shopify demo.
 *
 * This is NOT a refund decision, a permit, a coverage scan, or evidence of
 * customer eligibility. It only drafts an operator's next step from a
 * server-authenticated Shopify order read. No mutations or notifications.
 */
import type { ShopifyOrder } from "./admin.js";
import { deriveRefundFacts, SUPPORTED_CURRENCY } from "./facts.js";

export type PreviewDisposition = "routine_candidate" | "needs_attention" | "unavailable";
export type PreviewNextStep =
  | "verify_business_eligibility"
  | "inspect_payment_history"
  | "inspect_order_status"
  | "verify_refundable_amount"
  | "obtain_supported_currency"
  | "retry_source_read";

export interface RefundOperationsPreview {
  schema: "atlasent.shopify_refund_operations_preview.v1";
  mode: "read_only";
  authorization: "not_evaluated";
  execution: "not_attempted";
  customer_notification: "not_sent";
  disposition: PreviewDisposition;
  next_step: PreviewNextStep;
  /** Only what was actually observed from Shopify, not authenticated ownership. */
  observed: {
    order_id: string;
    currency: string;
    order_status: string;
    refundable_cents: number | null;
    requested_cents: number;
  };
  /** The source read was performed at this server time; NOT the age of Shopify's records. */
  read_at: string;
  missing_proofs: string[];
  operator_message: string;
}

const MISSING = [
  "authenticated_customer_order_ownership",
  "merchant_reason_and_return_policy",
  "return_or_service_evidence",
  "other_compensation_and_full_refund_history",
  "current_dispute_state",
  "independent_authority_and_approval",
  "cumulative_budgets_and_execution_path",
] as const;

function result(
  orderId: string, amountCents: number, readAt: string,
  disposition: PreviewDisposition, nextStep: PreviewNextStep,
  message: string, facts?: { currency: string; order_status: string; refundable_cents: number },
): RefundOperationsPreview {
  return {
    schema: "atlasent.shopify_refund_operations_preview.v1",
    mode: "read_only",
    authorization: "not_evaluated",
    execution: "not_attempted",
    customer_notification: "not_sent",
    disposition,
    next_step: nextStep,
    observed: {
      order_id: orderId,
      currency: facts?.currency ?? "unknown",
      order_status: facts?.order_status ?? "unknown",
      refundable_cents: facts?.refundable_cents ?? null,
      requested_cents: amountCents,
    },
    read_at: readAt,
    missing_proofs: [...MISSING],
    operator_message: message,
  };
}

/**
 * No allow/deny output is possible. Unknown source values must never become
 * zero, false, "eligible", or a completed refund.
 */
export function previewShopifyRefundOperation(
  order: ShopifyOrder | null, amountCents: number, now: Date,
): RefundOperationsPreview {
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) throw new RangeError("invalid refund amount");
  if (!Number.isFinite(now.getTime())) throw new RangeError("invalid observation time");
  const at = now.toISOString();
  if (order === null) {
    return result("unknown", amountCents, at, "unavailable", "retry_source_read",
      "Order was not found in the connected store. No refund was evaluated.");
  }
  // The existing Shopify adapter reads at most 100 transactions and does not
  // paginate. An exactly-full page cannot prove a complete refund history.
  if (!Array.isArray(order.transactions) || order.transactions.length >= 100 ||
      !Array.isArray(order.fulfillments) || order.fulfillments.length >= 50) {
    return result(order.id, amountCents, at, "unavailable", "inspect_payment_history",
      "Order data may be incomplete; verify all transaction and fulfillment pages.");
  }
  try {
    const facts = deriveRefundFacts(order, now);
    const observed = {
      currency: facts.currency,
      order_status: facts.order_status,
      refundable_cents: facts.refundable_cents,
    };
    // Unknown, pending or failed payment/refund transactions cannot prove a
    // complete payment history. Never silently drop them and call it routine.
    if (order.transactions.some(t =>
      ["SALE", "CAPTURE", "REFUND"].includes(t.kind.toUpperCase()) &&
      t.status.toUpperCase() !== "SUCCESS")) {
      return result(order.id, amountCents, at, "needs_attention", "inspect_payment_history",
        "Payment or refund transactions are unresolved or unsuccessful; reconcile before proceeding.", observed);
    }
    // Multiple successful captures/sales require payment-specific allocation.
    const captures = order.transactions.filter(t =>
      (t.kind === "SALE" || t.kind === "CAPTURE") && t.status === "SUCCESS");
    if (facts.currency !== SUPPORTED_CURRENCY ||
        order.transactions.some(t => t.amountSet?.shopMoney?.currencyCode !== facts.currency)) {
      return result(order.id, amountCents, at, "needs_attention", "obtain_supported_currency",
        "Currency or transaction currency is unsupported or inconsistent; no automatic action.", observed);
    }
    // A pending or failed refund can represent an unresolved compensation
    // attempt. Do not propose another routine refund until reconciled.
    if (order.transactions.some(t => t.kind === "REFUND" && t.status !== "SUCCESS")) {
      return result(order.id, amountCents, at, "needs_attention", "inspect_payment_history",
        "A prior refund has an unresolved or non-success status; reconcile before proceeding.", observed);
    }
    if (captures.length !== 1 || facts.parent_transaction === null) {
      return result(order.id, amountCents, at, "needs_attention", "inspect_payment_history",
        "Payment history requires review before a refund can be proposed.", observed);
    }
    if (facts.order_status !== "delivered" || facts.days_since_delivery === undefined) {
      return result(order.id, amountCents, at, "needs_attention", "inspect_order_status",
        "Check the reason and fulfillment status; non-delivery may still qualify under merchant policy.", observed);
    }
    if (facts.refundable_cents < amountCents) {
      return result(order.id, amountCents, at, "needs_attention", "verify_refundable_amount",
        "Requested amount exceeds the currently observed refundable balance; reconcile all payment and credit sources.", observed);
    }
    return result(order.id, amountCents, at, "routine_candidate", "verify_business_eligibility",
      "A routine refund case may be prepared for policy, return and authority checks. Nothing has been authorized or paid.", observed);
  } catch {
    // Provider records can be malformed or internally inconsistent; do not
    // surface their raw contents or error strings to the customer.
    return result(order.id, amountCents, at, "unavailable", "retry_source_read",
      "Shopify returned incomplete or inconsistent order facts. Review the source before proceeding.");
  }
}
