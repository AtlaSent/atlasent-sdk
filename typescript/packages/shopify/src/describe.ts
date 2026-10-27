import { centsToMoney } from "./facts.js";
import type { RefundResult } from "./guard.js";

/** What the admin button shows. */
export function describeResult(r: RefundResult): Record<string, unknown> {
  if (r.refunded) {
    return {
      refunded: true,
      message: `Refunded $${centsToMoney(r.amountCents)}`,
      refundId: r.refund.id,
      gateRef: r.gateRef,
    };
  }
  const message =
    r.decision === "unconfirmed"
      ? "Refund status is unconfirmed. Reconcile this request before issuing another refund."
      : r.decision === "duplicate_request"
        ? "This request was already recorded. Review its original outcome; no additional refund was issued."
        : r.decision === "reconciliation_required"
          ? "An earlier refund needs reconciliation. No additional refund was issued."
          : r.decision === "escalate"
      ? "Sent to a manager for approval. No refund has been issued yet."
      : r.decision === "hold"
        ? r.approvalRequestId !== undefined
          ? "Still waiting for a manager. No refund has been issued yet."
          : "On hold. No refund has been issued."
        : `Not refunded: ${r.reason}`;
  return {
    refunded: false,
    decision: r.decision,
    message,
    ...(r.denyCode !== undefined ? { denyCode: r.denyCode } : {}),
    gateRef: r.gateRef,
    ...(r.escalationId !== undefined ? { escalationId: r.escalationId } : {}),
    ...(r.approvalRequestId !== undefined ? { approvalRequestId: r.approvalRequestId } : {}),
    ...(r.refundId !== undefined ? { refundId: r.refundId } : {}),
  };
}

