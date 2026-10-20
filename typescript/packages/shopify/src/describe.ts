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
    r.decision === "escalate"
      ? "Sent to a manager for approval. No refund has been issued."
      : r.decision === "hold"
        ? "On hold. No refund has been issued."
        : `Not refunded: ${r.reason}`;
  return {
    refunded: false,
    decision: r.decision,
    message,
    ...(r.denyCode !== undefined ? { denyCode: r.denyCode } : {}),
    gateRef: r.gateRef,
    ...(r.escalationId !== undefined ? { escalationId: r.escalationId } : {}),
  };
}
