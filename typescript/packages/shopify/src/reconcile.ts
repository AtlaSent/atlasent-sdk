/** Read-only provider reconciliation. Never sends or retries a refund. */
import type { RefundCreateInput, ShopifyAdmin } from "./admin.js";
import { centsToMoney } from "./facts.js";
import type { PermitLedger } from "./ledger.js";
import { confirmRefundReadback } from "./refund-completion.js";

export interface RefundReconciliation {
  gateRef: string;
  status: "succeeded" | "unconfirmed" | "refused";
  reason: string;
  refundId?: string;
}

export async function reconcileShopifyRefund(
  shopify: Pick<ShopifyAdmin, "getRefund">,
  ledger: PermitLedger,
  request: { gateRef: string; shop: string; environment: string; candidateRefundId?: string },
): Promise<RefundReconciliation> {
  const result = (status: RefundReconciliation["status"], reason: string, refundId?: string): RefundReconciliation =>
    ({ gateRef: request.gateRef, status, reason, ...(refundId ? { refundId } : {}) });
  try {
    const entry = await ledger.get(request.gateRef);
    if (!entry || entry.shop !== request.shop || entry.environment !== request.environment || entry.aborted_reason !== undefined ||
        !entry.parent_transaction_id || !entry.gateway || !entry.currency || !entry.refund_note) {
      return result("refused", "no matching, scoped execution record to reconcile");
    }
    const knownId = entry.refund_id ?? entry.observed_refund_id ?? entry.matched_refund_id;
    // A candidate is just a lookup hint, never evidence or authorization.
    const id = knownId ?? request.candidateRefundId;
    if (!id || !shopify.getRefund) return result("unconfirmed", "native refund readback is required; do not resubmit the request");
    const refundId = /^\d+$/.test(id) ? `gid://shopify/Refund/${id}` : id;
    const input: RefundCreateInput = {
      orderId: entry.order_id, note: entry.refund_note, notify: false,
      transactions: [{ orderId: entry.order_id, parentId: entry.parent_transaction_id, kind: "REFUND", gateway: entry.gateway, amount: centsToMoney(entry.amount_cents) }],
    };
    const native = await shopify.getRefund(refundId);
    if (!confirmRefundReadback(native, refundId, input, entry.currency)) {
      return result("unconfirmed", "native transaction does not yet prove the exact successful refund", refundId);
    }
    await ledger.recordExecuted(entry.gate_ref, refundId);
    return result("succeeded", "the exact successful refund transaction was read back from Shopify", refundId);
  } catch {
    return result("unconfirmed", "reconciliation could not be completed; do not resubmit the request");
  }
}
