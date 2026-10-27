/** Financial completion needs exact native transaction evidence, not a Refund ID. */
import type { RefundCreateInput, RefundReadback } from "./admin.js";
import { moneyToCents } from "./facts.js";

export function confirmRefundReadback(
  readback: RefundReadback | null | undefined,
  refundId: string,
  input: RefundCreateInput,
  currency: string,
): boolean {
  try {
    if (!readback || readback.id !== refundId || readback.order.id !== input.orderId || readback.note !== input.note ||
        readback.transactions.pageInfo.hasNextPage !== false || readback.transactions.nodes.length !== 1 || input.transactions.length !== 1) return false;
    const native = readback.transactions.nodes[0]!;
    const expected = input.transactions[0]!;
    return native.kind === "REFUND" && native.status === "SUCCESS" &&
      native.parentTransaction?.id === expected.parentId && native.gateway === expected.gateway &&
      native.amountSet.shopMoney.currencyCode === currency &&
      moneyToCents(native.amountSet.shopMoney.amount) === moneyToCents(expected.amount);
  } catch {
    return false;
  }
}
