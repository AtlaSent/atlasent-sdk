/**
 * Turns a Shopify order into the facts the refund policy reads.
 *
 * Every fact comes from the order as Shopify holds it, never from whoever is
 * asking for the refund. The names match the demo policy in atlasent-api
 * (`examples/fake-store-refunds/policy.json`): `amount_cents`,
 * `order_status`, `days_since_delivery`.
 */

import type { ShopifyOrder, ShopifyTransaction } from "./admin.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** The demo policy's thresholds are USD cents; other currencies are refused. */
export const SUPPORTED_CURRENCY = "USD";

export type OrderStatusFact = "delivered" | "not_delivered" | "unfulfilled" | "cancelled";

export interface RefundFacts {
  order_id: string;
  order_name: string;
  currency: string;
  order_status: OrderStatusFact;
  /** Absent unless every fulfillment is delivered. */
  days_since_delivery?: number;
  /** Paid minus already refunded, from successful transactions. */
  refundable_cents: number;
  /** The payment a refund is issued against. */
  parent_transaction: { id: string; gateway: string } | null;
}

/** "18.99" -> 1899. Throws on anything that is not a plain non-negative decimal. */
export function moneyToCents(amount: string): number {
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(amount.trim());
  if (!m) throw new RangeError(`not a money amount: ${JSON.stringify(amount)}`);
  const cents = Number(m[1]) * 100 + Number((m[2] ?? "").padEnd(2, "0"));
  if (!Number.isSafeInteger(cents)) throw new RangeError(`amount out of range: ${amount}`);
  return cents;
}

/** 1899 -> "18.99" */
export function centsToMoney(cents: number): string {
  if (!Number.isSafeInteger(cents) || cents < 0) throw new RangeError(`not a cent amount: ${cents}`);
  return `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}

const isSuccess = (t: ShopifyTransaction) => t.status.toUpperCase() === "SUCCESS";
const isPayment = (t: ShopifyTransaction) => ["SALE", "CAPTURE"].includes(t.kind.toUpperCase());
const isRefund = (t: ShopifyTransaction) => t.kind.toUpperCase() === "REFUND";

export function deriveRefundFacts(order: ShopifyOrder, now: Date): RefundFacts {
  const paid = order.transactions.filter((t) => isSuccess(t) && isPayment(t));
  const refunded = order.transactions.filter((t) => isSuccess(t) && isRefund(t));
  const sum = (ts: ShopifyTransaction[]) => ts.reduce((n, t) => n + moneyToCents(t.amountSet.shopMoney.amount), 0);
  const refundable = Math.max(0, sum(paid) - sum(refunded));

  // Refunds go against the first successful payment. A multi-payment order
  // (split tender, several captures) is out of scope for this demo.
  const parent = paid[0];

  let order_status: OrderStatusFact;
  let days: number | undefined;
  const live = order.fulfillments.filter((f) => f.status.toUpperCase() !== "CANCELLED");
  if (order.cancelledAt !== null) {
    order_status = "cancelled";
  } else if (live.length === 0) {
    order_status = "unfulfilled";
  } else if (live.every((f) => f.displayStatus?.toUpperCase() === "DELIVERED" && f.deliveredAt !== null)) {
    order_status = "delivered";
    // The window runs from the LAST delivery, so a split shipment is measured
    // from when the customer finally had everything.
    const last = Math.max(...live.map((f) => Date.parse(f.deliveredAt as string)));
    if (Number.isFinite(last)) days = Math.floor((now.getTime() - last) / DAY_MS);
  } else {
    order_status = "not_delivered";
  }

  return {
    order_id: order.id,
    order_name: order.name,
    currency: order.currencyCode,
    order_status,
    ...(days !== undefined && days >= 0 ? { days_since_delivery: days } : {}),
    refundable_cents: refundable,
    parent_transaction: parent ? { id: parent.id, gateway: parent.gateway } : null,
  };
}
