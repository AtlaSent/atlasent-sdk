/**
 * The facts the refund policy reads, for a refund issued through Stripe.
 *
 * Stripe knows the money: what was captured, what is already refunded, the
 * currency, whether the charge is disputed. It does not know whether the
 * goods arrived. Delivery comes from the store's own order system through a
 * `DeliveryFactsSource`, keyed by the order reference the store put in the
 * PaymentIntent's metadata at checkout (server-side, never at refund time).
 *
 * The names match the demo policy in atlasent-api
 * (`examples/fake-store-refunds/policy.json`): `amount_cents`,
 * `order_status`, `days_since_delivery`.
 */

import type { StripePaymentIntent } from "./stripe.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** The demo policy's thresholds are USD cents; other currencies are refused. */
export const SUPPORTED_CURRENCY = "USD";

export type OrderStatusFact = "delivered" | "not_delivered" | "unfulfilled" | "cancelled";

export interface DeliveryFacts {
  order_status: OrderStatusFact;
  /** ISO timestamp of the (last) delivery; required for "delivered" to count. */
  delivered_at?: string;
}

/** The store's order system: Shopify, a warehouse system, its own database. */
export interface DeliveryFactsSource {
  getDeliveryFacts(orderRef: string): Promise<DeliveryFacts | null>;
}

export interface StripeRefundFacts {
  payment_intent: string;
  charge: string | null;
  order_ref: string | null;
  currency: string;
  payment_succeeded: boolean;
  disputed: boolean;
  refundable_cents: number;
  order_status: OrderStatusFact | "unknown";
  /** Absent unless the order is delivered with a usable date. */
  days_since_delivery?: number;
}

export function deriveStripeRefundFacts(
  pi: StripePaymentIntent,
  delivery: DeliveryFacts | null,
  orderRef: string | null,
  now: Date,
): StripeRefundFacts {
  const charge = pi.latest_charge;
  const refundable = charge ? Math.max(0, charge.amount_captured - charge.amount_refunded) : 0;

  let days: number | undefined;
  let status: StripeRefundFacts["order_status"] = delivery?.order_status ?? "unknown";
  if (status === "delivered") {
    const at = delivery?.delivered_at ? Date.parse(delivery.delivered_at) : Number.NaN;
    if (Number.isFinite(at)) {
      const d = Math.floor((now.getTime() - at) / DAY_MS);
      // A delivery date in the future leaves the window unknown, which denies.
      if (d >= 0) days = d;
    } else {
      // "Delivered" with no date is not delivered (same rule as the Shopify gate).
      status = "not_delivered";
    }
  }

  return {
    payment_intent: pi.id,
    charge: charge?.id ?? null,
    order_ref: orderRef,
    currency: pi.currency.toUpperCase(),
    payment_succeeded: pi.status === "succeeded" && charge?.status === "succeeded",
    disputed: charge?.disputed === true,
    refundable_cents: refundable,
    order_status: status,
    ...(days !== undefined ? { days_since_delivery: days } : {}),
  };
}

/** A fixed map, for demos and tests. */
export function staticDeliveryFacts(map: Record<string, DeliveryFacts>): DeliveryFactsSource {
  return { getDeliveryFacts: async (ref) => map[ref] ?? null };
}

/** "18.99" -> 1899. Throws on anything that is not a plain non-negative decimal. */
export function moneyToCents(amount: string): number {
  const m = /^(\d+)(?:\.(\d{1,2}))?$/.exec(amount.trim());
  if (!m) throw new RangeError(`not a money amount: ${JSON.stringify(amount)}`);
  const cents = Number(m[1]) * 100 + Number((m[2] ?? "").padEnd(2, "0"));
  if (!Number.isSafeInteger(cents)) throw new RangeError(`amount out of range: ${amount}`);
  return cents;
}

export function centsToMoney(cents: number): string {
  if (!Number.isSafeInteger(cents) || cents < 0) throw new RangeError(`not a cent amount: ${cents}`);
  return `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}
