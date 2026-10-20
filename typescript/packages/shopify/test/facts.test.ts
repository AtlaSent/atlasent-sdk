import { describe, expect, it } from "vitest";
import { centsToMoney, deriveRefundFacts, moneyToCents } from "../src/facts.js";
import { makeOrder, NOW } from "./fakes.js";

describe("money", () => {
  it("parses Shopify decimal strings without floating point", () => {
    expect(moneyToCents("18.99")).toBe(1899);
    expect(moneyToCents("0.1")).toBe(10);
    expect(moneyToCents("50")).toBe(5000);
    expect(moneyToCents("49.99")).toBe(4999);
    expect(centsToMoney(1899)).toBe("18.99");
    expect(centsToMoney(5)).toBe("0.05");
  });
  for (const bad of ["", "-1.00", "1.999", "1e3", "abc", "1,00", " "]) {
    it(`rejects ${JSON.stringify(bad)}`, () => expect(() => moneyToCents(bad)).toThrow());
  }
});

describe("deriveRefundFacts", () => {
  it("a delivered order reports days since delivery and what is left to refund", () => {
    const f = deriveRefundFacts(makeOrder({ id: 1, delivery: "delivered", deliveredDaysAgo: 5, paid: "34.99", refunded: "4.99" }), NOW);
    expect(f).toMatchObject({ order_status: "delivered", days_since_delivery: 5, refundable_cents: 3000, currency: "USD" });
    expect(f.parent_transaction).toEqual({ id: "gid://shopify/OrderTransaction/11", gateway: "manual" });
  });

  it("in transit, unfulfilled and cancelled orders are not delivered and carry no window", () => {
    expect(deriveRefundFacts(makeOrder({ id: 2, delivery: "in_transit" }), NOW)).toMatchObject({ order_status: "not_delivered" });
    expect(deriveRefundFacts(makeOrder({ id: 3, delivery: "none" }), NOW)).toMatchObject({ order_status: "unfulfilled" });
    expect(deriveRefundFacts(makeOrder({ id: 4, delivery: "cancelled" }), NOW)).toMatchObject({ order_status: "cancelled" });
    for (const d of ["in_transit", "none", "cancelled"] as const) {
      expect(deriveRefundFacts(makeOrder({ id: 5, delivery: d }), NOW)).not.toHaveProperty("days_since_delivery");
    }
  });

  it("a split shipment is delivered only when every part is, measured from the last delivery", () => {
    const o = makeOrder({ id: 6, delivery: "delivered", deliveredDaysAgo: 20 });
    const later = { ...o.fulfillments[0]!, id: "f2", deliveredAt: new Date(NOW.getTime() - 2 * 86_400_000).toISOString() };
    expect(deriveRefundFacts({ ...o, fulfillments: [...o.fulfillments, later] }, NOW)).toMatchObject({ days_since_delivery: 2 });
    const pending = { ...o.fulfillments[0]!, id: "f3", displayStatus: "IN_TRANSIT", deliveredAt: null };
    expect(deriveRefundFacts({ ...o, fulfillments: [...o.fulfillments, pending] }, NOW).order_status).toBe("not_delivered");
  });

  it("a cancelled fulfillment is ignored", () => {
    const o = makeOrder({ id: 7, delivery: "delivered", deliveredDaysAgo: 3 });
    const cancelled = { id: "fx", status: "CANCELLED", displayStatus: "CANCELED", deliveredAt: null };
    expect(deriveRefundFacts({ ...o, fulfillments: [...o.fulfillments, cancelled] }, NOW).order_status).toBe("delivered");
  });

  it("a delivery date in the future leaves the window unknown rather than 'day 0'", () => {
    const o = makeOrder({ id: 8, delivery: "delivered", deliveredDaysAgo: -2 });
    expect(deriveRefundFacts(o, NOW)).not.toHaveProperty("days_since_delivery");
  });

  it("DELIVERED without a deliveredAt is not delivered", () => {
    const o = makeOrder({ id: 9, delivery: "delivered" });
    o.fulfillments[0]!.deliveredAt = null;
    expect(deriveRefundFacts(o, NOW).order_status).toBe("not_delivered");
  });

  it("failed and authorization-only transactions are not refundable money", () => {
    const o = makeOrder({ id: 10, delivery: "delivered", paid: "20.00" });
    o.transactions.push({ ...o.transactions[0]!, id: "a", kind: "AUTHORIZATION", amountSet: { shopMoney: { amount: "99.00", currencyCode: "USD" } } });
    o.transactions.push({ ...o.transactions[0]!, id: "b", status: "FAILURE", amountSet: { shopMoney: { amount: "99.00", currencyCode: "USD" } } });
    expect(deriveRefundFacts(o, NOW).refundable_cents).toBe(2000);
  });
});
