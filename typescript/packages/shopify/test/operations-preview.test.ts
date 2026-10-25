import { describe, expect, it } from "vitest";
import { previewShopifyRefundOperation } from "../src/operations-preview.js";
import { makeOrder, NOW } from "./fakes.js";

const order = () => makeOrder({ id: 1001, delivery: "delivered", paid: "34.99", refunded: "4.99", deliveredDaysAgo: 5 });

describe("read-only Shopify post-purchase operations preview", () => {
  it("triages a routine-looking case but never authorizes, pays or notifies", () => {
    const result = previewShopifyRefundOperation(order(), 1899, NOW);
    expect(result).toMatchObject({
      mode: "read_only", disposition: "routine_candidate", next_step: "verify_business_eligibility",
      authorization: "not_evaluated", execution: "not_attempted", customer_notification: "not_sent",
      observed: { requested_cents: 1899, refundable_cents: 3000, order_status: "delivered" },
    });
    expect(result.missing_proofs).toContain("independent_authority_and_approval");
    expect(result.missing_proofs).toContain("other_compensation_and_full_refund_history");
    expect(JSON.stringify(result)).not.toContain("email");
  });

  it("does not treat non-delivery or cancellation as universally ineligible", () => {
    for (const delivery of ["in_transit", "none", "cancelled"] as const) {
      const result = previewShopifyRefundOperation(makeOrder({ id: 1001, delivery }), 100, NOW);
      expect(result).toMatchObject({ disposition: "needs_attention", next_step: "inspect_order_status" });
      expect(result.authorization).toBe("not_evaluated");
    }
  });

  it("requires human reconciliation when requested amount exceeds observed balance", () => {
    expect(previewShopifyRefundOperation(order(), 3100, NOW)).toMatchObject({
      disposition: "needs_attention", next_step: "verify_refundable_amount",
    });
  });

  it("does not claim routine eligibility for multiple captures or inconsistent currency", () => {
    const multi = order();
    multi.transactions.push({ ...multi.transactions[0]!, id: "another_capture" });
    expect(previewShopifyRefundOperation(multi, 100, NOW).next_step).toBe("inspect_payment_history");
    const foreign = makeOrder({ id: 1002, delivery: "delivered", currency: "EUR" });
    expect(previewShopifyRefundOperation(foreign, 100, NOW).next_step).toBe("obtain_supported_currency");
  });

  it("holds full pages, malformed sources and absent orders as unknown", () => {
    const full = order();
    full.transactions = Array.from({ length: 100 }, (_, i) => ({ ...full.transactions[0]!, id: `tx-${i}` }));
    expect(previewShopifyRefundOperation(full, 100, NOW)).toMatchObject({ disposition: "unavailable", next_step: "inspect_payment_history" });
    const malformed = order();
    malformed.transactions[0]!.amountSet.shopMoney.amount = "NaN";
    expect(previewShopifyRefundOperation(malformed, 100, NOW).disposition).toBe("unavailable");
    expect(previewShopifyRefundOperation(null, 100, NOW)).toMatchObject({ disposition: "unavailable", next_step: "retry_source_read" });
  });

  it("rejects invalid amounts and observation clocks", () => {
    for (const n of [0, -1, 0.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => previewShopifyRefundOperation(order(), n, NOW)).toThrow();
    }
    expect(() => previewShopifyRefundOperation(order(), 100, new Date("invalid"))).toThrow();
  });
});
