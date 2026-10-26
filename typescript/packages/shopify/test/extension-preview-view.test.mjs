import { describe, expect, it } from "vitest";
import { centsFromAmount, parseRefundPreview } from "../app/extensions/atlasent-refund/src/preview-view.js";

const ORDER = "gid://shopify/Order/1001";
const AMOUNT = "18.99";
const good = () => ({
  schema: "atlasent.shopify_refund_operations_preview.v1",
  mode: "read_only",
  authorization: "not_evaluated",
  execution: "not_attempted",
  customer_notification: "not_sent",
  disposition: "routine_candidate",
  next_step: "verify_business_eligibility",
  observed: {
    order_id: ORDER,
    currency: "USD",
    order_status: "delivered",
    refundable_cents: 3499,
    requested_cents: 1899,
  },
  read_at: "2026-10-25T18:00:00.000Z",
  missing_proofs: ["independent_authority_and_approval", "current_dispute_state"],
  operator_message: "A routine case may be prepared. No refund was authorized.",
});

describe("read-only Shopify operations preview presentation boundary", () => {
  it("converts decimal strings to cents exactly and rejects unsafe amounts", () => {
    expect(centsFromAmount("18.99")).toBe(1899);
    expect(centsFromAmount("0.01")).toBe(1);
    expect(centsFromAmount("2")).toBe(200);
    for (const amount of ["0", "0.00", "-1", "1e3", "0.001", "Infinity", "", "90071992547409999.00"]) {
      expect(centsFromAmount(amount)).toBeNull();
    }
  });

  it("shows the exact order and amount with an explicit missing-proof next step", () => {
    const parsed = parseRefundPreview(good(), ORDER, AMOUNT);
    expect(parsed).toMatchObject({
      disposition: "routine_candidate",
      requestedCents: 1899,
      refundableCents: 3499,
      statusLabel: expect.stringContaining("checks still required"),
      nextStepLabel: expect.stringContaining("Verify"),
      readAt: "2026-10-25T18:00:00.000Z",
    });
    expect(parsed.missingProofLabels).toEqual(["independent authority and approval", "current dispute state"]);
  });

  it("rejects mismatched order or amount, even when the server response claims routine", () => {
    expect(parseRefundPreview(good(), "gid://shopify/Order/OTHER", AMOUNT)).toBeNull();
    expect(parseRefundPreview(good(), ORDER, "19.00")).toBeNull();
    expect(parseRefundPreview({ ...good(), observed: { ...good().observed, order_id: "other" } }, ORDER, AMOUNT)).toBeNull();
    expect(parseRefundPreview({ ...good(), observed: { ...good().observed, requested_cents: 1900 } }, ORDER, AMOUNT)).toBeNull();
  });

  it("refuses any response that implies authority, payment or customer notification", () => {
    for (const mutation of [
      { mode: "write" },
      { authorization: "approved" },
      { execution: "succeeded" },
      { customer_notification: "sent" },
      { schema: "unknown" },
      { disposition: "allow" },
      { next_step: "execute_refund" },
    ]) expect(parseRefundPreview({ ...good(), ...mutation }, ORDER, AMOUNT)).toBeNull();
  });

  it("rejects unknown, incomplete and malformed facts instead of inventing completion", () => {
    for (const mutation of [
      { read_at: "unknown" },
      { missing_proofs: [] },
      { missing_proofs: ["<script>"] },
      { operator_message: "" },
      { observed: { ...good().observed, refundable_cents: undefined } },
      { observed: { ...good().observed, refundable_cents: -1 } },
    ]) expect(parseRefundPreview({ ...good(), ...mutation }, ORDER, AMOUNT)).toBeNull();
  });

  it("preserves a genuine needs-attention next step without presenting it as a denial", () => {
    const parsed = parseRefundPreview({
      ...good(), disposition: "needs_attention", next_step: "inspect_payment_history",
    }, ORDER, AMOUNT);
    expect(parsed.statusLabel).toBe("Needs operator review");
    expect(parsed.nextStepLabel).toMatch(/Reconcile payment/);
  });
});
