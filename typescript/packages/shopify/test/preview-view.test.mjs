import { describe, it, expect } from "vitest";
import { centsFromAmount, parseRefundPreview, parseInboxDestination, parseObservationReceipt } from "../app/extensions/atlasent-refund/src/preview-view.js";

const orderId = "gid://shopify/Order/1001";
const amount = "18.99";

const destination = { organization_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", connector_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" };
const receipt = () => ({
  schema: "atlasent.connector-observation-receipt.v1", ...destination,
  event_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", observation_id: "dddddddd-dddd-dddd-dddd-dddddddddddd",
  idempotency_key: "dddddddd-dddd-dddd-dddd-dddddddddddd", received_at: "2026-10-26T01:00:00Z",
  capability_level: "observe", authority_effect: "none", execution: "not_attempted", verification: "not_performed", duplicate: false,
});

describe("Observe handoff presentation", () => {
  it("offers only an explicit valid destination and displays a matching non-authorizing receipt", () => {
    expect(parseInboxDestination(null)).toBeNull();
    expect(parseInboxDestination({ organization_id: "bad", connector_id: destination.connector_id })).toBeNull();
    expect(parseInboxDestination(destination)).toEqual(destination);
    expect(parseObservationReceipt(receipt(), destination)).toMatchObject({ organization_id: destination.organization_id });
  });

  it.each([
    { organization_id: "other-org" }, { connector_id: "other-connector" }, { event_id: "bad" },
    { observation_id: "other-request" }, { capability_level: "enforce" }, { authority_effect: "approved" },
    { execution: "succeeded" }, { verification: "verified" }, { decision: "allow" }, { permit_token: "forged" },
  ])("never shows success for a wrong-destination or authorizing receipt %j", (patch) => {
    expect(parseObservationReceipt({ ...receipt(), ...patch }, destination)).toBeNull();
  });
});
const valid = () => ({
  schema: "atlasent.shopify_refund_operations_preview.v1",
  mode: "read_only",
  authorization: "not_evaluated",
  execution: "not_attempted",
  customer_notification: "not_sent",
  disposition: "routine_candidate",
  next_step: "verify_business_eligibility",
  observed: {
    order_id: orderId,
    currency: "USD",
    order_status: "delivered",
    refundable_cents: 3500,
    requested_cents: 1899,
  },
  read_at: "2026-10-25T20:00:00.000Z",
  missing_proofs: ["independent_authority_and_approval", "current_dispute_state"],
  operator_message: "Routine candidate; eligibility and authority not established.",
});

describe("Shopify admin read-only refund preview presentation", () => {
  it("parses cents exactly and rejects invalid or unsafe amounts", () => {
    expect(centsFromAmount("18.99")).toBe(1899);
    expect(centsFromAmount("0.01")).toBe(1);
    expect(centsFromAmount("18.9")).toBe(1890);
    for (const v of ["0", "0.00", "-1", "1.001", "1e3", "NaN", "Infinity", "", "  ", "900719925474099.99"]) {
      expect(centsFromAmount(v)).toBeNull();
    }
  });

  it("shows the operator next step without claiming authorization or execution", () => {
    const view = parseRefundPreview(valid(), orderId, amount);
    expect(view).toMatchObject({
      disposition: "routine_candidate",
      statusLabel: expect.stringMatching(/checks still required/),
      nextStepLabel: expect.stringMatching(/merchant policy/),
      requestedCents: 1899,
      orderId,
    });
    expect(view?.missingProofLabels).toContain("independent authority and approval");
    expect(JSON.stringify(view)).not.toMatch(/"refunded":true|"authorized":true/);
  });

  it("rejects wrong order, wrong amount, or a response claiming payment or authority", () => {
    expect(parseRefundPreview(valid(), "gid://shopify/Order/2002", amount)).toBeNull();
    expect(parseRefundPreview(valid(), orderId, "19.00")).toBeNull();
    for (const change of [
      { authorization: "approved" },
      { execution: "succeeded" },
      { customer_notification: "sent" },
      { mode: "write" },
      { schema: "unknown" },
      { disposition: "allow" },
      { next_step: "execute_refund" },
    ]) expect(parseRefundPreview({ ...valid(), ...change }, orderId, amount)).toBeNull();
  });

  it("refuses malformed, missing, stale-looking or incomplete response shapes", () => {
    for (const data of [
      null,
      [],
      {},
      { ...valid(), observed: { ...valid().observed, requested_cents: 1900 } },
      { ...valid(), observed: { ...valid().observed, refundable_cents: -1 } },
      { ...valid(), observed: { ...valid().observed, refundable_cents: "35" } },
      { ...valid(), read_at: "not-a-date" },
      { ...valid(), missing_proofs: [] },
      { ...valid(), missing_proofs: ["<script>"] },
      { ...valid(), operator_message: "" },
    ]) expect(parseRefundPreview(data, orderId, amount)).toBeNull();
  });

  it("keeps unknown source facts and review dispositions explicit", () => {
    const data = valid();
    data.disposition = "needs_attention";
    data.next_step = "inspect_payment_history";
    data.observed.refundable_cents = null;
    const view = parseRefundPreview(data, orderId, amount);
    expect(view).toMatchObject({
      statusLabel: "Needs operator review",
      refundableCents: null,
      nextStepLabel: expect.stringMatching(/Reconcile payment/),
    });
  });
});

