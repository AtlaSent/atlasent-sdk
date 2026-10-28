import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  computeRefundDigest, CUSTOMER_REFUND_ISSUE, FINANCE_PAYMENT_AUTHORIZE,
  guardedShopifyRefund, resolveRefundActionType, resumeApprovedShopifyRefund,
  type RefundActionType, type RefundGuardOptions,
} from "../src/guard.js";
import { InMemoryLedger, JsonFileLedger, type PendingApproval } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const SHOP = "pinecone-pet-supply.myshopify.com";
const base = { shop: SHOP, order_id: "gid://shopify/Order/1001", amount_cents: 1899,
  currency: "USD", parent_transaction_id: "gid://shopify/OrderTransaction/10011", gateway: "manual" };
function setup(actionType?: RefundActionType) {
  const runtime = fakeRuntime();
  const shopify = new FakeShopify(demoOrders());
  const options: RefundGuardOptions = { actor: "shopify-staff:test/1", environment: "test",
    shop: SHOP, ledger: new InMemoryLedger(), now: () => NOW,
    ...(actionType !== undefined ? { actionType } : {}) };
  const request = { orderId: "1001", amountCents: 1899, businessRequestId: "case-123" };
  const refund = () => guardedShopifyRefund(shopify, runtime.client, request, options);
  const escalate = async () => {
    const result = await guardedShopifyRefund(shopify, runtime.client,
      { orderId: "1002", amountCents: 7200, businessRequestId: "case-approval" }, options);
    if (result.refunded || !result.approvalRequestId) throw new Error("expected approval");
    return result.approvalRequestId;
  };
  const resume = (id: string, override: Partial<RefundGuardOptions> = {}) =>
    resumeApprovedShopifyRefund(shopify, runtime.client, runtime.approvals,
      { approvalRequestId: id }, { ...options, ...override });
  return { runtime, shopify, options, request, refund, escalate, resume };
}

describe("explicit Shopify refund action binding (scripted runtime only)", () => {
  it("preserves the exact legacy v1 digest", () => {
    expect(computeRefundDigest(base)).toBe("d48a3fb17b41c4159953b44c2655bce79df0a6b4770d0cf57e12481d6c9943cb");
  });

  it("defaults to legacy and never silently substitutes an unknown action", () => {
    expect(resolveRefundActionType()).toBe(FINANCE_PAYMENT_AUTHORIZE);
    expect(resolveRefundActionType(CUSTOMER_REFUND_ISSUE)).toBe(CUSTOMER_REFUND_ISSUE);
    for (const value of [null, "", "customer.refund.other", false, {}]) {
      expect(() => resolveRefundActionType(value)).toThrow(/unsupported refund action/);
    }
  });

  it("keeps optional business IDs out of legacy v1 bindings", async () => {
    const s = setup();
    expect((await s.refund()).refunded).toBe(true);
    expect(s.runtime.evaluateBodies[0]).toMatchObject({
      action_type: FINANCE_PAYMENT_AUTHORIZE, execution_payload_hash: computeRefundDigest(base),
    });
  });

  it("binds the canonical action and stable request to evaluate, verify and the execution entry", async () => {
    const s = setup(CUSTOMER_REFUND_ISSUE);
    const result = await s.refund();
    expect(result.refunded).toBe(true);
    const digest = computeRefundDigest({ ...base, action_type: CUSTOMER_REFUND_ISSUE, business_request_id: "case-123" });
    // Independent SHA-256 over sorted, compact JSON including binding_version v2.
    expect(digest).toBe("25fbc96a64901ccaddbc4a5157eb809d63ce97c9e62d6abe2b8650a4149f8d0e");
    expect(digest).not.toBe(computeRefundDigest(base));
    expect(s.runtime.evaluateBodies[0]).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE, execution_payload_hash: digest });
    expect(s.runtime.verifyBodies[0]).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE, execution_hash: digest });
    expect(await s.options.ledger.get(result.gateRef)).toMatchObject({
      action_type: CUSTOMER_REFUND_ISSUE, business_request_id: "case-123", execution_digest: digest,
    });
    expect(s.shopify.refunds).toHaveLength(1);
  });

  it("different canonical business requests cannot share a digest", () => {
    const canonical = { ...base, action_type: CUSTOMER_REFUND_ISSUE, business_request_id: "case-123" };
    expect(computeRefundDigest(canonical)).not.toBe(computeRefundDigest({ ...canonical, business_request_id: "case-124" }));
    expect(computeRefundDigest(canonical)).not.toBe(computeRefundDigest({ ...canonical, action_type: FINANCE_PAYMENT_AUTHORIZE }));
  });

  it("requires a canonical business ID before reading a provider or evaluating", async () => {
    const s = setup(CUSTOMER_REFUND_ISSUE);
    const result = await guardedShopifyRefund(s.shopify, s.runtime.client,
      { orderId: "1001", amountCents: 1899 }, s.options);
    expect(result).toMatchObject({ refunded: false, decision: "invalid_request", reason: expect.stringMatching(/requires a stable businessRequestId/) });
    expect(s.shopify.reads).toBe(0);
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("rejects invalid host action values before provider reads", async () => {
    for (const value of ["unknown", null]) {
      const s = setup(value as RefundActionType);
      expect(await s.refund()).toMatchObject({ refunded: false, decision: "invalid_request" });
      expect(s.shopify.reads).toBe(0);
      expect(s.runtime.evaluateBodies).toHaveLength(0);
    }
  });

  it("persists and reloads the canonical action and business ID before approval claim", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shopify-action-"));
    try {
      const s = setup(CUSTOMER_REFUND_ISSUE);
      const path = join(dir, "ledger.json");
      s.options.ledger = new JsonFileLedger(path);
      const id = await s.escalate();
      const p = await s.options.ledger.getPendingApproval(id);
      expect(p?.snapshot).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE, business_request_id: "case-approval" });
      s.runtime.decide(id, "approved");
      const reloaded = new JsonFileLedger(path);
      // An omitted host override still uses the action frozen under this approval.
      const { actionType: _configuredAction, ...withoutAction } = s.options;
      const result = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals,
        { approvalRequestId: id }, { ...withoutAction, ledger: reloaded });
      expect(result.refunded).toBe(true);
      expect(s.runtime.claims).toEqual([id]);
      expect(s.runtime.verifyBodies.at(-1)).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE, execution_hash: p!.digest });
      expect(await reloaded.get(result.gateRef)).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  for (const [from, to] of [[FINANCE_PAYMENT_AUTHORIZE, CUSTOMER_REFUND_ISSUE], [CUSTOMER_REFUND_ISSUE, FINANCE_PAYMENT_AUTHORIZE]] as const) {
    it(`does not reuse a completed business request from ${from} under ${to}`, async () => {
      const s = setup(from);
      expect((await s.refund()).refunded).toBe(true);
      const result = await guardedShopifyRefund(s.shopify, s.runtime.client, s.request, { ...s.options, actionType: to });
      expect(result).toMatchObject({ refunded: false, decision: "invalid_request" });
      expect(s.shopify.refunds).toHaveLength(1);
    });

    it(`cannot resume ${from} as ${to}`, async () => {
      const s = setup(from);
      const id = await s.escalate();
      s.runtime.decide(id, "approved");
      const reads = s.shopify.reads;
      expect(await s.resume(id, { actionType: to })).toMatchObject({ refunded: false, decision: "invalid_request" });
      expect(s.shopify.reads).toBe(reads);
      expect(s.runtime.claims).toHaveLength(0);
      expect(s.shopify.refunds).toHaveLength(0);
      expect((await s.options.ledger.getPendingApproval(id))?.resolved).toBeUndefined();
    });
  }

  for (const defect of ["unknown-action", "null-action", "missing-request", "different-request", "changed-both-request-copies", "removed-action"] as const) {
    it(`refuses stored binding corruption: ${defect}`, async () => {
      const s = setup(CUSTOMER_REFUND_ISSUE);
      const id = await s.escalate();
      s.runtime.decide(id, "approved");
      const pending = await s.options.ledger.getPendingApproval(id) as PendingApproval;
      if (defect === "unknown-action") pending.snapshot.action_type = "other.action";
      if (defect === "null-action") pending.snapshot.action_type = null;
      if (defect === "missing-request") delete pending.snapshot.business_request_id;
      if (defect === "different-request") pending.business_request_id = "other-case";
      if (defect === "changed-both-request-copies") {
        pending.snapshot.business_request_id = "other-case"; pending.business_request_id = "other-case";
      }
      if (defect === "removed-action") delete pending.snapshot.action_type;
      const ledger = new InMemoryLedger();
      await ledger.recordPendingApproval(pending);
      const { actionType: _configuredAction, ...withoutAction } = s.options;
      const result = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals,
        { approvalRequestId: id }, { ...withoutAction, ledger });
      expect(result.refunded).toBe(false);
      expect(s.runtime.claims).toHaveLength(0);
      expect(s.shopify.refunds).toHaveLength(0);
    });
  }

  it("the runtime refuses a claimed permit issued for the other action", async () => {
    const s = setup(CUSTOMER_REFUND_ISSUE);
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    const claim = s.runtime.approvals.claimPermit.bind(s.runtime.approvals);
    s.runtime.approvals.claimPermit = async (approvalId) => {
      const result = await claim(approvalId);
      if (result.claimed) s.runtime.permits.get(result.permitToken)!.action = FINANCE_PAYMENT_AUTHORIZE;
      return result;
    };
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed" });
    expect(s.shopify.refunds).toHaveLength(0);
  });
});
