/**
 * Resuming an escalated refund after a manager decides it.
 * The fake runtime creates an approval request for every escalate; tests
 * play the person deciding it with `decide(id, status)`.
 */

import { describe, expect, it } from "vitest";
import type { RefundDecisionRecord } from "../src/decision-record.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, type RefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger, JsonFileLedger } from "../src/ledger.js";
import { auditRefundWebhook } from "../src/webhook.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SHOP = "pinecone-pet-supply.myshopify.com";

function setup(rt: Parameters<typeof fakeRuntime>[0] = {}) {
  const runtime = fakeRuntime(rt);
  const shopify = new FakeShopify(demoOrders());
  const ledger = new InMemoryLedger();
  const records: RefundDecisionRecord[] = [];
  const options: RefundGuardOptions = {
    actor: "shopify-staff:test/1",
    environment: "test",
    ledger,
    shop: SHOP,
    now: () => NOW,
    onDecision: (r) => void records.push(r),
  };
  const escalate = async () => {
    const r = await guardedShopifyRefund(shopify, runtime.client, { orderId: "1002", amountCents: 7200, reason: "wrong size" }, options);
    if (r.refunded || r.approvalRequestId === undefined) throw new Error("expected an escalation with an approval id");
    return r.approvalRequestId;
  };
  const resume = (approvalRequestId: string, opts: Partial<RefundGuardOptions> = {}) =>
    resumeApprovedShopifyRefund(shopify, runtime.client, runtime.approvals, { approvalRequestId, resumedBy: "shopify-staff:test/2" }, { ...options, ...opts });
  return { runtime, shopify, ledger, records, options, escalate, resume };
}

describe("escalation saves the frozen refund", () => {
  it("returns the approval id and records it as pending", async () => {
    const s = setup();
    const id = await s.escalate();
    const p = await s.ledger.getPendingApproval(id);
    expect(p).toMatchObject({ approval_request_id: id, order_id: "gid://shopify/Order/1002", amount_cents: 7200, actor_id: "shopify-staff:test/1", reason: "wrong size" });
    expect(p?.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(s.records[0]).toMatchObject({ outcome: "escalated", approval_request_id: id });
  });
});

describe("resumeApprovedShopifyRefund", () => {
  it("while pending: holds, claims nothing, refunds nothing", async () => {
    const s = setup();
    const id = await s.escalate();
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "hold", approvalRequestId: id });
    expect(s.runtime.claims).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
    expect((await s.ledger.getPendingApproval(id))?.resolved).toBeUndefined();
  });

  it("approved: claims once, verifies against the frozen digest, refunds exactly the escalated refund", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    const r = await s.resume(id);
    expect(r.refunded).toBe(true);
    if (!r.refunded) return;
    const pending = await s.ledger.getPendingApproval(id);
    expect(s.runtime.claims).toEqual([id]);
    expect(s.runtime.verifyBodies.at(-1)).toMatchObject({ actor_id: "shopify-staff:test/1", execution_hash: pending!.digest });
    expect(s.shopify.refunds).toHaveLength(1);
    expect(s.shopify.refunds[0]).toMatchObject({
      orderId: "gid://shopify/Order/1002",
      note: `AtlaSent gate ref ${r.gateRef} — wrong size; approved by a manager`,
      transactions: [{ amount: "72.00", parentId: "gid://shopify/OrderTransaction/10021" }],
    });
    expect(pending?.resolved).toMatchObject({ outcome: "refunded", detail: r.refund.id });
    expect(s.records.at(-1)).toMatchObject({
      outcome: "refunded",
      decision: "allow_after_approval",
      reason: "approved by a manager (resumed by shopify-staff:test/2)",
      approval_request_id: id,
      refund_id: r.refund.id,
    });
    expect(JSON.stringify(s.records)).not.toContain("pt.v3");
  });

  it("the alarm accounts for the approved refund", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    const r = await s.resume(id);
    if (!r.refunded) throw new Error("expected a refund");
    const v = await auditRefundWebhook(
      { id: r.refund.id.replace(/^gid:\/\/shopify\/Refund\//, ""), order_id: 1002, note: s.shopify.refunds[0]!.note, transactions: [{ kind: "refund", status: "success", amount: "72.00" }] },
      s.ledger,
    );
    expect(v.verdict).toBe("authorized");
  });

  it("cannot be resumed twice", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect((await s.resume(id)).refunded).toBe(true);
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "invalid_request", reason: expect.stringMatching(/already resolved/) });
    expect(s.shopify.refunds).toHaveLength(1);
  });

  for (const status of ["denied", "expired", "revoked", "denied_by_timeout"]) {
    it(`${status}: closes with no claim and no refund`, async () => {
      const s = setup();
      const id = await s.escalate();
      s.runtime.decide(id, status);
      const r = await s.resume(id);
      expect(r).toMatchObject({ refunded: false, decision: "deny", denyCode: `APPROVAL_${status.toUpperCase()}` });
      expect(s.runtime.claims).toHaveLength(0);
      expect(s.shopify.refunds).toHaveLength(0);
      expect((await s.ledger.getPendingApproval(id))?.resolved?.outcome).toBe("not_approved");
      expect(s.records.at(-1)).toMatchObject({ outcome: "denied", decision: "approval_not_granted", approval_request_id: id });
      expect(s.records.at(-1)).toMatchObject({ order_ref: "#PPS-1002", amount_cents: 7200 });
      expect(s.records.at(-1)?.currency).toBeTruthy();
    });
  }

  it("refuses an approval this gate did not escalate", async () => {
    const s = setup();
    expect(await s.resume("apr-unknown")).toMatchObject({ refunded: false, decision: "invalid_request" });
    expect(s.runtime.claims).toHaveLength(0);
  });

  it("refuses an approval escalated for another shop", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect(await s.resume(id, { shop: "other.myshopify.com" })).toMatchObject({ refunded: false, reason: expect.stringMatching(/different shop/) });
    expect(s.runtime.claims).toHaveLength(0);
  });

  it("an order refunded elsewhere since the escalation is not claimed or refunded", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    const o = s.shopify.orders.get("gid://shopify/Order/1002")!;
    o.transactions.push({ ...o.transactions[0]!, id: "gid://shopify/OrderTransaction/x", kind: "REFUND", amountSet: { shopMoney: { amount: "100.00", currencyCode: "USD" } } });
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "order_changed" });
    expect(s.runtime.claims).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("a permit bound to a different refund is not used", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.runtime.claimFaults.boundTo = "0".repeat(64);
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/different refund/) });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("an approved permit that is not reported consumed refunds nothing", async () => {
    const s = setup({ consumed: false });
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/not reported consumed/) });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("verifies as the actor who requested the refund, whoever resumes it", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    await s.resume(id, { actor: "someone-else" });
    expect(s.runtime.verifyBodies.at(-1)).toMatchObject({ actor_id: "shopify-staff:test/1" });
  });

  it("a failed claim refunds nothing", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.runtime.claimFaults.failure = "already_claimed";
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/already_claimed/) });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("refundCreate failure retains an unresolved execution for reconciliation", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.shopify.failRefund = true;
    const r = await s.resume(id);
    expect(r).toMatchObject({ refunded: false, decision: "unconfirmed" });
    expect((await s.ledger.get(r.gateRef))?.aborted_reason).toBeUndefined();
    expect((await s.ledger.get(r.gateRef))?.unconfirmed_reason).toMatch(/unknown/);
  });

  it("pending approvals survive a restart (JSON file ledger)", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "ledger-")), "ledger.json");
    const s = setup();
    const ledger = new JsonFileLedger(path);
    const opts = { ...s.options, ledger };
    const r = await guardedShopifyRefund(s.shopify, s.runtime.client, { orderId: "1002", amountCents: 7200 }, opts);
    const id = (r as { approvalRequestId: string }).approvalRequestId;
    s.runtime.decide(id, "approved");
    const reopened = new JsonFileLedger(path);
    const resumed = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals, { approvalRequestId: id }, { ...s.options, ledger: reopened });
    expect(resumed.refunded).toBe(true);
  });
});

