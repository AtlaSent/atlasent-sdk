/** Adversarial local integration tests. Fakes are NOT merchant acceptance. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAdminClient } from "../src/admin.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, type RefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger, JsonFileLedger } from "../src/ledger.js";
import { describeResult } from "../src/describe.js";
import { reconcileShopifyRefund } from "../src/reconcile.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const SHOP = "pinecone.myshopify.com";
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function setup(file = false) {
  const runtime = fakeRuntime();
  const shopify = new FakeShopify(demoOrders());
  const dir = file ? mkdtempSync(join(tmpdir(), "refund-loop-")) : undefined;
  if (dir) dirs.push(dir);
  const path = dir ? join(dir, "ledger.json") : undefined;
  const ledger = path ? new JsonFileLedger(path) : new InMemoryLedger();
  const options: RefundGuardOptions = { shop: SHOP, environment: "test", actor: "shopify-staff:test/1", ledger, now: () => NOW };
  const refund = (id = "case-1001", amountCents = 1899, opts = options) =>
    guardedShopifyRefund(shopify, runtime.client, { orderId: "1001", amountCents, businessRequestId: id }, opts);
  return { runtime, shopify, ledger, options, refund, path };
}

describe("supported source facts at both execution reads", () => {
  for (const phase of ["initial", "after_verify"] as const) {
    const changes: Array<[string, (o: ReturnType<typeof demoOrders>[number]) => void]> = [
      ["wrong order", o => { o.id = "gid://shopify/Order/999"; }],
      ["full transaction page", o => { o.transactions = Array.from({ length: 100 }, () => structuredClone(o.transactions[0]!)); }],
      ["full fulfillment page", o => { o.fulfillments = Array.from({ length: 50 }, () => structuredClone(o.fulfillments[0]!)); }],
      ["pending refund", o => { o.transactions.push({ ...structuredClone(o.transactions[0]!), kind: "REFUND", status: "PENDING" }); }],
      ["failed payment", o => { o.transactions[0]!.status = "FAILURE"; }],
      ["mixed currency", o => { o.transactions[0]!.amountSet.shopMoney.currencyCode = "EUR"; }],
      ["split payment", o => { o.transactions.push({ ...structuredClone(o.transactions[0]!), id: "gid://shopify/OrderTransaction/2" }); }],
    ];
    for (const [name, mutate] of changes) it(`${phase}: ${name} never reaches refundCreate`, async () => {
      const s = setup();
      const change = () => mutate(s.shopify.orders.get("gid://shopify/Order/1001")!);
      if (phase === "initial") change();
      else s.shopify.onRead = n => { if (n === 1) change(); };
      expect((await s.refund()).refunded).toBe(false);
      expect(s.shopify.refunds).toHaveLength(0);
      if (phase === "initial") expect(s.runtime.evaluateBodies).toHaveLength(0);
    });
  }
  it("a changed gateway stops even when status, amount and parent ID still match", async () => {
    const s = setup();
    s.shopify.onRead = n => { if (n === 1) s.shopify.orders.get("gid://shopify/Order/1001")!.transactions[0]!.gateway = "other"; };
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "order_changed" });
    expect(s.shopify.refunds).toHaveLength(0);
  });
});

describe("business request replay and single-payment interlock", () => {
  it("the same ID cannot issue a second refund or change its amount", async () => {
    const s = setup();
    const first = await s.refund();
    expect(first.refunded).toBe(true);
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "duplicate_request", gateRef: first.gateRef });
    expect(await s.refund("case-1001", 1900)).toMatchObject({ refunded: false, decision: "invalid_request" });
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("a definitively pre-send aborted request retries with fresh authorization and the same stable ID", async () => {
    const s = setup();
    s.shopify.onRead = n => { if (n === 1) s.shopify.failGet = true; };
    const first = await s.refund();
    expect((await s.ledger.get(first.gateRef))?.aborted_reason).toBe("error");
    expect(s.shopify.refunds).toHaveLength(0);
    s.shopify.failGet = false;
    delete s.shopify.onRead;
    expect((await s.refund()).refunded).toBe(true);
    expect(s.runtime.evaluateBodies).toHaveLength(2);
    expect(s.runtime.verifyBodies).toHaveLength(2);
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("normalizes the configured shop so spelling changes cannot bypass request replay", async () => {
    const s = setup();
    expect((await s.refund()).refunded).toBe(true);
    expect(await s.refund("case-1001", 1899, { ...s.options, shop: `https://${SHOP.toUpperCase()}/` })).toMatchObject({ decision: "duplicate_request" });
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("invalid business IDs stop before evaluating", async () => {
    const s = setup();
    for (const id of ["", " ", "a".repeat(129)]) expect(await s.refund(id)).toMatchObject({ decision: "invalid_request" });
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });
  it("a parallel request cannot cross the payment boundary while the first send waits", async () => {
    const s = setup();
    let release!: () => void;
    let entered!: () => void;
    const arrived = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    const original = s.shopify.createRefund.bind(s.shopify);
    s.shopify.createRefund = async input => { entered(); await held; return original(input); };
    const first = s.refund();
    await arrived;
    try {
      expect(await s.refund("another-case")).toMatchObject({ refunded: false, decision: "reconciliation_required" });
      expect(s.shopify.refunds).toHaveLength(0);
    } finally { release(); }
    expect((await first).refunded).toBe(true);
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("a lost response remains blocked after restart, even with a fresh business ID", async () => {
    const s = setup(true);
    const original = s.shopify.createRefund.bind(s.shopify);
    s.shopify.createRefund = async input => { await original(input); throw new Error("lost response after commit"); };
    const first = await s.refund();
    expect(first).toMatchObject({ refunded: false, decision: "unconfirmed" });
    expect(describeResult(first).message).toMatch(/unconfirmed.*before issuing another refund/);
    const reopened = new JsonFileLedger(s.path!);
    expect(await s.refund("fresh-key", 1899, { ...s.options, ledger: reopened })).toMatchObject({ decision: "reconciliation_required", gateRef: first.gateRef });
    expect(s.shopify.refunds).toHaveLength(1);
    const nativeId = [...s.shopify.nativeRefunds.keys()][0]!;
    expect(await reconcileShopifyRefund(s.shopify, reopened, { gateRef: first.gateRef, shop: SHOP, environment: "test", candidateRefundId: nativeId }))
      .toMatchObject({ status: "succeeded", refundId: nativeId });
    expect(await s.refund("case-1001", 1899, { ...s.options, ledger: reopened })).toMatchObject({ decision: "duplicate_request" });
    expect(s.shopify.refunds).toHaveLength(1);
  });
});

describe("completion is native transaction truth", () => {
  for (const status of ["PENDING", "FAILURE", "ERROR", "UNKNOWN"]) it(`${status} never becomes refunded`, async () => {
    const s = setup();
    s.shopify.refundStatus = status;
    const r = await s.refund();
    expect(r).toMatchObject({ refunded: false, decision: "unconfirmed" });
    expect((await s.ledger.get(r.gateRef))?.refund_id).toBeUndefined();
    expect(await s.refund("new-id")).toMatchObject({ decision: "reconciliation_required" });
  });
  const mutations = [
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.order.id = "gid://shopify/Order/999"; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.note = "unrelated"; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.transactions.pageInfo.hasNextPage = true; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.transactions.nodes[0]!.amountSet.shopMoney.amount = "19.00"; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.transactions.nodes[0]!.amountSet.shopMoney.currencyCode = "EUR"; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.transactions.nodes[0]!.parentTransaction = { id: "other-payment" }; },
    (n: NonNullable<Awaited<ReturnType<FakeShopify["getRefund"]>>>) => { n.transactions.nodes[0]!.gateway = "other"; },
  ];
  for (const [i, mutate] of mutations.entries()) it(`mismatched native proof ${i + 1} stays unconfirmed`, async () => {
    const s = setup();
    const get = s.shopify.getRefund.bind(s.shopify);
    s.shopify.getRefund = async id => { const n = await get(id); if (n) mutate(n); return n; };
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "unconfirmed" });
  });
  it("unavailable readback stays unconfirmed and a later read can reconcile without a send", async () => {
    const s = setup();
    s.shopify.failRefundRead = true;
    const first = await s.refund();
    expect(first).toMatchObject({ decision: "unconfirmed" });
    expect(await reconcileShopifyRefund(s.shopify, s.ledger, { gateRef: first.gateRef, shop: "other.myshopify.com", environment: "test" })).toMatchObject({ status: "refused" });
    s.shopify.failRefundRead = false;
    expect(await reconcileShopifyRefund(s.shopify, s.ledger, { gateRef: first.gateRef, shop: SHOP, environment: "test" })).toMatchObject({ status: "succeeded" });
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("a mismatched candidate or a cancel call cannot release an uncertain execution", async () => {
    const s = setup();
    s.shopify.failRefund = true;
    const first = await s.refund();
    await expect(s.ledger.recordAborted(first.gateRef, "operator retry")).rejects.toThrow(/reconciled/);
    expect(await reconcileShopifyRefund(s.shopify, s.ledger, { gateRef: first.gateRef, shop: SHOP, environment: "test", candidateRefundId: "gid://shopify/Refund/123" })).toMatchObject({ status: "unconfirmed" });
    expect(await s.refund("fresh-key")).toMatchObject({ decision: "reconciliation_required" });
    expect(s.shopify.refunds).toHaveLength(0);
  });
  it("missing getRefund support does not fall back to the mutation response", async () => {
    const s = setup();
    const noReadback = { getOrder: s.shopify.getOrder.bind(s.shopify), createRefund: s.shopify.createRefund.bind(s.shopify) };
    expect(await guardedShopifyRefund(noReadback, s.runtime.client, { orderId: "1001", amountCents: 1899 }, s.options)).toMatchObject({ decision: "unconfirmed" });
  });
  it("uses the authenticated Admin client for a separate refund read", async () => {
    let calls = 0;
    const admin = createAdminClient({ shop: SHOP, accessToken: "fake-token", fetch: (async (_url, init) => {
      calls++;
      const body = JSON.parse(String(init?.body));
      expect(body.query).toContain("AtlaSentRefundReadback");
      expect(body.query).not.toContain("refundCreate");
      expect(body.variables).toEqual({ id: "gid://shopify/Refund/91" });
      return Response.json({ data: { node: null } });
    }) as typeof fetch });
    expect(await admin.getRefund!("gid://shopify/Refund/91")).toBeNull();
    await expect(admin.getRefund!("not-a-refund")).rejects.toThrow();
    expect(calls).toBe(1);
  });
});

describe("approval continuity", () => {
  it("native reconciliation updates an approved case's saved outcome without resubmission", async () => {
    const s = setup();
    const held = await guardedShopifyRefund(s.shopify, s.runtime.client, { orderId: "1002", amountCents: 7200, businessRequestId: "case-1002" }, s.options);
    if (held.refunded || !held.approvalRequestId) throw new Error("expected approval");
    s.runtime.decide(held.approvalRequestId, "approved");
    s.shopify.failRefundRead = true;
    const attempted = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals, { approvalRequestId: held.approvalRequestId }, s.options);
    expect(attempted).toMatchObject({ decision: "unconfirmed" });
    s.shopify.failRefundRead = false;
    expect(await reconcileShopifyRefund(s.shopify, s.ledger, { gateRef: attempted.gateRef, shop: SHOP, environment: "test" })).toMatchObject({ status: "succeeded" });
    expect((await s.ledger.getPendingApproval(held.approvalRequestId))?.resolved?.outcome).toBe("refunded");
    expect(s.shopify.refunds).toHaveLength(1);
  });
  for (const mode of ["expired_facts", "environment", "legacy_without_facts"] as const) it(`${mode} cannot resume`, async () => {
    const s = setup();
    const held = await guardedShopifyRefund(s.shopify, s.runtime.client, { orderId: "1002", amountCents: 7200 }, s.options);
    if (held.refunded || !held.approvalRequestId) throw new Error("expected approval");
    s.runtime.decide(held.approvalRequestId, "approved");
    const opts = { ...s.options };
    if (mode === "expired_facts") opts.now = () => new Date(NOW.getTime() + 40 * 86_400_000);
    if (mode === "environment") opts.environment = "production";
    if (mode === "legacy_without_facts") {
      const p = (await s.ledger.getPendingApproval(held.approvalRequestId))!;
      delete p.source_facts_hash;
      const ledger = new InMemoryLedger();
      await ledger.recordPendingApproval(p);
      opts.ledger = ledger;
    }
    expect((await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals, { approvalRequestId: held.approvalRequestId }, opts)).refunded).toBe(false);
    expect(s.runtime.claims).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
  });
});
