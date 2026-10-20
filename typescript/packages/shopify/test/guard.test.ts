import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { computeRefundDigest, FINANCE_PAYMENT_AUTHORIZE, guardedShopifyRefund, type RefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger, type LedgerEntry } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, makeOrder, NOW, type RuntimeOptions } from "./fakes.js";

const SHOP = "pinecone-pet-supply.myshopify.com";

function setup(rt: RuntimeOptions = {}, orders = demoOrders()) {
  const runtime = fakeRuntime(rt);
  const shopify = new FakeShopify(orders);
  const ledger = new InMemoryLedger();
  const options: RefundGuardOptions = { actor: "shopify-staff:test/1", environment: "test", ledger, shop: SHOP, now: () => NOW };
  const refund = (orderId: string, amountCents: number, reason?: string) =>
    guardedShopifyRefund(shopify, runtime.client, { orderId, amountCents, ...(reason ? { reason } : {}) }, options);
  return { runtime, shopify, ledger, refund };
}

describe("guardedShopifyRefund — the demo scenarios", () => {
  it("refunds $18.99 on a delivered order inside the window", async () => {
    const { refund, shopify, runtime, ledger } = setup();
    const r = await refund("1001", 1899, "chew toy arrived torn");
    expect(r.refunded).toBe(true);
    if (!r.refunded) return;
    expect(shopify.refunds).toHaveLength(1);
    expect(shopify.refunds[0]).toEqual({
      orderId: "gid://shopify/Order/1001",
      note: `AtlaSent gate ref ${r.gateRef} — chew toy arrived torn`,
      notify: false,
      transactions: [
        { orderId: "gid://shopify/Order/1001", parentId: "gid://shopify/OrderTransaction/10011", kind: "REFUND", gateway: "manual", amount: "18.99" },
      ],
    });
    // The ledger holds a hash of the permit, never the permit token.
    const entry = (await ledger.get(r.gateRef)) as LedgerEntry;
    const token = String(runtime.evaluateBodies.length && [...runtime.permits.keys()][0]);
    expect(entry.permit_sha256).toBe(createHash("sha256").update(token).digest("hex"));
    expect(JSON.stringify(entry)).not.toContain(token);
    expect(JSON.stringify(r)).not.toContain(token);
    expect(entry.refund_id).toBe(r.refund.id);
  });

  const blocked: Array<[string, string, number, string, string]> = [
    ["$72 escalates to a manager", "1002", 7200, "escalate", "MANAGER_APPROVAL_REQUIRED"],
    ["condition 1: in transit is denied", "1003", 1200, "deny", "ORDER_NOT_DELIVERED"],
    ["condition 2: 45 days after delivery is denied", "1004", 2500, "deny", "RETURN_WINDOW_EXPIRED"],
  ];
  for (const [name, order, cents, decision, code] of blocked) {
    it(name, async () => {
      const { refund, shopify, runtime } = setup();
      const r = await refund(order, cents);
      expect(r).toMatchObject({ refunded: false, decision, denyCode: code });
      expect(runtime.verifyBodies).toHaveLength(0);
      expect(shopify.refunds).toHaveLength(0);
    });
  }

  it("surfaces the escalation id for the manager-review step", async () => {
    const { refund } = setup();
    const r = await refund("1002", 7200);
    expect(!r.refunded && r.escalationId).toMatch(/^esc-/);
  });
});

describe("what evaluate and verify receive", () => {
  it("sends only Shopify-derived facts and binds the exact refund", async () => {
    const { refund, runtime } = setup();
    await refund("1001", 1899);
    const ev = runtime.evaluateBodies[0]!;
    const digest = computeRefundDigest({
      shop: SHOP,
      order_id: "gid://shopify/Order/1001",
      amount_cents: 1899,
      currency: "USD",
      parent_transaction_id: "gid://shopify/OrderTransaction/10011",
      gateway: "manual",
    });
    expect(ev).toMatchObject({
      action_type: FINANCE_PAYMENT_AUTHORIZE,
      actor_id: "shopify-staff:test/1",
      environment: "test",
      resource_id: "gid://shopify/Order/1001",
      execution_payload_hash: digest,
    });
    expect(ev.context).toEqual({
      amount_cents: 1899,
      currency: "USD",
      order_status: "delivered",
      days_since_delivery: 5,
      refundable_cents: 3499,
      target: { id: "gid://shopify/Order/1001" },
    });
    expect(runtime.verifyBodies[0]).toMatchObject({ action_type: FINANCE_PAYMENT_AUTHORIZE, environment: "test", execution_hash: digest });
  });

  it("a different amount on the same order binds a different digest", () => {
    const base = { shop: SHOP, order_id: "o", amount_cents: 1899, currency: "USD", parent_transaction_id: "t", gateway: "g" };
    expect(computeRefundDigest(base)).not.toBe(computeRefundDigest({ ...base, amount_cents: 1900 }));
    expect(computeRefundDigest(base)).not.toBe(computeRefundDigest({ ...base, shop: "other.myshopify.com" }));
  });
});

describe("refused before AtlaSent is asked", () => {
  const cases: Array<[string, () => ReturnType<typeof setup>, string, number, RegExp]> = [
    ["a non-positive amount", () => setup(), "1001", 0, /positive whole number/],
    ["a fractional cent amount", () => setup(), "1001", 18.5, /positive whole number/],
    ["an unknown order", () => setup(), "999", 100, /order not found/],
    ["more than is left to refund", () => setup(), "1001", 3500, /more than the 34.99/],
    ["a non-USD order", () => setup({}, [makeOrder({ id: 7, delivery: "delivered", currency: "EUR" })]), "7", 100, /USD/],
    ["a malformed order id", () => setup(), "not-an-id", 100, /not a Shopify order id/],
  ];
  for (const [name, mk, order, cents, msg] of cases) {
    it(name, async () => {
      const s = mk();
      const r = await s.refund(order, cents);
      expect(r.refunded).toBe(false);
      expect(!r.refunded && r.reason).toMatch(msg);
      expect(s.runtime.evaluateBodies).toHaveLength(0);
      expect(s.shopify.refunds).toHaveLength(0);
    });
  }

  it("counts earlier refunds against what is left", async () => {
    const s = setup({}, [makeOrder({ id: 8, delivery: "delivered", paid: "40.00", refunded: "30.00" })]);
    const r = await s.refund("8", 1500);
    expect(!r.refunded && r.reason).toMatch(/more than the 10.00/);
  });
});

describe("fails closed", () => {
  const cases: Array<[string, RuntimeOptions, (s: ReturnType<typeof setup>) => void, string]> = [
    ["evaluate transport error", { evaluateThrows: true }, () => {}, "error"],
    ["unknown decision from the runtime", { forceDecision: "maybe" }, () => {}, "error"],
    ["verify transport error", { verifyThrows: true }, () => {}, "error"],
    ["verify says not valid", { verifyValid: false }, () => {}, "verify_failed"],
    ["verified but reported not consumed", { consumed: false }, () => {}, "verify_failed"],
    ["verified with consumed omitted", { consumed: null }, () => {}, "verify_failed"],
    ["Shopify read fails", {}, (s) => (s.shopify.failGet = true), "error"],
    ["refundCreate fails", {}, (s) => (s.shopify.failRefund = true), "error"],
  ];
  for (const [name, rt, arrange, decision] of cases) {
    it(name, async () => {
      const s = setup(rt);
      arrange(s);
      const r = await s.refund("1001", 1899);
      expect(r.refunded).toBe(false);
      expect(!r.refunded && r.decision).toBe(decision);
      expect(s.shopify.refunds).toHaveLength(0);
    });
  }

  it("a ledger that cannot record the permit stops the refund", async () => {
    const s = setup();
    s.ledger.recordAuthorized = async () => {
      throw new Error("disk full");
    };
    const r = await s.refund("1001", 1899);
    expect(!r.refunded && r.reason).toMatch(/could not record the permit/);
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("an order refunded elsewhere during verify is not refunded again", async () => {
    const s = setup();
    s.shopify.onRead = (n, fake) => {
      if (n === 1) {
        const o = fake.orders.get("gid://shopify/Order/1001")!;
        o.transactions.push({ ...o.transactions[0]!, id: "gid://shopify/OrderTransaction/x", kind: "REFUND", amountSet: { shopMoney: { amount: "30.00", currencyCode: "USD" } } });
      }
    };
    const r = await s.refund("1001", 1899);
    expect(r).toMatchObject({ refunded: false, decision: "order_changed" });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("a ledger that cannot record the refund id still reports the refund, with a warning", async () => {
    const s = setup();
    s.ledger.recordExecuted = async () => {
      throw new Error("disk full");
    };
    const r = await s.refund("1001", 1899);
    expect(r.refunded).toBe(true);
    expect(r.refunded && r.ledgerWarning).toMatch(/ledger did not record/);
  });
});
