import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { staticDeliveryFacts } from "../src/facts.js";
import { computeStripeRefundDigest, FINANCE_PAYMENT_AUTHORIZE, guardedStripeRefund, type StripeRefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { auditStripeRefund } from "../src/webhook.js";
import { delivered, demoPayments, FakeStripe, fakeRuntime, makePaymentIntent, NOW, type RuntimeOptions } from "./fakes.js";

function setup(rt: RuntimeOptions = {}, data = demoPayments()) {
  const runtime = fakeRuntime(rt);
  const stripe = new FakeStripe(data.pis);
  const ledger = new InMemoryLedger();
  const options: StripeRefundGuardOptions = {
    actor: "support-tool:dana",
    environment: "test",
    ledger,
    delivery: staticDeliveryFacts(data.delivery),
    account: "acct_demo",
    now: () => NOW,
  };
  const refund = (paymentIntentId: string, amountCents: number, reason?: string) =>
    guardedStripeRefund(stripe, runtime.client, { paymentIntentId, amountCents, ...(reason ? { reason } : {}) }, options);
  return { runtime, stripe, ledger, refund };
}

describe("guardedStripeRefund — the demo scenarios", () => {
  it("refunds $18.99 on a delivered order inside the window, keyed by the gateRef", async () => {
    const s = setup();
    const r = await s.refund("pi_1001", 1899, "chew toy arrived torn");
    expect(r.refunded).toBe(true);
    if (!r.refunded) return;
    expect(s.stripe.refunds).toEqual([
      {
        input: {
          payment_intent: "pi_1001",
          amount: 1899,
          reason: "requested_by_customer",
          metadata: { atlasent_gate_ref: r.gateRef, order_ref: "PPS-1001", atlasent_reason: "chew toy arrived torn" },
        },
        key: r.gateRef,
      },
    ]);
    const entry = await s.ledger.get(r.gateRef);
    const token = [...s.runtime.permits.keys()][0]!;
    expect(entry?.permit_sha256).toBe(createHash("sha256").update(token).digest("hex"));
    expect(JSON.stringify(r)).not.toContain(token);
    expect(entry?.refund_id).toBe(r.refund.id);
  });

  const blocked: Array<[string, string, number, string, string]> = [
    ["$72 escalates to a manager", "pi_1002", 7200, "escalate", "MANAGER_APPROVAL_REQUIRED"],
    ["condition 1: not delivered is denied", "pi_1003", 1200, "deny", "ORDER_NOT_DELIVERED"],
    ["condition 2: 45 days after delivery is denied", "pi_1004", 2500, "deny", "RETURN_WINDOW_EXPIRED"],
  ];
  for (const [name, pi, cents, decision, code] of blocked) {
    it(name, async () => {
      const s = setup();
      const r = await s.refund(pi, cents);
      expect(r).toMatchObject({ refunded: false, decision, denyCode: code });
      expect(s.runtime.verifyBodies).toHaveLength(0);
      expect(s.stripe.refunds).toHaveLength(0);
    });
  }
});

describe("what evaluate and verify receive", () => {
  it("only Stripe- and order-system facts, bound to the exact refund", async () => {
    const s = setup();
    await s.refund("pi_1001", 1899);
    const digest = computeStripeRefundDigest({
      account: "acct_demo",
      payment_intent: "pi_1001",
      charge: "ch_1001",
      order_ref: "PPS-1001",
      amount_cents: 1899,
      currency: "USD",
    });
    expect(s.runtime.evaluateBodies[0]).toMatchObject({
      action_type: FINANCE_PAYMENT_AUTHORIZE,
      actor_id: "support-tool:dana",
      environment: "test",
      resource_id: "pi_1001",
      execution_payload_hash: digest,
    });
    expect(s.runtime.evaluateBodies[0]!.context).toEqual({
      amount_cents: 1899,
      currency: "USD",
      environment: "test",
      order_status: "delivered",
      days_since_delivery: 5,
      refundable_cents: 3499,
      target: { id: "pi_1001" },
    });
    expect(s.runtime.verifyBodies[0]).toMatchObject({ execution_hash: digest });
  });

  it("the digest changes with amount, account and order", () => {
    const b = { account: "a", payment_intent: "pi_1", charge: "ch_1", order_ref: "o", amount_cents: 1, currency: "USD" };
    for (const change of [{ amount_cents: 2 }, { account: "b" }, { order_ref: "p" }, { charge: "ch_2" }]) {
      expect(computeStripeRefundDigest({ ...b, ...change })).not.toBe(computeStripeRefundDigest(b));
    }
  });
});

describe("refused before AtlaSent is asked", () => {
  const one = (spec: Parameters<typeof makePaymentIntent>[0], deliveryFor: Record<string, ReturnType<typeof delivered>> = {}) => ({
    pis: [makePaymentIntent(spec)],
    delivery: { [`order-${spec.id}`]: delivered(5), ...deliveryFor },
  });
  const cases: Array<[string, () => ReturnType<typeof setup>, string, number, RegExp]> = [
    ["a fractional amount", () => setup(), "pi_1001", 18.5, /positive whole number/],
    ["a zero amount", () => setup(), "pi_1001", 0, /positive whole number/],
    ["an unknown payment", () => setup(), "pi_9999", 100, /payment not found/],
    ["a malformed payment id", () => setup(), "ch_1001", 100, /not a Stripe PaymentIntent id/],
    ["more than is left to refund", () => setup(), "pi_1001", 3500, /more than the 34.99/],
    ["a payment that did not succeed", () => setup({}, one({ id: "pi_7", captured: 1000, status: "requires_payment_method" })), "pi_7", 100, /not succeeded/],
    ["a disputed charge", () => setup({}, one({ id: "pi_8", captured: 1000, disputed: true })), "pi_8", 100, /disputed/],
    ["a payment not linked to an order", () => setup({}, one({ id: "pi_9", captured: 1000, orderRef: null })), "pi_9", 100, /not linked to an order/],
    ["a non-USD payment", () => setup({}, one({ id: "pi_10", captured: 1000, currency: "eur" })), "pi_10", 100, /USD/],
  ];
  for (const [name, mk, pi, cents, msg] of cases) {
    it(name, async () => {
      const s = mk();
      const r = await s.refund(pi, cents);
      expect(!r.refunded && r.reason).toMatch(msg);
      expect(s.runtime.evaluateBodies).toHaveLength(0);
      expect(s.stripe.refunds).toHaveLength(0);
    });
  }

  it("an order the store has no record of is not delivered", async () => {
    const s = setup({}, { pis: [makePaymentIntent({ id: "pi_11", captured: 1000, orderRef: "ghost" })], delivery: {} });
    expect(await s.refund("pi_11", 100)).toMatchObject({ refunded: false, denyCode: "ORDER_NOT_DELIVERED" });
  });
});

describe("fails closed", () => {
  const cases: Array<[string, RuntimeOptions, (s: ReturnType<typeof setup>) => void, string]> = [
    ["evaluate transport error", { evaluateThrows: true }, () => {}, "error"],
    ["unknown decision", { forceDecision: "maybe" }, () => {}, "error"],
    ["verify transport error", { verifyThrows: true }, () => {}, "error"],
    ["verify says not valid", { verifyValid: false }, () => {}, "verify_failed"],
    ["verified but not consumed", { consumed: false }, () => {}, "verify_failed"],
    ["verified with consumed omitted", { consumed: null }, () => {}, "verify_failed"],
    ["Stripe read fails", {}, (s) => (s.stripe.failGet = true), "error"],
    ["refund request rejected by Stripe (400)", {}, (s) => (s.stripe.failRefund = 400), "error"],
    ["refund request outcome unknown (transport error)", {}, (s) => (s.stripe.failRefund = true), "unconfirmed"],
    ["refund request outcome unknown (Stripe 500)", {}, (s) => (s.stripe.failRefund = 500), "unconfirmed"],
    ["Stripe returns the refund as failed", {}, (s) => (s.stripe.refundStatus = "failed"), "error"],
  ];
  for (const [name, rt, arrange, decision] of cases) {
    it(name, async () => {
      const s = setup(rt);
      arrange(s);
      const r = await s.refund("pi_1001", 1899);
      expect(r.refunded).toBe(false);
      expect(!r.refunded && r.decision).toBe(decision);
    });
  }

  it("a ledger that cannot record the permit stops the refund", async () => {
    const s = setup();
    s.ledger.recordAuthorized = async () => {
      throw new Error("disk full");
    };
    expect(await s.refund("pi_1001", 1899)).toMatchObject({ refunded: false, reason: expect.stringMatching(/could not record/) });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("a payment disputed during verify is not refunded", async () => {
    const s = setup();
    s.stripe.onRead = (n, fake) => {
      if (n === 1) fake.pis.get("pi_1001")!.latest_charge!.disputed = true;
    };
    expect(await s.refund("pi_1001", 1899)).toMatchObject({ refunded: false, decision: "payment_changed" });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("a payment refunded elsewhere during verify is not refunded again", async () => {
    const s = setup();
    s.stripe.onRead = (n, fake) => {
      if (n === 1) fake.pis.get("pi_1001")!.latest_charge!.amount_refunded = 3000;
    };
    expect(await s.refund("pi_1001", 1899)).toMatchObject({ refunded: false, decision: "payment_changed" });
  });

  it("every definite stop after recording cancels the entry, so a copied gateRef is flagged", async () => {
    const s = setup();
    s.stripe.failRefund = 400;
    const r = await s.refund("pi_1001", 1899);
    expect((await s.ledger.get(r.gateRef))?.aborted_reason).toBe("error");
    const copied = {
      id: "re_dashboard",
      status: "succeeded",
      amount: 1899,
      currency: "usd",
      charge: "ch_1001",
      payment_intent: "pi_1001",
      metadata: { atlasent_gate_ref: r.gateRef },
    };
    expect(await auditStripeRefund(copied, s.ledger)).toMatchObject({ verdict: "unauthorized", reason: expect.stringMatching(/stopped/) });
  });
});

describe("onDecision (evidence log)", () => {
  it("records every decision with Stripe and order-system facts", async () => {
    const records: import("../src/decision-record.js").RefundDecisionRecord[] = [];
    const s = setup();
    const data = demoPayments();
    const options = { actor: "support-tool:dana", environment: "test", ledger: s.ledger, delivery: staticDeliveryFacts(data.delivery), account: "acct_demo", now: () => NOW, onDecision: (r: (typeof records)[number]) => void records.push(r) };
    const ok = await guardedStripeRefund(s.stripe, s.runtime.client, { paymentIntentId: "pi_1001", amountCents: 1899 }, options);
    await guardedStripeRefund(s.stripe, s.runtime.client, { paymentIntentId: "pi_1004", amountCents: 2500 }, options);
    expect(records.map((r) => r.outcome)).toEqual(["refunded", "denied"]);
    expect(records[0]).toMatchObject({
      system: "stripe",
      gate_ref: ok.gateRef,
      target: "pi_1001",
      order_ref: "PPS-1001",
      amount_cents: 1899,
      refund_id: ok.refunded ? ok.refund.id : "x",
    });
    expect(records[1]).toMatchObject({ deny_code: "RETURN_WINDOW_EXPIRED", days_since_delivery: 45 });
  });
});
