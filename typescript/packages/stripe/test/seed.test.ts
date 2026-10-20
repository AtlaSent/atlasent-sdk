import { describe, expect, it } from "vitest";
import { staticDeliveryFacts } from "../src/facts.js";
import { guardedStripeRefund } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { assertTestSetupKey, deliveryFile, paymentIntentForm, runbook, SEED_SCENARIOS, seedTestPayments } from "../src/seed.js";
import { FakeStripe, fakeRuntime, makePaymentIntent, NOW } from "./fakes.js";

describe("seed scenarios", () => {
  it("each seeded payment, refunded as the runbook says, gets the outcome the seed promises", async () => {
    const runtime = fakeRuntime();
    const pis = SEED_SCENARIOS.map((s, i) => makePaymentIntent({ id: `pi_seed${i}`, orderRef: s.orderRef, captured: s.amountCents }));
    const stripe = new FakeStripe(pis);
    const options = { actor: "stripe-cli:t", environment: "test", ledger: new InMemoryLedger(), delivery: staticDeliveryFacts(deliveryFile(SEED_SCENARIOS, NOW)), account: "acct", now: () => NOW };
    const outcomes = [];
    for (const [i, s] of SEED_SCENARIOS.entries()) {
      const r = await guardedStripeRefund(stripe, runtime.client, { paymentIntentId: `pi_seed${i}`, amountCents: s.refundCents }, options);
      outcomes.push(r.refunded ? "refunded" : `${r.decision} ${r.denyCode ?? ""}`.trim());
    }
    expect(outcomes).toEqual([
      "refunded",
      "escalate MANAGER_APPROVAL_REQUIRED",
      "escalate MANAGER_APPROVAL_REQUIRED",
      "deny ORDER_NOT_DELIVERED",
      "deny RETURN_WINDOW_EXPIRED",
    ]);
  });

  it("builds a confirmed test-card PaymentIntent linked to its order", () => {
    const f = new URLSearchParams(paymentIntentForm(SEED_SCENARIOS[0]!));
    expect(Object.fromEntries(f)).toMatchObject({
      amount: "3499",
      currency: "usd",
      payment_method: "pm_card_visa",
      confirm: "true",
      "automatic_payment_methods[allow_redirects]": "never",
      "metadata[order_id]": "PPS-S101",
    });
  });
});

describe("seedTestPayments", () => {
  it("refuses anything but a test secret key, before any call", async () => {
    let called = false;
    const f = (async () => {
      called = true;
      return new Response("{}");
    }) as typeof fetch;
    for (const k of ["sk_live_x", "rk_test_x", "rk_live_x", ""]) {
      expect(() => assertTestSetupKey(k)).toThrow(/test-mode secret key/);
      await expect(seedTestPayments(f, k, SEED_SCENARIOS, { runId: "r" })).rejects.toThrow();
    }
    expect(called).toBe(false);
  });

  it("creates one payment per scenario with a stable idempotency key, and stops on an unsucceeded one", async () => {
    const keys: string[] = [];
    let n = 0;
    const f = (async (_u: string | URL, init?: RequestInit) => {
      keys.push((init?.headers as Record<string, string>)["idempotency-key"]!);
      n++;
      return new Response(JSON.stringify({ id: `pi_${n}`, status: n === 3 ? "requires_action" : "succeeded" }), { status: 200 });
    }) as typeof fetch;
    await expect(seedTestPayments(f, "sk_test_x", SEED_SCENARIOS, { runId: "2026-10-21" })).rejects.toThrow(/PPS-S103 .* requires_action/);
    expect(keys).toEqual(["atlasent-refund-demo-2026-10-21-PPS-S101", "atlasent-refund-demo-2026-10-21-PPS-S102", "atlasent-refund-demo-2026-10-21-PPS-S103"]);
  });

  it("the runbook never names the setup key", () => {
    const text = runbook([{ orderRef: "PPS-S101", paymentIntent: "pi_1", status: "succeeded", refundCents: 1899, expect: "refunded" }], "out");
    expect(text).toContain("--payment pi_1 --amount 18.99");
    expect(text).not.toMatch(/sk_test/);
  });
});
