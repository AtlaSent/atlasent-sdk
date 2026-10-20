import { describe, expect, it } from "vitest";
import { centsToMoney, deriveStripeRefundFacts, moneyToCents } from "../src/facts.js";
import { assertPaymentIntentId, createStripeClient, formEncode } from "../src/stripe.js";
import { delivered, makePaymentIntent, NOW } from "./fakes.js";

describe("Stripe client", () => {
  function recorder(responses: Array<{ status: number; body: unknown }>) {
    const calls: { url: string; init: RequestInit }[] = [];
    const impl = (async (url: string | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      const r = responses.shift()!;
      return new Response(JSON.stringify(r.body), { status: r.status });
    }) as typeof fetch;
    return { impl, calls };
  }

  it("reads a PaymentIntent with its latest charge expanded", async () => {
    const http = recorder([{ status: 200, body: makePaymentIntent({ id: "pi_1", captured: 100 }) }]);
    const stripe = createStripeClient({ secretKey: "rk_test_x", stripeAccount: "acct_9", fetch: http.impl });
    await stripe.getPaymentIntent("pi_1");
    expect(http.calls[0]!.url).toBe("https://api.stripe.com/v1/payment_intents/pi_1?expand%5B%5D=latest_charge");
    const h = new Headers(http.calls[0]!.init.headers);
    expect(h.get("authorization")).toBe("Bearer rk_test_x");
    expect(h.get("stripe-account")).toBe("acct_9");
  });

  it("returns null for a missing PaymentIntent, and throws on other errors", async () => {
    const http = recorder([
      { status: 404, body: { error: { message: "No such payment_intent" } } },
      { status: 401, body: { error: { message: "Invalid API Key" } } },
    ]);
    const stripe = createStripeClient({ secretKey: "rk_test_x", fetch: http.impl });
    expect(await stripe.getPaymentIntent("pi_1")).toBeNull();
    await expect(stripe.getPaymentIntent("pi_1")).rejects.toThrow(/401: Invalid API Key/);
  });

  it("creates a refund form-encoded, with the idempotency key", async () => {
    const http = recorder([{ status: 200, body: { id: "re_1", status: "succeeded", amount: 1899, metadata: {} } }]);
    const stripe = createStripeClient({ secretKey: "rk_test_x", fetch: http.impl });
    await stripe.createRefund({ payment_intent: "pi_1", amount: 1899, reason: "requested_by_customer", metadata: { atlasent_gate_ref: "g-1" } }, "g-1");
    const { init } = http.calls[0]!;
    expect(new Headers(init.headers).get("idempotency-key")).toBe("g-1");
    expect(String(init.body)).toBe("payment_intent=pi_1&amount=1899&reason=requested_by_customer&metadata%5Batlasent_gate_ref%5D=g-1");
  });

  it("refuses ids that are not PaymentIntents, without a request", () => {
    for (const id of ["", "ch_1", "pi_", "pi_1/../refunds", "pi_1?x=1"]) expect(() => assertPaymentIntentId(id)).toThrow();
  });

  it("form-encodes nested metadata and skips nulls", () => {
    expect(formEncode({ a: 1, b: null, metadata: { k: "v w" } })).toBe("a=1&metadata%5Bk%5D=v+w");
  });
});

describe("deriveStripeRefundFacts", () => {
  it("combines Stripe money with the store's delivery facts", () => {
    const pi = makePaymentIntent({ id: "pi_1", captured: 3499, refunded: 499, orderRef: "o-1" });
    expect(deriveStripeRefundFacts(pi, delivered(5), "o-1", NOW)).toMatchObject({
      currency: "USD",
      payment_succeeded: true,
      refundable_cents: 3000,
      order_status: "delivered",
      days_since_delivery: 5,
      order_ref: "o-1",
    });
  });

  it("an unknown order is unknown, with no window", () => {
    const f = deriveStripeRefundFacts(makePaymentIntent({ id: "pi_1", captured: 100 }), null, "o", NOW);
    expect(f.order_status).toBe("unknown");
    expect(f).not.toHaveProperty("days_since_delivery");
  });

  it("'delivered' without a date is not delivered; a future date leaves the window unknown", () => {
    const pi = makePaymentIntent({ id: "pi_1", captured: 100 });
    expect(deriveStripeRefundFacts(pi, { order_status: "delivered" }, "o", NOW).order_status).toBe("not_delivered");
    expect(deriveStripeRefundFacts(pi, delivered(-2), "o", NOW)).not.toHaveProperty("days_since_delivery");
  });

  it("a payment without a charge has nothing refundable", () => {
    const pi = { ...makePaymentIntent({ id: "pi_1", captured: 100 }), latest_charge: null };
    expect(deriveStripeRefundFacts(pi, delivered(1), "o", NOW)).toMatchObject({ refundable_cents: 0, payment_succeeded: false });
  });
});

describe("money", () => {
  it("round-trips", () => {
    expect(moneyToCents("18.99")).toBe(1899);
    expect(centsToMoney(1899)).toBe("18.99");
    for (const bad of ["", "-1", "1.999", "1e3"]) expect(() => moneyToCents(bad)).toThrow();
  });
});
