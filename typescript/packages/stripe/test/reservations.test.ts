import { describe, expect, it } from "vitest";
import { createRefundReservationsClient, type RefundBudgetSubject } from "../src/reservations.js";
import { CUSTOMER_REFUND_ISSUE, guardedStripeRefund, reconcileStripeRefund, resumeApprovedStripeRefund,
  type StripeRefundGuardOptions } from "../src/guard.js";
import { staticDeliveryFacts } from "../src/facts.js";
import { InMemoryLedger } from "../src/ledger.js";
import { demoPayments, FakeStripe, fakeRuntime, NOW } from "./fakes.js";

const id = "83900000-0000-4000-8000-000000000021";
const subject: RefundBudgetSubject = { environment: "test", provider_account: "acct_demo",
  business_request_id: "ticket-4411:line-1", payment_ref: "pi_1001", customer_ref: "cus_real",
  amount_minor: "1899", currency: "usd" };
function receipt(body: Record<string, unknown> | RefundBudgetSubject) {
  return { ok: true, state: "reserved", reservation_id: id, budget_status: "enforced",
    budget_remaining_minor: "0", authority_effect: "none", binding: { ...body, reservation_id: id, provider: "stripe" } };
}
function setup() {
  const data = demoPayments();
  for (const pi of data.pis) pi.customer = "cus_real";
  const stripe = new FakeStripe(data.pis), runtime = fakeRuntime();
  const calls: { action: string; body: Record<string, unknown> }[] = [];
  let refused: string | undefined;
  const api = createRefundReservationsClient({ apiKey: "test-runtime-key", fetch: async (url, init) => {
    const action = String(url).split("/").at(-1)!;
    const body = JSON.parse(String(init?.body)); calls.push({ action, body });
    return new Response(JSON.stringify(refused === action ? { ok: false, code: "budget_exceeded" } : receipt(body)),
      { status: refused === action ? 409 : 200 });
  } });
  const options: StripeRefundGuardOptions = { actor: "agent:one", environment: "test", account: "acct_demo",
    ledger: new InMemoryLedger(), delivery: staticDeliveryFacts(data.delivery), now: () => NOW,
    actionType: CUSTOMER_REFUND_ISSUE, runtimeReservations: api };
  const refund = (paymentIntentId = "pi_1001", amountCents = 1899) => guardedStripeRefund(stripe, runtime.client,
    { paymentIntentId, amountCents, businessRequestId: subject.business_request_id }, options);
  return { stripe, runtime, options, calls, refund, refuse: (action: string) => { refused = action; } };
}

describe("runtime budget HTTP receipts", () => {
  it("uses the existing function, bounded timeout, no redirects, and exact immutable binding", async () => {
    const mutable = { ...subject };
    const api = createRefundReservationsClient({ apiKey: "test-key", baseUrl: "https://api.atlasent.io", fetch: async (url, init) => {
      expect(String(url)).toBe("https://api.atlasent.io/functions/v1/v1-consequential-operations/refund-reserve");
      expect(init?.redirect).toBe("error"); expect(init?.signal).toBeInstanceOf(AbortSignal);
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer test-key");
      const body = JSON.parse(String(init?.body)); mutable.amount_minor = "999999";
      return new Response(JSON.stringify(receipt(body)));
    } });
    expect(await api.reserve(mutable)).toEqual({ reservationId: id });
  });
  it.each([
    { ok: "true" }, { budget_status: "not_configured" }, { state: "released" }, { authority_effect: "allow" },
    { budget_remaining_minor: "-1" }, { budget_remaining_minor: 0 }, { reservation_id: "not-a-uuid" },
    { binding: { ...subject, amount_minor: "1900", reservation_id: id, provider: "stripe" } },
  ])("rejects a malformed or wrong-subject receipt %j", async (patch) => {
    const api = createRefundReservationsClient({ apiKey: "test-key", fetch: async () =>
      new Response(JSON.stringify({ ...receipt(subject), ...patch })) });
    await expect(api.reserve(subject)).rejects.toThrow("invalid budget receipt");
  });
  it("rejects recheck receipts naming another reservation", async () => {
    const api = createRefundReservationsClient({ apiKey: "test-key", fetch: async () => new Response(JSON.stringify(receipt(subject))) });
    await expect(api.recheck(subject, "83900000-0000-4000-8000-000000000099")).rejects.toThrow("invalid budget receipt");
  });
  it("normalizes a valid uppercase reservation UUID for a recheck", async () => {
    const reservationId = "839abcde-0000-4abc-8def-000000000021";
    const api = createRefundReservationsClient({ apiKey: "test-key", fetch: async (_url, init) => {
      const body = JSON.parse(String(init?.body)); expect(body.reservation_id).toBe(reservationId);
      return new Response(JSON.stringify({ ...receipt(body), reservation_id: reservationId,
        binding: { ...body, provider: "stripe" } }));
    } });
    await expect(api.recheck(subject, reservationId.toUpperCase())).resolves.toBeUndefined();
  });
  it("never exposes a credential included in a transport error", async () => {
    const api = createRefundReservationsClient({ apiKey: "test-key", fetch: async () => { throw new Error("test-key private server details"); } });
    await expect(api.reserve(subject)).rejects.toThrow(/^refund budget refused or unavailable$/);
  });
  it("rejects non-JSON, failed HTTP and oversized actual response bytes", async () => {
    for (const response of [new Response("{"), new Response("private database details", { status: 503 }), new Response("x".repeat(65537))]) {
      const api = createRefundReservationsClient({ apiKey: "test-key", fetch: async () => response });
      await expect(api.reserve(subject)).rejects.toThrow();
    }
  });
  it("rejects unsafe origins and invalid timeout configuration", () => {
    for (const baseUrl of ["http://remote.example", "https://key:secret@example.test", "https://example.test/?token=secret"]) {
      expect(() => createRefundReservationsClient({ apiKey: "test", baseUrl })).toThrow();
    }
    expect(() => createRefundReservationsClient({ apiKey: "test", timeoutMs: 0 })).toThrow();
  });
});

describe("Stripe guard budget boundaries", () => {
  it("canonical refunds require a runtime client and durable business request before evaluating", async () => {
    const s = setup(); delete s.options.runtimeReservations;
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "invalid_request" });
    expect(s.runtime.evaluateBodies).toHaveLength(0); expect(s.stripe.refunds).toHaveLength(0);
    const t = setup();
    expect(await guardedStripeRefund(t.stripe, t.runtime.client, { paymentIntentId: "pi_1001", amountCents: 1899 }, t.options))
      .toMatchObject({ refunded: false, decision: "invalid_request" });
    expect(t.calls).toHaveLength(0);
  });
  it("reserves before evaluation and rechecks before provider submission using provider customer facts", async () => {
    const s = setup(); expect((await s.refund()).refunded).toBe(true);
    expect(s.calls.map(c => c.action)).toEqual(["refund-reserve", "refund-reserve", "refund-recheck"]);
    expect(s.calls[0]!.body).toEqual(subject);
    expect(s.calls[2]!.body).toEqual({ ...subject, reservation_id: id });
    expect(s.runtime.evaluateBodies[0]!.action_type).toBe(CUSTOMER_REFUND_ISSUE);
    expect(s.runtime.verifyBodies).toHaveLength(1); expect(s.stripe.refunds).toHaveLength(1);
  });
  it("an exhausted or unavailable initial cap holds before evaluate, verify or Stripe", async () => {
    const s = setup(); s.refuse("refund-reserve");
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "hold" });
    expect(s.runtime.evaluateBodies).toHaveLength(0); expect(s.runtime.verifyBodies).toHaveLength(0);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("a changed cap after Permit consumption prevents Stripe submission", async () => {
    const s = setup(); s.refuse("refund-recheck");
    expect((await s.refund()).refunded).toBe(false);
    expect(s.runtime.verifyBodies).toHaveLength(1); expect(s.stripe.refunds).toHaveLength(0);
  });
  it("approval resumption encounters the same current shared cap", async () => {
    const s = setup(); const held = await s.refund("pi_1002", 7200);
    expect(held).toMatchObject({ refunded: false, decision: "escalate" });
    const approvalRequestId = !held.refunded && held.approvalRequestId || "missing";
    s.runtime.decide(approvalRequestId, "approved"); s.refuse("refund-recheck");
    const result = await resumeApprovedStripeRefund(s.stripe, s.runtime.client, s.runtime.approvals, { approvalRequestId }, s.options);
    expect(result.refunded).toBe(false); expect(s.calls.at(-1)!.action).toBe("refund-recheck");
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("unconfirmed resubmission cannot bypass the cap or use a new business request", async () => {
    const s = setup(); s.stripe.failRefund = true;
    const result = await s.refund(); expect(result).toMatchObject({ refunded: false, decision: "unconfirmed" });
    s.stripe.failRefund = false; s.refuse("refund-recheck");
    const retry = await reconcileStripeRefund(s.stripe, result.gateRef, s.options, { resubmit: true });
    expect(retry.state).toBe("unconfirmed"); expect(retry.resubmitted).toBeUndefined();
    expect(s.calls.at(-1)!.body.business_request_id).toBe(subject.business_request_id);
    expect(s.stripe.refunds).toHaveLength(0);
  });
  it("a malformed Stripe customer identity cannot skip customer-scoped constraints", async () => {
    const s = setup(); s.stripe.pis.get("pi_1001")!.customer = { id: "attacker" };
    expect(await s.refund()).toMatchObject({ refunded: false, decision: "hold" });
    expect(s.calls).toHaveLength(0); expect(s.stripe.refunds).toHaveLength(0);
  });
  it("an async caller cannot remove an opted-in legacy budget client during authorization", async () => {
    const s = setup(); delete s.options.actionType;
    const runtime = fakeRuntime({ afterVerify: () => { delete s.options.runtimeReservations; } });
    s.refuse("refund-recheck");
    const result = await guardedStripeRefund(s.stripe, runtime.client,
      { paymentIntentId: "pi_1001", amountCents: 1899, businessRequestId: subject.business_request_id }, s.options);
    expect(result.refunded).toBe(false); expect(s.calls.at(-1)!.action).toBe("refund-recheck");
    expect(s.stripe.refunds).toHaveLength(0);
  });
});
