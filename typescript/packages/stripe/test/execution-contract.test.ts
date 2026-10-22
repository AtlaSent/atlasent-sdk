/**
 * The refund execution contract (atlasent-api#4656): one durable operation per
 * business request, one in-flight refund per payment, uncertain submissions kept
 * unconfirmed (never failed, never retried under a new key), provider outcomes
 * read back and recorded, and the evaluated action named explicitly.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { staticDeliveryFacts } from "../src/facts.js";
import {
  computeStripeRefundDigest,
  CUSTOMER_REFUND_ISSUE,
  FINANCE_PAYMENT_AUTHORIZE,
  gateRefForBusinessRequest,
  guardedStripeRefund,
  reconcileStripeRefund,
  RESUBMIT_WINDOW_MS,
  resumeApprovedStripeRefund,
  submissionErrorIsDefinite,
  type StripeRefundGuardOptions,
} from "../src/guard.js";
import { InMemoryLedger, JsonFileLedger, type PermitLedger } from "../src/ledger.js";
import { createStripeClient, StripeApiError, type StripeRefund } from "../src/stripe.js";
import { auditStripeRefund, latestProviderStatus, recordRefundEvent, refundEventFromBody } from "../src/webhook.js";
import { demoPayments, FakeStripe, fakeRuntime, NOW } from "./fakes.js";

function setup(opts: { ledger?: PermitLedger; now?: () => Date; actionType?: StripeRefundGuardOptions["actionType"] } = {}) {
  const data = demoPayments();
  const runtime = fakeRuntime();
  const stripe = new FakeStripe(data.pis);
  const ledger = opts.ledger ?? new InMemoryLedger();
  const options: StripeRefundGuardOptions = {
    actor: "support-tool:dana",
    environment: "test",
    ledger,
    delivery: staticDeliveryFacts(data.delivery),
    account: "acct_demo",
    now: opts.now ?? (() => NOW),
    ...(opts.actionType ? { actionType: opts.actionType } : {}),
  };
  const refund = (paymentIntentId: string, amountCents: number, businessRequestId?: string, o = options) =>
    guardedStripeRefund(stripe, runtime.client, { paymentIntentId, amountCents, ...(businessRequestId ? { businessRequestId } : {}) }, o);
  return { runtime, stripe, ledger, options, refund };
}

const BR = "ticket-4411:line-1";

describe("durable business request identity", () => {
  it("derives the Idempotency-Key from the business request, stable across processes", async () => {
    const s = setup();
    const r = await s.refund("pi_1001", 1899, BR);
    expect(r.gateRef).toBe(gateRefForBusinessRequest("acct_demo", BR));
    expect(s.stripe.refunds[0]!.key).toBe(r.gateRef);
    expect(s.stripe.refunds[0]!.input.metadata.atlasent_business_request).toBe(BR);
    // Another account's same ticket id is a different operation.
    expect(gateRefForBusinessRequest("acct_other", BR)).not.toBe(r.gateRef);
  });

  it("a retry after success is answered from the ledger: no second evaluation, no second refund", async () => {
    const s = setup();
    const first = await s.refund("pi_1001", 1899, BR);
    expect(first.refunded).toBe(true);
    const again = await s.refund("pi_1001", 1899, BR);
    expect(again).toMatchObject({ refunded: false, decision: "duplicate_request", existingRefundId: "re_1" });
    expect(s.runtime.evaluateBodies).toHaveLength(1);
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("refuses reuse of a business request id for another amount or payment", async () => {
    const s = setup();
    await s.refund("pi_1001", 1899, BR);
    expect(await s.refund("pi_1001", 1000, BR)).toMatchObject({ decision: "invalid_request" });
    expect(await s.refund("pi_1005", 1899, BR)).toMatchObject({ decision: "invalid_request" });
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("refuses a malformed business request id before anything else", async () => {
    const s = setup();
    expect(await s.refund("pi_1001", 1899, "short")).toMatchObject({ decision: "invalid_request" });
    expect(await s.refund("pi_1001", 1899, "has spaces in it")).toMatchObject({ decision: "invalid_request" });
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("a denial releases the reservation, so the same request can be decided again (nothing was authorized)", async () => {
    const s = setup();
    expect(await s.refund("pi_1003", 1000, BR)).toMatchObject({ decision: "deny" });
    expect((await s.ledger.getReservation(gateRefForBusinessRequest("acct_demo", BR)))?.state).toBe("released");
    expect(await s.refund("pi_1003", 1000, BR)).toMatchObject({ decision: "deny" });
    expect(s.runtime.evaluateBodies).toHaveLength(2);
  });

  it("a held request keeps its reservation: a retry returns the same approval, never a second one", async () => {
    const s = setup();
    const held = await s.refund("pi_1002", 7200, BR);
    expect(held).toMatchObject({ refunded: false, decision: "escalate" });
    const id = !held.refunded ? held.approvalRequestId : undefined;
    expect(id).toBeDefined();
    expect(await s.refund("pi_1002", 7200, BR)).toMatchObject({ decision: "hold", approvalRequestId: id });
    expect(s.runtime.evaluateBodies).toHaveLength(1);
    // Another refund on the same payment waits for that approval.
    expect(await s.refund("pi_1002", 1000)).toMatchObject({ decision: "in_progress" });
    // Once the approval resolves, the payment is free again.
    s.runtime.decide(id!, "declined");
    await resumeApprovedStripeRefund(s.stripe, s.runtime.client, s.runtime.approvals, { approvalRequestId: id! }, s.options);
    expect(await s.refund("pi_1002", 1000)).toMatchObject({ refunded: true });
  });
});

describe("concurrent requests", () => {
  it("two simultaneous calls for one business request: one runs, one is refused, one refund", async () => {
    const s = setup();
    const [a, b] = await Promise.all([s.refund("pi_1001", 1899, BR), s.refund("pi_1001", 1899, BR)]);
    expect([a.refunded, b.refunded].filter(Boolean)).toHaveLength(1);
    const refused = a.refunded ? b : a;
    expect(!refused.refunded && ["in_progress", "duplicate_request"]).toContain(!refused.refunded && refused.decision);
    expect(s.runtime.evaluateBodies).toHaveLength(1);
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("two simultaneous refunds on one payment under different requests are serialized", async () => {
    const s = setup();
    const [a, b] = await Promise.all([s.refund("pi_1001", 1000, "ticket-1:line-1"), s.refund("pi_1001", 1000, "ticket-2:line-1")]);
    expect([a, b].filter((r) => !r.refunded && r.decision === "in_progress")).toHaveLength(1);
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("the reservation holds across processes sharing a JSON file ledger", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "ledger-")), "ledger.json");
    const one = setup({ ledger: new JsonFileLedger(path) });
    const two = { ...one, options: { ...one.options, ledger: new JsonFileLedger(path) } };
    const [a, b] = await Promise.all([
      one.refund("pi_1001", 1899, BR),
      guardedStripeRefund(one.stripe, one.runtime.client, { paymentIntentId: "pi_1001", amountCents: 1899, businessRequestId: BR }, two.options),
    ]);
    expect([a.refunded, b.refunded].filter(Boolean)).toHaveLength(1);
    expect(one.stripe.refunds).toHaveLength(1);
  });
});

describe("uncertain submissions", () => {
  it("only an HTTP status Stripe does not process is definite", () => {
    for (const s of [400, 401, 402, 403, 404]) expect(submissionErrorIsDefinite(new StripeApiError("x", s))).toBe(true);
    for (const s of [200, 409, 429, 500, 502, 503]) expect(submissionErrorIsDefinite(new StripeApiError("x", s))).toBe(false);
    expect(submissionErrorIsDefinite(new Error("socket hang up"))).toBe(false);
    expect(submissionErrorIsDefinite(undefined)).toBe(false);
  });

  it("an unreadable 2xx from Stripe is unconfirmed, not a failure", async () => {
    const client = createStripeClient({ secretKey: "rk_test_fake", fetch: async () => new Response("<html>gateway</html>", { status: 200 }) });
    const err = await client.createRefund({ payment_intent: "pi_1", amount: 1, reason: "requested_by_customer", metadata: {} }, "k").catch((e: unknown) => e);
    expect(submissionErrorIsDefinite(err)).toBe(false);
  });

  it("a lost response after Stripe created the refund stays unconfirmed, and the alarm accepts that refund", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    const r = await s.refund("pi_1001", 1899, BR);
    expect(r).toMatchObject({ refunded: false, decision: "unconfirmed" });
    const e = await s.ledger.get(r.gateRef);
    expect(e?.aborted_reason).toBeUndefined();
    expect(e?.submission).toMatchObject({ state: "unconfirmed", attempts: 1 });
    expect((await s.ledger.getReservation(r.gateRef))?.state).toBe("active");
    // Stripe's refund.created for it is authorized, not flagged.
    const created = (await s.stripe.listRefunds("pi_1001"))[0]!;
    expect(await auditStripeRefund(created, s.ledger)).toMatchObject({ verdict: "authorized" });
  });

  it("while unconfirmed, the same request is never re-evaluated or resubmitted, and no other refund on the payment starts", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    const r = await s.refund("pi_1001", 1899, BR);
    s.stripe.loseResponseAfterCreate = false;
    expect(await s.refund("pi_1001", 1899, BR)).toMatchObject({ decision: "unconfirmed" });
    expect(await s.refund("pi_1001", 500)).toMatchObject({ decision: "in_progress" });
    expect(s.runtime.evaluateBodies).toHaveLength(1);
    expect(s.stripe.refunds).toHaveLength(1);
    // Readback confirms it; the payment is released.
    expect(await reconcileStripeRefund(s.stripe, r.gateRef, s.options)).toMatchObject({ state: "succeeded", refundId: "re_1" });
    expect(await s.ledger.get(r.gateRef)).toMatchObject({ refund_id: "re_1", submission: { state: "accepted" } });
    expect(await s.refund("pi_1001", 1899, BR)).toMatchObject({ decision: "duplicate_request", existingRefundId: "re_1" });
    expect(await s.refund("pi_1001", 500)).toMatchObject({ refunded: true });
  });

  it("without a business request id, an unconfirmed refund still blocks a second refund on that payment", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    await s.refund("pi_1001", 1899);
    s.stripe.loseResponseAfterCreate = false;
    expect(await s.refund("pi_1001", 1899)).toMatchObject({ decision: "in_progress" });
    expect(s.stripe.refunds).toHaveLength(1);
  });
});

describe("reconcileStripeRefund", () => {
  async function unconfirmedNothingCreated(s: ReturnType<typeof setup>) {
    s.stripe.failRefund = true; // transport error before Stripe did anything
    const r = await s.refund("pi_1001", 1899, BR);
    s.stripe.failRefund = false;
    expect(r).toMatchObject({ decision: "unconfirmed" });
    return r.gateRef;
  }

  it("without resubmit, reports unconfirmed and sends nothing", async () => {
    const s = setup();
    const ref = await unconfirmedNothingCreated(s);
    expect(await reconcileStripeRefund(s.stripe, ref, s.options)).toMatchObject({ state: "unconfirmed" });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("resubmits with the SAME key and identical parameters, after re-checking the payment", async () => {
    const s = setup();
    const ref = await unconfirmedNothingCreated(s);
    const out = await reconcileStripeRefund(s.stripe, ref, s.options, { resubmit: true });
    expect(out).toMatchObject({ state: "succeeded", resubmitted: true, refundId: "re_1" });
    expect(s.stripe.refunds).toEqual([
      { input: { payment_intent: "pi_1001", amount: 1899, reason: "requested_by_customer", metadata: { atlasent_gate_ref: ref, order_ref: "PPS-1001", atlasent_business_request: BR } }, key: ref },
    ]);
    expect((await s.ledger.get(ref))?.submission?.attempts).toBe(2);
    expect(s.runtime.evaluateBodies).toHaveLength(1);
  });

  it("a resubmission whose first attempt DID create the refund returns that refund (Stripe idempotency), not a second", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    const r = await s.refund("pi_1002", 1000, BR); // $129 captured, so the balance still covers it after the first
    s.stripe.loseResponseAfterCreate = false;
    s.stripe.listRefunds = async () => []; // Stripe's list has not caught up yet
    const out = await reconcileStripeRefund(s.stripe, r.gateRef, s.options, { resubmit: true });
    expect(out).toMatchObject({ state: "succeeded", resubmitted: true, refundId: "re_1" });
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("refuses to resend when the charge balance no longer covers the refund, even if the list lags", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    const r = await s.refund("pi_1001", 1899, BR); // $34.99 captured: after the lost refund only $16.00 is left
    s.stripe.loseResponseAfterCreate = false;
    s.stripe.listRefunds = async () => [];
    expect(await reconcileStripeRefund(s.stripe, r.gateRef, s.options, { resubmit: true })).toMatchObject({ state: "unconfirmed" });
    expect(s.stripe.refunds).toHaveLength(1);
  });

  it("will not resubmit after the window, or once the payment is disputed", async () => {
    const late = setup();
    const ref = await unconfirmedNothingCreated(late);
    const lateOpts = { ...late.options, now: () => new Date(NOW.getTime() + RESUBMIT_WINDOW_MS + 1) };
    expect(await reconcileStripeRefund(late.stripe, ref, lateOpts, { resubmit: true })).toMatchObject({ state: "unconfirmed" });
    expect(late.stripe.refunds).toHaveLength(0);

    const disputed = setup();
    const ref2 = await unconfirmedNothingCreated(disputed);
    disputed.stripe.pis.get("pi_1001")!.latest_charge!.disputed = true;
    expect(await reconcileStripeRefund(disputed.stripe, ref2, disputed.options, { resubmit: true })).toMatchObject({ state: "unconfirmed" });
    expect(disputed.stripe.refunds).toHaveLength(0);
  });

  it("flags a Stripe refund carrying the gate reference with another amount as a mismatch", async () => {
    const s = setup();
    const ref = await unconfirmedNothingCreated(s);
    const forged: StripeRefund = { id: "re_forged", status: "succeeded", amount: 9999, currency: "usd", charge: "ch_1001", payment_intent: "pi_1001", metadata: { atlasent_gate_ref: ref } };
    s.stripe.existingRefunds = [forged];
    expect(await reconcileStripeRefund(s.stripe, ref, s.options, { resubmit: true })).toMatchObject({ state: "mismatch" });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("reports a stopped reference that Stripe shows nothing for as not issued", async () => {
    const s = setup();
    s.stripe.failRefund = 400;
    const r = await s.refund("pi_1001", 1899, BR);
    expect(await reconcileStripeRefund(s.stripe, r.gateRef, s.options)).toMatchObject({ state: "not_issued" });
  });

  it("distinguishes provider states: pending is accepted, not completed", async () => {
    const s = setup();
    s.stripe.refundStatus = "pending";
    const r = await s.refund("pi_1001", 1899, BR);
    expect(r).toMatchObject({ refunded: true, completion: "pending" });
    expect(await reconcileStripeRefund(s.stripe, r.gateRef, s.options)).toMatchObject({ state: "pending" });
  });
});

describe("authenticated refund outcome events", () => {
  const body = (type: string, refund: StripeRefund, id = "evt_1") => JSON.stringify({ id, type, data: { object: refund } });

  it("records refund.updated / refund.failed for the gated refund, once per event", async () => {
    const s = setup();
    s.stripe.refundStatus = "pending";
    const r = await s.refund("pi_1001", 1899, BR);
    if (!r.refunded) throw new Error("expected accepted");
    const failed = { ...r.refund, status: "failed" };
    const ev = refundEventFromBody(body("refund.failed", failed, "evt_f1"))!;
    expect(await recordRefundEvent(ev, s.ledger, NOW)).toMatchObject({ recorded: true });
    await recordRefundEvent(ev, s.ledger, NOW); // redelivery
    const e = await s.ledger.get(r.gateRef);
    expect(e?.observations?.map((o) => `${o.source}:${o.status}`)).toEqual(["submission:pending", "event:failed"]);
    expect(latestProviderStatus(e!)).toBe("failed");
  });

  it("never records an outcome for a refund that does not match the authorization", async () => {
    const s = setup();
    const r = await s.refund("pi_1001", 1899, BR);
    if (!r.refunded) throw new Error("expected accepted");
    for (const refund of [{ ...r.refund, amount: 1 }, { ...r.refund, id: "re_other" }, { ...r.refund, metadata: {} }]) {
      expect((await recordRefundEvent(refundEventFromBody(body("refund.updated", refund))!, s.ledger, NOW)).recorded).toBe(false);
    }
    expect(refundEventFromBody(body("charge.succeeded", r.refund))).toBeNull();
  });

  it("an event for an unconfirmed submission confirms it and frees the payment", async () => {
    const s = setup();
    s.stripe.loseResponseAfterCreate = true;
    const r = await s.refund("pi_1001", 1899, BR);
    s.stripe.loseResponseAfterCreate = false;
    const created = (await s.stripe.listRefunds("pi_1001"))[0]!;
    await auditStripeRefund(created, s.ledger);
    expect(await recordRefundEvent(refundEventFromBody(body("refund.created", created))!, s.ledger, NOW)).toMatchObject({ recorded: true });
    expect((await s.ledger.get(r.gateRef))?.submission?.state).toBe("accepted");
    expect(await s.refund("pi_1001", 500)).toMatchObject({ refunded: true });
  });
});

describe("review findings (PR #609)", () => {
  it("a verified event that confirms the refund before a late local error is not regressed to unconfirmed", async () => {
    const s = setup();
    const original = s.stripe.createRefund.bind(s.stripe);
    s.stripe.createRefund = async (input, key) => {
      const created = await original(input, key);
      // refund.created arrives (alarm claim, then outcome) before the response is lost
      await auditStripeRefund(created, s.ledger);
      await recordRefundEvent({ eventId: "evt_early", type: "refund.created", refund: created }, s.ledger, NOW);
      throw new Error("socket hang up");
    };
    const r = await s.refund("pi_1001", 1899, BR);
    expect(r).toMatchObject({ refunded: true, completion: "succeeded" });
    expect((await s.ledger.get(r.gateRef))?.submission?.state).toBe("accepted");
  });

  it("a lifecycle event for a refund the entry does not yet account for records nothing", async () => {
    const s = setup();
    s.stripe.failRefund = true;
    const r = await s.refund("pi_1001", 1899, BR);
    const forged: StripeRefund = { id: "re_x", status: "succeeded", amount: 1899, currency: "usd", charge: "ch_1001", payment_intent: "pi_1001", metadata: { atlasent_gate_ref: r.gateRef } };
    expect((await recordRefundEvent({ eventId: "evt_x", type: "refund.updated", refund: forged }, s.ledger, NOW)).recorded).toBe(false);
    expect((await s.ledger.get(r.gateRef))?.submission?.state).toBe("unconfirmed");
  });
});

describe("explicit action binding", () => {
  it("defaults to finance.payment.authorize with the unchanged v1 digest", async () => {
    const s = setup();
    const r = await s.refund("pi_1001", 1899);
    expect(s.runtime.evaluateBodies[0]!.action_type).toBe(FINANCE_PAYMENT_AUTHORIZE);
    const v1 = computeStripeRefundDigest({ account: "acct_demo", payment_intent: "pi_1001", charge: "ch_1001", order_ref: "PPS-1001", amount_cents: 1899, currency: "USD" });
    expect(r.refunded && r.digest).toBe(v1);
  });

  it("customer.refund.issue is evaluated AND verified under that action and binds it into the digest", async () => {
    const s = setup({ actionType: CUSTOMER_REFUND_ISSUE });
    const r = await s.refund("pi_1001", 1899);
    expect(r.refunded).toBe(true);
    expect(s.runtime.evaluateBodies[0]!.action_type).toBe(CUSTOMER_REFUND_ISSUE);
    expect(JSON.stringify(s.runtime.verifyBodies[0])).toContain(CUSTOMER_REFUND_ISSUE);
    const v1 = computeStripeRefundDigest({ account: "acct_demo", payment_intent: "pi_1001", charge: "ch_1001", order_ref: "PPS-1001", amount_cents: 1899, currency: "USD" });
    expect(r.refunded && r.digest).not.toBe(v1);
  });

  it("refuses an action the adapter does not support", async () => {
    const s = setup({ actionType: "finance.wire.send" as never });
    expect(await s.refund("pi_1001", 1899)).toMatchObject({ decision: "invalid_request" });
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("an approval is only resumed under the action it was escalated for", async () => {
    const s = setup();
    const held = await s.refund("pi_1002", 7200);
    const id = !held.refunded ? held.approvalRequestId! : "";
    s.runtime.decide(id, "approved");
    const wrong = { ...s.options, actionType: CUSTOMER_REFUND_ISSUE };
    expect(await resumeApprovedStripeRefund(s.stripe, s.runtime.client, s.runtime.approvals, { approvalRequestId: id }, wrong)).toMatchObject({ decision: "invalid_request" });
    expect(s.runtime.claims).toHaveLength(0);
    expect(await resumeApprovedStripeRefund(s.stripe, s.runtime.client, s.runtime.approvals, { approvalRequestId: id }, s.options)).toMatchObject({ refunded: true });
    expect(JSON.stringify(s.runtime.verifyBodies.at(-1))).toContain(FINANCE_PAYMENT_AUTHORIZE);
  });
});
