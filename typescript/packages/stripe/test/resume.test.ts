/**
 * Resuming an escalated Stripe refund after a manager decides it.
 * The fake runtime creates an approval request for every escalate; tests
 * play the person deciding it with `decide(id, status)`.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { RefundDecisionRecord } from "../src/decision-record.js";
import { staticDeliveryFacts } from "../src/facts.js";
import { guardedStripeRefund, resumeApprovedStripeRefund, type StripeRefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger, JsonFileLedger } from "../src/ledger.js";
import { auditStripeRefund } from "../src/webhook.js";
import { demoPayments, FakeStripe, fakeRuntime, NOW } from "./fakes.js";

function setup(rt: Parameters<typeof fakeRuntime>[0] = {}) {
  const runtime = fakeRuntime(rt);
  const data = demoPayments();
  const stripe = new FakeStripe(data.pis);
  const ledger = new InMemoryLedger();
  const records: RefundDecisionRecord[] = [];
  const options: StripeRefundGuardOptions = {
    actor: "support-tool:dana",
    environment: "test",
    ledger,
    delivery: staticDeliveryFacts(data.delivery),
    account: "acct_demo",
    now: () => NOW,
    onDecision: (r) => void records.push(r),
  };
  const escalate = async () => {
    const r = await guardedStripeRefund(stripe, runtime.client, { paymentIntentId: "pi_1002", amountCents: 7200, reason: "wrong size" }, options);
    if (r.refunded || r.approvalRequestId === undefined) throw new Error("expected an escalation with an approval id");
    return r.approvalRequestId;
  };
  const resume = (approvalRequestId: string, opts: Partial<StripeRefundGuardOptions> = {}) =>
    resumeApprovedStripeRefund(stripe, runtime.client, runtime.approvals, { approvalRequestId, resumedBy: "support-lead:sam" }, { ...options, ...opts });
  return { runtime, stripe, ledger, records, options, escalate, resume };
}

describe("escalation saves the frozen refund", () => {
  it("returns the approval id and records it as pending", async () => {
    const s = setup();
    const id = await s.escalate();
    const p = await s.ledger.getPendingApproval(id);
    expect(p).toMatchObject({ approval_request_id: id, payment_intent: "pi_1002", amount_cents: 7200, actor_id: "support-tool:dana", reason: "wrong size" });
    expect(p?.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(s.records[0]).toMatchObject({ outcome: "escalated", approval_request_id: id });
  });
});

describe("resumeApprovedStripeRefund", () => {
  it("while pending: holds, claims nothing, refunds nothing", async () => {
    const s = setup();
    const id = await s.escalate();
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "hold", approvalRequestId: id });
    expect(s.runtime.claims).toHaveLength(0);
    expect(s.stripe.refunds).toHaveLength(0);
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
    expect(s.runtime.verifyBodies.at(-1)).toMatchObject({ actor_id: "support-tool:dana", execution_hash: pending!.digest });
    expect(s.stripe.refunds).toEqual([
      {
        input: {
          payment_intent: "pi_1002",
          amount: 7200,
          reason: "requested_by_customer",
          metadata: { atlasent_gate_ref: r.gateRef, order_ref: "PPS-1002", atlasent_approval: id, atlasent_reason: "wrong size" },
        },
        key: r.gateRef,
      },
    ]);
    expect(r.gateRef).toBe(pending!.gate_ref);
    expect(pending?.resolved).toMatchObject({ outcome: "refunded", detail: r.refund.id });
    expect(s.records.at(-1)).toMatchObject({
      outcome: "refunded",
      decision: "allow_after_approval",
      reason: "approved by a manager (resumed by support-lead:sam)",
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
    expect((await auditStripeRefund(r.refund, s.ledger)).verdict).toBe("authorized");
  });

  it("cannot be resumed twice", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect((await s.resume(id)).refunded).toBe(true);
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "invalid_request", reason: expect.stringMatching(/already resolved/) });
    expect(s.stripe.refunds).toHaveLength(1);
  });

  for (const status of ["denied", "expired", "revoked"]) {
    it(`${status}: closes with no claim and no refund`, async () => {
      const s = setup();
      const id = await s.escalate();
      s.runtime.decide(id, status);
      expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "deny", denyCode: `APPROVAL_${status.toUpperCase()}` });
      expect(s.runtime.claims).toHaveLength(0);
      expect(s.stripe.refunds).toHaveLength(0);
      expect((await s.ledger.getPendingApproval(id))?.resolved?.outcome).toBe("not_approved");
      expect(s.records.at(-1)).toMatchObject({ outcome: "denied", decision: "approval_not_granted", approval_request_id: id });
      expect(s.records.at(-1)).toMatchObject({ order_ref: "PPS-1002", amount_cents: 7200 });
      expect(s.records.at(-1)?.currency).toBeTruthy();
    });
  }

  it("refuses an approval this gate did not escalate", async () => {
    const s = setup();
    expect(await s.resume("apr-unknown")).toMatchObject({ refunded: false, decision: "invalid_request" });
    expect(s.runtime.claims).toHaveLength(0);
  });

  it("refuses an approval escalated for another Stripe account", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect(await s.resume(id, { account: "acct_other" })).toMatchObject({ refunded: false, reason: expect.stringMatching(/different Stripe account/) });
    expect(s.runtime.claims).toHaveLength(0);
  });

  it("a payment disputed since the escalation is not claimed or refunded", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.stripe.pis.get("pi_1002")!.latest_charge!.disputed = true;
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "payment_changed" });
    expect(s.runtime.claims).toHaveLength(0);
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("a payment refunded elsewhere since the escalation is not claimed or refunded", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.stripe.pis.get("pi_1002")!.latest_charge!.amount_refunded = 10_000;
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "payment_changed" });
    expect(s.runtime.claims).toHaveLength(0);
  });

  it("a permit bound to a different refund is not used", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.runtime.claimFaults.boundTo = "0".repeat(64);
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/different refund/) });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("an approved permit that is not reported consumed refunds nothing", async () => {
    const s = setup({ consumed: false });
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/not reported consumed/) });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("verifies as the actor who requested the refund, whoever resumes it", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    await s.resume(id, { actor: "someone-else" });
    expect(s.runtime.verifyBodies.at(-1)).toMatchObject({ actor_id: "support-tool:dana" });
  });

  it("a failed claim refunds nothing", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.runtime.claimFaults.failure = "already_claimed";
    expect(await s.resume(id)).toMatchObject({ refunded: false, decision: "verify_failed", reason: expect.stringMatching(/already_claimed/) });
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("a dispute opened between verify and refund cancels the ledger entry", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    const before = s.stripe.reads;
    s.stripe.onRead = (n, fake) => {
      if (n === before + 1) fake.pis.get("pi_1002")!.latest_charge!.disputed = true;
    };
    const r = await s.resume(id);
    expect(r).toMatchObject({ refunded: false, decision: "payment_changed" });
    expect((await s.ledger.get(r.gateRef))?.aborted_reason).toBe("payment_changed");
    expect(s.stripe.refunds).toHaveLength(0);
  });

  it("a Stripe refund failure cancels the ledger entry", async () => {
    const s = setup();
    const id = await s.escalate();
    s.runtime.decide(id, "approved");
    s.stripe.failRefund = true;
    const r = await s.resume(id);
    expect(r).toMatchObject({ refunded: false, decision: "error" });
    expect((await s.ledger.get(r.gateRef))?.aborted_reason).toBe("error");
  });

  it("pending approvals survive a restart (JSON file ledger)", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "ledger-")), "ledger.json");
    const s = setup();
    const opts = { ...s.options, ledger: new JsonFileLedger(path) };
    const r = await guardedStripeRefund(s.stripe, s.runtime.client, { paymentIntentId: "pi_1002", amountCents: 7200 }, opts);
    const id = (r as { approvalRequestId: string }).approvalRequestId;
    s.runtime.decide(id, "approved");
    const resumed = await resumeApprovedStripeRefund(s.stripe, s.runtime.client, s.runtime.approvals, { approvalRequestId: id }, { ...s.options, ledger: new JsonFileLedger(path) });
    expect(resumed.refunded).toBe(true);
  });
});
