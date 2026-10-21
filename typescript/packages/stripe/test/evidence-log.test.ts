import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { alarmRecord, appendEvidence } from "../src/evidence-log.js";
import { staticDeliveryFacts } from "../src/facts.js";
import { guardedStripeRefund } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import type { StripeRefund } from "../src/stripe.js";
import { demoPayments, FakeStripe, fakeRuntime, NOW } from "./fakes.js";

const refund = (over: Partial<StripeRefund> = {}): StripeRefund => ({
  id: "re_1",
  status: "succeeded",
  amount: 1899,
  currency: "usd",
  charge: "ch_1",
  payment_intent: "pi_1001",
  metadata: { atlasent_gate_ref: "g-1" },
  ...over,
});

describe("alarmRecord", () => {
  it("records an authorized, an unauthorized and an ignored verdict", () => {
    expect(alarmRecord({ verdict: "authorized", refundId: "re_1", paymentIntent: "pi_1001", amountCents: 1899, gateRef: "g-1" }, refund(), NOW)).toEqual({
      schema: "atlasent.refund_alarm.v1",
      at: NOW.toISOString(),
      system: "stripe",
      refund_id: "re_1",
      target: "pi_1001",
      amount_cents: 1899,
      currency: "USD",
      verdict: "authorized",
      reason: null,
      gate_ref: "g-1",
    });
    expect(alarmRecord({ verdict: "unauthorized", refundId: "re_2", paymentIntent: "pi_2", amountCents: 8500, reason: "no gate reference" }, refund(), NOW)).toMatchObject({
      verdict: "unauthorized",
      reason: "no gate reference",
      gate_ref: null,
      amount_cents: 8500,
    });
    expect(alarmRecord({ verdict: "ignored", refundId: "re_3", reason: "refund status failed" }, refund(), NOW)).toMatchObject({
      verdict: "ignored",
      target: null,
      amount_cents: null,
      gate_ref: null,
    });
  });
});

describe("appendEvidence", () => {
  it("appends one JSON line per decision, never the permit token", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "evidence-")), "log.jsonl");
    const runtime = fakeRuntime();
    const data = demoPayments();
    const stripe = new FakeStripe(data.pis);
    const options = {
      actor: "stripe-cli:t",
      environment: "test",
      ledger: new InMemoryLedger(),
      delivery: staticDeliveryFacts(data.delivery),
      account: "acct",
      now: () => NOW,
      onDecision: (r: Parameters<typeof appendEvidence>[1]) => appendEvidence(path, r),
    };
    await guardedStripeRefund(stripe, runtime.client, { paymentIntentId: "pi_1001", amountCents: 1899 }, options);
    await guardedStripeRefund(stripe, runtime.client, { paymentIntentId: "pi_1002", amountCents: 7200 }, options);
    const text = readFileSync(path, "utf8");
    const lines = text.trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.map((l) => [l.schema, l.outcome])).toEqual([
      ["atlasent.refund_decision.v1", "refunded"],
      ["atlasent.refund_decision.v1", "escalated"],
    ]);
    expect(text).not.toContain("pt.v3");
  });
});
