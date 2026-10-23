import { describe, expect, it } from "vitest";
import { runAcceptance, summarize, type AcceptanceDeps } from "../src/acceptance.js";
import { staticDeliveryFacts, type DeliveryFacts } from "../src/facts.js";
import { InMemoryLedger } from "../src/ledger.js";
import { delivered, FakeStripe, fakeRuntime, makePaymentIntent, NOW, type RuntimeOptions } from "./fakes.js";

function deps(rt: RuntimeOptions = {}) {
  const stripe = new FakeStripe([]);
  const runtime = fakeRuntime(rt);
  const facts: Record<string, DeliveryFacts> = {};
  let n = 0;
  const d: AcceptanceDeps = {
    stripe,
    atlasent: runtime.client,
    ledger: new InMemoryLedger(),
    runId: "t1",
    async newPayment(caseId, cents) {
      const id = `pi_acc${++n}`;
      const orderRef = `ACC-t1-${caseId}`;
      stripe.pis.set(id, makePaymentIntent({ id, orderRef, captured: cents }));
      facts[orderRef] = delivered(1);
      return id;
    },
    options: { actor: "acceptance:test", environment: "test", account: "acct_test", delivery: staticDeliveryFacts(facts), now: () => NOW },
  };
  return { d, stripe, runtime };
}

describe("refund execution acceptance runner", () => {
  it("passes every case against a correct adapter", async () => {
    const { d, stripe } = deps();
    const cases = await runAcceptance(d);
    expect(cases.map((c) => [c.id, c.verdict])).toEqual([
      ["A1", "pass"], ["A2", "pass"], ["A3", "pass"], ["A4", "pass"], ["A5", "pass"], ["A6", "pass"],
    ]);
    // One refund per business operation: A1, A4 (one of two), A5, A6.
    expect(stripe.refunds).toHaveLength(4);
  });

  it("reports blocked, never pass, when the policy does not allow", async () => {
    const { d, stripe } = deps({ forceDecision: "deny" });
    const cases = await runAcceptance(d);
    expect(summarize(cases)).toEqual({ pass: 0, fail: 0, blocked: 6, total: 6 });
    expect(stripe.refunds).toHaveLength(0);
  });

  it("reports fail when a contract breaks (a second refund for one business request)", async () => {
    const { d } = deps();
    // A defective ledger that forgets every reservation and entry.
    const ledger = d.ledger as InMemoryLedger;
    ledger.reserve = async () => ({ reserved: true });
    ledger.get = async () => undefined;
    const cases = await runAcceptance(d);
    expect(cases.find((c) => c.id === "A2")?.verdict).toBe("fail");
  });
});
