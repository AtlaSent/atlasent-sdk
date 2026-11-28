import { describe, expect, it } from "vitest";
import { acceptanceAction, checkCanonicalAcceptanceKey, validateAcceptanceScope, runAcceptance, summarize, type AcceptanceDeps } from "../src/acceptance.js";
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

  it("a permit that fails verification is a failed case, not a blocked one", async () => {
    const { d } = deps({ verifyValid: false });
    const cases = await runAcceptance(d);
    expect(cases.find((c) => c.id === "A1")?.verdict).toBe("fail");
    expect(summarize(cases).blocked).toBe(0);
  });

  it("a refund Stripe returns as requires_action is accepted, not failed", async () => {
    const { d, stripe } = deps();
    stripe.refundStatus = "requires_action";
    const cases = await runAcceptance(d);
    expect(cases.map((c) => c.verdict)).toEqual(["pass", "pass", "pass", "pass", "pass", "pass"]);
  });

  it("two simultaneous refunds that are both refused in_progress fail A4, never count as blocked", async () => {
    const { d, stripe } = deps();
    // A defective ledger that refuses every reservation as already in flight.
    const ledger = d.ledger as InMemoryLedger;
    ledger.reserve = async (r) => ({ reserved: false, conflict: "payment_in_flight", gateRef: r.gate_ref });
    const cases = await runAcceptance(d);
    expect(cases.find((c) => c.id === "A4")?.verdict).toBe("fail");
    expect(stripe.refunds).toHaveLength(0);
  });
});

describe("native acceptance scope", () => {
  it("preserves legacy compatibility and accepts only explicit canonical refund action", () => {
    expect(acceptanceAction(undefined)).toBe("finance.payment.authorize");
    expect(acceptanceAction("customer.refund.issue")).toBe("customer.refund.issue");
    expect(() => acceptanceAction("unknown")).toThrow();
  });
  it("refuses production and unexpected paths or query strings before creating payments", () => {
    const base = "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1";
    expect(() => validateAcceptanceScope(base, "test")).not.toThrow();
    for (const url of [undefined, "https://api.atlasent.io", base + "/other", base + "?x=1", base + "#x"]) {
      expect(() => validateAcceptanceScope(url, "test")).toThrow();
    }
    expect(() => validateAcceptanceScope(base, "production")).toThrow();
  });
  it("canonical mode cannot exercise a refund without shared budget admission", async () => {
    const { d, stripe } = deps();
    d.options.actionType = "customer.refund.issue";
    const cases = await runAcceptance(d);
    expect(stripe.refunds).toHaveLength(0);
    expect(summarize(cases).pass).toBe(0);
  });
  it("does not pass A1 when an extra untagged refund appears on the same payment", async () => {
    const { d, stripe } = deps();
    const original = stripe.listRefunds.bind(stripe);
    stripe.listRefunds = async (id) => {
      const rows = await original(id);
      return rows.length && id === "pi_acc1" ? [...rows, { ...rows[0]!, id: "re_unexpected", metadata: {} }] : rows;
    };
    const cases = await runAcceptance(d);
    expect(cases.find(c => c.id === "A1")?.verdict).toBe("fail");
  });
});

describe("canonical runtime key preflight", () => {
  const baseUrl = "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1";
  const expectedOrgId = "11111111-1111-4111-8111-111111111111";
  const input = {baseUrl, expectedOrgId, apiKey:"synthetic-test-key"};
  const valid = {valid:true,org_id:expectedOrgId,key_id:"test-key-id",environment:"test",scopes:["evaluate:write","verify:execute","consequential_operations:write"]};
  it("reads the exact staging key check without redirects or writes", async () => {
    await checkCanonicalAcceptanceKey(input, async (url, init) => {
      expect(String(url)).toBe(baseUrl+"/v1-api-keys/check");
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toBe("error");
      return new Response(JSON.stringify(valid));
    });
  });
  it("refuses the wrong org, production key, missing scope, malformed or unavailable response", async () => {
    for (const body of [{...valid,org_id:"22222222-2222-4222-8222-222222222222"},{...valid,environment:"live"},{...valid,scopes:["evaluate:write","verify:execute"]},{...valid,valid:false},null]) {
      await expect(checkCanonicalAcceptanceKey(input, async () => new Response(JSON.stringify(body)))).rejects.toThrow("scope could not be verified");
    }
    await expect(checkCanonicalAcceptanceKey(input, async () => new Response("unavailable",{status:503}))).rejects.toThrow("scope could not be verified");
    await expect(checkCanonicalAcceptanceKey(input, async () => {throw new Error("synthetic-secret");})).rejects.toThrow("scope could not be verified");
  });
});
