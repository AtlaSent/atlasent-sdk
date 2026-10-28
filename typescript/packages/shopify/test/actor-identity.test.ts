/** Scripted HTTP only. No cryptographic, live broker or Shopify acceptance. */
import { describe, expect, it, vi } from "vitest";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, CUSTOMER_REFUND_ISSUE,
  type RefundActorIdentityBinding, type RefundGuardOptions } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const SHOP = "pinecone.myshopify.com";
const assertion = (id: string) => ({ schema: "actor_identity.v1", test_marker: id,
  nested: { source: "scripted-broker" } });
function setup() {
  const runtime = fakeRuntime();
  const shopify = new FakeShopify(demoOrders());
  const ledger = new InMemoryLedger();
  const options: RefundGuardOptions = { actor: "agent:refund-test", environment: "test",
    actionType: CUSTOMER_REFUND_ISSUE, ledger, shop: SHOP, now: () => NOW };
  const request = { orderId: "1001", amountCents: 1899, businessRequestId: "case-identity" };
  const run = () => guardedShopifyRefund(shopify, runtime.client, request, options);
  return { runtime, shopify, ledger, options, request, run };
}

describe("Shopify trusted-host actor identity transport", () => {
  it("gets a distinct assertion at each boundary and forwards it top-level through the real SDK", async () => {
    const s = setup();
    const bindings: RefundActorIdentityBinding[] = [];
    const records: unknown[] = [];
    s.options.onDecision = r => { records.push(r); };
    s.options.resolveActorIdentity = vi.fn(async binding => {
      expect(Object.isFrozen(binding)).toBe(true);
      bindings.push(binding);
      return assertion(binding.phase);
    });
    const result = await s.run();
    expect(result.refunded).toBe(true);
    expect(bindings).toEqual(["evaluate", "verify"].map(phase => ({ phase,
      actor: s.options.actor, actionType: CUSTOMER_REFUND_ISSUE, environment: "test",
      shop: SHOP, resourceId: "gid://shopify/Order/1001", executionHash: result.digest })));
    expect(s.runtime.evaluateBodies[0]?.actor_identity).toEqual(assertion("evaluate"));
    expect(s.runtime.verifyBodies[0]?.actor_identity).toEqual(assertion("verify"));
    expect(s.runtime.evaluateBodies[0]?.context).not.toHaveProperty("actor_identity");
    expect(s.runtime.verifyBodies[0]).not.toHaveProperty("actorIdentity");
    expect(s.shopify.refunds).toHaveLength(1);
    expect(JSON.stringify([result, await s.ledger.get(result.gateRef), records])).not.toContain("test_marker");
  });

  it("preserves legacy wire omission when no resolver is configured", async () => {
    const s = setup();
    delete s.options.actionType;
    expect((await s.run()).refunded).toBe(true);
    expect(s.runtime.evaluateBodies[0]).not.toHaveProperty("actor_identity");
    expect(s.runtime.verifyBodies[0]).not.toHaveProperty("actor_identity");
  });

  for (const phase of ["evaluate", "verify"] as const) {
    it(`stops on ${phase} broker failure without exposing its error`, async () => {
      const s = setup();
      s.options.resolveActorIdentity = async binding => {
        if (binding.phase === phase) throw new Error("sensitive-broker-response");
        return assertion(binding.phase);
      };
      const result = await s.run();
      expect(result).toMatchObject({ refunded: false, decision: "error" });
      expect(result.refunded || result.reason).toMatch(/configured identity source/);
      expect(JSON.stringify(result)).not.toContain("sensitive-broker-response");
      expect(s.runtime.evaluateBodies).toHaveLength(phase === "evaluate" ? 0 : 1);
      expect(s.runtime.verifyBodies).toHaveLength(0);
      expect(s.shopify.refunds).toHaveLength(0);
    });

    for (const [name, value] of Object.entries({ null: null, missing: undefined,
      empty: {}, array: ["assertion"], string: "assertion", erased: { token: undefined },
      toJSON: { toJSON: () => "assertion" } })) {
      it(`refuses a configured ${phase} resolver returning ${name}`, async () => {
        const s = setup();
        s.options.resolveActorIdentity = async binding =>
          (binding.phase === phase ? value : assertion(binding.phase)) as Record<string, unknown>;
        expect(await s.run()).toMatchObject({ refunded: false, decision: "error" });
        expect(s.runtime.evaluateBodies).toHaveLength(phase === "evaluate" ? 0 : 1);
        expect(s.runtime.verifyBodies).toHaveLength(0);
        expect(s.shopify.refunds).toHaveLength(0);
      });
    }
  }

  it("leaves identity authenticity and revocation decisions to the runtime and stops on refusal", async () => {
    const s = setup();
    s.options.resolveActorIdentity = async binding => assertion(binding.phase);
    const verify = vi.spyOn(s.runtime.client, "verifyPermit").mockResolvedValue({
      verified: false, consumed: false, outcome: "deny",
    } as Awaited<ReturnType<typeof s.runtime.client.verifyPermit>>);
    expect(await s.run()).toMatchObject({ refunded: false, decision: "verify_failed" });
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ actorIdentity: assertion("verify") }));
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("resolves fresh identity for the original actor when another staff member resumes", async () => {
    const s = setup();
    const seen: RefundActorIdentityBinding[] = [];
    s.options.resolveActorIdentity = async binding => { seen.push(binding); return assertion(`call-${seen.length}`); };
    const held = await guardedShopifyRefund(s.shopify, s.runtime.client,
      { ...s.request, orderId: "1002", amountCents: 7200 }, s.options);
    if (held.refunded || !held.approvalRequestId) throw new Error("expected held approval");
    const saved = await s.ledger.getPendingApproval(held.approvalRequestId);
    expect(JSON.stringify(saved)).not.toContain("test_marker");
    expect(seen).toHaveLength(1);
    s.runtime.decide(held.approvalRequestId, "approved");
    const result = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals,
      { approvalRequestId: held.approvalRequestId, resumedBy: "staff:second" },
      { ...s.options, actor: "staff:second" });
    expect(result.refunded).toBe(true);
    expect(seen[1]).toEqual({ phase: "verify", actor: "agent:refund-test", actionType: CUSTOMER_REFUND_ISSUE,
      environment: "test", shop: SHOP, resourceId: "gid://shopify/Order/1002", executionHash: held.digest });
    expect(s.runtime.verifyBodies[0]).toMatchObject({ actor_id: "agent:refund-test", actor_identity: assertion("call-2") });
    expect(s.shopify.refunds).toHaveLength(1);
  });

  it("refuses approval resume if the fresh identity source is unavailable", async () => {
    const s = setup();
    s.options.resolveActorIdentity = async binding => {
      if (binding.phase === "verify") throw new Error("broker-sensitive-error");
      return assertion("initial");
    };
    const held = await guardedShopifyRefund(s.shopify, s.runtime.client,
      { ...s.request, orderId: "1002", amountCents: 7200 }, s.options);
    if (held.refunded || !held.approvalRequestId) throw new Error("expected held approval");
    s.runtime.decide(held.approvalRequestId, "approved");
    const result = await resumeApprovedShopifyRefund(s.shopify, s.runtime.client, s.runtime.approvals,
      { approvalRequestId: held.approvalRequestId }, s.options);
    expect(result).toMatchObject({ refunded: false, decision: "error" });
    expect(JSON.stringify(result)).not.toContain("broker-sensitive-error");
    expect(s.runtime.verifyBodies).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
  });
});
