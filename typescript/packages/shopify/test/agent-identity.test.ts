/** Scripted broker HTTP only; this suite does not prove signatures or live authority. */
import { describe, expect, it } from "vitest";
import { createAgentActorIdentityResolver } from "../src/agent-identity.js";
import type { RefundActorIdentityBinding } from "../src/guard.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, CUSTOMER_REFUND_ISSUE } from "../src/guard.js";
import { createApprovalsClient } from "../src/approvals.js";
import { InMemoryLedger } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const AGENT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TENANT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ACTOR = `agent:${AGENT}`;
const binding: RefundActorIdentityBinding = { phase: "evaluate", actor: ACTOR,
  actionType: "customer.refund.issue", environment: "test", shop: "demo.myshopify.com",
  resourceId: "gid://shopify/Order/1001", executionHash: "a".repeat(64) };
function response() {
  const expires = new Date(NOW.getTime() + 300_000).toISOString();
  return { kind: "actor_identity.v1", actor_id: ACTOR, agent_identity_id: AGENT, expires_at: expires,
    assertion: { version: "actor_identity.v1", subject: { principal_id: ACTOR, principal_kind: "agent", role: "agent" },
      binding: { tenant_id: TENANT, action_type: "customer.refund.issue", environment: "test" } as Record<string, unknown>,
      issuer: { type: "oidc", issuer_id: "atlasent-agent-key-issuer", kid: "test-only-kid" },
      issued_at: new Date(NOW.getTime() - 60_000).toISOString(), expires_at: expires, signature: "a".repeat(128) },
  };
}
function source(make: () => Response = () => new Response(JSON.stringify(response()))) {
  const calls: { url: string; init: RequestInit }[] = [];
  const opts = { apiKey: "ask_test_sensitive", actor: ACTOR, tenantId: TENANT,
    baseUrl: "https://lwnqpmnxpeyhpxvastku.supabase.co", now: () => NOW,
    fetch: (async (url, init) => { calls.push({ url: String(url), init: init! }); return make(); }) as typeof fetch };
  return { calls, opts, resolve: createAgentActorIdentityResolver(opts) };
}

describe("existing agent-key identity broker integration", () => {
  it("composes broker, real approval transport and guard across an escalated refund", async () => {
    const runtime = fakeRuntime(), shopify = new FakeShopify(demoOrders()), ledger = new InMemoryLedger();
    let minted = 0;
    const issued: Record<string, unknown>[] = [];
    const s = source(() => {
      const r = response(); r.assertion.issuer.kid = `test-only-${++minted}`;
      issued.push(r.assertion);
      return new Response(JSON.stringify(r));
    });
    const options = { actor: ACTOR, environment: "test", actionType: CUSTOMER_REFUND_ISSUE,
      shop: "pinecone.myshopify.com", ledger, now: () => NOW, resolveActorIdentity: s.resolve };
    const held = await guardedShopifyRefund(shopify, runtime.client,
      { orderId: "1002", amountCents: 7200, businessRequestId: "case-broker" }, options);
    if (held.refunded || !held.approvalRequestId) throw new Error("expected approval");
    runtime.decide(held.approvalRequestId, "approved");
    const transport = createApprovalsClient({ apiKey: s.opts.apiKey, fetch: (async (_url, init) => {
      expect(JSON.parse(String(init?.body))).toEqual({ actor_identity: issued[1] });
      const claim = await runtime.approvals.claimPermit(held.approvalRequestId!);
      return new Response(JSON.stringify(claim.claimed ? { claimed: true, permit_token: claim.permitToken } : { claimed: false }));
    }) as typeof fetch });
    const result = await resumeApprovedShopifyRefund(shopify, runtime.client,
      { getStatus: async () => ({ found: true, status: "approved_awaiting_claim" }), claimPermit: transport.claimPermit },
      { approvalRequestId: held.approvalRequestId, resumedBy: "staff:second" }, { ...options, actor: "staff:second" });
    expect(result.refunded).toBe(true);
    expect(s.calls).toHaveLength(3);
    expect(runtime.evaluateBodies[0]?.actor_identity).toEqual(issued[0]);
    expect(runtime.verifyBodies[0]?.actor_identity).toEqual(issued[2]);
    expect(shopify.refunds).toHaveLength(1);
    expect(JSON.stringify([result, await ledger.getPendingApproval(held.approvalRequestId), await ledger.get(result.gateRef)])).not.toContain("test-only-");
  });

  it("mints fresh identity per phase, sending only the documented action/environment fields", async () => {
    const s = source();
    for (const phase of ["evaluate", "claim", "verify"] as const) expect(await s.resolve({ ...binding, phase })).toEqual(response().assertion);
    expect(s.calls).toHaveLength(3);
    for (const call of s.calls) {
      expect(call.url).toBe("https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1/v1-agent-actor-identity");
      expect(call.init).toMatchObject({ method: "POST", redirect: "error" });
      expect(JSON.parse(String(call.init.body))).toEqual({ action_type: "customer.refund.issue", environment: "test" });
      expect(call.init.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it("captures trusted configuration and refuses another actor before HTTP", async () => {
    const s = source();
    s.opts.apiKey = "changed-key"; s.opts.tenantId = "changed-tenant";
    await s.resolve(binding);
    expect(s.calls[0]!.init.headers).toMatchObject({ authorization: "Bearer ask_test_sensitive" });
    await expect(s.resolve({ ...binding, actor: "staff:other" })).rejects.toThrow(/invalid binding/);
    expect(s.calls).toHaveLength(1);
  });

  const mutations: Record<string, (r: ReturnType<typeof response>) => void> = {
    actor: r => { r.actor_id = "agent:other"; }, agent: r => { r.agent_identity_id = "other"; },
    subject: r => { r.assertion.subject.principal_id = "agent:other"; },
    human: r => { r.assertion.subject.principal_kind = "human"; },
    approver: r => { r.assertion.subject.role = "approver"; },
    tenant: r => { r.assertion.binding.tenant_id = "other-tenant"; },
    action: r => { r.assertion.binding.action_type = "finance.payment.authorize"; },
    environment: r => { r.assertion.binding.environment = "production"; },
    request_hash: r => { r.assertion.binding.request_hash = "a".repeat(64); },
    issuer: r => { r.assertion.issuer.issuer_id = "another-issuer"; },
    kid: r => { r.assertion.issuer.kid = ""; }, signature: r => { r.assertion.signature = "unsigned"; },
    expired: r => { r.assertion.expires_at = r.expires_at = NOW.toISOString(); },
    future: r => { r.assertion.issued_at = new Date(NOW.getTime() + 120_000).toISOString(); },
    long_ttl: r => { r.assertion.issued_at = new Date(NOW.getTime() - 120_000).toISOString(); },
    expiry_mismatch: r => { r.expires_at = NOW.toISOString(); },
    schema: r => { r.assertion.version = "another-version"; },
  };
  for (const [name, mutate] of Object.entries(mutations)) it(`refuses ${name} mismatch`, async () => {
    const r = response(); mutate(r);
    const s = source(() => new Response(JSON.stringify(r)));
    await expect(s.resolve(binding)).rejects.toThrow("agent identity source unavailable or returned an invalid binding");
    expect(s.calls).toHaveLength(1);
  });

  for (const status of [302, 307, 400, 401, 403, 429, 500, 503]) it(`refuses HTTP ${status} without a retry or response disclosure`, async () => {
    const s = source(() => new Response("sensitive-provider-error", { status }));
    await expect(s.resolve(binding)).rejects.toThrow("agent identity source unavailable or returned an invalid binding");
    expect(s.calls).toHaveLength(1);
  });

  it("refuses malformed and oversized bodies, and a pre-followed redirect", async () => {
    for (const make of [() => new Response("not-json"), () => new Response("x".repeat(65537)),
      () => { const r = new Response(JSON.stringify(response())); Object.defineProperty(r, "redirected", { value: true }); return r; }]) {
      await expect(source(make).resolve(binding)).rejects.toThrow(/invalid binding/);
    }
  });

  it("sanitizes thrown transport errors and validates host configuration", async () => {
    const s = source(() => { throw new Error("ask_test_sensitive"); });
    await expect(s.resolve(binding)).rejects.toThrow("agent identity source unavailable or returned an invalid binding");
    for (const over of [{ actor: "staff:1" }, { tenantId: "invalid" }, { apiKey: "" },
      { baseUrl: "http://rt.example" }, { baseUrl: "https://user:password@rt.example" },
      { baseUrl: "https://rt.example?query=secret" }, { timeoutMs: 0 }]) {
      expect(() => createAgentActorIdentityResolver({ ...s.opts, ...over })).toThrow();
    }
  });
});
