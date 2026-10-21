import { describe, expect, it } from "vitest";
import type { ApiKeySelfResponse, EvaluateRequest, EvaluateResponse } from "@atlasent/sdk";
import { checkAtlaSent, checkShopify, checkStripe, ESCALATION_PROBE, formatChecks, POLICY_PROBES, type AtlaSentProbeClient, type Check } from "../src/preflight.js";
import { createSimulatedRuntime } from "../src/sim.js";

const self = (over: Partial<ApiKeySelfResponse> = {}): ApiKeySelfResponse => ({
  keyId: "key-1",
  orgId: "org-1",
  environment: "test",
  scopes: ["evaluate:write", "verify:execute"],
  allowedCidrs: null,
  rateLimitPerMinute: 60,
  clientIp: null,
  expiresAt: null,
  rateLimit: null,
  ...over,
});

/** keySelf from a fixture; evaluate from the demo's policy stand-in, or a forced answer. */
function client(over: Partial<ApiKeySelfResponse> = {}, force?: Partial<EvaluateResponse>) {
  const sim = createSimulatedRuntime();
  const calls: EvaluateRequest[] = [];
  const c: AtlaSentProbeClient = {
    keySelf: async () => self(over),
    evaluate: async (req) => {
      calls.push(req);
      const ev = await sim.client.evaluate(req);
      return force ? { ...ev, ...force } : ev;
    },
  };
  return { c, calls };
}

const status = (checks: Check[], name: string) => checks.find((x) => x.name.startsWith(name))?.status;

describe("checkAtlaSent", () => {
  it("passes a test key with the gate scopes, and says what it could not check", async () => {
    const { c, calls } = client();
    const checks = await checkAtlaSent(c, { environment: "test", probes: [], actor: "preflight:t" });
    expect(status(checks, "API key accepted")).toBe("pass");
    expect(status(checks, "Test key")).toBe("pass");
    expect(status(checks, "Key scopes")).toBe("pass");
    expect(status(checks, "Approval claim")).toBe("not_checked");
    expect(status(checks, "Refund policy")).toBe("not_checked");
    expect(calls).toHaveLength(0);
  });

  it("fails a live key and a key missing a scope", async () => {
    const checks = await checkAtlaSent(client({ environment: "live", scopes: ["evaluate:write"] }).c, { environment: "test", probes: [], actor: "p" });
    expect(status(checks, "Test key")).toBe("fail");
    expect(checks.find((x) => x.name === "Key scopes")?.detail).toBe("missing verify:execute");
  });

  it("does not accept bare scope names", async () => {
    const checks = await checkAtlaSent(client({ scopes: ["evaluate", "verify"] }).c, { environment: "test", probes: [], actor: "p" });
    expect(status(checks, "Key scopes")).toBe("fail");
  });

  it("stops at a rejected key", async () => {
    const c: AtlaSentProbeClient = { keySelf: async () => Promise.reject(new Error("HTTP 401")), evaluate: async () => Promise.reject(new Error("unreachable")) };
    const checks = await checkAtlaSent(c, { environment: "test", probes: POLICY_PROBES, actor: "p" });
    expect(checks).toEqual([expect.objectContaining({ name: "API key accepted", status: "fail" })]);
  });

  it("probes each rule and passes when the org carries the demo policy", async () => {
    const { c, calls } = client();
    const checks = await checkAtlaSent(c, { environment: "test", probes: [...POLICY_PROBES, ESCALATION_PROBE], actor: "preflight:t" });
    expect(checks.filter((x) => x.name.startsWith("Policy:")).map((x) => x.status)).toEqual(["pass", "pass", "pass", "pass"]);
    expect(checks.at(-1)?.detail).toMatch(/approval request sim-approval-\d+ opened\. Decline it/);
    for (const r of calls) {
      expect(r).toMatchObject({ action_type: "finance.payment.authorize", environment: "test", resource_id: "preflight-probe" });
      expect(r.execution_payload_hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("explains a small refund that routes to a manager", async () => {
    const checks = await checkAtlaSent(client({}, { decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED" }).c, { environment: "test", probes: [POLICY_PROBES[0]!], actor: "p" });
    const c = checks.find((x) => x.name.startsWith("Policy:"))!;
    expect(c.status).toBe("fail");
    expect(c.detail).toMatch(/expected allow, got escalate.*requires human or independent approval/);
  });

  it("explains a missing policy", async () => {
    const checks = await checkAtlaSent(client({}, { decision: "deny", deny_code: "NO_TEMPLATE_MATCH" }).c, { environment: "test", probes: POLICY_PROBES, actor: "p" });
    expect(checks.filter((x) => x.name.startsWith("Policy:")).every((x) => x.status === "fail")).toBe(true);
    expect(checks.find((x) => x.name.startsWith("Policy:"))?.detail).toMatch(/may not carry the demo policy/);
  });

  it("fails an escalation the gate could not resume (no approval request id)", async () => {
    const { c } = client();
    const noId: AtlaSentProbeClient = { keySelf: c.keySelf, evaluate: async (r) => {
        const { approvalRequestId: _dropped, ...rest } = await c.evaluate(r);
        return rest;
      },
    };
    const checks = await checkAtlaSent(noId, { environment: "test", probes: [ESCALATION_PROBE], actor: "p" });
    expect(checks.at(-1)).toMatchObject({ status: "fail", detail: expect.stringMatching(/no approval request id/) });
  });
});

function shopifyFetch(responses: Record<string, unknown>[]) {
  const seen: { url: string; headers: Record<string, string> }[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    seen.push({ url: String(url), headers: init?.headers as Record<string, string> });
    const next = responses.shift() ?? { errors: ["unexpected"] };
    return new Response(JSON.stringify(next), { status: 200 });
  }) as typeof fetch;
  return { f, seen };
}

describe("checkShopify", () => {
  const opts = { shop: "pinecone-demo.myshopify.com", accessToken: "shpat_x", apiVersion: "2025-10" };

  it("passes a dev store with order scopes", async () => {
    const { f, seen } = shopifyFetch([
      { data: { shop: { name: "Pinecone", myshopifyDomain: opts.shop }, currentAppInstallation: { accessScopes: [{ handle: "write_orders" }] } } },
      { data: { shop: { plan: { partnerDevelopment: true } } } },
    ]);
    const checks = await checkShopify(f, opts);
    expect(checks.map((x) => [x.name, x.status])).toEqual([
      ["Admin API token accepted", "pass"],
      ["Development store", "pass"],
      ["Access scopes", "pass"],
      ["Staff cannot refund in the admin", "not_checked"],
    ]);
    expect(seen[0]?.url).toBe("https://pinecone-demo.myshopify.com/admin/api/2025-10/graphql.json");
  });

  it("fails a real store and missing scopes", async () => {
    const { f } = shopifyFetch([
      { data: { shop: { name: "Real" }, currentAppInstallation: { accessScopes: [{ handle: "read_products" }] } } },
      { data: { shop: { plan: { partnerDevelopment: false } } } },
    ]);
    const checks = await checkShopify(f, opts);
    expect(status(checks, "Development store")).toBe("fail");
    expect(checks.find((x) => x.name === "Access scopes")?.detail).toMatch(/missing read_orders, write_orders/);
  });

  it("a plan field this API version lacks is not checked, not a token failure", async () => {
    const { f } = shopifyFetch([
      { data: { shop: { name: "P" }, currentAppInstallation: { accessScopes: [{ handle: "write_orders" }] } } },
      { errors: [{ message: "Field 'partnerDevelopment' doesn't exist" }] },
    ]);
    const checks = await checkShopify(f, opts);
    expect(status(checks, "Admin API token accepted")).toBe("pass");
    expect(status(checks, "Development store")).toBe("not_checked");
  });

  it("fails a rejected token", async () => {
    const f = (async () => new Response(JSON.stringify({ errors: "Invalid API key or access token" }), { status: 401 })) as typeof fetch;
    const checks = await checkShopify(f, opts);
    expect(checks).toEqual([expect.objectContaining({ status: "fail", detail: expect.stringMatching(/HTTP 401/) })]);
  });
});

describe("checkStripe", () => {
  const ok = (async () => new Response("{}", { status: 200 })) as typeof fetch;

  it("refuses a live key without calling Stripe", async () => {
    let called = false;
    const f = (async () => {
      called = true;
      return new Response("{}");
    }) as typeof fetch;
    for (const k of ["sk_live_x", "rk_live_x"]) {
      expect(await checkStripe(f, { secretKey: k })).toEqual([expect.objectContaining({ name: "Test-mode key", status: "fail", detail: expect.stringMatching(/live-mode key/) })]);
    }
    expect(called).toBe(false);
  });

  it("passes a restricted test key that can read PaymentIntents, and does not claim refund rights", async () => {
    const checks = await checkStripe(ok, { secretKey: "rk_test_x" });
    expect(checks.map((x) => [x.name, x.status])).toEqual([
      ["Test-mode key", "pass"],
      ["Read PaymentIntents", "pass"],
      ["Write Refunds", "not_checked"],
      ["Only the gate can refund", "not_checked"],
    ]);
  });

  it("fails a full secret key, and a key that cannot read", async () => {
    expect(status(await checkStripe(ok, { secretKey: "sk_test_x" }), "Restricted key")).toBe("fail");
    const denied = (async () => new Response("{}", { status: 403 })) as typeof fetch;
    expect(status(await checkStripe(denied, { secretKey: "rk_test_x" }), "Read PaymentIntents")).toBe("fail");
  });
});

describe("formatChecks", () => {
  it("never reports ready with a failure, and never prints a credential", async () => {
    const checks = [...(await checkStripe((async () => new Response("{}", { status: 401 })) as typeof fetch, { secretKey: "rk_test_SECRETVALUE" }))];
    const out = formatChecks(checks);
    expect(out).toMatch(/1 failure\(s\)/);
    expect(out).not.toContain("SECRETVALUE");
  });
});
