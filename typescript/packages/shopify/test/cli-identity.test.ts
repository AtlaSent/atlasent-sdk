/** Real CLI/guard/SDK with scripted broker/runtime and fake Shopify; no live authority. */
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refundCliIdentity } from "../src/cli-identity.js";
import { runRefundCli } from "../src/cli.js";
import { runSupportAgentCli } from "../src/agent-cli.js";
import { JsonFileLedger } from "../src/ledger.js";
import { demoOrders, FakeShopify, NOW } from "./fakes.js";

const mocks = vi.hoisted(() => ({ admin: vi.fn(), question: vi.fn(), close: vi.fn(), model: vi.fn() }));
vi.mock("../src/admin.js", async original => ({ ...await original<typeof import("../src/admin.js")>(), createAdminClient: mocks.admin }));
vi.mock("node:readline/promises", () => ({ createInterface: () => ({ question: mocks.question, close: mocks.close }) }));
vi.mock("@anthropic-ai/sdk", () => ({ default: class { beta = { messages: { create: mocks.model } }; } }));

const AGENT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TENANT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ACTOR = `agent:${AGENT}`;
type Body = Record<string, any>;
let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "atlasent-cli-identity-"));
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(NOW);
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  mocks.admin.mockReset(); mocks.question.mockReset(); mocks.close.mockReset(); mocks.model.mockReset();
});
afterEach(async () => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); await rm(dir, { recursive: true, force: true }); });

function setup() {
  const shopify = new FakeShopify(demoOrders()); mocks.admin.mockReturnValue(shopify);
  // The real Admin client accepts numeric order ids as well as GraphQL ids.
  const getOrder = shopify.getOrder.bind(shopify);
  vi.spyOn(shopify, "getOrder").mockImplementation((id, options) =>
    getOrder(id.startsWith("gid://") ? id : `gid://shopify/Order/${id}`, options));
  const config: Record<string, string | undefined> = {
    SHOPIFY_SHOP: "pinecone.myshopify.com", SHOPIFY_ADMIN_TOKEN: "test-only-admin",
    ATLASENT_API_KEY: "ask_test_fake", ATLASENT_BASE_URL: "https://runtime.test",
    ATLASENT_ENVIRONMENT: "test", ATLASENT_REFUND_ACTION_TYPE: "customer.refund.issue",
    ATLASENT_ACTOR_IDENTITY: "agent-key", ATLASENT_ACTOR: ACTOR, ATLASENT_TENANT_ID: TENANT,
    LEDGER_PATH: join(dir, "ledger.json"), EVIDENCE_LOG: join(dir, "evidence.jsonl"),
    CUSTOMER_EMAIL: "robin@example.com", SUPPORT_CASE_ID: "case-agent", USER: "operator",
  };
  const calls: { path: string; body: Body; init: RequestInit }[] = [];
  let minted = 0, digest: string, actor: string;
  const state = { brokerStatus: 200, wrongTenant: false, approvalStatus: "approved_awaiting_claim", claimStatus: 200, verifyValid: true };
  const brokerAssertion = (body: Body) => ({ version: "actor_identity.v1",
    subject: { principal_id: ACTOR, principal_kind: "agent", role: "agent" },
    binding: { tenant_id: state.wrongTenant ? "other-tenant" : TENANT, action_type: body.action_type, environment: body.environment },
    issuer: { type: "oidc", issuer_id: "atlasent-agent-key-issuer", kid: `test-only-${++minted}` },
    issued_at: NOW.toISOString(), expires_at: new Date(NOW.getTime() + 300_000).toISOString(), signature: "a".repeat(128) });
  vi.stubGlobal("fetch", (async (url, init = {}) => {
    const path = new URL(String(url)).pathname, body = JSON.parse(String(init.body ?? "{}"));
    calls.push({ path, body, init });
    let data: Body; let status = 200;
    if (path.endsWith("/v1-agent-actor-identity")) {
      status = state.brokerStatus;
      const assertion = brokerAssertion(body);
      data = status === 200 ? { kind: "actor_identity.v1", actor_id: ACTOR, agent_identity_id: AGENT, expires_at: assertion.expires_at, assertion } : { error: "sensitive-broker-error" };
    } else if (path.endsWith("/v1-evaluate")) {
      digest = body.execution_payload_hash; actor = body.actor_id;
      data = body.context.amount_cents >= 5000
        ? { decision: "escalate", approval_request_id: "apr-cli", audit_hash: "audit-test" }
        : { decision: "allow", permit_token: "pt.v3.test-only", audit_hash: "audit-test" };
    } else if (path.endsWith("/v1-approvals/apr-cli")) data = { status: state.approvalStatus };
    else if (path.endsWith("/claim-permit")) {
      status = state.claimStatus;
      data = status === 200 ? { claimed: true, permit_token: "pt.v3.test-only", execution_hash_expected: digest } : { error: "policy_changed" };
    } else if (path.endsWith("/v1-verify-permit")) {
      expect(body.actor_id).toBe(actor);
      expect(body.payload_hash ?? body.execution_hash).toBe(digest);
      data = { valid: state.verifyValid, consumed: state.verifyValid, outcome: state.verifyValid ? "allow" : "deny" };
    } else throw new Error(`unexpected test request ${path}`);
    return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch);
  const callsFor = (ending: string) => calls.filter(c => c.path.endsWith(ending));
  const refund = (order = "1001", amount = "18.99") => runRefundCli(["refund", "--order", order, "--amount", amount, "--request-id", "case-cli"], config);
  const resume = () => runRefundCli(["resume", "--approval", "apr-cli"], config);
  return { config, shopify, state, calls, callsFor, refund, resume };
}

describe("explicit CLI agent-key identity", () => {
  it("preserves legacy actors when broker mode is absent", () => {
    expect(refundCliIdentity({ ATLASENT_ACTOR: ACTOR }, "ask_test_fake", "legacy:operator")).toEqual({ actor: "legacy:operator" });
  });

  for (const [name, change] of Object.entries({
    mode: { ATLASENT_ACTOR_IDENTITY: "disabled" }, empty_mode: { ATLASENT_ACTOR_IDENTITY: "" },
    partial: { ATLASENT_ACTOR_IDENTITY: undefined }, actor: { ATLASENT_ACTOR: "shopify-staff:42" },
    missing_actor: { ATLASENT_ACTOR: undefined }, missing_tenant: { ATLASENT_TENANT_ID: undefined },
    tenant: { ATLASENT_TENANT_ID: "not-a-tenant" }, http: { ATLASENT_BASE_URL: "http://runtime.test" },
  })) it(`refuses ${name} configuration before any source or runtime call`, async () => {
    const s = setup(); Object.assign(s.config, change);
    await expect(s.refund()).rejects.toThrow();
    expect(s.calls).toHaveLength(0); expect(s.shopify.reads).toBe(0); expect(s.shopify.refunds).toHaveLength(0);
  });

  it("carries distinct fresh assertions through initial CLI evaluation and verification", async () => {
    const s = setup(); expect(await s.refund()).toBe(0);
    const ev = s.callsFor("/v1-evaluate")[0]!.body, verify = s.callsFor("/v1-verify-permit")[0]!.body;
    expect(ev.actor_id).toBe(ACTOR); expect(verify.actor_id).toBe(ACTOR);
    expect(ev.actor_identity.issuer.kid).toBe("test-only-1"); expect(verify.actor_identity.issuer.kid).toBe("test-only-2");
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(2);
    expect(s.shopify.refunds).toHaveLength(1);
    const saved = await readFile(s.config.LEDGER_PATH!, "utf8") + await readFile(s.config.EVIDENCE_LOG!, "utf8");
    const output = JSON.stringify(vi.mocked(console.log).mock.calls);
    for (const value of ["test-only-1", "test-only-2", "ask_test_fake", "pt.v3.test-only", "a".repeat(128)]) {
      expect(saved).not.toContain(value); expect(output).not.toContain(value);
    }
  });

  for (const fault of ["403", "503", "wrong-tenant"] as const) it(`stops initial refund on broker ${fault}`, async () => {
    const s = setup(); if (fault === "wrong-tenant") s.state.wrongTenant = true; else s.state.brokerStatus = Number(fault);
    expect(await s.refund()).toBe(1);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(1);
    expect(s.callsFor("/v1-evaluate")).toHaveLength(0); expect(s.callsFor("/v1-verify-permit")).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
    expect(JSON.stringify(vi.mocked(console.log).mock.calls)).not.toContain("sensitive-broker-error");
  });

  it("keeps a failed claim source resumable and later mints separate claim and verify identities", async () => {
    const s = setup(); expect(await s.refund("1002", "72.00")).toBe(1);
    s.state.brokerStatus = 503;
    expect(await s.resume()).toBe(1); expect(s.callsFor("/claim-permit")).toHaveLength(0);
    expect((await new JsonFileLedger(s.config.LEDGER_PATH!).getPendingApproval("apr-cli"))?.resolved).toBeUndefined();
    s.state.brokerStatus = 200;
    expect(await s.resume()).toBe(0);
    expect(s.callsFor("/claim-permit")[0]!.body.actor_identity.issuer.kid).toBe("test-only-3");
    expect(s.callsFor("/v1-verify-permit")[0]!.body.actor_identity.issuer.kid).toBe("test-only-4");
    expect(s.shopify.refunds).toHaveLength(1);
  });

  it("cannot resume the original approval using another configured agent", async () => {
    const s = setup(); await s.refund("1002", "72.00");
    s.config.ATLASENT_ACTOR = `agent:cccccccc-cccc-4ccc-8ccc-cccccccccccc`;
    expect(await s.resume()).toBe(1);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(1);
    expect(s.callsFor("/claim-permit")).toHaveLength(0); expect(s.shopify.refunds).toHaveLength(0);
  });

  it("still refuses runtime claim reevaluation or permit verification after a successful broker call", async () => {
    for (const phase of ["claim", "verify"]) {
      const s = setup(); await s.refund("1002", "72.00");
      if (phase === "claim") s.state.claimStatus = 409; else s.state.verifyValid = false;
      expect(await s.resume()).toBe(1); expect(s.shopify.refunds).toHaveLength(0);
      await rm(s.config.LEDGER_PATH!, { force: true });
    }
  });

  it("keeps facts and reconciliation read-only without broker configuration or runtime credentials", async () => {
    const s = setup(); await s.refund();
    const output = JSON.parse(String(vi.mocked(console.log).mock.calls.at(-1)![0]));
    s.calls.length = 0; s.config.ATLASENT_API_KEY = undefined; s.config.ATLASENT_ACTOR_IDENTITY = "bad-mode";
    expect(await runRefundCli(["facts", "--order", "1001"], s.config)).toBe(0);
    expect(await runRefundCli(["reconcile", "--gate-ref", output.gateRef], s.config)).toBe(0);
    expect(s.calls).toHaveLength(0); expect(s.shopify.refunds).toHaveLength(1);
  });

  it("preserves CLI legacy wire omission without broker mode", async () => {
    const s = setup(); delete s.config.ATLASENT_ACTOR_IDENTITY; delete s.config.ATLASENT_TENANT_ID;
    s.config.ATLASENT_ACTOR = "legacy:operator";
    expect(await s.refund()).toBe(0);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(0);
    expect(s.callsFor("/v1-evaluate")[0]!.body).toMatchObject({ actor_id: "legacy:operator" });
    expect(s.callsFor("/v1-evaluate")[0]!.body).not.toHaveProperty("actor_identity");
  });

  it("wires broker identity into the terminal agent while model identity fields are ignored", async () => {
    const s = setup(); const stop = new Error("test-terminal-closed");
    mocks.question.mockResolvedValueOnce("refund my order").mockRejectedValueOnce(stop);
    mocks.model.mockResolvedValueOnce({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "tool-test", name: "issue_refund", input: {
      order_id: "1001", amount: "18.99", reason: "torn", actor: "forged:human", actor_identity: { role: "approver" },
    } }] }).mockResolvedValueOnce({ stop_reason: "end_turn", content: [{ type: "text", text: "Refund result received." }] });
    await expect(runSupportAgentCli(s.config)).rejects.toBe(stop);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(2);
    expect(s.callsFor("/v1-evaluate")[0]!.body.actor_id).toBe(ACTOR);
    expect(s.callsFor("/v1-evaluate")[0]!.body.actor_identity.subject.role).toBe("agent");
    expect(s.shopify.refunds).toHaveLength(1); expect(mocks.close).toHaveBeenCalledOnce();
  });

  it("rejects terminal agent misconfiguration before opening a session or calling the model", async () => {
    const s = setup(); s.config.ATLASENT_ACTOR = "agent:pinecone-support";
    await expect(runSupportAgentCli(s.config)).rejects.toThrow();
    expect(mocks.question).not.toHaveBeenCalled(); expect(mocks.model).not.toHaveBeenCalled(); expect(s.calls).toHaveLength(0);
  });

  it("does not let the terminal agent bypass an unavailable broker", async () => {
    const s = setup(); s.state.brokerStatus = 503; const stop = new Error("test-terminal-closed");
    mocks.question.mockResolvedValueOnce("refund").mockRejectedValueOnce(stop);
    mocks.model.mockResolvedValueOnce({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "tool-test", name: "issue_refund",
      input: { order_id: "1001", amount: "18.99", reason: "torn" } }] })
      .mockResolvedValueOnce({ stop_reason: "end_turn", content: [{ type: "text", text: "The request was blocked." }] });
    await expect(runSupportAgentCli(s.config)).rejects.toBe(stop);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(1);
    expect(s.callsFor("/v1-evaluate")).toHaveLength(0); expect(s.shopify.refunds).toHaveLength(0);
    expect(JSON.stringify(mocks.model.mock.calls)).not.toContain("sensitive-broker-error");
    expect(JSON.stringify(mocks.model.mock.calls)).not.toContain("ask_test_fake");
  });

  it("retains the terminal demo's legacy actor without explicit broker mode", async () => {
    const s = setup(); delete s.config.ATLASENT_ACTOR_IDENTITY; delete s.config.ATLASENT_TENANT_ID;
    const stop = new Error("test-terminal-closed");
    mocks.question.mockResolvedValueOnce("refund").mockRejectedValueOnce(stop);
    mocks.model.mockResolvedValueOnce({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "tool-test", name: "issue_refund",
      input: { order_id: "1001", amount: "18.99", reason: "torn" } }] })
      .mockResolvedValueOnce({ stop_reason: "end_turn", content: [{ type: "text", text: "Result received." }] });
    await expect(runSupportAgentCli(s.config)).rejects.toBe(stop);
    expect(s.callsFor("/v1-agent-actor-identity")).toHaveLength(0);
    expect(s.callsFor("/v1-evaluate")[0]!.body.actor_id).toBe("agent:pinecone-support");
    expect(s.callsFor("/v1-evaluate")[0]!.body).not.toHaveProperty("actor_identity");
    expect(s.shopify.refunds).toHaveLength(1);
  });
});
