/**
 * Human-approval binding on the wire (contract/schemas/evaluate-request
 * `resource_id` + `approval`, evaluate-response `signing_hint`,
 * verify-permit-response `consumed`).
 *
 * The runtime's approval `action_hash` covers `resource_id` and the enriched
 * context, and it reads the artifact only from `body.approval.artifact`. The
 * contract declared both request fields, but `buildEvaluateBody` whitelisted
 * the body and dropped them, so no SDK caller could name the resource an
 * approval covers or deliver the approval at all. These tests assert the
 * posted BODIES, for the reason protect-execution-binding.test.ts gives.
 */

import { describe, expect, it, vi } from "vitest";

import { AtlaSentClient } from "../src/index.js";
import { buildEvaluateBody } from "../src/client.js";

const ARTIFACT = { version: "approval_artifact.v1", action_hash: "a".repeat(64), signature: "ab".repeat(32) };
const HINT = {
  assertion_type: "approval_artifact.v1",
  bind: { action_hash: "b".repeat(64), tenant_id: "org-1", environment: "production", required_role: "email_send_approver" },
};

interface Captured {
  url: string;
  body: Record<string, unknown>;
}

function recordingFetch(captured: Captured[], responses: unknown[]) {
  const queue = [...responses];
  return vi.fn(async (input: unknown, init?: RequestInit) => {
    captured.push({ url: String(input), body: JSON.parse(String(init?.body ?? "{}")) });
    const next = queue.shift();
    if (next === undefined) throw new Error("mock fetch queue exhausted");
    return new Response(JSON.stringify(next), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
}

function only(captured: Captured[]): Record<string, unknown> {
  expect(captured).toHaveLength(1);
  return captured[0]!.body;
}

describe("evaluate: resource_id and approval reach the top level of the body", () => {
  it("canonical shape", async () => {
    const captured: Captured[] = [];
    const client = new AtlaSentClient({
      apiKey: "ask_live_test",
      fetch: recordingFetch(captured, [{ decision: "deny", deny_code: "INSUFFICIENT_APPROVALS" }]),
    });
    await client.evaluate({
      action_type: "communication.external.send",
      actor_id: "agent:a1",
      context: { recipient_domain: "example.com" },
      resource_id: "c".repeat(64),
      approval: { artifact: ARTIFACT },
    });
    const body = only(captured);
    expect(body.resource_id).toBe("c".repeat(64));
    expect(body.approval).toEqual({ artifact: ARTIFACT });
    expect((body.context as Record<string, unknown>).resource_id).toBeUndefined();
    expect((body.context as Record<string, unknown>).approval).toBeUndefined();
  });

  it("legacy {agent, action} shape, which normalizeEvaluateRequest rebuilds field by field", () => {
    const body = buildEvaluateBody({
      agent: "agent:a1",
      action: "communication.external.send",
      context: {},
      resource_id: "d".repeat(64),
      approval: { approval_id: "appr-1" },
    });
    expect(body.resource_id).toBe("d".repeat(64));
    expect(body.approval).toEqual({ approval_id: "appr-1" });
  });

  it("a request without them posts neither key", () => {
    const body = buildEvaluateBody({ action_type: "x.y", actor_id: "a" });
    expect("resource_id" in body).toBe(false);
    expect("approval" in body).toBe(false);
  });
});

describe("evaluate: signingHint", () => {
  async function evaluateWith(wire: Record<string, unknown>) {
    const client = new AtlaSentClient({ apiKey: "ask_live_test", fetch: recordingFetch([], [wire]) });
    return client.evaluate({ action_type: "communication.external.send", actor_id: "agent:a1" });
  }

  it("surfaces a well-formed hint unchanged", async () => {
    const res = await evaluateWith({ decision: "deny", deny_code: "INSUFFICIENT_APPROVALS", signing_hint: HINT });
    expect(res.signingHint).toEqual(HINT);
  });

  it.each([
    ["absent", undefined],
    ["null", null],
    ["a string", "b".repeat(64)],
    ["an array", [HINT]],
    ["no assertion_type", { bind: HINT.bind }],
    ["no bind", { assertion_type: "approval_artifact.v1" }],
    ["bind is an array", { assertion_type: "approval_artifact.v1", bind: [HINT.bind] }],
    ["a short action_hash", { ...HINT, bind: { ...HINT.bind, action_hash: "b".repeat(63) } }],
    ["an uppercase action_hash", { ...HINT, bind: { ...HINT.bind, action_hash: "B".repeat(64) } }],
    ["no tenant_id", { ...HINT, bind: { action_hash: "b".repeat(64), environment: "production" } }],
    ["no environment", { ...HINT, bind: { action_hash: "b".repeat(64), tenant_id: "org-1" } }],
  ])("omits a hint that is %s", async (_label, hint) => {
    const res = await evaluateWith({ decision: "deny", deny_code: "INSUFFICIENT_APPROVALS", signing_hint: hint });
    expect("signingHint" in res).toBe(false);
  });
});

describe("verifyPermit: consumed", () => {
  async function verifyWith(wire: Record<string, unknown>) {
    const client = new AtlaSentClient({ apiKey: "ask_live_test", fetch: recordingFetch([], [wire]) });
    return client.verifyPermit({ permitId: "pt.v3.x" });
  }

  it("reports true and false as sent", async () => {
    expect((await verifyWith({ valid: true, outcome: "allow", consumed: true })).consumed).toBe(true);
    expect((await verifyWith({ valid: true, outcome: "allow", consumed: false })).consumed).toBe(false);
  });

  it("leaves it undefined when the runtime does not report a boolean", async () => {
    expect("consumed" in (await verifyWith({ valid: true, outcome: "allow" }))).toBe(false);
    expect("consumed" in (await verifyWith({ valid: true, outcome: "allow", consumed: "yes" }))).toBe(false);
  });
});
