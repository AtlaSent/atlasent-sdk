/**
 * `actor_identity` on the wire (atlasent-api#3915).
 *
 * The runtime requires an `actor_identity.v1` at evaluate for the mandatory
 * change-control action types, and at verify when the action class is
 * classified `verified_actor`. Both read it from the TOP LEVEL of the body.
 * The SDK forwards it unchanged and never mints or inspects it. These tests
 * assert the posted BODIES, for the reason given in
 * protect-execution-binding.test.ts: an argument-level assertion cannot see
 * whether a field reaches the wire, or where it lands.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

import { AtlaSentClient, configure, protect, protectWithEvidence } from "../src/index.js";
import { __resetSharedClientForTests } from "../src/protect.js";
import { canonicalizePayload } from "../src/payloadHash.js";

const EVALUATE_ALLOW_WIRE = {
  permitted: true,
  decision_id: "dec_ident",
  reason: "allowed",
  audit_hash: "hash_ident",
  timestamp: "2026-10-10T10:00:00Z",
};
const VERIFY_OK_WIRE = {
  verified: true,
  outcome: "verified",
  permit_hash: "permit_ident",
  timestamp: "2026-10-10T10:00:01Z",
};

const IDENTITY = {
  version: "actor_identity.v1",
  subject: { principal_id: "agent:a1", principal_kind: "agent", role: "agent" },
  binding: { action_type: "production.deploy", tenant_id: "org-1", environment: "production" },
  signature: "ab".repeat(64),
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
    return new Response(JSON.stringify(next), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

/** The i-th posted body; fails loudly instead of reading `undefined`. */
function bodyAt(captured: Captured[], i: number): Captured {
  const c = captured[i];
  if (c === undefined) throw new Error(`expected a request at index ${i}`);
  return c;
}

/** Mirrors v1-evaluate's own hash of the posted body (see protect-execution-binding). */
function serverBoundHashOf(evaluateBody: Record<string, unknown>): string {
  const { traceparent: _t, shadow: _s, explain: _e, ...core } = evaluateBody;
  return "sha256:" + createHash("sha256").update(canonicalizePayload(core), "utf8").digest("hex");
}

const REQUEST = {
  agent: "agent:a1",
  action: "production.deploy",
  context: { environment: "production", service: "api" },
};

describe("protect(): actor_identity at both boundaries", () => {
  const ORIGINAL_ENV = process.env.ATLASENT_API_KEY;
  beforeEach(() => {
    __resetSharedClientForTests();
    delete process.env.ATLASENT_API_KEY;
  });
  afterEach(() => {
    __resetSharedClientForTests();
    if (ORIGINAL_ENV !== undefined) process.env.ATLASENT_API_KEY = ORIGINAL_ENV;
    else delete process.env.ATLASENT_API_KEY;
  });

  for (const [name, run] of [
    ["protect", protect],
    ["protectWithEvidence", protectWithEvidence],
  ] as const) {
    it(`${name}: presents it top-level at evaluate and at verify, unchanged`, async () => {
      const captured: Captured[] = [];
      configure({
        apiKey: "ask_live_test",
        fetch: recordingFetch(captured, [EVALUATE_ALLOW_WIRE, VERIFY_OK_WIRE]),
      });
      await run({ ...REQUEST, actorIdentity: IDENTITY });

      const evaluate = bodyAt(captured, 0);
      const verify = bodyAt(captured, 1);
      expect(evaluate.url).toMatch(/\/v1-evaluate$/);
      expect(verify.url).toMatch(/\/v1-verify-permit$/);
      expect(evaluate.body.actor_identity).toEqual(IDENTITY);
      expect(verify.body.actor_identity).toEqual(IDENTITY);
      // Never nested, and never under its camelCase SDK name.
      expect(evaluate.body.context).not.toHaveProperty("actor_identity");
      expect(evaluate.body).not.toHaveProperty("actorIdentity");
      expect(verify.body).not.toHaveProperty("actorIdentity");
      // The fallback digest is a hash of the body that was actually posted,
      // identity included, so it still matches what the server bound.
      expect(verify.body.execution_hash).toBe(serverBoundHashOf(evaluate.body));
    });

    it(`${name}: without one, neither body carries the field`, async () => {
      const captured: Captured[] = [];
      configure({
        apiKey: "ask_live_test",
        fetch: recordingFetch(captured, [EVALUATE_ALLOW_WIRE, VERIFY_OK_WIRE]),
      });
      await run(REQUEST);
      expect(bodyAt(captured, 0).body).not.toHaveProperty("actor_identity");
      expect(bodyAt(captured, 1).body).not.toHaveProperty("actor_identity");
    });
  }
});

describe("AtlaSentClient: actor_identity on evaluate and verifyPermit", () => {
  it("evaluate sends actor_identity top-level, canonical and legacy shapes", async () => {
    const captured: Captured[] = [];
    const client = new AtlaSentClient({
      apiKey: "ask_live_test",
      fetch: recordingFetch(captured, [EVALUATE_ALLOW_WIRE, EVALUATE_ALLOW_WIRE]),
    });
    await client.evaluate({
      actor_id: "agent:a1",
      action_type: "production.deploy",
      context: {},
      actor_identity: IDENTITY,
    });
    await client.evaluate({
      agent: "agent:a1",
      action: "production.deploy",
      context: {},
      actor_identity: IDENTITY,
    } as Parameters<typeof client.evaluate>[0]);
    expect(bodyAt(captured, 0).body.actor_identity).toEqual(IDENTITY);
    expect(bodyAt(captured, 1).body.actor_identity).toEqual(IDENTITY);
  });

  it("verifyPermit sends actorIdentity as actor_identity, and nothing when absent", async () => {
    const captured: Captured[] = [];
    const client = new AtlaSentClient({
      apiKey: "ask_live_test",
      fetch: recordingFetch(captured, [VERIFY_OK_WIRE, VERIFY_OK_WIRE]),
    });
    await client.verifyPermit({ permitId: "pt.v4.x", actorIdentity: IDENTITY });
    await client.verifyPermit({ permitId: "pt.v4.x" });
    expect(bodyAt(captured, 0).body.actor_identity).toEqual(IDENTITY);
    expect(bodyAt(captured, 1).body).not.toHaveProperty("actor_identity");
  });
});
