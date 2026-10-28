import { describe, expect, it } from "vitest";
import { ApprovalsApiError, createApprovalsClient } from "../src/approvals.js";

// Response bodies copied from atlasent-api supabase/functions/v1-approvals/handler.ts
// (GET /:id, POST /:id/claim-permit) and _shared/errors.ts's envelope.
function fake(status: number, body: unknown) {
  const calls: { url: string; method: string; body: string | undefined }[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    calls.push({ url, method: String(init.method), body: init.body as string | undefined });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { calls, api: createApprovalsClient({ apiKey: "k", baseUrl: "https://rt.example/functions/v1/", fetch: fetchImpl }) };
}

describe("approvals client against the runtime's wire shapes", () => {
  it("sends only actor_identity in an explicit claim and preserves empty legacy claims", async () => {
    const c = fake(200, { claimed: true, permit_token: "pt.v3.x" });
    const identity = { version: "actor_identity.v1", signature: "test-only" };
    await c.api.claimPermit("a1", { actorIdentity: identity, actor_id: "forged", approval: "forged" } as { actorIdentity: Record<string, unknown> });
    expect(JSON.parse(c.calls[0]!.body!)).toEqual({ actor_identity: identity });
  });

  it("refuses malformed identity before sending a claim", async () => {
    for (const value of [null, [], {}, "token", { toJSON: () => null }]) {
      const c = fake(200, { claimed: true, permit_token: "pt.v3.x" });
      await expect(c.api.claimPermit("a1", { actorIdentity: value as Record<string, unknown> })).rejects.toThrow(/nonempty JSON object/);
      expect(c.calls).toHaveLength(0);
    }
  });

  it("refuses credential-bearing redirects and sanitizes transport failures", async () => {
    const requests: RequestInit[] = [];
    const c = createApprovalsClient({ apiKey: "sensitive-test-key", fetch: (async (_u, init) => {
      requests.push(init!); throw new Error("sensitive-test-key");
    }) as typeof fetch });
    await expect(c.claimPermit("a1")).rejects.toThrow("approval transport unavailable");
    expect(requests[0]?.redirect).toBe("error");
    const f = fake(500, { error: "sensitive response with spaces" });
    expect(await f.api.claimPermit("a1")).toEqual({ claimed: false, failure: "HTTP 500" });
  });

  it("polls and claims on the function path the runtime routes", async () => {
    const g = fake(200, { id: "a1", status: "approved", re_evaluation_decision: "allow" });
    expect(await g.api.getStatus("a1")).toEqual({ found: true, status: "approved", reEvaluationDecision: "allow" });
    expect(g.calls[0]).toMatchObject({ url: "https://rt.example/functions/v1/v1-approvals/a1", method: "GET" });
    const c = fake(200, { claimed: true, permit_token: "pt.v3.x", re_evaluation_decision: "allow", status: "approved" });
    // The legacy claim response carries no execution_hash_expected; the guard verifies with its own digest.
    expect(await c.api.claimPermit("a1")).toEqual({ claimed: true, permitToken: "pt.v3.x" });
    expect(c.calls[0]).toMatchObject({ url: "https://rt.example/functions/v1/v1-approvals/a1/claim-permit", method: "POST", body: "{}" });
  });

  it("an already-claimed permit is not a claim", async () => {
    expect(await fake(200, { claimed: false, permit_token: null, re_evaluation_decision: "allow", status: "approved" }).api.claimPermit("a1")).toEqual({
      claimed: false,
      failure: "not_claimed",
    });
    // A token without claimed: true is not taken either.
    expect(await fake(200, { claimed: false, permit_token: "pt.v3.x", status: "approved" }).api.claimPermit("a1")).toEqual({ claimed: false, failure: "not_claimed" });
  });

  it("a claim-time approval (needs an actor identity this package cannot mint) fails closed with the runtime's code", async () => {
    const r = await fake(400, { error: "actor_identity_required", message: "…", status: 400 }).api.claimPermit("a1");
    expect(r).toEqual({ claimed: false, failure: "actor_identity_required" });
  });

  it("names the missing approvals:read scope and the same-key rule instead of a bare 403", async () => {
    const scope = { error: "insufficient_scope", message: "Missing permission: approvals:read", status: 403 };
    await expect(fake(403, scope).api.getStatus("a1")).rejects.toThrow(/lacks approvals:read/);
    await expect(fake(403, scope).api.getStatus("a1")).rejects.toBeInstanceOf(ApprovalsApiError);
    expect(await fake(403, scope).api.claimPermit("a1")).toEqual({ claimed: false, failure: expect.stringMatching(/lacks approvals:read/) });
    const key = { error: "forbidden", message: "Permit claim requires the originating API key", status: 403 };
    expect(await fake(403, key).api.claimPermit("a1")).toEqual({ claimed: false, failure: expect.stringMatching(/only the API key that asked/) });
    expect(await fake(403, { error: "other" }).api.claimPermit("a1")).toEqual({ claimed: false, failure: "HTTP 403" });
  });

  it("a 404 is not found, any other failure throws", async () => {
    expect(await fake(404, { error: "not_found" }).api.getStatus("a1")).toEqual({ found: false });
    await expect(fake(500, { error: "db_error" }).api.getStatus("a1")).rejects.toThrow(/HTTP 500/);
  });
});

