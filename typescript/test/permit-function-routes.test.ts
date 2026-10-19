// Pins the per-permit routes to the `v1-permits` function.
//
// Under the hosted functions root (`.../functions/v1`) the first path
// segment is the function name, so the slash form `/v1/permits/...`
// reaches no function. Every per-permit call must address `v1-permits`.
//
// Also pins that `verifyPermit()` (POST /v1-verify-permit, the
// execution-boundary verifier) is not deprecated, and that
// `verifyPermitById()` is documented as a lifecycle/status operation.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { AtlaSentClient } from "../src/index.js";

const ROOT = "https://api.atlasent.io/functions/v1";
// An id that needs encoding: `/` would otherwise add a path segment
// (turning the id into a verb), `?` would start a query, space is invalid.
const NASTY_ID = "pt/a b?c";
const NASTY_ENC = "pt%2Fa%20b%3Fc";

const PERMIT_ROW = {
  id: "pt_alpha",
  org_id: "org_x",
  actor_id: "agent-1",
  action_id: "ehr.write",
  status: "verified",
  issued_at: "2026-05-07T01:00:00Z",
  expires_at: "2026-05-07T01:15:00Z",
  consumed_at: null,
  revoked_at: null,
  revoked_by: null,
  revoke_reason: null,
  payload_hash: null,
  decision_id: "eval_a",
};

const VERIFY_BY_ID_WIRE = {
  valid: true,
  verification_type: "permit",
  reason: null,
  verified_at: "2026-05-07T01:00:00.214Z",
  evidence: { permit_id: "pt_alpha", status: "verified" },
  ...PERMIT_ROW,
};

function client(body: unknown) {
  const fetchImpl = vi.fn(
    async (_input: Parameters<typeof fetch>[0], _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
  );
  const c = new AtlaSentClient({
    apiKey: "ask_live_test",
    fetch: fetchImpl as unknown as typeof fetch,
    timeoutMs: 5_000,
    retryPolicy: { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0 },
  });
  const call = () => {
    const [input, init] = fetchImpl.mock.calls[0]!;
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    return { url, method: init?.method, body: init?.body };
  };
  return { c, call };
}

describe("per-permit routes address the v1-permits function", () => {
  it("getPermit → GET /v1-permits/{id} with the id encoded", async () => {
    const { c, call } = client(PERMIT_ROW);
    await c.getPermit(NASTY_ID);
    expect(call()).toMatchObject({
      url: `${ROOT}/v1-permits/${NASTY_ENC}`,
      method: "GET",
    });
  });

  it("checkPermitValid → GET /v1-permits/{id}/valid with the id encoded", async () => {
    const { c, call } = client({ valid: true, status: "active" });
    await c.checkPermitValid(NASTY_ID);
    expect(call()).toMatchObject({
      url: `${ROOT}/v1-permits/${NASTY_ENC}/valid`,
      method: "GET",
    });
  });

  it("verifyPermitById → POST /v1-permits/{id}/verify with the id encoded and an empty body", async () => {
    const { c, call } = client(VERIFY_BY_ID_WIRE);
    await c.verifyPermitById(NASTY_ID);
    const got = call();
    expect(got).toMatchObject({
      url: `${ROOT}/v1-permits/${NASTY_ENC}/verify`,
      method: "POST",
    });
    expect(JSON.parse(String(got.body))).toEqual({});
  });

  it("revokePermitById → POST /v1-permits/{id}/revoke with the id encoded and an unchanged body", async () => {
    const { c, call } = client({ ...PERMIT_ROW, status: "revoked" });
    await c.revokePermitById(NASTY_ID, { reason: "superseded" });
    const got = call();
    expect(got).toMatchObject({
      url: `${ROOT}/v1-permits/${NASTY_ENC}/revoke`,
      method: "POST",
    });
    expect(JSON.parse(String(got.body))).toEqual({ reason: "superseded" });
  });

  it("listPermits → GET /v1-permits (no id segment)", async () => {
    const { c, call } = client({ permits: [PERMIT_ROW], total: 1 });
    await c.listPermits({ status: "verified" });
    const u = new URL(call().url);
    expect(u.pathname).toBe("/functions/v1/v1-permits");
    expect(u.searchParams.get("status")).toBe("verified");
    expect(call().method).toBe("GET");
  });

  it("never emits the slash form /v1/permits on any per-permit call", async () => {
    const urls: string[] = [];
    for (const [body, run] of [
      [PERMIT_ROW, (c: AtlaSentClient) => c.getPermit("p1")],
      [{ valid: true, status: "active" }, (c: AtlaSentClient) => c.checkPermitValid("p1")],
      [VERIFY_BY_ID_WIRE, (c: AtlaSentClient) => c.verifyPermitById("p1")],
      [PERMIT_ROW, (c: AtlaSentClient) => c.revokePermitById("p1")],
      [{ permits: [] }, (c: AtlaSentClient) => c.listPermits()],
    ] as const) {
      const { c, call } = client(body);
      await run(c);
      urls.push(call().url);
    }
    for (const url of urls) {
      expect(url).not.toContain("/v1/permits");
      expect(new URL(url).pathname.startsWith("/functions/v1/v1-permits")).toBe(true);
    }
  });

  it("verifyPermit stays on the execution-boundary verifier POST /v1-verify-permit", async () => {
    const { c, call } = client({
      verified: true,
      outcome: "verified",
      permit_hash: "h",
      timestamp: "t",
    });
    await c.verifyPermit({ permitId: "pt.v4.x" });
    expect(call()).toMatchObject({ url: `${ROOT}/v1-verify-permit`, method: "POST" });
  });
});

describe("verifyPermit is not deprecated; verifyPermitById is a lifecycle op", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(here, "..", "src", "client.ts"), "utf8");
  const types = readFileSync(join(here, "..", "src", "types.ts"), "utf8");

  // JSDoc block immediately preceding a declaration.
  function docFor(text: string, decl: string): string {
    const at = text.indexOf(decl);
    expect(at, `declaration not found: ${decl}`).toBeGreaterThan(-1);
    const end = text.lastIndexOf("*/", at);
    const start = text.lastIndexOf("/**", end);
    return text.slice(start, end + 2);
  }

  it("verifyPermit() carries no @deprecated tag", () => {
    expect(docFor(src, "async verifyPermit(")).not.toMatch(/@deprecated/);
  });

  it("VerifyPermitResponse carries no @deprecated tag", () => {
    expect(docFor(types, "export interface VerifyPermitResponse")).not.toMatch(
      /@deprecated/,
    );
  });

  it("verifyPermitById() is documented as lifecycle/status and points to verifyPermit", () => {
    const doc = docFor(src, "async verifyPermitById(");
    expect(doc).toMatch(/lifecycle\/status operation/);
    expect(doc).toMatch(/not\*\* the execution-boundary/);
    expect(doc).toMatch(/\{@link verifyPermit\}/);
  });
});
