/**
 * Base-URL resolution (./src/baseUrl.ts).
 *
 * The hosted runtime's gateway answers every path outside `/functions/v1`
 * with 404 "requested path is invalid", so a base URL of bare
 * `https://api.atlasent.io` made every call from a default-constructed client
 * fail. These tests pin the default and the bare-host normalization, and that
 * nothing else is rewritten.
 */
import { describe, expect, it, vi } from "vitest";
import { AtlaSentClient } from "../src/index.js";
import {
  DEFAULT_BASE_URL,
  HOSTED_FUNCTIONS_PATH,
  resolveBaseUrl,
} from "../src/baseUrl.js";

const KEY = "ask_live_test_key_000000000000";

function allowFetch() {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
    new Response(
      JSON.stringify({
        decision: "allow",
        permit_token: "pt.v4.test",
        request_id: "req_1",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    ),
  );
}

async function evaluateUrl(baseUrl?: string): Promise<string> {
  const fetchImpl = allowFetch();
  const client = new AtlaSentClient({
    apiKey: KEY,
    fetch: fetchImpl as unknown as typeof fetch,
    functionRegion: "auto",
    ...(baseUrl !== undefined ? { baseUrl } : {}),
  });
  await client.evaluate({ action_type: "a.b", actor_id: "u" });
  return String(fetchImpl.mock.calls[0]![0]);
}

describe("DEFAULT_BASE_URL", () => {
  it("is the hosted runtime's functions root", () => {
    expect(HOSTED_FUNCTIONS_PATH).toBe("/functions/v1");
    expect(DEFAULT_BASE_URL).toBe("https://api.atlasent.io/functions/v1");
  });

  it("a default-constructed client posts to /functions/v1/v1-evaluate", async () => {
    expect(await evaluateUrl()).toBe(
      "https://api.atlasent.io/functions/v1/v1-evaluate",
    );
  });

  it("a default-constructed client verifies at /functions/v1/v1-verify-permit", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ valid: true, outcome: "allow" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const client = new AtlaSentClient({
      apiKey: KEY,
      fetch: fetchImpl as unknown as typeof fetch,
      functionRegion: "auto",
    });
    await client.verifyPermit({ permitId: "pt.v4.test" });
    expect(String((fetchImpl.mock.calls[0] as unknown[])[0])).toBe(
      "https://api.atlasent.io/functions/v1/v1-verify-permit",
    );
  });
});

describe("resolveBaseUrl()", () => {
  it.each([
    ["https://api.atlasent.io", "https://api.atlasent.io/functions/v1"],
    ["https://api.atlasent.io/", "https://api.atlasent.io/functions/v1"],
    ["https://api.atlasent.io///", "https://api.atlasent.io/functions/v1"],
    ["https://API.AtlaSent.io", "https://API.AtlaSent.io/functions/v1"],
    [
      "https://kttccumlnmdtupgbyfue.supabase.co",
      "https://kttccumlnmdtupgbyfue.supabase.co/functions/v1",
    ],
    [
      "https://lwnqpmnxpeyhpxvastku.supabase.co/",
      "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1",
    ],
  ])("appends /functions/v1 to the bare hosted host %s", (input, expected) => {
    expect(resolveBaseUrl(input)).toBe(expected);
  });

  it.each([
    // Already at the functions root, with or without a trailing slash.
    ["https://api.atlasent.io/functions/v1", "https://api.atlasent.io/functions/v1"],
    ["https://api.atlasent.io/functions/v1/", "https://api.atlasent.io/functions/v1"],
    // Any explicit path on a hosted host is the caller's choice.
    ["https://api.atlasent.io/custom", "https://api.atlasent.io/custom"],
    // Other hosts are never rewritten: self-hosted runtimes and proxies may
    // mount functions anywhere.
    ["https://atlasent.example.com", "https://atlasent.example.com"],
    ["https://other-project.supabase.co", "https://other-project.supabase.co"],
    ["https://api.atlasent.io.evil.example", "https://api.atlasent.io.evil.example"],
    ["http://localhost:54321", "http://localhost:54321"],
    // A query or fragment means the caller built something deliberate.
    ["https://api.atlasent.io/?x=1", "https://api.atlasent.io/?x=1"],
    // Unparseable: trailing slashes stripped, nothing else.
    ["not a url/", "not a url"],
  ])("leaves %s as %s", (input, expected) => {
    expect(resolveBaseUrl(input)).toBe(expected);
  });

  it("is idempotent", () => {
    const once = resolveBaseUrl("https://api.atlasent.io");
    expect(resolveBaseUrl(once)).toBe(once);
  });
});

describe("AtlaSentClient baseUrl option", () => {
  it("normalizes the bare host earlier READMEs documented as the default", async () => {
    expect(await evaluateUrl("https://api.atlasent.io")).toBe(
      "https://api.atlasent.io/functions/v1/v1-evaluate",
    );
  });

  it("uses an explicit functions root unchanged", async () => {
    expect(
      await evaluateUrl("https://kttccumlnmdtupgbyfue.supabase.co/functions/v1/"),
    ).toBe("https://kttccumlnmdtupgbyfue.supabase.co/functions/v1/v1-evaluate");
  });

  it("does not rewrite a non-hosted host", async () => {
    expect(await evaluateUrl("https://atlasent.example.com/fn")).toBe(
      "https://atlasent.example.com/fn/v1-evaluate",
    );
  });

  it("still refuses a non-https base URL before resolving it", () => {
    expect(
      () => new AtlaSentClient({ apiKey: KEY, baseUrl: "http://api.atlasent.io" }),
    ).toThrow(/https/);
  });
});
