import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

import { AtlaSentClient } from "../src/index.js";
import {
  DEFAULT_FUNCTION_REGION,
  FUNCTION_REGION_ENV,
  FunctionRegionConfigError,
  functionRegionHeaders,
  resolveFunctionRegion,
} from "../src/functionRegion.js";

const HOSTED = "https://api.atlasent.io";
const HOSTED_PROD_REF = "https://kttccumlnmdtupgbyfue.supabase.co/functions/v1";
const SELF_HOSTED = "https://runtime.customer.example/functions/v1";
const SERVER = { env: {}, isBrowser: false };
const BROWSER = { env: {}, isBrowser: true };

const PERMIT = {
  permitted: true,
  decision_id: "dec_alpha",
  reason: "ok",
  audit_hash: "hash_alpha",
  timestamp: "2026-04-17T10:00:00Z",
};

function recordingFetch() {
  const calls: Array<{ url: string; headers: Record<string, string>; body: unknown }> = [];
  const impl = vi.fn(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    calls.push({
      url: typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url,
      headers: { ...(init?.headers as Record<string, string>) },
      body: init?.body,
    });
    return new Response(JSON.stringify(PERMIT), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

function client(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return new AtlaSentClient({
    apiKey: "ask_live_test",
    fetch: fetchImpl,
    retryPolicy: { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0 },
    ...extra,
  });
}

describe("resolveFunctionRegion", () => {
  it("pins the hosted runtime to us-west-1 on a server", () => {
    expect(DEFAULT_FUNCTION_REGION).toBe("us-west-1");
    expect(resolveFunctionRegion(HOSTED, undefined, SERVER)).toBe("us-west-1");
    expect(resolveFunctionRegion(HOSTED_PROD_REF, undefined, SERVER)).toBe("us-west-1");
  });

  it("does not pin a self-hosted runtime or a lookalike host by default", () => {
    expect(resolveFunctionRegion(SELF_HOSTED, undefined, SERVER)).toBeNull();
    expect(resolveFunctionRegion("https://api.atlasent.io.evil.example", undefined, SERVER)).toBeNull();
  });

  it("does not pin by default in a browser, where the header would fail CORS preflight", () => {
    expect(resolveFunctionRegion(HOSTED, undefined, BROWSER)).toBeNull();
    expect(resolveFunctionRegion(HOSTED, "us-west-1", BROWSER)).toBe("us-west-1");
  });

  it("explicit beats environment beats default; auto and null disable", () => {
    const env = { env: { [FUNCTION_REGION_ENV]: "us-east-1" }, isBrowser: false };
    expect(resolveFunctionRegion(SELF_HOSTED, undefined, env)).toBe("us-east-1");
    expect(resolveFunctionRegion(HOSTED, "eu-west-1", env)).toBe("eu-west-1");
    expect(resolveFunctionRegion(HOSTED, "auto", env)).toBeNull();
    expect(resolveFunctionRegion(HOSTED, null, env)).toBeNull();
    expect(resolveFunctionRegion(HOSTED, undefined, { env: { [FUNCTION_REGION_ENV]: "auto" }, isBrowser: false })).toBeNull();
  });

  it("throws on a malformed value", () => {
    for (const bad of ["US-WEST-1", "west", "us-west-1\r\nx-evil: 1"]) {
      expect(() => resolveFunctionRegion(HOSTED, bad, SERVER)).toThrow(FunctionRegionConfigError);
    }
  });

  it("returns no headers when unpinned", () => {
    expect(functionRegionHeaders(SELF_HOSTED, undefined, SERVER)).toEqual({});
    expect(functionRegionHeaders(HOSTED, undefined, SERVER)).toEqual({ "x-region": "us-west-1" });
  });
});

describe("AtlaSentClient region header", () => {
  const saved = process.env[FUNCTION_REGION_ENV];
  afterEach(() => {
    if (saved === undefined) delete process.env[FUNCTION_REGION_ENV];
    else process.env[FUNCTION_REGION_ENV] = saved;
  });

  it("evaluate and verifyPermit against the hosted runtime carry x-region: us-west-1", async () => {
    delete process.env[FUNCTION_REGION_ENV];
    const { impl, calls } = recordingFetch();
    const c = client(impl);
    await c.evaluate({ agent: "a", action: "b" });
    await c.verifyPermit({ permitId: "dec_alpha", agent: "a", action: "b" }).catch(() => undefined);
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const call of calls) {
      expect(call.headers["x-region"]).toBe("us-west-1");
      expect(call.headers["Authorization"]).toBe("Bearer ask_live_test");
    }
  });

  it("a self-hosted baseUrl sends no x-region and an otherwise identical request", async () => {
    delete process.env[FUNCTION_REGION_ENV];
    const a = recordingFetch();
    await client(a.impl, { baseUrl: SELF_HOSTED }).evaluate({ agent: "a", action: "b" });
    const b = recordingFetch();
    await client(b.impl, { functionRegion: "auto" }).evaluate({ agent: "a", action: "b" });
    expect(a.calls[0]!.headers["x-region"]).toBeUndefined();
    expect(b.calls[0]!.headers["x-region"]).toBeUndefined();
    expect(b.calls[0]!.body).toBe(a.calls[0]!.body);
  });

  it("functionRegion option overrides ATLASENT_FUNCTION_REGION", async () => {
    process.env[FUNCTION_REGION_ENV] = "us-east-1";
    const { impl, calls } = recordingFetch();
    await client(impl, { functionRegion: "eu-west-1" }).evaluate({ agent: "a", action: "b" });
    expect(calls[0]!.headers["x-region"]).toBe("eu-west-1");
  });

  it("a malformed functionRegion fails at construction, before any request", () => {
    const { impl } = recordingFetch();
    expect(() => client(impl, { functionRegion: "US-WEST-1" })).toThrow(FunctionRegionConfigError);
    expect(impl).not.toHaveBeenCalled();
  });
});

describe("region pinning stays centralized", () => {
  const SRC = path.resolve(__dirname, "..", "src");
  const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts"));
  // Files that fetch but never call a runtime edge function.
  const NOT_RUNTIME = new Set(["trust.ts", "trustRoot.ts"]);

  it("only functionRegion.ts writes the x-region header", () => {
    expect(files.length).toBeGreaterThan(50);
    const offenders = files.filter(
      (f) =>
        f !== "functionRegion.ts" && /["'`]x-region["'`]/i.test(fs.readFileSync(path.join(SRC, f), "utf-8")),
    );
    expect(offenders).toEqual([]);
  });

  it("every file that sends a request uses functionRegionHeaders or the client's resolved headers", () => {
    const missing = files.filter((f) => {
      if (f === "functionRegion.ts" || NOT_RUNTIME.has(f)) return false;
      const src = fs.readFileSync(path.join(SRC, f), "utf-8");
      const sends = /\bfetch\(|fetchImpl\(|\.fetch\(/.test(src);
      return sends && !/functionRegionHeaders\(|\.\.\.this\.regionHeaders/.test(src);
    });
    expect(missing).toEqual([]);
  });
});
