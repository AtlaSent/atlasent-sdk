import { afterEach, beforeEach, describe, expect, it } from "vitest";

import atlasent, { AtlaSentClient, AtlaSentError } from "../src/index.js";
import { API_KEY_SIGNUP_URL } from "../src/apiKeyHint.js";
import { createEscalation } from "../src/approvalRuntime.js";
import { BCCAEClient } from "../src/bccae.js";
import { __resetSharedClientForTests } from "../src/protect.js";

// Every missing-key error tells the developer where to get a key, with a
// link attributed to this SDK.
function messageOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(AtlaSentError);
    expect((err as AtlaSentError).code).toBe("invalid_api_key");
    return (err as AtlaSentError).message;
  }
  throw new Error("expected a missing-key error");
}

describe("missing API key errors link to sign-up", () => {
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

  it("the link is the console sign-up, tagged as the TypeScript error path", () => {
    expect(API_KEY_SIGNUP_URL).toBe(
      "https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=ts-error",
    );
  });

  it("new AtlaSentClient without a key", () => {
    expect(messageOf(() => new AtlaSentClient({ apiKey: "" }))).toContain(API_KEY_SIGNUP_URL);
  });

  it("protect() with no configure() and no env var", async () => {
    let caught: unknown;
    try {
      await atlasent.protect({ agent: "a", action: "test.action", context: { environment: "production" } });
    } catch (err) {
      caught = err;
    }
    expect((caught as AtlaSentError).message).toContain(API_KEY_SIGNUP_URL);
    expect((caught as AtlaSentError).message).toMatch(/ATLASENT_API_KEY/);
  });

  it("approval runtime and BCCAE client without a key", async () => {
    const err = await createEscalation({} as never).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AtlaSentError);
    expect((err as AtlaSentError).message).toContain(API_KEY_SIGNUP_URL);
    expect(messageOf(() => new BCCAEClient({ apiKey: "" } as never))).toContain(API_KEY_SIGNUP_URL);
  });

  it("a malformed key is not told to sign up: it already has one", () => {
    const msg = messageOf(() => new AtlaSentClient({ apiKey: "not-a-key" }));
    expect(msg).not.toContain(API_KEY_SIGNUP_URL);
  });
});
