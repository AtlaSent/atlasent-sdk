/**
 * Inventory item 6 (permit-authority build list): the SDK surfaces the
 * runtime's `execution_payload_hash_accepted` on evaluate and a typed
 * `verify_error_code` on verify, so a caller can see when its digest was
 * dropped and branch on a stable code instead of the reason string.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

import {
  AtlaSentClient,
  isVerifyErrorCode,
  LEGACY_VERIFY_ERROR_CODES,
  TRANSIENT_VERIFY_ERROR_CODES,
  VERIFY_ERROR_CODES,
} from "../src/index.js";

function fetchReturning(wire: unknown) {
  return vi.fn(async () =>
    new Response(JSON.stringify(wire), { status: 200, headers: { "Content-Type": "application/json" } }),
  ) as unknown as typeof fetch;
}

const client = (wire: unknown) => new AtlaSentClient({ apiKey: "ask_live_test", fetch: fetchReturning(wire) });
const REQ = { action_type: "production.deploy", actor_id: "github:octocat", context: {} };
const ALLOW = { decision: "allow", permit_token: "pt.v4.x" };

describe("evaluate: execution_payload_hash_accepted", () => {
  it.each([true, false])("passes %s through on evaluate()", async (v) => {
    const res = await client({ ...ALLOW, execution_payload_hash_accepted: v }).evaluate(REQ);
    expect(res.execution_payload_hash_accepted).toBe(v);
  });

  it.each([true, false])("passes %s through on evaluatePreflight()", async (v) => {
    const res = await client({ ...ALLOW, execution_payload_hash_accepted: v }).evaluatePreflight(REQ);
    expect(res.evaluation.execution_payload_hash_accepted).toBe(v);
  });

  it.each([undefined, "false", 0, null])("omits it when the runtime sends %s", async (v) => {
    const res = await client({ ...ALLOW, execution_payload_hash_accepted: v }).evaluate(REQ);
    expect("execution_payload_hash_accepted" in res).toBe(false);
  });
});

describe("verifyPermit: verifyErrorCode / verifyReason", () => {
  it("reports the code and reason on a deny", async () => {
    const res = await client({
      valid: false,
      outcome: "deny",
      verify_error_code: "PAYLOAD_MISMATCH",
      reason: "execution payload hash does not match",
    }).verifyPermit({ permitId: "pt.v4.x" });
    expect(res.verified).toBe(false);
    expect(res.verifyErrorCode).toBe("PAYLOAD_MISMATCH");
    expect(isVerifyErrorCode(res.verifyErrorCode)).toBe(true);
    expect(res.verifyReason).toBe("execution payload hash does not match");
  });

  it("keeps an unknown future code as-is (open string), never coerces it", async () => {
    const res = await client({ valid: false, outcome: "deny", verify_error_code: "FUTURE_CODE" })
      .verifyPermit({ permitId: "pt.v4.x" });
    expect(res.verifyErrorCode).toBe("FUTURE_CODE");
    expect(isVerifyErrorCode(res.verifyErrorCode)).toBe(false);
    expect(res.verified).toBe(false);
  });

  it("is null on success and when absent or empty", async () => {
    expect((await client({ valid: true, outcome: "allow" }).verifyPermit({ permitId: "pt.v4.x" })).verifyErrorCode)
      .toBeNull();
    expect(
      (await client({ valid: false, outcome: "deny", verify_error_code: "" }).verifyPermit({ permitId: "pt.v4.x" }))
        .verifyErrorCode,
    ).toBeNull();
  });
});

describe("verify error-code list matches the pinned contract vector", () => {
  const pinned = JSON.parse(
    readFileSync(new URL("../../contract/vectors/verify-error-codes.json", import.meta.url), "utf8"),
  ) as { emitted: string[]; legacy_documented_only: string[]; transient: string[] };

  it("emitted, legacy and transient sets equal the vector", () => {
    expect([...VERIFY_ERROR_CODES].sort()).toEqual([...pinned.emitted].sort());
    expect([...LEGACY_VERIFY_ERROR_CODES].sort()).toEqual([...pinned.legacy_documented_only].sort());
    expect([...TRANSIENT_VERIFY_ERROR_CODES].sort()).toEqual([...pinned.transient].sort());
  });
});
