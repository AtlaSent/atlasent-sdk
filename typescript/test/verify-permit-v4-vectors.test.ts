/**
 * Cross-language parity: every pt.v4 vector in
 * contract/vectors/permit-v4/vectors.json was minted by atlasent-api's own
 * signPermitV4 and decoded by its own decodePermitClaimsV4
 * (contract/tools/gen_permit_v4_vectors.ts). The SDK decoder must return
 * exactly the runtime's claim bag — every key, every value — for each one.
 * python/tests/test_verify_permit_v4_vectors.py runs the same file.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PermitV4VerifyError, verifyPermitV4 } from "../src/verify-permit-v4.js";

interface VectorFile {
  public_key_b64: string;
  vectors: Array<{ name: string; token: string; expected_claims: Record<string, unknown> }>;
  negative: Array<{ name: string; token: string; expected_reason: string }>;
}

const file = JSON.parse(
  readFileSync(new URL("../../contract/vectors/permit-v4/vectors.json", import.meta.url), "utf8"),
) as VectorFile;

describe("pt.v4 runtime-generated parity vectors", () => {
  it("covers every claim key the runtime encodes (4, 6, 7, -1..-35)", () => {
    const full = file.vectors.find((v) => v.name === "full");
    expect(full).toBeDefined();
    // 38 claims: 3 CWT + 35 private keys.
    expect(Object.keys(full!.expected_claims)).toHaveLength(38);
  });

  for (const v of file.vectors) {
    it(`decodes ${v.name} exactly as the runtime does`, async () => {
      const res = await verifyPermitV4(v.token, file.public_key_b64);
      expect(res.claims).toEqual(v.expected_claims);
    });
  }

  for (const n of file.negative) {
    it(`rejects ${n.name} with ${n.expected_reason}`, async () => {
      const err = await verifyPermitV4(n.token, file.public_key_b64).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(PermitV4VerifyError);
      expect((err as PermitV4VerifyError).reason).toBe(n.expected_reason);
    });
  }
});
