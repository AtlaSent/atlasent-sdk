/**
 * Kid-aware pt.v4 verification (reading side only). The runtime mints a
 * kid-less `{1:-8}` header today; verifiers must already accept
 * `{1:-8, 4:bstr(kid)}` and select the key by kid from a trust-root key set,
 * so the runtime can start stamping a kid without breaking SDKs in the field.
 * Vectors: contract/vectors/permit-v4/kid-vectors.json (same file as
 * python/tests/test_verify_permit_v4_kid.py).
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  PermitV4VerifyError,
  type PermitVerificationKeySet,
  verifyPermitV4,
} from "../src/index.js";

interface KidFile {
  pinned_key_b64: string;
  key_set: PermitVerificationKeySet;
  single_set: PermitVerificationKeySet;
  expected_claims: Record<string, unknown>;
  cases: Array<{ name: string; token: string; key: "pinned" | "key_set" | "single_set"; expect: string; kid?: string }>;
}

const file = JSON.parse(
  readFileSync(new URL("../../contract/vectors/permit-v4/kid-vectors.json", import.meta.url), "utf8"),
) as KidFile;

const keyFor = (k: KidFile["cases"][number]["key"]) =>
  k === "pinned" ? file.pinned_key_b64 : k === "key_set" ? file.key_set : file.single_set;

describe("kid-aware pt.v4 verification vectors", () => {
  for (const c of file.cases) {
    it(`${c.name} -> ${c.expect}`, async () => {
      if (c.expect === "ok") {
        const res = await verifyPermitV4(c.token, keyFor(c.key));
        expect(res.claims).toEqual(file.expected_claims);
        expect(res.kid).toBe(c.kid ?? null);
        if (c.key === "pinned") expect(res.verifiedWithKid).toBeNull();
        else expect(res.verifiedWithKid).toBe(c.kid ?? "permit-2026-a");
      } else {
        const err = await verifyPermitV4(c.token, keyFor(c.key)).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(PermitV4VerifyError);
        expect((err as PermitV4VerifyError).reason).toBe(c.expect);
      }
    });
  }

  it("defaultKid resolves a kid-less token against a multi-key set", async () => {
    const c = file.cases.find((x) => x.name === "no_kid_ambiguous_key_set")!;
    const res = await verifyPermitV4(c.token, file.key_set, { defaultKid: "permit-2026-a" });
    expect(res.verifiedWithKid).toBe("permit-2026-a");
  });

  it("defaultKid never overrides a kid the token names", async () => {
    const c = file.cases.find((x) => x.name === "kid_selects_key_b")!;
    const res = await verifyPermitV4(c.token, file.key_set, { defaultKid: "permit-2026-a" });
    expect(res.verifiedWithKid).toBe("permit-2026-b");
  });

  it("a flat revoked_kids list (TrustSnapshot shape) also revokes", async () => {
    const c = file.cases.find((x) => x.name === "kid_selects_key_a")!;
    const set = { ...file.key_set, revoked_kids: ["permit-2026-a"] };
    const err = await verifyPermitV4(c.token, set).catch((e: unknown) => e);
    expect((err as PermitV4VerifyError).reason).toBe("key_revoked");
  });

  it("a ledger-revoked key is not a usable fallback for a kid-less token", async () => {
    const c = file.cases.find((x) => x.name === "no_kid_single_key_set")!;
    const set = { ...file.single_set, revoked_keys: [{ kid: "permit-2026-a" }] };
    const err = await verifyPermitV4(c.token, set).catch((e: unknown) => e);
    expect((err as PermitV4VerifyError).reason).toBe("kid_required");
  });
});
