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
import { DEFAULT_TRUST_TTL_MS, type TrustSnapshot } from "../src/trust.js";
import { TRUST_SNAPSHOT_MAX_AGE_MS } from "../src/verify-permit-v4.js";

interface KidFile {
  pinned_key_b64: string;
  key_set: PermitVerificationKeySet;
  single_set: PermitVerificationKeySet;
  rotation_set: PermitVerificationKeySet;
  expired_set: PermitVerificationKeySet;
  alias_set: PermitVerificationKeySet;
  roleless_alias_set: PermitVerificationKeySet;
  expected_claims: Record<string, unknown>;
  cases: Array<{ name: string; token: string; key: "pinned" | "key_set" | "single_set" | "rotation_set" | "expired_set" | "alias_set" | "roleless_alias_set"; expect: string; kid?: string }>;
}

const file = JSON.parse(
  readFileSync(new URL("../../contract/vectors/permit-v4/kid-vectors.json", import.meta.url), "utf8"),
) as KidFile;

const keyFor = (k: KidFile["cases"][number]["key"]) =>
  k === "pinned" ? file.pinned_key_b64 : file[k];

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

  it("a TrustSnapshot older than the age limit is refused even with a later expires_at", async () => {
    const c = file.cases.find((x) => x.name === "kid_selects_key_a")!;
    const now = Date.now();
    // Typed as the SDK's own TrustSnapshot: it must be accepted without a cast.
    const snap: TrustSnapshot = {
      keys: file.key_set.keys as unknown as TrustSnapshot["keys"],
      revoked_kids: [],
      fetched_at: now - TRUST_SNAPSHOT_MAX_AGE_MS - 60_000,
      expires_at: now + 60 * 60 * 1000,
    };
    const err = await verifyPermitV4(c.token, snap).catch((e: unknown) => e);
    expect((err as PermitV4VerifyError).reason).toBe("key_set_expired");
    const fresh = await verifyPermitV4(c.token, { ...snap, fetched_at: now - 60_000 });
    expect(fresh.verifiedWithKid).toBe("permit-2026-a");
    const bad = await verifyPermitV4(c.token, { ...snap, fetched_at: "yesterday" as unknown as number }).catch((e: unknown) => e);
    expect((bad as PermitV4VerifyError).reason).toBe("key_set_expired");
  });

  it("an entry declaring a non-EdDSA alg is never a permit key", async () => {
    const a = file.cases.find((x) => x.name === "kid_selects_key_a")!;
    const keys = file.key_set.keys.map((k) => (k.kid === "permit-2026-a" ? { ...k, alg: "RS256" } : k));
    const err = await verifyPermitV4(a.token, { ...file.key_set, keys }).catch((e: unknown) => e);
    expect((err as PermitV4VerifyError).reason).toBe("unknown_kid");
  });

  it("an entry with no role (or no kty/crv/alg) is never a permit key", async () => {
    // Codex repro: the audit key with its role dropped must not sign permits.
    const c = file.cases.find((x) => x.name === "kid_of_non_permit_role")!;
    for (const field of ["role", "kty", "crv", "alg"]) {
      const keys = file.key_set.keys.map((k) => {
        if (k.kid !== "audit-a" && k.kid !== "permit-2026-a") return k;
        const { [field]: _drop, ...rest } = k;
        return k.kid === "audit-a" && field !== "role" ? k : rest;
      });
      const set = { ...file.key_set, keys } as PermitVerificationKeySet;
      const err = await verifyPermitV4(c.token, set).catch((e: unknown) => e);
      expect((err as PermitV4VerifyError).reason, `audit key, ${field} dropped`).toBe("unknown_kid");
      const a = file.cases.find((x) => x.name === "kid_selects_key_a")!;
      const errA = await verifyPermitV4(a.token, set).catch((e: unknown) => e);
      expect((errA as PermitV4VerifyError).reason, `permit key, ${field} dropped`).toBe("unknown_kid");
    }
  });

  it("the age limit equals trust.ts DEFAULT_TRUST_TTL_MS", () => {
    expect(TRUST_SNAPSHOT_MAX_AGE_MS).toBe(DEFAULT_TRUST_TTL_MS);
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

  describe("cross-role key aliases (permit material re-published under another role)", () => {
    const kidA = () => file.cases.find((x) => x.name === "kid_selects_key_a")!;
    const kidB = () => file.cases.find((x) => x.name === "kid_selects_key_b")!;
    const keyOf = (kid: string) => file.key_set.keys.find((k) => k.kid === kid)!;

    it("an audit alias of one permit key refuses that key only", async () => {
      const set = {
        ...file.key_set,
        keys: [...file.key_set.keys, { ...keyOf("permit-2026-b"), kid: "audit-b", role: "R3_audit" }],
      } as PermitVerificationKeySet;
      const err = await verifyPermitV4(kidB().token, set).catch((e: unknown) => e);
      expect((err as PermitV4VerifyError).reason).toBe("key_role_conflict");
      // permit-2026-a's material has only R2_permit entries: still verifies.
      expect((await verifyPermitV4(kidA().token, set)).verifiedWithKid).toBe("permit-2026-a");
    });

    for (const [label, role] of [
      ["lower-case role", "r2_permit"],
      ["role as an array", ["R2_permit"]],
      ["role null", null],
      ["empty role", ""],
    ] as const) {
      it(`a non-permit alias with ${label} refuses the permit key`, async () => {
        const set = {
          ...file.key_set,
          keys: [...file.key_set.keys, { ...keyOf("permit-2026-a"), kid: "alias", role }],
        } as unknown as PermitVerificationKeySet;
        const err = await verifyPermitV4(kidA().token, set).catch((e: unknown) => e);
        expect((err as PermitV4VerifyError).reason).toBe("key_role_conflict");
      });
    }

    it("the alias is matched on decoded bytes, whatever its spelling", async () => {
      const x = keyOf("permit-2026-a").x;
      const std = Buffer.from(x, "base64url").toString("base64"); // padded, standard alphabet
      const set = {
        ...file.key_set,
        keys: [...file.key_set.keys, { ...keyOf("permit-2026-a"), kid: "audit-std", role: "R3_audit", x: std }],
      } as PermitVerificationKeySet;
      const err = await verifyPermitV4(kidA().token, set).catch((e: unknown) => e);
      expect((err as PermitV4VerifyError).reason).toBe("key_role_conflict");
    });

    it("defaultKid cannot route a kid-less token around the alias", async () => {
      const c = file.cases.find((x) => x.name === "no_kid_with_cross_role_alias")!;
      const err = await verifyPermitV4(c.token, file.alias_set, { defaultKid: "permit-2026-a" }).catch(
        (e: unknown) => e,
      );
      expect((err as PermitV4VerifyError).reason).toBe("key_role_conflict");
    });

    it("the vectors' audit key no longer shares material with any permit key", () => {
      const audit = new Set(file.key_set.keys.filter((k) => k.role !== "R2_permit").map((k) => k.x.replace(/=+$/, "")));
      for (const k of file.key_set.keys.filter((k) => k.role === "R2_permit")) {
        expect(audit.has(k.x.replace(/=+$/, "")), k.kid).toBe(false);
      }
    });
  });
});
