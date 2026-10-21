/**
 * Hostile key sets (atlasent-api#4640 parity). A key set whose revocation
 * state cannot be read is refused as a whole, for kid-bearing and kid-less
 * tokens, and a kid-less token is bounded by every R2_permit entry sharing
 * the selected key's material. The shared cases live in
 * contract/vectors/permit-v4/kid-vectors.json; these add the shapes a vector
 * file cannot carry (SDK snapshot types) and the edge values per field.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  PermitV4VerifyError,
  type PermitVerificationKey,
  type PermitVerificationKeySet,
  verifyPermitV4,
} from "../src/index.js";
import type { TrustSnapshot } from "../src/trust.js";
import { VENDORED_TRUST_ROOT_SNAPSHOT } from "../src/vendoredTrustRoot.generated.js";

const file = JSON.parse(
  readFileSync(new URL("../../contract/vectors/permit-v4/kid-vectors.json", import.meta.url), "utf8"),
) as {
  single_set: PermitVerificationKeySet;
  key_set: PermitVerificationKeySet;
  cases: Array<{ name: string; token: string }>;
};
const tok = (name: string) => file.cases.find((c) => c.name === name)!.token;
const KID_A = tok("kid_selects_key_a");
const NO_KID = tok("no_kid_single_key_set");
const A = file.single_set.keys[0]!;
const B = file.key_set.keys.find((k) => k.kid === "permit-2026-b")!;

async function reason(token: string, set: unknown, defaultKid?: string): Promise<string> {
  const err = await verifyPermitV4(token, set as PermitVerificationKeySet, defaultKid ? { defaultKid } : undefined).then(
    () => "ok",
    (e: unknown) => {
      expect(e).toBeInstanceOf(PermitV4VerifyError);
      return (e as PermitV4VerifyError).reason;
    },
  );
  return err;
}

async function refusedBoth(set: unknown): Promise<void> {
  expect(await reason(KID_A, set), "kid-bearing token").toBe("key_set_untrustworthy");
  expect(await reason(NO_KID, set), "kid-less token").toBe("key_set_untrustworthy");
  expect(await reason(NO_KID, set, "permit-2026-a"), "kid-less token with defaultKid").toBe("key_set_untrustworthy");
}

describe("an entry without a boolean revoked makes the whole set untrustworthy", () => {
  for (const [label, value] of [
    ["the number 0", 0],
    ["the number 1", 1],
    ["null", null],
    ['the string "false"', "false"],
    ['the string "true"', "true"],
    ["an object", { value: false }],
  ] as const) {
    it(`another entry's revoked is ${label}`, async () => {
      await refusedBoth({ keys: [A, { ...B, revoked: value }] });
    });
    it(`the selected entry's own revoked is ${label}`, async () => {
      await refusedBoth({ keys: [{ ...A, revoked: value }] });
    });
  }

  for (const [label, entry] of [
    ["null", null],
    ["a string", "permit-2026-b"],
    ["an array", [B]],
  ] as const) {
    it(`an entry that is ${label}`, async () => {
      await refusedBoth({ keys: [A, entry] });
    });
  }

  it("a sound set with the same keys still verifies (control)", async () => {
    expect(await reason(KID_A, { keys: [A, B] })).toBe("ok");
  });
});

describe("an unresolved revocation trusts no key in the set", () => {
  it("a ledger kid absent from keys (TrustRootSnapshot shape)", async () => {
    await refusedBoth({ valid_until: "2099-01-01T00:00:00Z", issued_at: "2026-01-01T00:00:00Z", keys: [A], revoked_keys: [{ kid: "permit-gone", revoked_at: "2026-10-01T00:00:00Z" }], revoked_identities: [] });
  });

  it("a revoked_kids entry absent from keys (TrustSnapshot shape)", async () => {
    const snap: TrustSnapshot = {
      keys: [A] as unknown as TrustSnapshot["keys"],
      revoked_kids: ["permit-gone"],
      fetched_at: Date.now(),
      expires_at: Date.now() + 60_000,
    };
    await refusedBoth(snap);
  });

  for (const [label, x] of [
    // Four characters, so a lenient decoder that skips them still reads B's
    // key: only a strict alphabet check refuses these spellings.
    ["whitespace inside", `${B.x.slice(0, 10)}    ${B.x.slice(10)}`],
    ["characters outside the alphabet", `${B.x.slice(0, 40)}!!!!${B.x.slice(40)}`],
    ["an impossible length", `${B.x}A`.slice(0, 41)],
    ["a number", 42],
  ] as const) {
    it(`a revoked entry whose material has ${label}`, async () => {
      await refusedBoth({ keys: [A, { ...B, revoked: true, x }] });
    });
    it(`a ledger-revoked entry whose material has ${label}`, async () => {
      await refusedBoth({ keys: [A, { ...B, x }], revoked_keys: [{ kid: B.kid }] });
    });
  }

  it("a ledger kid whose only entry has readable material resolves (control)", async () => {
    expect(await reason(KID_A, { keys: [A, B], revoked_keys: [{ kid: B.kid }] })).toBe("ok");
  });

  it("a revocation with neither kid nor material", async () => {
    const { kid: _k, x: _x, ...anon } = B;
    await refusedBoth({ keys: [A, { ...anon, revoked: true }] });
  });
});

describe("a malformed revocation ledger or keys list", () => {
  for (const [label, extra] of [
    ["revoked_keys null", { revoked_keys: null }],
    ["revoked_keys an object", { revoked_keys: { kid: "x" } }],
    ["revoked_keys a row with an empty kid", { revoked_keys: [{ kid: "" }] }],
    ["revoked_keys a row with a numeric kid", { revoked_keys: [{ kid: 7 }] }],
    ["revoked_keys a null row", { revoked_keys: [null] }],
    ["revoked_kids null", { revoked_kids: null }],
    ["revoked_kids a string", { revoked_kids: "permit-2026-b" }],
    ["revoked_kids with an empty kid", { revoked_kids: [""] }],
  ] as const) {
    it(label, async () => {
      await refusedBoth({ keys: [A], ...extra });
    });
  }

  it("keys missing", async () => {
    await refusedBoth({ revoked_keys: [] });
  });

  it("a duplicate kid, even on a non-permit entry", async () => {
    await refusedBoth({ keys: [A, { ...B, kid: "permit-2026-a", role: "R3_audit" }] });
  });
});

describe("kid-less fallback validity window", () => {
  const alias = (extra: Record<string, unknown>) => ({ ...A, kid: "permit-a-alias", ...extra });

  for (const [label, extra] of [
    ["retired before the permit's iat", { valid_until: "2026-02-01T00:00:00Z" }],
    ["not yet valid at the permit's iat", { valid_from: "2099-01-01T00:00:00Z" }],
    ["a numeric valid_from", { valid_from: 0 }],
    ["an unparseable valid_until", { valid_until: "soon" }],
  ] as const) {
    it(`an R2_permit alias ${label} bounds the kid-less fallback`, async () => {
      const set = { keys: [A, alias(extra)] };
      expect(await reason(NO_KID, set)).toBe("key_not_valid_for_permit");
      expect(await reason(NO_KID, set, "permit-2026-a")).toBe("key_not_valid_for_permit");
      // A kid names one entry: only that entry's window applies.
      expect(await reason(KID_A, set)).toBe("ok");
    });
  }

  it("an alias spelled in standard padded base64 still bounds it", async () => {
    const std = Buffer.from(A.x, "base64url").toString("base64");
    expect(await reason(NO_KID, { keys: [A, alias({ x: std, valid_until: "2026-02-01T00:00:00Z" })] })).toBe(
      "key_not_valid_for_permit",
    );
  });

  it("an in-window alias does not bound it (control)", async () => {
    expect(await reason(NO_KID, { keys: [A, alias({ valid_from: null, valid_until: null })] }, "permit-2026-a")).toBe("ok");
  });

  it("a revoked-material alias is still refused as revoked, not by window", async () => {
    expect(await reason(NO_KID, { keys: [A, alias({ revoked: true })] })).toBe("kid_required");
  });
});

describe("the published trust root is still trusted", () => {
  // VENDORED_TRUST_ROOT_SNAPSHOT is atlasent-keys' .well-known verifier keys
  // plus its revocation ledger. Under the new rules it must reach the
  // signature check (the test token is not signed by the production key).
  it("a kid-less token selects the live permit key and fails only on the signature", async () => {
    expect(await reason(NO_KID, VENDORED_TRUST_ROOT_SNAPSHOT)).toBe("signature_invalid");
  });

  it("every entry states revoked as a boolean and every ledger kid resolves", () => {
    const keys = VENDORED_TRUST_ROOT_SNAPSHOT.keys as unknown as PermitVerificationKey[];
    expect(keys.every((k) => typeof k.revoked === "boolean")).toBe(true);
    for (const r of VENDORED_TRUST_ROOT_SNAPSHOT.revoked_keys) {
      expect(keys.some((k) => k.kid === r.kid && typeof k.x === "string"), r.kid).toBe(true);
    }
  });
});

describe("revocation material must be a 32-byte Ed25519 key (Codex P1)", () => {
  for (const [label, x] of [
    ["empty", ""],
    ["one byte", "AA"],
    ["31 bytes", Buffer.alloc(31, 1).toString("base64url")],
    ["33 bytes", Buffer.alloc(33, 1).toString("base64url")],
  ] as const) {
    it(`a revoked entry whose x decodes to ${label} is unresolved`, async () => {
      await refusedBoth({ keys: [A, { ...B, revoked: true, x }] });
    });
    it(`a ledger kid whose entry's x decodes to ${label} is unresolved`, async () => {
      await refusedBoth({ keys: [A, { ...B, x }], revoked_keys: [{ kid: B.kid }] });
    });
  }
});

describe("SDK loaders keep unreadable revocation data visible (Codex P1)", () => {
  const index = { valid_until: "2099-01-01T00:00:00Z", issued_at: "2026-01-01T00:00:00Z" };
  const fetchOf = (keys: unknown, revocations: unknown): typeof fetch =>
    (async (url: string | URL) => {
      const u = String(url);
      const body = u.endsWith("atlasent-verifier-keys.json")
        ? { keys }
        : u.endsWith("atlasent-revocations.json")
          ? revocations
          : index;
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof fetch;

  for (const [label, revocations] of [
    ["a ledger that is an object", { revoked_keys: { kid: "permit-gone" } }],
    ["a ledger that is null", { revoked_keys: null }],
    ["a ledger row without a kid", { revoked_keys: [{ revoked_at: "2026-10-01T00:00:00Z" }] }],
    ["a ledger row with an empty kid", { revoked_keys: [{ kid: "" }] }],
  ] as const) {
    it(`bootstrapTrust marks ${label} and the verifier refuses the snapshot`, async () => {
      const { bootstrapTrust } = await import("../src/trust.js");
      const snap = await bootstrapTrust("https://keys.example", undefined, undefined, fetchOf([A], revocations));
      expect(snap.revocations_unreadable).toBe(true);
      await refusedBoth(snap);
    });
  }

  it("bootstrapTrust marks a dropped key entry (it may have been a revocation)", async () => {
    const { kid: _k, ...anon } = { ...B, revoked: true };
    const { bootstrapTrust } = await import("../src/trust.js");
    const snap = await bootstrapTrust("https://keys.example", undefined, undefined, fetchOf([A, anon], { revoked_keys: [] }));
    expect(snap.keys).toHaveLength(1);
    await refusedBoth(snap);
  });

  it("a sound bootstrap carries no marker and verifies (control)", async () => {
    const { bootstrapTrust } = await import("../src/trust.js");
    const snap = await bootstrapTrust("https://keys.example", undefined, undefined, fetchOf([A, B], {}));
    expect(snap.revocations_unreadable).toBeUndefined();
    expect(await reason(KID_A, snap)).toBe("ok");
  });

  it("TrustRootManager keeps its snapshot when the refreshed ledger is unreadable", async () => {
    const { TrustRootManager } = await import("../src/trustRoot.js");
    const mgr = new TrustRootManager(VENDORED_TRUST_ROOT_SNAPSHOT, {
      disableRefresh: true,
      refreshBaseUrl: "https://keys.example",
      fetch: fetchOf([A], { revoked_keys: { kid: "permit-gone" } }),
    });
    await (mgr as unknown as { _doRefresh(): Promise<void> })._doRefresh();
    expect(mgr.getSnapshot().keys).toBe(VENDORED_TRUST_ROOT_SNAPSHOT.keys);
    const sound = new TrustRootManager(VENDORED_TRUST_ROOT_SNAPSHOT, {
      disableRefresh: true,
      refreshBaseUrl: "https://keys.example",
      fetch: fetchOf([A], {}),
    });
    await (sound as unknown as { _doRefresh(): Promise<void> })._doRefresh();
    expect(sound.getSnapshot().keys).toEqual([A]);
  });
});
