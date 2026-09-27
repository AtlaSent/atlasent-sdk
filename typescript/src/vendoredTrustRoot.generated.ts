// GENERATED-DERIVED — do not edit directly.
// Source: atlasent-keys' .well-known/{atlasent-trust-root,atlasent-verifier-keys,
//   atlasent-revocations}.json — the canonical public trust root published at
//   https://keys.atlasent.io/.well-known/.
// Re-vendor: node scripts/vendor-trust-root.mjs [path/to/atlasent-keys/.well-known]
// Do NOT hand-edit — update atlasent-keys upstream and re-vendor.
//
// This is the SDK's embedded baseline trust-root snapshot (see trustRoot.ts).
// It is a plain object literal on purpose: no file I/O, no path resolution,
// nothing Node-specific, so it is safe to bundle for any target (Node,
// browser, edge). TrustRootManager's background refresh keeps a
// long-running process current between vendoring passes; this baseline is
// what every process has from the very first call, with no network
// round-trip and no reliance on files shipping alongside dist/.

import type { TrustRootSnapshot } from "./trustRoot.js";

export const VENDORED_TRUST_ROOT_SNAPSHOT: TrustRootSnapshot = {
  "valid_until": "2027-06-01T00:00:00Z",
  "issued_at": "2026-09-26T00:00:00Z",
  "keys": [
    {
      "kid": "v2-audit-2026",
      "role": "R3_audit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "IctfKl2VEOaRBX9jvoYnUc2cInF81WgywU5iY3_Ui44",
      "crv": "Ed25519",
      "valid_from": "2026-05-28T00:00:00Z",
      "valid_until": "2027-06-01T00:00:00Z",
      "replaced_by": "v1",
      "revoked": true,
      "tenant": null
    },
    {
      "kid": "test-key",
      "role": "R3_audit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "uCfAGR92U9gKXqMmGs4MCoaTq-LmzoRe_aiwZE6UcnQ",
      "crv": "Ed25519",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "replaced_by": "v2-audit-2026",
      "revoked": true,
      "tenant": null
    },
    {
      "kid": "permit-kid",
      "role": "R2_permit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "uCfAGR92U9gKXqMmGs4MCoaTq-LmzoRe_aiwZE6UcnQ",
      "crv": "Ed25519",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "replaced_by": "ak_2026_q3_atlasent_permit",
      "revoked": true,
      "tenant": null
    },
    {
      "kid": "revoked-kid",
      "role": "R3_audit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "uCfAGR92U9gKXqMmGs4MCoaTq-LmzoRe_aiwZE6UcnQ",
      "crv": "Ed25519",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "replaced_by": null,
      "revoked": true,
      "tenant": null
    },
    {
      "kid": "ak_2026_q3_atlasent_permit",
      "role": "R2_permit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "3psqJ3CGPIKe4N2oSgu75f1cnJgnbWLcBFThFk4N_qc",
      "crv": "Ed25519",
      "valid_from": "2026-07-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "replaced_by": null,
      "revoked": false,
      "tenant": "atlasent"
    },
    {
      "kid": "v1",
      "role": "R3_audit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "r0leDQfIerrgVCb8M1shVf6L5Qer0C13qV3Dee70D3o",
      "crv": "Ed25519",
      "valid_from": "2026-06-07T00:00:00Z",
      "valid_until": "2027-07-08T00:00:00Z",
      "replaced_by": null,
      "revoked": false,
      "tenant": null
    },
    {
      "kid": "ak_2026_q3_atlasent_audit",
      "role": "R3_audit",
      "kty": "OKP",
      "alg": "EdDSA",
      "x": "AXSz2fwodpUxDxL-KV-rwFU2_2VQDORbnClLivQZ9Ug",
      "crv": "Ed25519",
      "valid_from": "2026-09-13T21:51:00Z",
      "valid_until": "2027-03-31T00:00:00Z",
      "replaced_by": null,
      "revoked": false,
      "tenant": "atlasent"
    }
  ],
  "revoked_keys": [
    {
      "kid": "revoked-kid",
      "role": "R3_audit",
      "revoked_at": "2026-05-28T00:00:00Z",
      "reason": "Test key; superseded by v2-audit-2026"
    },
    {
      "kid": "test-key",
      "role": "R3_audit",
      "revoked_at": "2026-06-10T00:00:00Z",
      "reason": "Replaced by v2-audit-2026; revocation flag corrected to match replaced_by field"
    },
    {
      "kid": "permit-kid",
      "role": "R2_permit",
      "revoked_at": "2026-08-10T09:39:34Z",
      "reason": "Vendor-fixture placeholder R2_permit key, superseded by ak_2026_q3_atlasent_permit; revoked in atlasent-verifier-keys.json commit 0f97f0c but omitted from this ledger at the time"
    },
    {
      "kid": "v2-audit-2026",
      "role": "R3_audit",
      "revoked_at": "2026-09-12T21:06:42Z",
      "reason": "Never the production audit signer: 0/7 sampled production audit_events signatures (2026-06-07 → 2026-09-12) verify under it, and every production v1-export-audit envelope to date recorded an empty key_id, so it never signed an export either. Added 2026-05-28 without a derivation record. Superseded by kid v1, the verified per-row signer (7/7). See atlasent-internal compliance/soc2/audits/2026-09-audit-key-publication-verification.md and its 2026-09-12 resolution record."
    }
  ],
  "revoked_identities": []
};
