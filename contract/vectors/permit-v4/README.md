# pt.v4 permit parity vectors

`vectors.json` holds `pt.v4` COSE Sign1 permit tokens minted by
**atlasent-api's own** `signPermitV4`. Each `expected_claims` value is what
the runtime's own `decodePermitClaimsV4` returns for that token. Both SDK
decoders must reproduce `expected_claims` exactly:

- TypeScript: `typescript/test/verify-permit-v4-vectors.test.ts`
- Python: `python/tests/test_verify_permit_v4_vectors.py`

The `full` vector carries every claim key the runtime encodes (4, 6, 7 and
-1 to -35). The `negative` vectors must be rejected with the stated reason.

**Generated from:** atlasent-api `ace85ce9b9100f6daac68f01130aaeec3169ddf0`
(`supabase/functions/_shared/permit-token.ts` and `_shared/cose.ts`).

**Regenerate** after the runtime adds a claim key:

```sh
ATLASENT_API_DIR=/path/to/atlasent-api \
  deno run --allow-read --allow-env --allow-write \
  contract/tools/gen_permit_v4_vectors.ts > contract/vectors/permit-v4/vectors.json
```

Then update this file's commit pin. The signing key is the RFC 8032 test-1
seed: public test material that signs nothing real. The identifiers in the
vectors are synthetic.

## Kid-aware vectors (`kid-vectors.json`)

These are for verifiers only; the runtime does not mint a kid yet. Each token
reuses the claims bytes of the runtime-minted `full` token, under a different
protected header, re-signed with the same test seed (or with the RFC 8032
test-2 seed for `permit-2026-b`). The audit entry `audit-a` has its own seed
(RFC 8032 test-1024): an audit key that shares material with a permit key is
a cross-role alias, and `alias_set` / `roleless_alias_set` pin that a verifier
refuses it (`key_role_conflict`). Both SDKs must accept or reject every case
with the stated reason:

- TypeScript: `typescript/test/verify-permit-v4-kid.test.ts`
- Python: `python/tests/test_verify_permit_v4_kid.py`

Regenerate with `python3 contract/tools/gen_permit_v4_kid_vectors.py >
contract/vectors/permit-v4/kid-vectors.json`.
