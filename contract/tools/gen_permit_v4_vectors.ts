// Generate pt.v4 permit cross-language parity vectors FROM atlasent-api's own
// encoder, so the TypeScript and Python offline decoders are checked against
// the bytes the runtime actually mints, not against a re-implementation.
//
// Usage (Deno 2.x):
//   ATLASENT_API_DIR=/path/to/atlasent-api \
//     deno run --allow-read --allow-env --allow-write \
//     contract/tools/gen_permit_v4_vectors.ts > contract/vectors/permit-v4/vectors.json
//
// It imports `signPermitV4` / `verifyPermitV4Signature` from
// `<api>/supabase/functions/_shared/permit-token.ts` and `decodePermitClaimsV4`
// from `_shared/cose.ts`. `expected_claims` is what the runtime's own decoder
// returns for each token. Record the atlasent-api commit you generated from in
// `contract/vectors/permit-v4/README.md`.
//
// The signing key is a FIXED TEST SEED below. It signs nothing real; never
// reuse it. Ed25519 signatures are deterministic, but `permit_id` is random
// per mint, so a re-run produces different tokens with the same structure.

const apiDir = Deno.env.get("ATLASENT_API_DIR");
if (!apiDir) {
  console.error("set ATLASENT_API_DIR to an atlasent-api checkout");
  Deno.exit(2);
}
const shared = `file://${apiDir.replace(/\/$/, "")}/supabase/functions/_shared`;
const { signPermitV4, verifyPermitV4Signature } = await import(`${shared}/permit-token.ts`);
const { decodePermitClaimsV4, coseSign1Decode } = await import(`${shared}/cose.ts`);

// RFC 8032 test-vector-1 seed. Public test material only.
const SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const pkcs8 = new Uint8Array([...hex("302e020100300506032b657004220420"), ...hex(SEED_HEX)]);
const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
const jwk = await crypto.subtle.exportKey("jwk", priv);
const pubRaw = Uint8Array.from(atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/") + "="), (c) => c.charCodeAt(0));
const pub = await crypto.subtle.importKey("raw", pubRaw, { name: "Ed25519" }, true, ["verify"]);
const pubB64 = btoa(String.fromCharCode(...pubRaw));

const base = {
  evaluation_id: "0b8f7e9a-6c1d-4f2e-9a3b-5c7d8e9f0a1b",
  org_id: "7e57c0de-0000-4000-8000-000000000001",
  action_type: "production.deploy",
  actor_id: "github:octocat",
  issued_at_ms: 1_790_000_000_000,
  expires_at_ms: 1_790_003_600_000,
  environment: "live",
};
const h = (c: string) => c.repeat(64);

const cases: Array<{ name: string; description: string; payload: Record<string, unknown> }> = [
  {
    name: "minimal",
    description: "Required claims only (keys 4, 6, 7, -1..-5).",
    payload: { ...base },
  },
  {
    name: "hashes_and_execution_binding",
    description: "cdo/policy hash (-6/-7), execution_hash_expected (-12), envelope_hash (-13).",
    payload: {
      ...base,
      cdo_hash: h("a"),
      policy_version_hash: h("b"),
      execution_hash_expected: h("c"),
      envelope_hash: h("d"),
    },
  },
  {
    name: "delegation_child",
    description: "P4 delegation lineage (-8..-11).",
    payload: {
      ...base,
      actor_id: "agent:deployer-7",
      parent_permit_hash: h("e"),
      parent_permit_id: "11111111-2222-4333-8444-555555555555",
      delegation_depth: 2,
      delegating_actor_id: "github:octocat",
    },
  },
  {
    name: "full",
    description: "Every claim key the runtime encodes (4, 6, 7, -1..-35).",
    payload: {
      ...base,
      environment: "test",
      cdo_hash: h("1"),
      policy_version_hash: h("2"),
      parent_permit_hash: h("3"),
      parent_permit_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      delegation_depth: 1,
      delegating_actor_id: "github:root-operator",
      execution_hash_expected: h("4"),
      envelope_hash: h("5"),
      exception_id: "12345678-90ab-4cde-8f01-23456789abcd",
      exception_type: "break_glass",
      aws_account_id: "123456789012",
      aws_region: "us-west-2",
      operation_intent_id: "intent-2026-10-21-001",
      change_brief_id: "cb_01HZXAMPLE",
      change_brief_digest: "sha256:" + h("6"),
      authorization_identity_id: "21212121-3434-4565-8787-909090909090",
      authorization_issuance_id: "31313131-4545-4676-8898-a0a0a0a0a0a0",
      authorization_generation: 7,
      agent_runtime_identity: {
        version: "agent_runtime_identity.v1",
        binding_id: "bind-1",
        agent_identity_id: "agent-id-1",
        agent_registry_id: "registry-1",
        agent_version: "1.2.3",
        agent_deployment_id: "deploy-1",
        deployment_digest: "sha256:" + h("7"),
        provider_proof: {
          provider: "microsoft_entra",
          credential_type: "oidc_workload_token",
          subject_kind: "service_principal",
          issuer: "https://login.microsoftonline.com/tid/v2.0",
          provider_tenant_id: "tid",
          provider_subject: "sp-oid",
          audience: "api://atlasent",
          proof_fingerprint: h("8"),
          proof_issued_at: "2026-10-21T00:00:00Z",
          proof_expires_at: "2026-10-21T01:00:00Z",
          verified_at: "2026-10-21T00:00:01Z",
          verification_method: "rs256_jwks",
        },
      },
      entra_tenant_id: "7e57c0de-0000-4000-8000-0000000000e1",
      entra_org_binding_id: "41414141-5656-4767-8989-b0b0b0b0b0b0",
      entra_request_mapping_id: "51515151-6767-4878-8a9a-c0c0c0c0c0c0",
      entra_request_mapping_version: 3,
      entra_approve_mapping_id: "61616161-7878-4989-8bab-d0d0d0d0d0d0",
      entra_approve_mapping_version: 4,
      pep_audience_executor_id: "entra:00000000-1111-4222-8333-444444444444",
      entra_approve_principal_oid: "approver-oid",
      azure_subscription_id: "00000000-aaaa-4bbb-8ccc-dddddddddddd",
      azure_resource_group: "rg-prod",
      entra_request_principal_oid: "requester-oid",
    },
  },
];

function b64urlToBytes(s: string): Uint8Array {
  const p = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - (s.length * 3) % 4) % 4);
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
}

const vectors = [];
for (const c of cases) {
  const token: string = await signPermitV4(c.payload, priv);
  const roundTrip = await verifyPermitV4Signature(token, pub);
  if (!roundTrip) throw new Error(`${c.name}: runtime did not verify its own token`);
  const parts = coseSign1Decode(b64urlToBytes(token.slice("pt.v4.".length)));
  const expected = decodePermitClaimsV4(parts.payloadBytes);
  vectors.push({ name: c.name, description: c.description, token, expected_claims: expected });
}

// Negative vectors derived from the "full" token.
const full = vectors.find((v) => v.name === "full")!.token;
// Flip a character well inside the signature (not the last one, whose low
// bits may be base64 padding and decode to the same bytes).
const flipInSignature = (t: string) => t.slice(0, -10) + (t.at(-10) === "A" ? "B" : "A") + t.slice(-9);

console.log(JSON.stringify({
  schema: "atlasent.permit_v4_vectors.v1",
  generator: "contract/tools/gen_permit_v4_vectors.ts",
  public_key_b64: pubB64,
  public_key_note: "Ed25519 from the RFC 8032 test-1 seed. Test material only.",
  vectors,
  negative: [
    { name: "signature_tampered", token: flipInSignature(full), expected_reason: "signature_invalid" },
    { name: "wrong_prefix", token: "pt.v3." + full.slice("pt.v4.".length), expected_reason: "bad_prefix" },
  ],
}, null, 2));
