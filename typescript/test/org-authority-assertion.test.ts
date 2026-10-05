// org_authority_assertion.v1 on approval_artifact.v1 (atlasent-api#3798 B2a).
// Pins TS type <-> contract schema parity: a fully-populated typed value
// (tsc enforces every required field) must carry exactly the schema's
// property set, and the artifact schema must expose the field additively
// and forbid it alongside either other identity basis.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ApprovalArtifactV1 } from "../src/approvalArtifact.js";
import type { OrgAuthorityAssertionV1 } from "../src/orgAuthorityAssertion.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS = resolve(__dirname, "..", "..", "contract", "schemas");
const load = (f: string) => JSON.parse(readFileSync(resolve(SCHEMAS, f), "utf8"));

const org: OrgAuthorityAssertionV1 = {
  version: "org_authority_assertion.v1",
  basis: "atlasent_verified_org_authority",
  subject: {
    principal_id: "88888888-8888-4888-8888-888888888888",
    principal_kind: "human",
    console_user_id: "22222222-2222-4222-8222-222222222222",
  },
  org_role: "owner",
  binding: {
    approval_id: "apr_123",
    action_hash: "f".repeat(64),
    tenant_id: "tnt_1",
    environment: "production",
  },
  issuer: { issuer_id: "atlasent-console.org-authority", kid: "kid-1" },
  auth_context: { step_up: "password_reauth", step_up_at: "2026-10-03T00:00:00Z" },
  issued_at: "2026-10-03T00:00:00Z",
  expires_at: "2026-10-03T00:05:00Z",
  nonce: "0123456789abcdef",
  signature: "c2ln",
};

describe("org_authority_assertion.v1 contract parity", () => {
  it("typed value carries exactly the schema's properties, all required", () => {
    const schema = load("org-authority-assertion.schema.json");
    expect(Object.keys(org).sort()).toEqual(Object.keys(schema.properties).sort());
    expect([...schema.required].sort()).toEqual(Object.keys(schema.properties).sort());
    expect(schema.properties.version.const).toBe(org.version);
    expect(schema.properties.basis.const).toBe(org.basis);
    expect(schema.properties.org_role.enum).toEqual(["owner", "admin"]);
    for (const k of ["subject", "binding", "issuer", "auth_context"] as const) {
      expect(Object.keys(org[k]).sort()).toEqual(Object.keys(schema.properties[k].properties).sort());
      expect([...schema.properties[k].required].sort()).toEqual(Object.keys(org[k]).sort());
    }
    expect(schema.properties.auth_context.properties.step_up.enum).toEqual(["aal2", "password_reauth"]);
  });

  it("approval artifact exposes it optionally and forbids it alongside either other basis", () => {
    const schema = load("approval-artifact.schema.json");
    expect(schema.properties.org_authority_assertion.$ref).toBe("org-authority-assertion.schema.json");
    expect(schema.required).not.toContain("org_authority_assertion");
    const pairs = (schema.allOf as Array<{ not: { required: string[] } }>).map((c) => [...c.not.required].sort());
    expect(pairs).toContainEqual(["identity_assertion", "org_authority_assertion"]);
    expect(pairs).toContainEqual(["approver_grant_assertion", "org_authority_assertion"]);
    // The pre-existing identity/grant exclusion is untouched.
    expect([...schema.not.required].sort()).toEqual(["approver_grant_assertion", "identity_assertion"]);
    const artifact: ApprovalArtifactV1 = {
      version: "approval_artifact.v1",
      approval_id: "apr_123",
      tenant_id: "tnt_1",
      action_type: "production.deploy",
      resource_id: "release:abc123",
      action_hash: "f".repeat(64),
      reviewer: { principal_id: org.subject.principal_id, principal_kind: "human" },
      issuer: { type: "approval_service", issuer_id: "atlasent-console.org-authority-approval", kid: "kid-1" },
      issued_at: org.issued_at,
      expires_at: org.expires_at,
      nonce: "n_abcdef01",
      signature: "deadbeef",
      org_authority_assertion: org,
    };
    expect(artifact.org_authority_assertion?.basis).toBe("atlasent_verified_org_authority");
  });
});
