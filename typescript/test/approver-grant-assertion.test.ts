// approver_grant_assertion.v1 on approval_artifact.v1 (atlasent-api#3876).
// Pins TS type <-> contract schema parity: a fully-populated typed value
// (tsc enforces every required field) must carry exactly the schema's
// property set, and the artifact schema must expose the field additively.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ApprovalArtifactV1 } from "../src/approvalArtifact.js";
import type { ApproverGrantAssertionV1 } from "../src/approverGrantAssertion.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS = resolve(__dirname, "..", "..", "contract", "schemas");
const load = (f: string) => JSON.parse(readFileSync(resolve(SCHEMAS, f), "utf8"));

const grant: ApproverGrantAssertionV1 = {
  version: "approver_grant_assertion.v1",
  basis: "atlasent_approver_grant",
  subject: { principal_id: "11111111-1111-4111-8111-111111111111", principal_kind: "human" },
  grant_id: "22222222-2222-4222-8222-222222222222",
  binding: {
    approval_id: "apr_123",
    action_hash: "f".repeat(64),
    action_type: "production.deploy",
    tenant_id: "tnt_1",
    environment: "production",
  },
  issuer: { issuer_id: "atlasent-console", kid: "kid-1" },
  auth_context: { acr: "aal2", amr: ["pwd", "totp"], step_up: "aal2", step_up_at: "2026-10-03T00:00:00Z" },
  issued_at: "2026-10-03T00:00:00Z",
  expires_at: "2026-10-03T00:05:00Z",
  nonce: "0123456789abcdef",
  signature: "deadbeef",
};

describe("approver_grant_assertion.v1 contract parity", () => {
  it("typed value carries exactly the schema's properties, all required", () => {
    const schema = load("approver-grant-assertion.schema.json");
    expect(Object.keys(grant).sort()).toEqual(Object.keys(schema.properties).sort());
    expect([...schema.required].sort()).toEqual(Object.keys(schema.properties).sort());
    expect(schema.properties.version.const).toBe(grant.version);
    expect(schema.properties.basis.const).toBe(grant.basis);
    for (const k of ["subject", "binding", "issuer", "auth_context"] as const) {
      expect(Object.keys(grant[k]).sort()).toEqual(Object.keys(schema.properties[k].properties).sort());
    }
    expect(schema.properties.auth_context.properties.acr.enum).toEqual(["aal1", "aal2"]);
    expect(schema.properties.auth_context.properties.step_up.enum).toEqual(["aal2", "password_reauth"]);
  });

  it("approval artifact exposes it optionally and forbids it alongside identity_assertion", () => {
    const schema = load("approval-artifact.schema.json");
    expect(schema.properties.approver_grant_assertion.$ref).toBe("approver-grant-assertion.schema.json");
    expect(schema.required).not.toContain("approver_grant_assertion");
    expect(schema.not.required.sort()).toEqual(["approver_grant_assertion", "identity_assertion"]);
    const artifact: ApprovalArtifactV1 = {
      version: "approval_artifact.v1",
      approval_id: "apr_123",
      tenant_id: "tnt_1",
      action_type: "production.deploy",
      resource_id: "release:abc123",
      action_hash: "f".repeat(64),
      reviewer: { principal_id: grant.subject.principal_id, principal_kind: "human" },
      issuer: { type: "approval_service", issuer_id: "atlasent-console", kid: "kid-1" },
      issued_at: grant.issued_at,
      expires_at: grant.expires_at,
      nonce: "n_abcdef01",
      signature: "deadbeef",
      approver_grant_assertion: grant,
    };
    expect(artifact.approver_grant_assertion?.basis).toBe("atlasent_approver_grant");
  });
});
