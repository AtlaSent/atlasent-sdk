// meaning / entra_provenance / approval_kind / subject_agent_identity_id on
// approval_artifact.v1 (additive, 2026-10-03). The runtime
// (atlasent-api _shared/approval_artifact.ts) emits and signs these four
// optional fields; before this change the schema forbade them
// (additionalProperties: false). Pins TS type <-> contract schema parity.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type {
  ApprovalArtifactV1,
  ApprovalKind,
  EntraProvenanceV1,
  SignatureMeaning,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS = resolve(__dirname, "..", "..", "contract", "schemas");
const load = (f: string) => JSON.parse(readFileSync(resolve(SCHEMAS, f), "utf8"));

const ACTION_HASH = "3f".repeat(32);

// Shaped after what the runtime's v1-idp-broker returns from an Entra ID
// approval mint (_shared/evidence-minter.ts mintApprovalArtifact).
const entraArtifact: ApprovalArtifactV1 = {
  version: "approval_artifact.v1",
  approval_id: "apr-0b6c3f0e-5a1d-4c55-9c2e-7a9d2f41e8b3",
  tenant_id: "923a3b8d-cdaa-4fc7-885f-8d8b11232ca4",
  action_type: "production.deploy",
  resource_id: "api-service",
  action_hash: ACTION_HASH,
  reviewer: {
    principal_id: "entra:5d1e2f3a-0b4c-4d6e-8f7a-9b0c1d2e3f40",
    principal_kind: "human",
    roles: ["release-approver"],
  },
  issuer: { type: "approval_service", issuer_id: "atlasent-idp-broker", kid: "broker-2026-09" },
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-03T00:10:00.000Z",
  nonce: "6f1d2c3b-4a59-4e8d-9c7b-1a2b3c4d5e6f",
  meaning: "approved",
  entra_provenance: {
    tenant_id: "72f988bf-86f1-41af-91ab-2d7cd011db47",
    org_binding_id: "0e9f8a7b-6c5d-4e3f-a2b1-c0d9e8f7a6b5",
    mapping_id: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
    mapping_version: 3,
    relation: "approve",
  },
  signature: "MEUCIQDexampleArtifactSignature",
};

// Shaped after the ADR CROSS-056 artifact the runtime verifier accepts.
const kindArtifact: ApprovalArtifactV1 = {
  version: "approval_artifact.v1",
  approval_id: "apr-kind-1",
  tenant_id: "org-1",
  action_type: "agent.tool.invoke",
  resource_id: "tool:deploy",
  action_hash: ACTION_HASH,
  reviewer: { principal_id: "owner-1", principal_kind: "human", roles: ["agent_owner"] },
  issuer: { type: "approval_service", issuer_id: "atlasent-console", kid: "kid-o" },
  issued_at: "2026-10-03T00:00:00Z",
  expires_at: "2026-10-03T00:05:00Z",
  nonce: "nonce-kind-123456",
  approval_kind: "single_human_over_machine",
  subject_agent_identity_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  signature: "sig",
};

describe("approval_artifact.v1 runtime fields: contract parity", () => {
  const schema = load("approval-artifact.schema.json");

  it("schema declares all four fields as optional", () => {
    for (const k of ["meaning", "entra_provenance", "approval_kind", "subject_agent_identity_id"]) {
      expect(schema.properties[k], k).toBeDefined();
      expect(schema.required).not.toContain(k);
    }
    expect(schema.additionalProperties).toBe(false);
  });

  it("enums match the TS literal unions", () => {
    const meanings: SignatureMeaning[] = ["approved", "reviewed", "authored"];
    const kinds: ApprovalKind[] = ["single_human_over_machine"];
    expect(schema.properties.meaning.enum).toEqual(meanings);
    expect(schema.properties.approval_kind.enum).toEqual(kinds);
  });

  it("kind and subject are mutually dependent; subject is a uuid", () => {
    expect(schema.dependentRequired).toEqual({
      approval_kind: ["subject_agent_identity_id"],
      subject_agent_identity_id: ["approval_kind"],
    });
    const re = new RegExp(schema.properties.subject_agent_identity_id.pattern);
    expect(re.test(kindArtifact.subject_agent_identity_id!)).toBe(true);
    expect(re.test(kindArtifact.subject_agent_identity_id!.toUpperCase())).toBe(true);
    expect(re.test("not-a-uuid")).toBe(false);
  });

  it("entra_provenance refs the sub-schema and pins relation to approve", () => {
    const [ref, pin] = schema.properties.entra_provenance.allOf;
    expect(ref.$ref).toBe("entra-provenance.schema.json");
    expect(pin.properties.relation.const).toBe("approve");
  });

  it("EntraProvenanceV1 carries exactly the sub-schema's properties, all required", () => {
    const prov = load("entra-provenance.schema.json");
    const value: EntraProvenanceV1 = entraArtifact.entra_provenance!;
    expect(Object.keys(value).sort()).toEqual(Object.keys(prov.properties).sort());
    expect([...prov.required].sort()).toEqual(Object.keys(prov.properties).sort());
    expect(prov.additionalProperties).toBe(false);
    expect(prov.properties.relation.enum).toEqual(["request", "approve"]);
  });

  it("runtime-shaped artifacts only use schema-declared keys", () => {
    const declared = new Set(Object.keys(schema.properties));
    for (const a of [entraArtifact, kindArtifact]) {
      for (const k of Object.keys(a)) {
        expect(declared.has(k), k).toBe(true);
      }
    }
  });
});
