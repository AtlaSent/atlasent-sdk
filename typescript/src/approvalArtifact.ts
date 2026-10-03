/**
 * Public types for the AtlaSent **Approval Artifact** — a signed
 * attestation that a *human* reviewer approved a specific action.
 *
 * Wire-stable as `approval_artifact.v1`. The contract lives in
 * `contract/schemas/approval-artifact.schema.json`. Verification is
 * server-side inside `/v1-evaluate`; the SDK exposes the types so
 * callers can construct the `approval` field on an evaluate request.
 *
 * Why this matters: the calling agent cannot self-declare authority
 * by passing reviewer flags in `context`. The artifact is bound to
 * the exact action via `action_hash`, signed by a trusted issuer,
 * and replay-protected via `nonce`.
 */

/** What kind of principal performed the approval. */
export type PrincipalKind = "human" | "agent" | "service_account";

/** Identity of the reviewer recorded inside the artifact. */
export interface ApprovalReviewer {
  principal_id: string;
  principal_kind: PrincipalKind;
  email?: string;
  groups?: string[];
  roles?: string[];
}

/** Trusted issuer identification — used to look up the verification key. */
export interface ApprovalIssuer {
  type: "oidc" | "approval_service";
  issuer_id: string;
  kid: string;
}

/**
 * 21 CFR Part 11 §11.50(a)(2) signature meaning. Absent means the
 * runtime records the historical implied meaning `"approved"`.
 */
export type SignatureMeaning = "approved" | "reviewed" | "authored";

/** ADR CROSS-056 approval kind. Absent means an ordinary human approval. */
export type ApprovalKind = "single_human_over_machine";

/**
 * Entra tenant-binding and authority-mapping facts the runtime's
 * `v1-idp-broker` resolved when it minted an envelope through Entra ID.
 * Carried inside the signed envelope; `relation` is `"approve"` on
 * `approval_artifact.v1` and `"request"` on `actor_identity.v1`.
 * Schema: `contract/schemas/entra-provenance.schema.json`.
 */
export interface EntraProvenanceV1 {
  /** Verified Entra tenant id (the `tid` claim). */
  tenant_id: string;
  org_binding_id: string;
  mapping_id: string;
  /** Authority-mapping version at mint time. */
  mapping_version: number;
  relation: "request" | "approve";
}

// Re-exported here so the artifact's optional identity_assertion
// field type-checks at SDK boundaries without consumers having to
// know about a second module.
import type { IdentityAssertionV1 } from "./identityAssertion.js";
import type { ApproverGrantAssertionV1 } from "./approverGrantAssertion.js";

/**
 * The full signed approval artifact. Producers (approval services)
 * compute `action_hash` over the canonical action payload and sign
 * the artifact with the `signature` field stripped; the SDK does not
 * sign or verify, it only carries the artifact to the server.
 *
 * `identity_assertion` is REQUIRED on the wire whenever
 * `/v1-evaluate` calls the verifier with `requireIdentityAssertion:
 * true` — i.e. when human approval is required. Without it, the
 * server returns deny:`missing identity assertion`. The SDK type
 * keeps the field optional to support shadow / preflight flows that
 * inspect an artifact without verifying.
 */
export interface ApprovalArtifactV1 {
  version: "approval_artifact.v1";
  approval_id: string;
  tenant_id: string;
  action_type: string;
  resource_id: string;
  action_hash: string;
  reviewer: ApprovalReviewer;
  issuer: ApprovalIssuer;
  issued_at: string;
  expires_at: string;
  nonce: string;
  signature: string;
  identity_assertion?: IdentityAssertionV1;
  /**
   * Optional, additive (atlasent-api#3876): the console-signed
   * approver_grant_assertion.v1 for the `atlasent_approver_grant`
   * basis. An alternative to `identity_assertion`; an artifact
   * carrying both is rejected by the runtime and by the schema.
   */
  approver_grant_assertion?: ApproverGrantAssertionV1;
  /**
   * Optional, additive (2026-10-03): §11.50(a)(2) signature meaning.
   * Signed. Absent means `"approved"`.
   */
  meaning?: SignatureMeaning;
  /**
   * Optional, additive (2026-10-03): present only on artifacts minted
   * through Entra ID for a governed action type. `relation` is always
   * `"approve"` here. Signed.
   */
  entra_provenance?: EntraProvenanceV1 & { relation: "approve" };
  /**
   * Optional, additive (ADR CROSS-056, 2026-10-03). Signed. Present
   * together with `subject_agent_identity_id` or not at all.
   */
  approval_kind?: ApprovalKind;
  /**
   * `agent_identities.id` (uuid) the approval is FOR. Required when
   * `approval_kind` is present; rejected without it. Signed.
   */
  subject_agent_identity_id?: string;
}

/**
 * Optional `approval` field on an evaluate request. Either embed the
 * full artifact, or pass an `approval_id` and let the server resolve
 * it from a side channel (preferred when the artifact is large).
 */
export interface ApprovalReference {
  approval_id?: string;
  artifact?: ApprovalArtifactV1;
}
