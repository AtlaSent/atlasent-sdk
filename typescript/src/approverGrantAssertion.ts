/**
 * Public types for the AtlaSent **Approver Grant Assertion** — a
 * console-signed attestation that a console user holding a specific
 * approver grant approved one specific approval, after a server-side
 * step-up (MFA `aal2` or a console-verified password re-auth).
 *
 * Evidence for the `atlasent_approver_grant` approver basis
 * (atlasent-api#3863). In an `approval_artifact.v1` it takes the place
 * of `identity_assertion` — never both. The runtime admits it only
 * inside an approval reevaluation of the exact approval it is bound to.
 *
 * Wire-stable as `approver_grant_assertion.v1`. The contract lives in
 * `contract/schemas/approver-grant-assertion.schema.json` and mirrors
 * atlasent-api `_shared/approver_grant_assertion.ts`. Verification is
 * server-side only; the SDK exposes the types so callers can carry or
 * inspect the block. Added 2026-10-03 (atlasent-api#3876), additive.
 */

/** The console principal: (issuer.issuer_id, subject.principal_id). */
export interface ApproverGrantSubject {
  /** Console user id (lower-case UUID). */
  principal_id: string;
  principal_kind: "human";
}

/** Binds the assertion to one approval. */
export interface ApproverGrantBinding {
  approval_id: string;
  action_hash: string;
  action_type: string;
  tenant_id: string;
  environment: string;
}

/** The console's approver issuer; looked up in the runtime's
 *  APPROVER_GRANT_TRUSTED_ISSUERS. */
export interface ApproverGrantIssuer {
  issuer_id: string;
  kid: string;
}

export type ApproverGrantStepUp = "aal2" | "password_reauth";

export interface ApproverGrantAuthContext {
  /** Authenticator assurance level of the console session when minted. */
  acr: "aal1" | "aal2";
  /** Methods the session authenticated with (RFC 8176 style), 1..16. */
  amr: string[];
  step_up: ApproverGrantStepUp;
  step_up_at: string;
}

/** A complete signed approver grant assertion. */
export interface ApproverGrantAssertionV1 {
  version: "approver_grant_assertion.v1";
  basis: "atlasent_approver_grant";
  subject: ApproverGrantSubject;
  /** The approver grant the console read for this person (lower-case UUID). */
  grant_id: string;
  binding: ApproverGrantBinding;
  issuer: ApproverGrantIssuer;
  auth_context: ApproverGrantAuthContext;
  issued_at: string;
  expires_at: string;
  /** Single-use, 16..256 chars. */
  nonce: string;
  /** Ed25519 over the canonical JSON of every field except `signature`. */
  signature: string;
}
