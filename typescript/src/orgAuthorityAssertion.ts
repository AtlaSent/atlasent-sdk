/**
 * Public types for the AtlaSent **Org Authority Assertion** — a
 * console-signed attestation that an owner or admin of the approval's
 * org approved one specific approval, after a server-side step-up (MFA
 * `aal2` or a console-verified password re-auth).
 *
 * Evidence for the `atlasent_verified_org_authority` approver basis
 * (atlasent-api#3798, B2a). In an `approval_artifact.v1` it takes the
 * place of `identity_assertion` and `approver_grant_assertion` — never
 * alongside either. The runtime admits it only inside an approval
 * reevaluation of the exact approval it is bound to, and only for an
 * `org_role` the approval's snapshot admits.
 *
 * Wire-stable as `org_authority_assertion.v1`. The contract lives in
 * `contract/schemas/org-authority-assertion.schema.json` and mirrors
 * atlasent-api `_shared/org_authority_assertion.ts`. Verification is
 * server-side only; the SDK exposes the types so callers can carry or
 * inspect the block. Added 2026-10-03, additive.
 */

export interface OrgAuthoritySubject {
  /** Runtime principal the console user maps to. */
  principal_id: string;
  principal_kind: "human";
  /** Console user id. */
  console_user_id: string;
}

export type OrgAuthorityRole = "owner" | "admin";

/** Binds the assertion to one approval. */
export interface OrgAuthorityBinding {
  approval_id: string;
  action_hash: string;
  tenant_id: string;
  environment: string;
}

/** The console's org-authority issuer; looked up in the runtime's
 *  ORG_AUTHORITY_TRUSTED_ISSUERS. */
export interface OrgAuthorityIssuer {
  issuer_id: string;
  kid: string;
}

export type OrgAuthorityStepUp = "aal2" | "password_reauth";

export interface OrgAuthorityAuthContext {
  step_up: OrgAuthorityStepUp;
  step_up_at: string;
}

/** A complete signed org authority assertion. */
export interface OrgAuthorityAssertionV1 {
  version: "org_authority_assertion.v1";
  basis: "atlasent_verified_org_authority";
  subject: OrgAuthoritySubject;
  org_role: OrgAuthorityRole;
  binding: OrgAuthorityBinding;
  issuer: OrgAuthorityIssuer;
  auth_context: OrgAuthorityAuthContext;
  issued_at: string;
  expires_at: string;
  /** Single-use, 16..256 chars. */
  nonce: string;
  /** Ed25519 (base64url, no padding) over the canonical JSON of every
   *  field except `signature`. */
  signature: string;
}
