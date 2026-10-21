/**
 * Typed `verify_error_code` values returned by `POST /v1-verify-permit`.
 *
 * Mirrors atlasent-api's verify error-code catalog
 * (`packages/deny-codes/src/verify-codes.ts`, `VERIFY_ERROR_CODES`), which a
 * CI guard there keeps equal to what the verifier actually emits. The wire
 * field stays an open string: a newer runtime can return a code this SDK
 * release does not know. Treat an unknown code as a denial, never as success.
 * `python/atlasent/verify_error_codes.py` carries the same list, and
 * `contract/vectors/verify-error-codes.json` pins both.
 */

/** Codes the current verifier emits. */
export const VERIFY_ERROR_CODES = [
  "MISSING_PERMIT",
  "INVALID_SIGNATURE",
  "PERMIT_NOT_FOUND",
  "PERMIT_NOT_ALLOWED",
  "PERMIT_EXPIRED",
  "PERMIT_NOT_FRESH",
  "PERMIT_ALREADY_USED",
  "PERMIT_REVOKED",
  "PERMIT_BINDING_MISMATCH",
  "PERMIT_UNBOUND_EXECUTION",
  "ORG_MISMATCH",
  "ACTOR_MISMATCH",
  "ACTOR_REQUIRED",
  "ACTOR_IDENTITY_REQUIRED",
  "ACTOR_IDENTITY_INVALID",
  "EXECUTION_PRINCIPAL_BINDING_UNAVAILABLE",
  "EXECUTION_PRINCIPAL_BINDING_INVALID",
  "ACTION_TYPE_MISMATCH",
  "ENVIRONMENT_MISMATCH",
  "ENVIRONMENT_REQUIRED",
  "AWS_LOCUS_MISMATCH",
  "AZURE_LOCUS_MISMATCH",
  "ENTRA_AUTHORITY_STALE",
  "ENVELOPE_HASH_MISMATCH",
  "CDO_HASH_MISMATCH",
  "CDO_LOOKUP_FAILED",
  "PAYLOAD_HASH_REQUIRED",
  "PAYLOAD_MISMATCH",
  "AUTHORIZATION_STATE_CHANGED",
  "MATERIAL_EXECUTION_FIELDS_POLICY_LOOKUP_FAILED",
  "MATERIAL_EXECUTION_FIELDS_POLICY_CHANGED",
  "APPROVAL_LINKAGE_MISSING",
  "AUDIT_EVIDENCE_MISSING",
  "AUDIT_EVIDENCE_WRITE_FAILED",
  "DELEGATION_CHAIN_ERROR",
  "DELEGATION_CHAIN_BROKEN",
  "DELEGATION_DEPTH_EXCEEDED",
  "PARENT_PERMIT_REVOKED",
  "ASYNC_WINDOW_EXPIRED",
  "ASYNC_PERMIT_CONSUMED",
  "SAFETY_HOLD",
  "WORKLOAD_ATTESTATION_MISSING",
  "WORKLOAD_ATTESTATION_MALFORMED",
  "WORKLOAD_ATTESTATION_UNKNOWN_KEY",
  "WORKLOAD_ATTESTATION_BAD_SIGNATURE",
  "WORKLOAD_ATTESTATION_EXPIRED",
  "WORKLOAD_ATTESTATION_WRONG_TARGET",
  "WORKLOAD_ATTESTATION_BODY_MISMATCH",
  "WORKLOAD_ATTESTATION_REPLAYED",
  "WORKLOAD_ATTESTATION_WORKLOAD_MISMATCH",
  "WORKLOAD_ATTESTATION_UNAVAILABLE",
  "INTERNAL_ERROR",
] as const;

/** Documented in the frozen V1 enum but never set by the current verifier. */
export const LEGACY_VERIFY_ERROR_CODES = [
  "UNAUTHORIZED",
  "INVALID_API_KEY",
  "INSUFFICIENT_SCOPE",
  "RATE_LIMITED",
  "EXECUTION_HASH_REQUIRED",
  "EXECUTION_HASH_MISMATCH",
] as const;

export type VerifyErrorCode =
  | (typeof VERIFY_ERROR_CODES)[number]
  | (typeof LEGACY_VERIFY_ERROR_CODES)[number];

const KNOWN: ReadonlySet<string> = new Set<string>([
  ...VERIFY_ERROR_CODES,
  ...LEGACY_VERIFY_ERROR_CODES,
]);

/** True when `code` is a verify error code this SDK release knows. */
export function isVerifyErrorCode(code: unknown): code is VerifyErrorCode {
  return typeof code === "string" && KNOWN.has(code);
}

/**
 * Codes whose catalog retry advice is `transient`: a verifier or store fault,
 * not a judgement about the permit. Retrying the SAME permit may succeed.
 * Every other code means this permit will not verify as presented.
 */
export const TRANSIENT_VERIFY_ERROR_CODES: ReadonlySet<VerifyErrorCode> = new Set<VerifyErrorCode>([
  "EXECUTION_PRINCIPAL_BINDING_UNAVAILABLE",
  "CDO_LOOKUP_FAILED",
  "MATERIAL_EXECUTION_FIELDS_POLICY_LOOKUP_FAILED",
  "AUDIT_EVIDENCE_WRITE_FAILED",
  "DELEGATION_CHAIN_ERROR",
  "WORKLOAD_ATTESTATION_UNAVAILABLE",
  "INTERNAL_ERROR",
]);
