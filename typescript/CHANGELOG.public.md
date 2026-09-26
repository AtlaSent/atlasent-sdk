### 2.21.2

- Fixed `protectStream()` to send the request body shape the streaming evaluate endpoint expects: a single-item `items` array (`{action_type, actor_id, context}`). The API key is now sent in the `Authorization` header and no longer in the request body.
- `parseSseStream()` now treats the `event: complete` frame as end-of-stream, in addition to `event: done`.
- `parseSseStream()` error frames now read the `error_code` field, falling back to `code`.
- Decision frames now prefer the `permit_token` field over the legacy `decision_id`.

### 2.21.1

- Fixed `evaluate()` silently dropping `evaluation_profile`, `override`, and `completion_proofs` from the request. These fields are now sent when set. Callers not using them are unaffected.

### 2.21.0

- New `AtlaSentClient.explainAuthority({ principalId, requestedScope, resourceId? })` read-only method. It returns `paths` (each matching authority mechanism: `direct_grant`, `delegation`, or `role_capability`) and `unresolved` findings.
- New `client.authorityIntelligence.integrityAudit(query?)` method, with an optional `decisionWindowDays` option (integer, 1–3650). Requires an API key with the `authority_intelligence:read` scope. Adds the `countFindingsByClassification()` helper and `IntegrityReport` and related types.
- `EvaluateResponse` gains optional `humanApprovalRequired` and `humanApprovalStatus` fields (`not_required`, `pending`, `satisfied`, `rejected`, `expired`, `revoked`). They are `undefined` on runtimes that do not emit them.
- `CrossOrgPermissionCheckResult` gains `trust_precheck_passed`, `authorizes_execution` (always `false`), `requires_local_authority_evaluation` (always `true`), and `conditions_evaluated`. New `summarizeTrustPrecheck()` helper.
- **Deprecated:** `allowed` and `summarizeCrossOrgPermission()` on cross-org permission checks, and `CrossOrgPermissionCheckRequest.identity_id`, which the server does not read.
- Added `NO_EXECUTION_WINDOW` and `OUTSIDE_EXECUTION_WINDOW` to `DENY_CODES`. Fixed `checkCrossOrgPermission()` and `listCrossOrgPermissionChecks()`, which called a path that returned 404. They now use `/v1/federation/permission-check[s]`.

### 2.20.0

- `EvaluateRequest` now uses the canonical `actor_id` and `action_type` field names.
- **Deprecated:** `agent` and `action` on `EvaluateRequest`. They are still accepted as aliases and emit a one-time `console.warn`. They will be removed in a future major release. The request sent over the wire is unchanged.
- New `resolveEvaluateIdentity(input)` helper resolves `{ action_type, actor_id }` from either the canonical or the legacy input shape. `evaluate()`, `evaluatePreflight()`, and `protectStream()` all accept both shapes.

### 2.19.0

- New `client.clinicalTrials` sub-client for the clinical trial unblinding gate. It provides `list`, `get`, and `history` (require `clinical:read`), plus `blind`, `requestUnblind`, `emergencyUnblind`, and `verifyPermit` (require `clinical:manage`).

### 2.18.0

- New `AtlaSentClient.complianceControls({ framework?, from?, to? })` method. It reads the compliance control catalog with a live enforcement status for each clause (`enforced`, `partial`, `not_enforced`, `no_data`, `attested`). Requires the `compliance:read` scope.
- New `AtlaSentClient.complianceEvidencePack({ framework, from?, to? })` method. It fetches a signed compliance evidence pack for one framework. The returned `bundle` can be hashed offline against `sha256`, and `signature`, `signingStatus`, and `keyId` carry the signing state.

### 2.17.0 — 2026-06-10

- New `client.smsOtp` sub-client with `send()` and `verify()` for one-time-passcode step-up authentication (`break_glass`, `api_key_create`, `governance_hold_approve`). It requires JWT session auth and does not accept API keys.
- New `client.usageMetering` sub-client with `list()` for paginated billable evaluation records and `summary()` for usage aggregated by billing period. Requires the `usage:read` scope.

### 2.16.0 — 2026-06-04

- New optional `evaluation_profile` field (`EvaluationProfile`) on `EvaluateRequest` controls which evaluation layers run. Pass `"basic"` to skip snapshot enforcement. Unknown values fall back to `"standard"` on the server.
- New optional `override` field (`EmergencyOverrideV1`) on `EvaluateRequest` for an emergency override that clears snapshot hard blocks. It is only evaluated when `evaluation_profile` is `"advanced"` or `"enterprise"`, and `authority_actor_id` must differ from `actor_id`.

### 2.15.0 — 2026-06-04

- New `client.submitAssertion()` submits a point-in-time fact from an external source (e.g. GitHub, Stripe, Slack) so that policy rules can gate on it during evaluation. It returns `assertion_id`, `payload_hash`, and `reused`. Requires the `assertions:write` scope.

### 2.14.0 — 2026-06-03

- New optional `state_snapshot` field on `EvaluateRequest`. Action classes that require a state snapshot return `decision: "deny"` with `deny_code: "SNAPSHOT_REQUIRED"` when it is omitted. The snapshot is recorded in the audit chain alongside the permit.

### 2.13.0 — 2026-06-03

- New `client.getLicense()` and `client.verifyLicense(blob)` methods for self-hosted and air-gapped deployments, with new `LicenseStatus` and `LicenseVerifyResult` types. A `valid: false` verification result is returned, not thrown.

### 2.12.0 — 2026-05-28

- The SDK now includes a trust-root snapshot and a `TrustRootManager` that refreshes it in the background every 4 hours. `getGlobalTrustRootManager()` returns a shared instance, and `checkExpiry()` reports `"ok"`, `"half_life"`, or `"expired"`.
- `verifyBundle()` uses the global trust-root snapshot automatically when no `trustRoot` option is passed.
- **Breaking:** `verifyAuditBundle()` now throws `BundleVerificationError` when the trust snapshot has expired, instead of returning `{ verified: false }`. Pass `allowExpiredSnapshot: true` to opt out, e.g. in air-gapped environments.
- Revoked signing keys and keys with the wrong role are now rejected with `BundleVerificationError` (`reason: "key_revoked"` or `"key_role_mismatch"`). Adds the `"permit_signing_key_revoked"` `PermitOutcome` and the `AtlaSentDeniedError.isSigningKeyRevoked` getter.

### 2.11.0 — 2026-05-27

- New sub-clients: `client.auth` (`refresh`, `refreshWithIdp`, `listIdpConnections`), `client.scim` (SCIM 2.0 users and groups), and `client.evidenceBundles` (`create`, `get`, `download`).
- New exported `Decision` type (`"allow" | "deny" | "hold" | "escalate"`), `Permit.permitExpiresAt`, and `EvaluateResult.reasons` (a `string[]` alongside `reason`).
- New `verifyEvidenceBundle(bundle)` function verifies an evidence bundle offline.
- Retries on transient errors now use full-jitter exponential back-off.
- The SDK now warns when it runs in a browser, because API keys should not be used client-side. Suppress the warning with `suppressBrowserWarning: true`.

### 2.9.0 — 2026-05-25

- `AtlaSentDeniedError` now carries an `outcome` field (`PermitOutcome`) with the `isRevoked`, `isExpired`, `isConsumed`, and `isNotFound` predicates. Also adds the `normalizePermitOutcome(raw)` helper.
- `protect()` and `protectWithEvidence()` now validate the `action` format before making a network call, and throw `AtlaSentError` with `code: "bad_request"` if it is invalid.
- Evaluate responses now include a `riskEnvelope` with the composite risk score. Pass `explain: true` to get the per-factor breakdown in `riskEnvelope.factors`.

### 2.8.0 — 2026-05-24

- New `client.replay({ evaluationId })` re-evaluates a recorded decision against its originally pinned policy bundle. It reports variance kinds such as `POLICY_DRIFT`, `ENGINE_DRIFT`, and `BUNDLE_MISSING` without throwing.

### 2.7.0 — 2026-05-24

- New `client.replayDecision(decisionId)` re-evaluates a recorded decision against its originally pinned policy bundle and engine version. It reports a `variance` of `NONE`, `DECISION_CHANGED`, or `ENVELOPE_DRIFT`. No permit is issued. The underlying endpoint is alpha, so its shapes may change.
