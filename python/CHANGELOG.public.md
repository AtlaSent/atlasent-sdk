### 2.20.0

- Added the `AtlaSentClient.clinical_trials` sub-client (`ClinicalTrialsClient`, in the new `atlasent.clinical_client` module) for the clinical trial unblinding gate.
- Read methods `list`, `get`, and `history` require the `clinical:read` scope.
- Write methods `blind`, `request_unblind`, `emergency_unblind`, and `verify_permit` require the `clinical:manage` scope.

### 2.19.0

- Added clinical trial blinding and unblinding wire types in `atlasent.clinical`: `ClinicalTrialBlind`, `ClinicalUnblindingEvent`, `ClinicalBlindRequest`, `ClinicalBlindResponse`, `ClinicalUnblindRequest`, `ClinicalEmergencyRequest`, `ClinicalMutationResponse`, `ClinicalTrialListResponse`, `ClinicalTrialGetResponse`, and `ClinicalHistoryResponse`.
- Added the `ClinicalBlindingStatus` and `ClinicalUnblindingEventType` literals.
- Added the helpers `is_unblinded()` and `latest_unblinding_event()`.
- All of these are exported from the top-level `atlasent` package.

### 2.18.0

- Added `AtlaSentClient.compliance_controls(*, framework=None, from_=None, to=None)` and its `AsyncAtlaSentClient` counterpart. They read the compliance control catalog, with live enforcement status per regulatory clause (`enforced`, `partial`, `not_enforced`, `no_data`, or `attested`). Requires the `compliance:read` scope.
- Added `AtlaSentClient.compliance_evidence_pack(*, framework, from_=None, to=None)` and its async counterpart, which fetch a signed compliance evidence pack for one framework. You can hash the returned `bundle` offline and compare it with `sha256`. The `signature`, `signing_status`, and `key_id` fields report the signing state.
- Added the result models `ComplianceControlsResult`, `ComplianceEvidencePackResult`, `ComplianceControl`, `ComplianceEvidenceControl`, `ComplianceEvidenceBundle`, `ComplianceSummary`, and `ComplianceWindow`, plus the `ComplianceControlStatus` literal.

### 2.17.0 — 2026-06-10

- Added `SmsOtpClient` (`atlasent.sms_otp`) for SMS OTP step-up authentication, with `send()` and `verify()` methods. It uses JWT session auth only, not API keys. Supported `action_context` values are `"break_glass"`, `"api_key_create"`, and `"governance_hold_approve"`.
- Added `UsageMeteringClient` (`atlasent.usage_metering`) for listing billable evaluation records (`list()`) and fetching aggregated usage summaries (`summary()`). Requires the `usage:read` scope.
- Both clients can be imported directly with `from atlasent import SmsOtpClient, UsageMeteringClient`.

### 2.16.0 — 2026-06-04

- Added the optional `EvaluateRequest.evaluation_profile` field (`"basic"`, `"standard"`, `"advanced"`, or `"enterprise"`). With `"basic"`, snapshot enforcement is skipped, while policy, risk envelope, and audit still run. The server treats unknown values as `"standard"`.
- Added the optional `EvaluateRequest.override` field for emergency overrides of snapshot hard blocks. It is only evaluated when `evaluation_profile` is `"advanced"` or `"enterprise"`. The `authority_actor_id` must hold the `override:execute` scope and must be different from `actor_id`.

### 2.15.0 — 2026-06-03

- Added the optional `EvaluateRequest.state_snapshot` field for attaching a system state snapshot to evaluate calls.
- The snapshot is required when the action class has `requires_state_snapshot=True`. If you omit it for such a class, the call returns `decision="deny"` with the deny code `SNAPSHOT_REQUIRED`.

### 2.14.0 — 2026-06-03

- Added `AtlaSentClient.get_license()`, which returns a `LicenseStatus` for self-hosted and air-gapped deployments. It reports `status`, `org_slug`, `posture`, `expires_at`, `grace_until`, `features`, and the capacity limits `eval_limit` and `seat_limit`.
- Added `AtlaSentClient.verify_license(blob)`, which returns a `LicenseVerifyResult`. A result with `valid=False` is returned rather than raised.
- `LicenseStatus` and `LicenseVerifyResult` are exported from the top-level `atlasent` package.

### 2.13.0 — 2026-05-28

- Added `TrustRootManager` (`atlasent.trust_root`). It loads a bundled trust-root snapshot at startup and refreshes it in the background from `https://keys.atlasent.io/.well-known/` every 4 hours. `get_global_trust_root_manager()` returns the process-wide instance, and `check_expiry()` returns `"ok"`, `"half_life"`, or `"expired"`.
- `verify_bundle()` now uses the global trust-root snapshot automatically when you don't pass a `trust_root` argument.
- Added the `BundleVerificationError` exception, the `"permit_signing_key_revoked"` value for `PermitOutcome`, and the `AtlaSentDeniedError.is_signing_key_revoked` property.
- **Breaking:** `verify_audit_bundle()` now raises `BundleVerificationError` on trust failures instead of returning a falsy result. In air-gapped environments, pass `allow_expired_snapshot=True` to opt out of expiry enforcement.

### 2.12.0 — 2026-05-28

- Added the `client.sso` sub-client (`SsoClient`) for managing SSO connections, JIT rules, SSO enforcement (`enforce`), and readiness status (`get_status`).
- Added the `client.access_governance_log` sub-client (`AccessGovernanceLogClient`), whose paginated `list()` accepts `limit`, `cursor`, `event_type`, `actor_id`, `from_`, and `to` filters.
- Added the `client.evidence_bundles` sub-client (`EvidenceBundlesClient`) with `list`, `create`, `get`, and `download` methods.
- Added the read-only `client.api_key` and `client.base_url` properties on `AtlaSentClient`.

### 2.11.0 — 2026-05-27

- Added the `atlasent.auth` module with `refresh_token()`, `refresh_with_idp()`, and `list_idp_connections()`.
- Added the `atlasent.scim_client` module (`ScimClient`, with `.users` and `.groups` sub-clients) for SCIM 2.0 provisioning.
- Added the `atlasent.evidence_bundle` module with `create_evidence_bundle()`, `get_evidence_bundle()`, and `download_evidence_bundle()`.
- Added `verify_evidence_bundle()` and `EvidenceVerificationResult` (in `atlasent.replay`) for verifying evidence bundles offline, without a call to the backend.
- Added the `DecisionValue` type alias, `Permit.permit_expires_at`, and `EvaluateResult.reasons`. When the server returns only a single `reason`, `reasons` holds it as a one-element list.

### 2.7.0 — 2026-05-24

- Added `EvaluateResult.risk_envelope` (`EvaluateRiskEnvelope`) with `weighted_score`, `engine_decision`, `envelope_decision`, `promoted`, `hard_blocks`, and `factors`. It is `None` on responses from older servers.
- Added `EvaluateRequest.explain`. Set it to `True` to have the server populate `risk_envelope.factors` with `EvaluateRiskEnvelopeFactor` entries.
- `EvaluateRiskEnvelope` and `EvaluateRiskEnvelopeFactor` are exported from `atlasent`.

### 2.6.0 — 2026-05-24

- Added `AtlaSentClient.replay(*, evaluation_id)`, which re-evaluates a recorded decision against its originally pinned policy bundle and engine version. Replay writes no audit record and mints no permit.
- Added the `ReplayResponse` model and the `ReplayVarianceKind` literal (`NONE`, `DECISION_CHANGED`, `ENVELOPE_DRIFT`, `POLICY_DRIFT`, `CHAIN_TAMPER`, `ENGINE_DRIFT`, and `BUNDLE_MISSING`).
- Fixed an `ImportError` when importing `atlasent.async_client`.

### 2.5.0 — 2026-05-22

- Added read methods for advisory governance agents on `AtlaSentClient` and `AsyncAtlaSentClient`: `list_governance_agents()`, `list_governance_findings(*, change_id, agent_slug=None)`, and `list_governance_evaluations(*, change_id, agent_slug=None)`.
- Added the `GovernanceAgent`, `GovernanceAgentFinding`, `GovernanceAgentEvaluation`, and `AgentEvidenceRef` models, plus the `highest_agent_finding_severity()` helper.

### 2.4.0 — 2026-05-14

- Added the `PRODUCTION_DEPLOY_ACTION` constant (`"production.deploy"`), the canonical Deploy Gate action.
- Examples and docstrings now use `"production.deploy"`. The legacy `"deployment.production"` action string still works.

### 2.2.0 — 2026-05-05

- Added identity assertion models: `IdentityAssertionV1`, `IdentityAssertionBinding`, `IdentityIssuer`, `IdentitySubject`, `IdentityIssuerKey`, and `IdentityTrustedIssuersConfig`.
- `ApprovalArtifactV1` gained an optional `identity_assertion` field. The server requires it whenever human approval is required.

### 2.1.0 — 2026-05-05

- Added approval artifact models, including `ApprovalArtifactV1`, `ApprovalReference`, and `PermitApprovalBinding`.
- `evaluate()` gained the `resource_id`, `amount`, `approval`, and `require_approval` keyword arguments, and `verify()` gained `require_approval`.
- Added `EvaluateResult.permit_approval`, `VerifyResult.consumed`, and `VerifyResult.approval`. If `consumed` is `True` on an `APPROVAL_LINKAGE_MISSING` result, the permit has been used up, so don't retry.

### 2.0.0 — 2026-04-30

- **Breaking:** The SDK now sends the canonical wire format (`action_type`, `actor_id`, `context`) and no longer includes `api_key` in request bodies. This requires an AtlaSent API deployment that accepts the canonical format.
- **Breaking:** `EvaluateResult.decision` is now a string (`"allow"`, `"deny"`, `"hold"`, or `"escalate"`) instead of a `bool`. The boolean is still available as `result.permitted`.
- Added canonical result attributes: `permit_token`, `request_id`, `expires_at`, and `denial` on `EvaluateResult`, and `valid`, `outcome`, and `verify_error_code` on `VerifyResult`. Legacy result attributes are still populated. Building `EvaluateRequest` or `VerifyRequest` with the legacy keyword names still works but emits a `DeprecationWarning`.
