"""AtlaSent SDK — execution-time authorization for AI agents.

Fail-closed by design: any failure to confirm authorization raises
an exception, so no action can proceed without an explicit permit.

Quick start::

    from atlasent import protect

    permit = protect(
        agent="deploy-bot",
        action="production.deploy",
        context={"commit": commit, "approver": approver},
    )
    # If we got here, the action is authorized end-to-end.
    # Otherwise protect() raised and the action never ran.

Canonical surface — three primitives, each with a distinct
lifecycle:

- :func:`atlasent.protect` — fail-closed execution primitive.
  Use when the caller wants "no permit, no execution." Raises on
  ``deny``, ``hold``, ``escalate``, or verification failure.
- :func:`atlasent.evaluate` — raw decision primitive. Use when the
  caller needs to inspect the four-value decision
  (``allow`` / ``deny`` / ``hold`` / ``escalate``). Does not
  collapse states; does not pretend denial is a permit path.
- :func:`atlasent.verify` — post-permit verification primitive,
  for callers that already hold a permit token.

``authorize()`` and ``gate()`` are deprecated legacy convenience
wrappers and will be removed in ``atlasent`` v3. Migrate to
``protect()`` (for fail-closed) or ``evaluate()`` (to inspect).

Lazy import surface (PEP 562)
-----------------------------
Top-level names are resolved **lazily** via :func:`__getattr__`: a name
is only imported from its submodule on first access. This keeps
``import atlasent`` (and, in particular, the network-free offline
verifier CLI ``atlasent-verify-bundle``) from eagerly pulling in the
HTTP client stack (``httpx``) or other heavy dependencies. The offline
``verify_evidence_bundle`` path needs only ``cryptography`` + the
standard library; lazy loading makes that true at import time, not just
at call time. The public surface (``__all__``) and attribute access
(``atlasent.protect``, etc.) are unchanged — only the *timing* of the
underlying imports moved.
"""

from __future__ import annotations

import importlib as _importlib
import sys as _sys
import types as _types
from typing import TYPE_CHECKING

from ._version import __version__

#: Canonical Deploy Gate V1 protected action. Mirrors the TypeScript
#: SDK's ``PRODUCTION_DEPLOY_ACTION``. Use this string (or the constant)
#: when calling ``protect()``/``evaluate()`` for the production deploy
#: gate; the server alias-tolerates the legacy ``deployment.production``
#: during the V1 alias window.
PRODUCTION_DEPLOY_ACTION = "production.deploy"

# ─── Lazy name → submodule map (PEP 562) ──────────────────────────────
# One entry per original ``from .<module> import (...)`` statement. The
# public name equals the source attribute except for the handful of
# aliased re-exports captured in ``_LAZY_ALIASES`` below.
_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    "._function_region": (
        "DEFAULT_FUNCTION_REGION",
        "FUNCTION_REGION_ENV",
        "SUPPORTED_FUNCTION_REGIONS",
        "FunctionRegionConfigError",
    ),
    ".access_governance_log": ("AccessGovernanceLogClient",),
    ".approval_artifact": (
        "ApprovalArtifactV1",
        "ApprovalIssuer",
        "ApprovalQuorumV1",
        "ApprovalReference",
        "ApprovalReviewer",
        "ApprovalTrustedIssuersConfig",
        "ApproverGrantAssertionV1",
        "ApproverGrantAuthContext",
        "ApproverGrantBinding",
        "ApproverGrantIssuer",
        "ApproverGrantSubject",
        "IdentityAssertionBinding",
        "IdentityAssertionV1",
        "IdentityIssuer",
        "IdentityIssuerKey",
        "IdentitySubject",
        "IdentityTrustedIssuersConfig",
        "PermitApprovalBinding",
        "PrincipalKind",
        "QuorumIndependence",
        "QuorumPolicy",
        "QuorumProof",
        "QuorumRoleRequirement",
        "TrustedIssuerKey",
    ),
    ".async_client": ("AsyncAtlaSentClient",),
    ".audit": (
        "AuditDecision",
        "AuditEvent",
        "AuditEventsResult",
        "AuditExportResult",
        "AuditExportSignatureStatus",
    ),
    ".audit_bundle": (
        "BundleVerificationResult",
        "VerifyKey",
        "verify_audit_bundle",
        "verify_bundle",
    ),
    ".authentication_assurance": (
        "ActionClassRequirement",
        "AssuranceEvaluationOutcome",
        "AssuranceEvaluationOutcomeAllow",
        "AssuranceEvaluationOutcomeNonAllow",
        "AssuranceRequirementLayer",
        "AssuranceResolutionReason",
        "AssuranceResolutionStatus",
        "AuthenticationAssuranceEvidence",
        "AuthenticationAssuranceOutcomeCode",
        "AuthenticationAssuranceRequirement",
        "EffectiveAssurancePredicateEntry",
        "EffectiveAuthenticationAssuranceRequirement",
        "ExternalObligationRequirement",
        "MethodProvenance",
        "OrganizationRequirement",
        "PredicateInstance",
        "PredicateRegistryEntry",
        "ResourceContextCondition",
        "ResourceContextConditionMatch",
        "ResourceContextRequirement",
        "is_authentication_assurance_outcome_code",
        "is_authentication_assurance_requirement",
        "matches_resource_context_condition",
        "validate_authentication_assurance_evidence",
        "validate_authentication_assurance_requirement",
    ),
    # NOTE: the module's ``authority_intelligence()`` factory is deliberately
    # NOT re-exported at package level. Doing so would make the export name
    # collide with the submodule name (``atlasent.authority_intelligence``),
    # joining the ``authorize`` / ``with_permit`` / ``require_permit`` special
    # case for no benefit — the documented access path is the
    # ``client.authority_intelligence`` attribute, and the factory stays
    # importable as ``from atlasent.authority_intelligence import …``.
    ".authority_intelligence": (
        "AuthorityIntelligenceClient",
        "IntegrityFinding",
        "IntegrityReport",
        "count_findings_by_classification",
    ),
    ".authorize": ("authorize", "evaluate", "gate", "protect", "verify"),
    ".bccae": ("BCCAEClient", "generate_bccae_nonce"),
    ".billing": (
        "AccessStatus",
        "AdminOverrideRequest",
        "AdminOverrideResponse",
        "AllowedAction",
        "AsyncBillingClient",
        "BillingClient",
        "BillingEntitlement",
        "BillingMode",
        "BillingWebhookSubscription",
        "DenyReason",
        "InvoiceStatus",
        "verify_billing_webhook_signature",
    ),
    ".cache": ("TTLCache",),
    ".claim_lineage": (
        "NOT_APPLICABLE",
        "ActionBundleInput",
        "ActionBundleReceipt",
        "ApprovalArtifactSlot",
        "ClaimEvidenceLink",
        "DeltaSlot",
        "DeltaStatus",
        "DeployEvidenceInput",
        "DeployEvidenceSlot",
        "DriftChangeType",
        "DriftDetail",
        "DriftSeverity",
        "EvidenceSlotStatus",
        "HitlChainSummaryInput",
        "IntegrationEvidenceInput",
        "IntegrationEvidenceSlot",
        "NotApplicable",
        "RuntimeEvidenceInput",
        "RuntimeEvidenceSlot",
        "SignedApprovalArtifactInput",
        "VerificationChecklist",
        "VerifyClaimEvidenceLinkResult",
        "build_claim_evidence_link",
        "build_claim_evidence_link_from_action_bundle",
        "verify_claim_evidence_link",
    ),
    ".client": ("AtlaSentClient",),
    ".clinical": (
        "ClinicalBlindRequest",
        "ClinicalBlindResponse",
        "ClinicalBlindingStatus",
        "ClinicalEmergencyRequest",
        "ClinicalHistoryResponse",
        "ClinicalMutationResponse",
        "ClinicalTrialBlind",
        "ClinicalTrialGetResponse",
        "ClinicalTrialListResponse",
        "ClinicalUnblindRequest",
        "ClinicalUnblindingEvent",
        "ClinicalUnblindingEventType",
        "is_unblinded",
        "latest_unblinding_event",
    ),
    ".clinical_client": ("ClinicalTrialsClient",),
    ".compliance_evidence": (
        "ComplianceEvidenceRun",
        "ControlStatus",
        "EvidenceControl",
        "EvidenceRunSummary",
        "SOC2ControlId",
        "evidence_run_passes",
        "non_passing_controls",
    ),
    ".config": ("configure",),
    ".context_envelope": (
        "CONTEXT_NAMESPACES",
        "RESOURCE_ASSERTION_TRUST_LEVELS",
        "ContextEnvelope",
        "ContextNamespaceEntry",
        "ContextSignal",
        "RecordContextEnvelopeInput",
        "ResourceClassificationAssertion",
        "validate_resource_classification_assertion",
    ),
    ".deny_codes": ("DenyCode", "requires_human_approval"),
    ".evidence_engine": (
        "ActionEvidenceBundle",
        "ComplianceControlCoverage",
        "DecisionReceipt",
        "DecisionReceiptPayload",
        "WhyPolicyEvaluation",
        "WhyStage",
        "WhyTrace",
    ),
    ".evidence_exports": (
        "create_evidence_export",
        "get_evidence_export",
        "list_evidence_exports",
    ),
    ".exceptions": (
        "AtlaSentDecision",
        "AtlaSentDenied",
        "AtlaSentDeniedError",
        "AtlaSentError",
        "AtlaSentErrorCode",
        "AtlaSentPermitMintFailedError",
        "BundleVerificationError",
        "ConfigurationError",
        "PermissionDeniedError",
        "PermitOutcome",
        "RateLimitError",
        "StreamParseError",
        "StreamTimeoutError",
    ),
    ".governance_agents": (
        "AgentEvidenceRef",
        "GovernanceAgent",
        "GovernanceAgentEvaluation",
        "GovernanceAgentFinding",
        "ListGovernanceAgentsResult",
        "ListGovernanceEvaluationsResult",
        "ListGovernanceFindingsResult",
        "highest_agent_finding_severity",
    ),
    ".governance_webhooks": (
        "EnforcementWebhookEvent",
        "GovernanceWebhookEvent",
        "WebhookDelivery",
        "WebhookDeliveryStatus",
        "WebhookPayload",
        "WebhookSubscription",
        "verify_webhook_signature",
    ),
    ".guard": ("async_atlasent_guard", "atlasent_guard"),
    ".hitl": (
        "HitlApprovalRecord",
        "HitlApprovalsResult",
        "HitlChainHop",
        "HitlChainResult",
        "HitlCreateRequest",
        "HitlEscalation",
        "HitlEscalationResult",
        "HitlFallbackDecision",
        "HitlQuorumProgress",
        "HitlQuorumTier",
        "HitlStatus",
        "ListHitlEscalationsResult",
        "hitl_required_approver_count",
    ),
    ".models": (
        "ApiKeySelfResult",
        "AuthError",
        "AuthorityExplanationPath",
        "AuthorityUnresolvedFinding",
        "AuthorizationResult",
        "CompletionProof",
        "ComplianceControl",
        "ComplianceControlsResult",
        "ComplianceControlStatus",
        "ComplianceEvidenceBundle",
        "ComplianceEvidenceControl",
        "ComplianceEvidencePackResult",
        "ComplianceSummary",
        "ComplianceWindow",
        "ConstraintTrace",
        "ConstraintTracePolicy",
        "ConstraintTraceStage",
        "DecisionValue",
        "EnforcementOutcome",
        "EvaluatePreflightResult",
        "EvaluateResult",
        "EvaluateRiskEnvelope",
        "EvaluateRiskEnvelopeFactor",
        "ExplainAuthorityResult",
        "GateResult",
        "GetPermitResult",
        "GovernanceDecision",
        "LicenseStatus",
        "LicenseVerifyResult",
        "ListPermitsResult",
        "Permit",
        "PermitRecord",
        "PermitVerifyEvidence",
        "RateLimitState",
        "ReplayResponse",
        "ReplayVarianceKind",
        "RevokePermitByIdResult",
        "RevokePermitResult",
        "StreamDecisionEvent",
        "StreamEvent",
        "StreamProgressEvent",
        "VerifyPermitByIdResult",
        "VerifyResult",
    ),
    ".policy_sync": (
        "PolicyBundleEntry",
        "PolicySyncDiff",
        "PolicySyncRun",
        "PolicySyncStatus",
        "SubmitPolicySyncRequest",
        "format_policy_sync_diff",
        "is_policy_sync_terminal",
    ),
    ".replay": ("EvidenceVerificationResult", "verify_evidence_bundle"),
    ".require_permit": (
        "CanonicalProtectedActionType",
        "ProtectedAction",
        "classify_command",
        "require_permit",
    ),
    ".runtime_v2": (
        "AuditChainPage",
        "AuthorityRecord",
        "AuthorizationDecision",
        "ChainIntegrityReport",
        "ComplianceExport",
        "ExecutionReceipt",
        "PostExecutionResult",
        "RuntimeAuditEntry",
        "RuntimeV2Client",
        "VerificationFailure",
        "VerificationResult",
        "runtime",
    ),
    ".scim": (
        "SCIM_GROUP_SCHEMA",
        "SCIM_PATCH_OP_SCHEMA",
        "SCIM_USER_SCHEMA",
        "scim_create_group",
        "scim_create_user",
        "scim_delete_group",
        "scim_delete_user",
        "scim_get_group",
        "scim_get_user",
        "scim_list_groups",
        "scim_list_users",
        "scim_patch_group",
        "scim_patch_user",
        "scim_replace_group",
        "scim_replace_user",
    ),
    ".siem": ("get_siem_config", "siem_test_delivery", "upsert_siem_config"),
    ".sms_otp": ("SmsOtpClient",),
    ".sso_client": ("SsoClient",),
    ".taxonomy": (
        "ACTION_CLASS_FAMILIES",
        "CONDITION_TYPES",
        "REASON_CODES",
        "TAXONOMY_SCHEMA_VERSION",
        "family_for_slug",
        "get_reason_code",
        "is_action_class_family_id",
        "is_condition_type_id",
        "is_reason_code",
    ),
    ".trust_root": (
        "TrustRootKey",
        "TrustRootManager",
        "TrustRootRevocationEntry",
        "TrustRootSnapshot",
        "_set_global_trust_root_manager_for_tests",
        "get_global_trust_root_manager",
    ),
    ".usage_metering": ("UsageMeteringClient",),
    ".v2_endpoints": (
        "EvaluateBatchItem",
        "EvaluateBatchResponse",
        "FeatureNotEnabledError",
        "GraphQLResponse",
        "StreamComplete",
        "StreamDecision",
        "StreamErrorFrame",
        "authorize_stream",
        "evaluate_many",
        "graphql",
    ),
    ".verify_permit_v4": (
        "PermitClaimsV4",
        "PermitV4VerifyError",
        "PermitV4VerifyResult",
        "verify_permit_v4",
    ),
    ".verticals.access_cert": (
        "protect_access_cert_action",
        "protect_access_cert_revoke",
    ),
    ".verticals.contract_actions": (
        "protect_contract_action",
        "protect_contract_execution",
    ),
    ".verticals.data_delete": ("protect_customer_data_delete",),
    ".verticals.database_actions": (
        "protect_database_action",
        "protect_database_migration",
        "protect_database_schema_drop",
        "protect_database_table_delete",
    ),
    ".verticals.financial_close": (
        "protect_financial_close_action",
        "protect_period_close_certify",
    ),
    ".verticals.gxp_actions": (
        "TrialActionType",
        "TrialBlindingActionType",
        "TrialDenialEvidence",
        "TrialPermitEvidence",
        "TrialUnblindingActionType",
        "protect_trial_action",
        "protect_trial_blinding_setup",
        "protect_trial_unblinding_emergency",
        "protect_trial_unblinding_execute",
    ),
    ".verticals.hr_actions": (
        "protect_hr_action",
        "protect_hr_offboard",
        "protect_hr_role_escalate",
    ),
    ".verticals.model_governance": (
        "protect_model_governance",
        "protect_model_promotion",
    ),
    ".verticals.pricing_actions": (
        "protect_pricing_action",
        "protect_pricing_rule",
    ),
    ".verticals.security_actions": (
        "protect_security_access_quarantine",
        "protect_security_action",
        "protect_security_incident_escalate",
    ),
    ".webhook": ("WebhookVerificationError", "assert_webhook", "verify_webhook"),
    ".with_permit": ("with_permit",),
}

#: Public re-exports whose exposed name differs from the source attribute
#: (module, source_attr). The V2 path constants are namespaced on export.
_LAZY_ALIASES: dict[str, tuple[str, str]] = {
    "V2_BATCH_PATH": (".v2_endpoints", "BATCH_PATH"),
    "V2_STREAM_PATH": (".v2_endpoints", "STREAM_PATH"),
    "V2_GRAPHQL_PATH": (".v2_endpoints", "GRAPHQL_PATH"),
    "V2_MAX_BATCH_ITEMS": (".v2_endpoints", "MAX_BATCH_ITEMS"),
}

# Inverted lookup: public name → submodule (built once, no imports).
_LAZY: dict[str, str] = {}
for _module, _names in _LAZY_MODULES.items():
    for _name in _names:
        _LAZY[_name] = _module
del _module, _names, _name

# Names that are BOTH an exported symbol and a submodule (e.g. ``authorize``
# is the function from ``.authorize`` and the submodule ``atlasent.authorize``).
# Importing the submodule anywhere binds the *module* onto this package, which
# would shadow the callable and break the documented contract
# ("`from atlasent import authorize` returns the function; reach the module via
# sys.modules"). The custom module class below forces these to resolve to the
# exported symbol on every access. Computed, so a future collision is covered.
_COLLISION_EXPORTS: frozenset[str] = frozenset(
    name for name in _LAZY if f".{name}" in _LAZY_MODULES
)


class _LazyExportModule(_types.ModuleType):
    """Module type keeping same-named exports winning over submodules.

    Everything not in ``_COLLISION_EXPORTS`` defers to the normal module
    attribute machinery, including the PEP 562 ``__getattr__`` lazy loader
    below (``super().__getattribute__`` triggers it on AttributeError).
    """

    def __getattribute__(self, name: str) -> object:
        if name in _COLLISION_EXPORTS:
            module = _importlib.import_module(_LAZY[name], "atlasent")
            return getattr(module, name)
        return super().__getattribute__(name)


_sys.modules[__name__].__class__ = _LazyExportModule


def __getattr__(name: str) -> object:
    """Lazily import a top-level export on first access (PEP 562).

    Resolves ``name`` to its owning submodule, imports that submodule,
    binds the value into this module's namespace (so subsequent lookups
    skip this path), and returns it. Unknown names raise ``AttributeError``
    so ``hasattr`` / introspection behave normally.
    """
    import importlib

    alias = _LAZY_ALIASES.get(name)
    if alias is not None:
        module_name, source_attr = alias
        module = importlib.import_module(module_name, __name__)
        value = getattr(module, source_attr)
        globals()[name] = value
        return value

    module_name = _LAZY.get(name)
    if module_name is not None:
        module = importlib.import_module(module_name, __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value

    # Submodule access (e.g. ``atlasent.taxonomy``). Eager imports used to
    # bind every referenced submodule onto the package as a side effect;
    # under lazy loading we import it on demand so ``atlasent.<submodule>``
    # keeps working. A genuine typo raises ImportError → AttributeError.
    if not name.startswith("_"):
        try:
            module = importlib.import_module(f".{name}", __name__)
        except ImportError:
            pass
        else:
            globals()[name] = module
            return module

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Expose the full public surface for tab-completion / introspection."""
    return sorted(set(__all__) | set(globals()))


# Static-analysis surface: type checkers and IDEs read these eager imports
# under TYPE_CHECKING (never executed at runtime, so no httpx/pydantic load).
if TYPE_CHECKING:
    from ._function_region import (
        DEFAULT_FUNCTION_REGION,
        FUNCTION_REGION_ENV,
        SUPPORTED_FUNCTION_REGIONS,
        FunctionRegionConfigError,
    )
    from .access_governance_log import AccessGovernanceLogClient
    from .approval_artifact import (
        ApprovalArtifactV1,
        ApprovalIssuer,
        ApprovalQuorumV1,
        ApprovalReference,
        ApprovalReviewer,
        ApprovalTrustedIssuersConfig,
        ApproverGrantAssertionV1,
        ApproverGrantAuthContext,
        ApproverGrantBinding,
        ApproverGrantIssuer,
        ApproverGrantSubject,
        IdentityAssertionBinding,
        IdentityAssertionV1,
        IdentityIssuer,
        IdentityIssuerKey,
        IdentitySubject,
        IdentityTrustedIssuersConfig,
        PermitApprovalBinding,
        PrincipalKind,
        QuorumIndependence,
        QuorumPolicy,
        QuorumProof,
        QuorumRoleRequirement,
        TrustedIssuerKey,
    )
    from .async_client import AsyncAtlaSentClient
    from .audit import (
        AuditDecision,
        AuditEvent,
        AuditEventsResult,
        AuditExportResult,
        AuditExportSignatureStatus,
    )
    from .audit_bundle import (
        BundleVerificationResult,
        VerifyKey,
        verify_audit_bundle,
        verify_bundle,
    )
    from .authentication_assurance import (
        ActionClassRequirement,
        AssuranceEvaluationOutcome,
        AssuranceEvaluationOutcomeAllow,
        AssuranceEvaluationOutcomeNonAllow,
        AssuranceRequirementLayer,
        AssuranceResolutionReason,
        AssuranceResolutionStatus,
        AuthenticationAssuranceEvidence,
        AuthenticationAssuranceOutcomeCode,
        AuthenticationAssuranceRequirement,
        EffectiveAssurancePredicateEntry,
        EffectiveAuthenticationAssuranceRequirement,
        ExternalObligationRequirement,
        MethodProvenance,
        OrganizationRequirement,
        PredicateInstance,
        PredicateRegistryEntry,
        ResourceContextCondition,
        ResourceContextConditionMatch,
        ResourceContextRequirement,
        is_authentication_assurance_outcome_code,
        is_authentication_assurance_requirement,
        matches_resource_context_condition,
        validate_authentication_assurance_evidence,
        validate_authentication_assurance_requirement,
    )
    from .authority_intelligence import (
        AuthorityIntelligenceClient,
        IntegrityFinding,
        IntegrityReport,
        count_findings_by_classification,
    )
    from .authorize import authorize, evaluate, gate, protect, verify
    from .bccae import BCCAEClient, generate_bccae_nonce
    from .billing import (
        AccessStatus,
        AdminOverrideRequest,
        AdminOverrideResponse,
        AllowedAction,
        AsyncBillingClient,
        BillingClient,
        BillingEntitlement,
        BillingMode,
        BillingWebhookSubscription,
        DenyReason,
        InvoiceStatus,
        verify_billing_webhook_signature,
    )
    from .cache import TTLCache
    from .claim_lineage import (
        NOT_APPLICABLE,
        ActionBundleInput,
        ActionBundleReceipt,
        ApprovalArtifactSlot,
        ClaimEvidenceLink,
        DeltaSlot,
        DeltaStatus,
        DeployEvidenceInput,
        DeployEvidenceSlot,
        DriftChangeType,
        DriftDetail,
        DriftSeverity,
        EvidenceSlotStatus,
        HitlChainSummaryInput,
        IntegrationEvidenceInput,
        IntegrationEvidenceSlot,
        NotApplicable,
        RuntimeEvidenceInput,
        RuntimeEvidenceSlot,
        SignedApprovalArtifactInput,
        VerificationChecklist,
        VerifyClaimEvidenceLinkResult,
        build_claim_evidence_link,
        build_claim_evidence_link_from_action_bundle,
        verify_claim_evidence_link,
    )
    from .client import AtlaSentClient
    from .clinical import (
        ClinicalBlindingStatus,
        ClinicalBlindRequest,
        ClinicalBlindResponse,
        ClinicalEmergencyRequest,
        ClinicalHistoryResponse,
        ClinicalMutationResponse,
        ClinicalTrialBlind,
        ClinicalTrialGetResponse,
        ClinicalTrialListResponse,
        ClinicalUnblindingEvent,
        ClinicalUnblindingEventType,
        ClinicalUnblindRequest,
        is_unblinded,
        latest_unblinding_event,
    )
    from .clinical_client import ClinicalTrialsClient
    from .compliance_evidence import (
        ComplianceEvidenceRun,
        ControlStatus,
        EvidenceControl,
        EvidenceRunSummary,
        SOC2ControlId,
        evidence_run_passes,
        non_passing_controls,
    )
    from .config import configure
    from .context_envelope import (
        CONTEXT_NAMESPACES,
        RESOURCE_ASSERTION_TRUST_LEVELS,
        ContextEnvelope,
        ContextNamespaceEntry,
        ContextSignal,
        RecordContextEnvelopeInput,
        ResourceClassificationAssertion,
        validate_resource_classification_assertion,
    )
    from .deny_codes import DenyCode, requires_human_approval
    from .evidence_engine import (
        ActionEvidenceBundle,
        ComplianceControlCoverage,
        DecisionReceipt,
        DecisionReceiptPayload,
        WhyPolicyEvaluation,
        WhyStage,
        WhyTrace,
    )
    from .evidence_exports import (
        create_evidence_export,
        get_evidence_export,
        list_evidence_exports,
    )
    from .exceptions import (
        AtlaSentDecision,
        AtlaSentDenied,
        AtlaSentDeniedError,
        AtlaSentError,
        AtlaSentErrorCode,
        AtlaSentPermitMintFailedError,
        BundleVerificationError,
        ConfigurationError,
        PermissionDeniedError,
        PermitOutcome,
        RateLimitError,
        StreamParseError,
        StreamTimeoutError,
    )
    from .governance_agents import (
        AgentEvidenceRef,
        GovernanceAgent,
        GovernanceAgentEvaluation,
        GovernanceAgentFinding,
        ListGovernanceAgentsResult,
        ListGovernanceEvaluationsResult,
        ListGovernanceFindingsResult,
        highest_agent_finding_severity,
    )
    from .governance_webhooks import (
        EnforcementWebhookEvent,
        GovernanceWebhookEvent,
        WebhookDelivery,
        WebhookDeliveryStatus,
        WebhookPayload,
        WebhookSubscription,
        verify_webhook_signature,
    )
    from .guard import async_atlasent_guard, atlasent_guard
    from .hitl import (
        HitlApprovalRecord,
        HitlApprovalsResult,
        HitlChainHop,
        HitlChainResult,
        HitlCreateRequest,
        HitlEscalation,
        HitlEscalationResult,
        HitlFallbackDecision,
        HitlQuorumProgress,
        HitlQuorumTier,
        HitlStatus,
        ListHitlEscalationsResult,
        hitl_required_approver_count,
    )
    from .models import (
        ApiKeySelfResult,
        AuthError,
        AuthorityExplanationPath,
        AuthorityUnresolvedFinding,
        AuthorizationResult,
        ComplianceControl,
        ComplianceControlsResult,
        ComplianceControlStatus,
        ComplianceEvidenceBundle,
        ComplianceEvidenceControl,
        ComplianceEvidencePackResult,
        ComplianceSummary,
        ComplianceWindow,
        ConstraintTrace,
        ConstraintTracePolicy,
        ConstraintTraceStage,
        DecisionValue,
        EnforcementOutcome,
        EvaluatePreflightResult,
        EvaluateResult,
        EvaluateRiskEnvelope,
        EvaluateRiskEnvelopeFactor,
        ExplainAuthorityResult,
        GateResult,
        GetPermitResult,
        GovernanceDecision,
        LicenseStatus,
        LicenseVerifyResult,
        ListPermitsResult,
        Permit,
        PermitRecord,
        PermitVerifyEvidence,
        RateLimitState,
        ReplayResponse,
        ReplayVarianceKind,
        RevokePermitByIdResult,
        RevokePermitResult,
        StreamDecisionEvent,
        StreamEvent,
        StreamProgressEvent,
        VerifyPermitByIdResult,
        VerifyResult,
    )
    from .models import (
        CompletionProof as CompletionProof,
    )
    from .policy_sync import (
        PolicyBundleEntry,
        PolicySyncDiff,
        PolicySyncRun,
        PolicySyncStatus,
        SubmitPolicySyncRequest,
        format_policy_sync_diff,
        is_policy_sync_terminal,
    )
    from .replay import EvidenceVerificationResult, verify_evidence_bundle
    from .require_permit import (
        CanonicalProtectedActionType,
        ProtectedAction,
        classify_command,
        require_permit,
    )
    from .runtime_v2 import (
        AuditChainPage,
        AuthorityRecord,
        AuthorizationDecision,
        ChainIntegrityReport,
        ComplianceExport,
        ExecutionReceipt,
        PostExecutionResult,
        RuntimeAuditEntry,
        RuntimeV2Client,
        VerificationFailure,
        VerificationResult,
        runtime,
    )
    from .scim import (
        SCIM_GROUP_SCHEMA,
        SCIM_PATCH_OP_SCHEMA,
        SCIM_USER_SCHEMA,
        scim_create_group,
        scim_create_user,
        scim_delete_group,
        scim_delete_user,
        scim_get_group,
        scim_get_user,
        scim_list_groups,
        scim_list_users,
        scim_patch_group,
        scim_patch_user,
        scim_replace_group,
        scim_replace_user,
    )
    from .siem import (
        get_siem_config,
        siem_test_delivery,
        upsert_siem_config,
    )
    from .sms_otp import SmsOtpClient
    from .sso_client import SsoClient
    from .taxonomy import (
        ACTION_CLASS_FAMILIES,
        CONDITION_TYPES,
        REASON_CODES,
        TAXONOMY_SCHEMA_VERSION,
        family_for_slug,
        get_reason_code,
        is_action_class_family_id,
        is_condition_type_id,
        is_reason_code,
    )
    from .trust_root import (
        TrustRootKey,
        TrustRootManager,
        TrustRootRevocationEntry,
        TrustRootSnapshot,
        get_global_trust_root_manager,
    )
    from .usage_metering import UsageMeteringClient
    from .v2_endpoints import (
        BATCH_PATH as V2_BATCH_PATH,
    )
    from .v2_endpoints import (
        GRAPHQL_PATH as V2_GRAPHQL_PATH,
    )
    from .v2_endpoints import (
        MAX_BATCH_ITEMS as V2_MAX_BATCH_ITEMS,
    )
    from .v2_endpoints import (
        STREAM_PATH as V2_STREAM_PATH,
    )
    from .v2_endpoints import (
        EvaluateBatchItem,
        EvaluateBatchResponse,
        FeatureNotEnabledError,
        GraphQLResponse,
        StreamComplete,
        StreamDecision,
        StreamErrorFrame,
        authorize_stream,
        evaluate_many,
        graphql,
    )
    from .verify_permit_v4 import (
        PermitClaimsV4,
        PermitV4VerifyError,
        PermitV4VerifyResult,
        verify_permit_v4,
    )
    from .verticals.access_cert import (
        protect_access_cert_action,
        protect_access_cert_revoke,
    )
    from .verticals.contract_actions import (
        protect_contract_action,
        protect_contract_execution,
    )
    from .verticals.data_delete import protect_customer_data_delete
    from .verticals.database_actions import (
        protect_database_action,
        protect_database_migration,
        protect_database_schema_drop,
        protect_database_table_delete,
    )
    from .verticals.financial_close import (
        protect_financial_close_action,
        protect_period_close_certify,
    )
    from .verticals.gxp_actions import (
        TrialActionType,
        TrialBlindingActionType,
        TrialDenialEvidence,
        TrialPermitEvidence,
        TrialUnblindingActionType,
        protect_trial_action,
        protect_trial_blinding_setup,
        protect_trial_unblinding_emergency,
        protect_trial_unblinding_execute,
    )
    from .verticals.hr_actions import (
        protect_hr_action,
        protect_hr_offboard,
        protect_hr_role_escalate,
    )
    from .verticals.model_governance import (
        protect_model_governance,
        protect_model_promotion,
    )
    from .verticals.pricing_actions import (
        protect_pricing_action,
        protect_pricing_rule,
    )
    from .verticals.security_actions import (
        protect_security_access_quarantine,
        protect_security_action,
        protect_security_incident_escalate,
    )
    from .webhook import WebhookVerificationError, assert_webhook, verify_webhook
    from .with_permit import with_permit

__all__ = [
    "__version__",
    "PRODUCTION_DEPLOY_ACTION",
    "AtlaSentClient",
    "AsyncAtlaSentClient",
    "configure",
    "protect",
    "with_permit",
    # Edge-function region pinning (see atlasent._function_region).
    "DEFAULT_FUNCTION_REGION",
    "FUNCTION_REGION_ENV",
    "SUPPORTED_FUNCTION_REGIONS",
    "FunctionRegionConfigError",
    # SMS OTP step-up authentication.
    "SmsOtpClient",
    # Usage metering.
    "UsageMeteringClient",
    # SCIM helpers + schema constants.
    "SCIM_USER_SCHEMA",
    "SCIM_GROUP_SCHEMA",
    "SCIM_PATCH_OP_SCHEMA",
    "scim_list_users",
    "scim_create_user",
    "scim_get_user",
    "scim_replace_user",
    "scim_patch_user",
    "scim_delete_user",
    "scim_list_groups",
    "scim_create_group",
    "scim_get_group",
    "scim_replace_group",
    "scim_patch_group",
    "scim_delete_group",
    # SIEM helpers.
    "get_siem_config",
    "upsert_siem_config",
    "siem_test_delivery",
    "require_permit",
    "classify_command",
    "ProtectedAction",
    "CanonicalProtectedActionType",
    "WhyTrace",
    "WhyPolicyEvaluation",
    "WhyStage",
    "DecisionReceipt",
    "DecisionReceiptPayload",
    "ActionEvidenceBundle",
    "ComplianceControlCoverage",
    "ContextEnvelope",
    "ContextSignal",
    "ContextNamespaceEntry",
    "RecordContextEnvelopeInput",
    "ResourceClassificationAssertion",
    "validate_resource_classification_assertion",
    "RESOURCE_ASSERTION_TRUST_LEVELS",
    "DenyCode",
    "requires_human_approval",
    "ACTION_CLASS_FAMILIES",
    "CONDITION_TYPES",
    "REASON_CODES",
    "TAXONOMY_SCHEMA_VERSION",
    "family_for_slug",
    "get_reason_code",
    "is_action_class_family_id",
    "is_condition_type_id",
    "is_reason_code",
    "CONTEXT_NAMESPACES",
    # Authentication assurance (CROSS-016 / proposal 0003) — evidence/requirement types.
    # Additive, not yet enforced: see authentication_assurance.py's module docstring.
    "AuthenticationAssuranceEvidence",
    "MethodProvenance",
    "PredicateRegistryEntry",
    "PredicateInstance",
    "ResourceContextCondition",
    "AssuranceRequirementLayer",
    "AuthenticationAssuranceRequirement",
    "ExternalObligationRequirement",
    "OrganizationRequirement",
    "ActionClassRequirement",
    "ResourceContextRequirement",
    "EffectiveAssurancePredicateEntry",
    "EffectiveAuthenticationAssuranceRequirement",
    "AuthenticationAssuranceOutcomeCode",
    "is_authentication_assurance_outcome_code",
    "AssuranceResolutionStatus",
    "AssuranceResolutionReason",
    "AssuranceEvaluationOutcome",
    "AssuranceEvaluationOutcomeAllow",
    "AssuranceEvaluationOutcomeNonAllow",
    "ResourceContextConditionMatch",
    "matches_resource_context_condition",
    "validate_authentication_assurance_evidence",
    "validate_authentication_assurance_requirement",
    "is_authentication_assurance_requirement",
    "authorize",
    "evaluate",
    "verify",
    "gate",
    "DecisionValue",
    "Permit",
    "AuthorizationResult",
    "EvaluateResult",
    "EvaluateRiskEnvelope",
    "EvaluateRiskEnvelopeFactor",
    "EvaluatePreflightResult",
    "ConstraintTrace",
    "ConstraintTracePolicy",
    "ConstraintTraceStage",
    "VerifyResult",
    "RateLimitState",
    "ReplayResponse",
    "ReplayVarianceKind",
    "ApiKeySelfResult",
    "ComplianceControl",
    "ComplianceControlsResult",
    "ComplianceControlStatus",
    "ComplianceEvidenceBundle",
    "ComplianceEvidenceControl",
    "ComplianceEvidencePackResult",
    "ComplianceSummary",
    "ComplianceWindow",
    "GateResult",
    "AtlaSentError",
    "AtlaSentErrorCode",
    "AtlaSentDecision",
    "AtlaSentDenied",
    "AtlaSentDeniedError",
    "AtlaSentPermitMintFailedError",
    "BundleVerificationError",
    "PermissionDeniedError",
    "PermitOutcome",
    "BundleVerificationError",
    "ConfigurationError",
    "RateLimitError",
    "StreamTimeoutError",
    "StreamParseError",
    "atlasent_guard",
    "async_atlasent_guard",
    "TTLCache",
    "verify_bundle",
    "verify_audit_bundle",
    "BundleVerificationResult",
    "VerifyKey",
    "AuditDecision",
    "AuditEvent",
    "AuditEventsResult",
    "AuditExportResult",
    "AuditExportSignatureStatus",
    "RevokePermitResult",
    "RevokePermitByIdResult",
    "VerifyPermitByIdResult",
    "PermitVerifyEvidence",
    "GetPermitResult",
    "ExplainAuthorityResult",
    "AuthorityExplanationPath",
    "AuthorityUnresolvedFinding",
    "LicenseStatus",
    "LicenseVerifyResult",
    "ListPermitsResult",
    "PermitRecord",
    "StreamDecisionEvent",
    "StreamProgressEvent",
    "StreamEvent",
    # Phase 7 typed models (provisional — see models.py).
    "GovernanceDecision",
    "AuthError",
    "EnforcementOutcome",
    # Governance agents read surface (parity with @atlasent/sdk 2.6.0).
    "GovernanceAgent",
    "GovernanceAgentFinding",
    "GovernanceAgentEvaluation",
    "AgentEvidenceRef",
    "ListGovernanceAgentsResult",
    "ListGovernanceFindingsResult",
    "ListGovernanceEvaluationsResult",
    "highest_agent_finding_severity",
    # HITL orchestration surface (parity with the TS SDK).
    "HitlApprovalRecord",
    "HitlApprovalsResult",
    "HitlChainHop",
    "HitlChainResult",
    "HitlCreateRequest",
    "HitlEscalation",
    "HitlEscalationResult",
    "HitlFallbackDecision",
    "HitlQuorumProgress",
    "HitlQuorumTier",
    "HitlStatus",
    "ListHitlEscalationsResult",
    "hitl_required_approver_count",
    # Approval artifact contract surface (parity with the TS SDK).
    "ApprovalArtifactV1",
    "ApprovalIssuer",
    "ApprovalQuorumV1",
    "ApprovalReference",
    "ApprovalReviewer",
    "ApprovalTrustedIssuersConfig",
    "ApproverGrantAssertionV1",
    "ApproverGrantAuthContext",
    "ApproverGrantBinding",
    "ApproverGrantIssuer",
    "ApproverGrantSubject",
    "IdentityAssertionBinding",
    "IdentityAssertionV1",
    "IdentityIssuer",
    "IdentityIssuerKey",
    "IdentitySubject",
    "IdentityTrustedIssuersConfig",
    "PermitApprovalBinding",
    "PrincipalKind",
    "QuorumIndependence",
    "QuorumPolicy",
    "QuorumProof",
    "QuorumRoleRequirement",
    "TrustedIssuerKey",
    # Governance webhooks (parity with the TS SDK).
    "GovernanceWebhookEvent",
    "EnforcementWebhookEvent",
    "WebhookSubscription",
    "WebhookDelivery",
    "WebhookDeliveryStatus",
    "WebhookPayload",
    "verify_webhook_signature",
    # Claims evidence lineage (parity with the TS SDK).
    "ClaimEvidenceLink",
    "RuntimeEvidenceSlot",
    "DeployEvidenceSlot",
    "IntegrationEvidenceSlot",
    "ApprovalArtifactSlot",
    "ActionBundleInput",
    "ActionBundleReceipt",
    "DeltaSlot",
    "DeltaStatus",
    "DriftDetail",
    "DriftChangeType",
    "DriftSeverity",
    "EvidenceSlotStatus",
    "VerificationChecklist",
    "NotApplicable",
    "NOT_APPLICABLE",
    "RuntimeEvidenceInput",
    "DeployEvidenceInput",
    "IntegrationEvidenceInput",
    "HitlChainSummaryInput",
    "SignedApprovalArtifactInput",
    "VerifyClaimEvidenceLinkResult",
    "build_claim_evidence_link",
    "build_claim_evidence_link_from_action_bundle",
    "verify_claim_evidence_link",
    # Clinical trial blinding / unblinding (parity with the TS SDK).
    "ClinicalBlindingStatus",
    "ClinicalUnblindingEventType",
    "ClinicalTrialBlind",
    "ClinicalUnblindingEvent",
    "ClinicalBlindRequest",
    "ClinicalBlindResponse",
    "ClinicalUnblindRequest",
    "ClinicalEmergencyRequest",
    "ClinicalMutationResponse",
    "ClinicalTrialListResponse",
    "ClinicalTrialGetResponse",
    "ClinicalHistoryResponse",
    "is_unblinded",
    "latest_unblinding_event",
    "ClinicalTrialsClient",
    # Compliance evidence (parity with the TS SDK).
    "SOC2ControlId",
    "ControlStatus",
    "EvidenceControl",
    "EvidenceRunSummary",
    "ComplianceEvidenceRun",
    "evidence_run_passes",
    "non_passing_controls",
    # Policy sync (parity with the TS SDK).
    "PolicySyncStatus",
    "PolicyBundleEntry",
    "PolicySyncDiff",
    "PolicySyncRun",
    "SubmitPolicySyncRequest",
    "format_policy_sync_diff",
    "is_policy_sync_terminal",
    # Billing entitlement + webhook management (enterprise grace period support).
    "AccessStatus",
    "AllowedAction",
    "AsyncBillingClient",
    "BillingClient",
    "BillingEntitlement",
    "BillingMode",
    "BillingWebhookSubscription",
    "DenyReason",
    "InvoiceStatus",
    "AdminOverrideRequest",
    "AdminOverrideResponse",
    "verify_billing_webhook_signature",
    # Webhook signature verification (parity with the TypeScript SDK).
    "verify_webhook",
    "assert_webhook",
    "WebhookVerificationError",
    # V2 Wave-A endpoints (V2-D3 batch, V2-D4 stream, V2-D8 graphql).
    # V1 substrate is frozen — these are additive and close-by-default
    # per tenant (FeatureNotEnabledError surfaces the 404 fall-back path).
    "FeatureNotEnabledError",
    "EvaluateBatchItem",
    "EvaluateBatchResponse",
    "StreamComplete",
    "StreamDecision",
    "StreamErrorFrame",
    "GraphQLResponse",
    "V2_BATCH_PATH",
    "V2_STREAM_PATH",
    "V2_GRAPHQL_PATH",
    "V2_MAX_BATCH_ITEMS",
    "evaluate_many",
    "authorize_stream",
    "graphql",
    # Phase 3 offline replay client — verify evidence bundles without backend.
    "verify_evidence_bundle",
    "SsoClient",
    "AccessGovernanceLogClient",
    "EvidenceVerificationResult",
    # BCCAE V1 — Phase 3 Execution Assurance substrate.
    # Standalone BCCAEClient with bccae:* scopes — not part of the
    # Deploy Gate V1 customer API surface.
    "BCCAEClient",
    "generate_bccae_nonce",
    # Evidence bundle exports (Wave B parity).
    "list_evidence_exports",
    "get_evidence_export",
    "create_evidence_export",
    # Trust-root V1 (bootstrap + snapshot management).
    "TrustRootKey",
    "TrustRootManager",
    "TrustRootRevocationEntry",
    "TrustRootSnapshot",
    "get_global_trust_root_manager",
    # Verticals — domain-specific protect() convenience wrappers.
    # GxP: clinical trial blinding / unblinding (ICH E6(R2) §4.8 / 21 CFR Part 11).
    "TrialActionType",
    "TrialBlindingActionType",
    "TrialDenialEvidence",
    "TrialPermitEvidence",
    "TrialUnblindingActionType",
    "protect_trial_action",
    "protect_trial_blinding_setup",
    "protect_trial_unblinding_emergency",
    "protect_trial_unblinding_execute",
    # Phase 4: HR, model governance, data delete, contract, pricing.
    "protect_hr_action",
    "protect_hr_offboard",
    "protect_hr_role_escalate",
    "protect_model_governance",
    "protect_model_promotion",
    "protect_customer_data_delete",
    "protect_contract_action",
    "protect_contract_execution",
    "protect_pricing_action",
    "protect_pricing_rule",
    # Phase 5: security, access-cert, financial-close.
    "protect_security_action",
    "protect_security_incident_escalate",
    "protect_security_access_quarantine",
    "protect_access_cert_action",
    "protect_access_cert_revoke",
    "protect_financial_close_action",
    "protect_period_close_certify",
    # Phase 6: database actions.
    "protect_database_action",
    "protect_database_migration",
    "protect_database_schema_drop",
    "protect_database_table_delete",
    # Authority intelligence — read-only authority analysis (integrity audit).
    "AuthorityIntelligenceClient",
    "IntegrityFinding",
    "IntegrityReport",
    "count_findings_by_classification",
    # Runtime v2 — four-plane authorized-state-change lifecycle.
    "RuntimeV2Client",
    "runtime",
    "AuthorizationDecision",
    "AuthorityRecord",
    "AuditChainPage",
    "ChainIntegrityReport",
    "ComplianceExport",
    "ExecutionReceipt",
    "PostExecutionResult",
    "RuntimeAuditEntry",
    "VerificationFailure",
    "VerificationResult",
    # pt.v4.* offline permit verifier (ADR-050).
    "verify_permit_v4",
    "PermitClaimsV4",
    "PermitV4VerifyError",
    "PermitV4VerifyResult",
]
