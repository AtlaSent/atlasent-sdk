"""Pydantic models for AtlaSent API requests and responses.

Wire format (post 2026-04-30 contract reconciliation): every model
serializes to the canonical wire shape read by
``atlasent-api/supabase/functions/v1-{evaluate,verify-permit}/handler.ts``.

POST /v1-evaluate request:
    canonical: ``{ action_type, actor_id, context }``
    legacy:    ``{ action, agent, context, api_key }``
               (accepted with DeprecationWarning)

POST /v1-evaluate response:
    canonical: ``{ decision: "allow"|"deny"|"hold"|"escalate",
                   permit_token?, request_id?, expires_at?,
                   denial?: {reason, code}, ... }``
    legacy:    ``{ permitted: bool, decision_id, reason?, audit_hash?,
                   timestamp? }``
               (legacy server, transparently translated)

POST /v1-verify-permit request:
    canonical: ``{ permit_token, action_type?, actor_id? }``
    legacy:    ``{ decision_id, action, agent, context, api_key }``
               (accepted with DeprecationWarning)

POST /v1-verify-permit response:
    canonical: ``{ valid, outcome: "allow"|"deny",
                   verify_error_code?, reason? }``
    legacy:    ``{ verified, outcome, permit_hash, timestamp }``
               (legacy, transparently translated)

Construction with legacy keyword names (``action=``, ``agent=``,
``decision_id=``, ``api_key=``) keeps working but emits
``DeprecationWarning``. Reading legacy attributes on result objects
(``permitted``, ``decision_id``, ``verified``, ``permit_hash``,
``audit_hash``, ``timestamp``) is supported transparently and will
remain so for the duration of the deprecation window.
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .approval_artifact import (
    ApprovalReference,
    PermitApprovalBinding,
)

# Soft cap on top-level context properties. The hosted API hard-rejects
# above 64 (see contract/openapi.yaml) and applies its own size limits;
# the SDK warns but does not raise so a slightly-oversize context still
# reaches the server, where the failure mode is a typed error rather
# than a silent client-side truncation. Mis-use surfaces loudly in dev
# without breaking production traffic on the day this SDK ships.
_CONTEXT_PROPERTIES_SOFT_CAP = 64

_logger = logging.getLogger("atlasent")


def _warn_oversize_context(value: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict) and len(value) > _CONTEXT_PROPERTIES_SOFT_CAP:
        _logger.warning(
            "context has %d top-level keys (soft cap %d); the server "
            "may reject this. Pack richer payloads under a single "
            "top-level key.",
            len(value),
            _CONTEXT_PROPERTIES_SOFT_CAP,
        )
    return value


# ── Canonical decision type (mirrors TypeScript Decision / DecisionCanonical) ─

#: Four-value decision vocabulary.  Mirrors the TypeScript SDK's
#: ``Decision`` / ``DecisionCanonical`` union type so polyglot users can
#: annotate decision variables identically in both languages.
#:
#: >>> from atlasent import DecisionValue
#: >>> def handle(decision: DecisionValue) -> None: ...
DecisionValue = Literal["allow", "deny", "hold", "escalate"]

# ── Rate-limit state (shared by evaluate + verify) ───────────────────


@dataclass(frozen=True)
class RateLimitState:
    """Per-key rate-limit state parsed from the server's
    ``X-RateLimit-*`` response headers.

    Present on every authenticated response (success and 429) when the
    server emits the headers. ``None`` on older deployments or on
    internal endpoints that skip per-key rate limiting.

    Consumers should check :attr:`remaining` and sleep until
    :attr:`reset_at` to preemptively back off before hitting a 429::

        result = client.evaluate(...)
        if result.rate_limit and result.rate_limit.remaining < 10:
            time.sleep(
                (result.rate_limit.reset_at - datetime.now(timezone.utc))
                .total_seconds()
            )

    Attributes:
        limit: Value of ``X-RateLimit-Limit`` — the per-minute budget.
        remaining: Value of ``X-RateLimit-Remaining`` — unused budget
            in the current window.
        reset_at: Parsed ``X-RateLimit-Reset`` — the UTC instant when
            the current window's counter zeroes. Accepts either a
            unix-seconds integer or an ISO 8601 string on the wire.
    """

    limit: int
    remaining: int
    reset_at: datetime


def _warn_legacy(label: str, mapping: str) -> None:
    """Emit a DeprecationWarning describing a single legacy input field.

    ``stacklevel=4`` lands on the caller of ``EvaluateRequest(...)`` /
    ``VerifyRequest(...)`` — the actionable site for fixing the code.
    """
    warnings.warn(
        f"AtlaSent SDK: legacy {label} ({mapping}) is deprecated and "
        "will be removed in a future major release.",
        DeprecationWarning,
        stacklevel=4,
    )


# ── Evaluate ──────────────────────────────────────────────────────────


class CompletionProof(BaseModel):
    """Proof that a specific actor consumed a specific permit for a specific
    action_type.  Pass an array of these as ``completion_proofs`` on an
    :class:`EvaluateRequest` to satisfy multi-actor quorum dependencies.

    The runtime verifies each proof via two gates (both must pass):

    1. A ``permit_uses`` row exists for ``permit_id`` (permit was consumed).
    2. An ``execution_evaluations`` row is bound to ``actor_id`` +
       ``action_type`` for the same permit (actor/action binding).

    Proofs that fail either gate are silently dropped (fail-closed).
    """

    action_type: str = Field(
        ...,
        description="action_type (slug) completed by the prior actor.",
    )
    actor_id: str = Field(..., description="The actor who completed the action.")
    permit_id: str = Field(
        ...,
        description="Permit token (or hash) issued when the action was permitted.",
    )


class EvaluateRequest(BaseModel):
    """Payload sent to ``POST /v1-evaluate``.

    Accepts both the canonical input shape
    (``action_type=``, ``actor_id=``) and the legacy shape
    (``action=``, ``agent=``, ``api_key=``). Legacy field names emit
    ``DeprecationWarning`` on construction. Always serializes to the
    canonical wire (``{action_type, actor_id, context}``); ``api_key``
    is intentionally excluded — the server reads it from the
    ``Authorization`` header.
    """

    action_type: str = Field(
        ...,
        validation_alias=AliasChoices("action_type", "action"),
        description="Action being authorized (e.g. 'modify_patient_record').",
    )
    actor_id: str = Field(
        ...,
        validation_alias=AliasChoices("actor_id", "agent"),
        description="Identifier of the calling actor / agent.",
    )
    context: dict[str, Any] = Field(default_factory=dict)
    # Optional canonical-action-hash inputs. The server binds these
    # into the action_hash that approval artifacts cover, so passing
    # them lets producers compute a matching hash off-line.
    resource_id: str | None = Field(default=None, max_length=512)
    amount: float | None = Field(default=None)
    # SHA-256 digest of the payload that will actually execute, as BARE
    # lowercase 64-hex. The server signs a value matching ``^[0-9a-f]{64}$``
    # into the permit as ``execution_hash_expected``; re-present it at
    # /v1-verify-permit and a payload altered after authorization fails closed
    # with PAYLOAD_MISMATCH.
    #
    # TOP LEVEL only -- the handler destructures it from the body alongside
    # ``context``, never from within it, so a copy nested under ``context`` is
    # not a binding. A non-matching value (notably the ``sha256:``-prefixed
    # form) is DROPPED rather than rejected on the ordinary-action path: allow,
    # permit, 200, no error. ``normalize_caller_payload_hash`` refuses both
    # shapes at the client boundary instead.
    execution_payload_hash: str | None = Field(default=None)
    # The actor's ``actor_identity.v1`` assertion, TOP LEVEL and unchanged.
    # The SDK never mints or inspects it. The runtime requires one at evaluate
    # for the mandatory change-control action types (``production.deploy``
    # and others; deny ACTOR_UNVERIFIED without it).
    actor_identity: dict[str, Any] | None = Field(default=None)
    # Optional signed approval. When the action requires human
    # approval (rule-driven OR action-type prefix per
    # ``requiresHumanApproval``), the server verifies this artifact
    # before issuing a permit; failure denies. Either a full
    # ``ApprovalArtifactV1`` or an ``approval_id`` reference.
    approval: ApprovalReference | None = Field(default=None)
    # Caller assertion that this action requires verified human
    # approval, even when the action_type heuristic doesn't match.
    # Carried server-side onto the audit row and echoed onto
    # /v1-verify-permit's require_approval gate.
    require_approval: bool | None = Field(default=None)
    # When True, the server populates risk_envelope.factors with a
    # per-factor breakdown of the weighted risk score. Absent (False)
    # by default to keep response payloads small.
    explain: bool | None = Field(default=None)
    # Deployment environment (e.g. 'production', 'staging').
    environment: str | None = Field(default=None)
    # Structured resource descriptor — preferred over flat resource_id for
    # new callers. Mutually exclusive; control plane accepts both.
    resource: dict[str, Any] | None = Field(default=None)
    # State-transition context. Enables policy rules that reason about what
    # changes (current → proposed) and where execution binds.
    current_state: dict[str, Any] | None = Field(default=None)
    proposed_state: dict[str, Any] | None = Field(default=None)
    execution_binding: dict[str, Any] | None = Field(default=None)
    # Multi-actor quorum completion proofs. Supply one entry per prior actor
    # whose completed action this evaluation depends on. Absent → no proofs
    # submitted (no behavioral change for non-quorum dependencies).
    completion_proofs: list[CompletionProof] | None = Field(default=None)
    # State snapshot of the system at evaluation time. Required when the action
    # class has requires_state_snapshot=True. Omitting this field on a required
    # action class causes the server to return a SNAPSHOT_REQUIRED deny.
    # Recovery: add state_snapshot to every evaluate call for the affected
    # action_type with observable system state at evaluation time.
    state_snapshot: dict[str, Any] | None = Field(default=None)
    # Algorithm profile controlling which evaluation layers run.
    # "basic" skips snapshot enforcement for pilot integrations.
    # "standard" (default) runs all stable layers.
    # "advanced"/"enterprise" additionally enable override logic.
    # Unknown values fall back to "standard" server-side (never "basic").
    evaluation_profile: (
        Literal["basic", "standard", "advanced", "enterprise"] | None
    ) = Field(default=None)
    # Emergency override block. Only evaluated when evaluation_profile is
    # "advanced" or "enterprise". Pass a dict with at minimum:
    #   {"version": "override.v1", "authority_actor_id": "<uuid>", "reason": "<text>"}
    # The authority actor must hold override:execute scope and differ from actor_id.
    override: dict[str, Any] | None = Field(default=None)
    # Kept for backward-compat with code that constructs the request
    # directly. Excluded from wire serialization — the server reads the
    # API key from the Authorization header, never from the body.
    api_key: str = Field(default="", exclude=True)

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def _warn_on_legacy_input(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "action" in data and "action_type" not in data:
            _warn_legacy("EvaluateRequest field", "action= -> action_type=")
        if "agent" in data and "actor_id" not in data:
            _warn_legacy("EvaluateRequest field", "agent= -> actor_id=")
        if data.get("api_key"):
            _warn_legacy(
                "EvaluateRequest field",
                "api_key= (request body) -> Authorization header (handled by client)",
            )
        return data

    @field_validator("context", mode="after")
    @classmethod
    def _check_context_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _warn_oversize_context(value)


# ── Risk envelope (Phase C) ───────────────────────────────────────────────────


class EvaluateRiskEnvelopeFactor(BaseModel):
    """One factor contribution inside a risk envelope ``factors`` breakdown."""

    factor: str
    value: float
    weight: float
    reason: str

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class EvaluateRiskEnvelope(BaseModel):
    """Top-level risk envelope returned by ``POST /v1-evaluate`` (Phase C).

    Always present on responses from engine version ``wire-v1@1.0.0+``.
    Enforces most-restrictive-wins: the envelope can raise the engine
    decision's severity but structurally cannot soften a deny.

    Attributes:
        weighted_score: Composite risk score in [0, 1]. Score ≥ 0.70
            triggers a hold promotion.
        engine_decision: Policy engine decision *before* envelope promotion.
        envelope_decision: Decision resolved by the envelope
            (may equal ``engine_decision`` when no promotion occurred).
        promoted: ``True`` when ``envelope_decision`` is more restrictive
            than ``engine_decision``.
        hard_blocks: Deny codes that unconditionally block regardless of score.
        factors: Per-factor breakdown. Only populated when the evaluate
            request carried ``explain=True``.
    """

    weighted_score: float
    engine_decision: Literal["allow", "deny", "hold", "escalate"]
    envelope_decision: Literal["allow", "deny", "hold", "escalate"]
    promoted: bool
    hard_blocks: list[str] = Field(default_factory=list)
    factors: list[EvaluateRiskEnvelopeFactor] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class EvaluateResult(BaseModel):
    """Response from ``POST /v1-evaluate``.

    Pydantic parses both the canonical handler.ts shape and the legacy
    ``{permitted, decision_id, ...}`` shape; legacy responses are
    translated to canonical fields via ``_accept_legacy_response``.

    In the fail-closed SDK you only receive this object when the
    decision is ``"allow"``. Anything else raises
    :class:`AtlaSentDenied` from the client.

    Canonical attributes:
        decision: Four-value decision (``"allow"|"deny"|"hold"|"escalate"``).
            Always ``"allow"`` when this object reaches user code via
            the fail-closed client; the other values may appear when
            constructing or parsing this model directly.
        permit_token: Opaque permit identifier. Pass to
            :meth:`AtlaSentClient.verify` to confirm the permit later.
        request_id: Server-side request identifier. Useful as an
            audit deep-link.
        expires_at: ISO 8601 timestamp at which the permit expires.
        denial: Populated on non-allow decisions. ``{"reason", "code"}``.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*``
            headers. ``None`` when the server didn't emit them.
        human_approval_required: Two-stage authorization lifecycle
            (#1617). Whether this evaluation requires a verified human
            approval, independent of whether that requirement is
            currently satisfied. ``None`` on responses from a runtime
            predating this field.
        human_approval_status: The current satisfaction state of the
            human-approval requirement — ``"not_required"``,
            ``"pending"``, ``"satisfied"``, ``"rejected"``,
            ``"expired"``, or ``"revoked"``. ``None`` on responses from
            a runtime predating this field.

    Legacy attributes (kept for backward-compat with existing readers,
    populated alongside their canonical counterparts):
        permitted: ``True`` iff ``decision == "allow"``.
        decision_id: Alias for :attr:`permit_token`.
        reason: Pulled from ``denial.reason`` when present.
        audit_hash: Legacy hash field. Empty under the canonical wire.
        timestamp: Legacy timestamp field. Empty under the canonical wire.
    """

    decision: Literal["allow", "deny", "hold", "escalate"] = "allow"
    permit_token: str = ""
    request_id: str = ""
    expires_at: str = ""
    denial: dict[str, Any] | None = None
    # Stable machine code naming *why* a non-allow decision was reached
    # (e.g. "SNAPSHOT_REQUIRED"). None on allow. Sourced from the wire
    # top-level ``deny_code`` with a fallback to the legacy ``denial.code``
    # shape. Branch on this, not on the human-readable ``reason``.
    deny_code: str | None = None
    # Mirrors TypeScript SDK's ``reasons: string[]``. For deny/hold/escalate
    # decisions contains the policy engine's explanation(s); for allow often
    # empty. ``reason`` (singular) is the first element and kept for compat.
    reasons: list[str] = field(default_factory=list)
    # Permit ↔ approval-artifact binding. Present iff /v1-evaluate
    # verified an ApprovalArtifactV1 for this issuance — the cryptographic
    # proof of which signed approval authorized this permit.
    permit_approval: PermitApprovalBinding | None = None
    rate_limit: RateLimitState | None = None
    # Risk envelope — present on responses from engine version wire-v1@1.0.0+.
    # None on legacy server responses that predate Phase C.
    risk_envelope: EvaluateRiskEnvelope | None = None
    # Resolved risk class from the evaluation (critical / high / medium / low).
    risk_class: str | None = None
    # WHY this was allowed — kind + reference (policy, quorum, emergency, etc.).
    authority_basis: dict[str, Any] | None = None
    # Present iff decision == 'hold'. ID of the auto-created HITL escalation.
    escalation_id: str | None = None
    # Two-stage authorization lifecycle (atlasent-api #1617): the human
    # approval REQUIREMENT for this evaluation, distinct from its current
    # satisfaction state (``human_approval_status``). ``None`` on responses
    # from a runtime predating this field — never coerced to ``False``.
    human_approval_required: bool | None = None
    # Two-stage authorization lifecycle (#1617): the current satisfaction
    # state, closed set ``not_required | pending | satisfied | rejected |
    # expired | revoked``. ``rejected``/``expired``/``revoked`` are distinct
    # states, never collapsed into ``pending``. ``None`` on responses from a
    # runtime predating this field.
    human_approval_status: (
        Literal[
            "not_required", "pending", "satisfied", "rejected", "expired", "revoked"
        ]
        | None
    ) = None

    # Legacy fields. Populated by the model_validator (from canonical
    # `decision` / `permit_token` / `denial`) so existing readers like
    # ``result.permitted`` and ``result.decision_id`` keep working.
    permitted: bool = False
    decision_id: str = ""
    reason: str = ""
    audit_hash: str = ""
    timestamp: str = ""

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_response(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        out = dict(data)

        # Legacy server shape: {permitted, decision_id, reason, audit_hash, timestamp}.
        # Translate to canonical {decision, permit_token, denial} so the rest of
        # the model populates uniformly.
        if "decision" not in out and isinstance(out.get("permitted"), bool):
            out["decision"] = "allow" if out["permitted"] else "deny"
        if "permit_token" not in out and "decision_id" in out:
            out["permit_token"] = out["decision_id"]
        if (
            "denial" not in out
            and out.get("decision") not in (None, "allow")
            and out.get("reason")
        ):
            out["denial"] = {"reason": out["reason"]}

        # Canonical handler.ts emits top-level `deny_code` / `deny_reason`;
        # the contract/legacy shape nests them under `denial`. Read both and
        # surface `deny_code` + ensure `denial` carries reason and code.
        _denial = out.get("denial") if isinstance(out.get("denial"), dict) else None
        _deny_code = out.get("deny_code") or (_denial.get("code") if _denial else None)
        _deny_reason = out.get("deny_reason") or (
            _denial.get("reason") if _denial else None
        )
        if _deny_code is not None:
            out["deny_code"] = _deny_code
        if out.get("decision") not in (None, "allow") and (_deny_reason or _deny_code):
            merged = dict(_denial or {})
            if _deny_reason and "reason" not in merged:
                merged["reason"] = _deny_reason
            if _deny_code and "code" not in merged:
                merged["code"] = _deny_code
            if merged:
                out["denial"] = merged
            if not out.get("reason") and _deny_reason:
                out["reason"] = _deny_reason

        # Now mirror canonical → legacy so consumers reading either shape see
        # consistent values.
        decision = out.get("decision", "allow")
        if "permitted" not in out:
            out["permitted"] = decision == "allow"
        if "decision_id" not in out and out.get("permit_token"):
            out["decision_id"] = out["permit_token"]
        if "reason" not in out and isinstance(out.get("denial"), dict):
            out["reason"] = str(out["denial"].get("reason", ""))

        # Populate `reasons` (mirrors TS `reasons: string[]`).
        # Accept a wire-provided list first; fall back to wrapping `reason`.
        if "reasons" not in out or not out["reasons"]:
            wire_reasons = out.get("reasons")
            if isinstance(wire_reasons, list) and wire_reasons:
                out["reasons"] = [str(r) for r in wire_reasons]
            elif out.get("reason"):
                out["reasons"] = [str(out["reason"])]
            else:
                out["reasons"] = []

        # Permit-approval binding. The atlasent-console wire shape
        # nests it under ``permit.approval`` (PermitV2.approval); the
        # atlasent-api wire shape exposes it under top-level
        # ``permit_approval``. Accept either; surface as
        # ``permit_approval`` on the model.
        if "permit_approval" not in out:
            permit_block = out.get("permit")
            if isinstance(permit_block, dict) and isinstance(
                permit_block.get("approval"), dict
            ):
                out["permit_approval"] = permit_block["approval"]

        return out


# ── Constraint trace (preflight) ──────────────────────────────────────


class ConstraintTraceStage(BaseModel):
    """One stage of a single policy's constraint evaluation.

    Mirrors ``ConstraintTraceStage`` in
    ``atlasent-api/packages/types/src/index.ts``. The trace is emitted
    by the rule engine when the request URL carries
    ``?include=constraint_trace``; consumers (approval-queue UIs,
    workflow pre-flight checks) read it to surface which stages /
    rules fired.

    Attributes:
        stage: Engine stage name (e.g. ``"role_check"``, ``"context"``).
        rule: Optional rule identifier; absent for wrapper stages
            that don't carry a single rule id.
        matched: ``True`` when this stage's predicate fired (matched
            input). Read in conjunction with ``detail``.
        detail: Optional human-readable note from the engine.
        order: Zero-based position of this stage within its policy's
            ``stages`` array. Stable across server restarts so UIs can
            sort without re-sorting.
    """

    stage: str
    rule: str | None = None
    matched: bool
    detail: str | None = None
    order: int

    # Forward-compat: tolerate unknown engine-side keys without raising.
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ConstraintTracePolicy(BaseModel):
    """Per-policy block of a constraint trace.

    Mirrors ``ConstraintTracePolicy`` in
    ``atlasent-api/packages/types/src/index.ts``. The handler iterates
    active policies in order until first non-allow; the policy that
    produced the outer decision has ``decision != "allow"``.

    Attributes:
        policy_id: Stable identifier of the evaluated policy.
        decision: Policy-level decision
            (``"allow"|"deny"|"hold"|"escalate"``).
        fingerprint: Engine-side fingerprint of the bundle row used to
            evaluate this policy. Useful for caching and replay.
        risk_score: Optional engine-computed risk score from a
            ``risk`` rule clause. Distinct from the heuristic score on
            the outer envelope.
        stages: Ordered list of :class:`ConstraintTraceStage` produced
            while evaluating this policy.
    """

    policy_id: str
    decision: str
    fingerprint: str
    risk_score: float | None = None
    stages: list[ConstraintTraceStage] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ConstraintTrace(BaseModel):
    """Top-level constraint trace returned by ``/v1-evaluate?include=constraint_trace``.

    Mirrors ``ConstraintTraceResponse`` in
    ``atlasent-api/packages/types/src/index.ts``. Present iff the
    caller requested the trace; the SDK's preflight helper always
    requests it.

    Attributes:
        rules_evaluated: Per-policy blocks in the order the engine
            evaluated them.
        matching_policy_id: Policy id whose evaluation produced the
            outer decision. Equals the outer ``matched_policy_id`` on
            non-allow paths; ``None`` on a clean allow (all policies
            passed).
    """

    rules_evaluated: list[ConstraintTracePolicy] = Field(default_factory=list)
    matching_policy_id: str | None = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)


@dataclass
class EvaluatePreflightResult:
    """Result of :meth:`AtlaSentClient.evaluate_preflight`.

    Wraps the regular :class:`EvaluateResult` plus the
    :class:`ConstraintTrace` returned when the request URL carries
    ``?include=constraint_trace``. The whole point of preflight is to
    surface which stages / policies WOULD fire BEFORE submitting an
    action for approval, so workflows can reject trivially defective
    requests at submission time and only forward viable requests to
    the approval queue.

    Attributes:
        evaluation: The regular :class:`EvaluateResult` (decision,
            permit_token, denial, ...).
        constraint_trace: The trace, populated on responses from
            atlasent-api versions that include the constraint-trace
            sub-object. ``None`` on older deployments — callers should
            handle the missing-trace case as "no trace available"
            rather than treat the response as malformed.
    """

    evaluation: EvaluateResult
    constraint_trace: ConstraintTrace | None = None


# ── Verify ────────────────────────────────────────────────────────────


class VerifyRequest(BaseModel):
    """Payload sent to ``POST /v1-verify-permit``.

    Accepts both canonical input (``permit_token=``) and legacy
    (``decision_id=``, ``action=``, ``agent=``, ``api_key=``). Legacy
    field names emit ``DeprecationWarning``. Always serializes to the
    canonical wire (``{permit_token, action_type, actor_id}``);
    ``context`` and ``api_key`` are intentionally excluded — the
    server doesn't read them.
    """

    permit_token: str = Field(
        ...,
        validation_alias=AliasChoices("permit_token", "decision_id"),
        description="The permit_token returned by a prior /v1-evaluate call.",
    )
    action_type: str = Field(
        default="",
        validation_alias=AliasChoices("action_type", "action"),
        description="Optional cross-check — re-state the action.",
    )
    actor_id: str = Field(
        default="",
        validation_alias=AliasChoices("actor_id", "agent"),
        description="Optional cross-check — re-state the actor.",
    )
    # Caller assertion that this consume MUST produce a permit row
    # with a populated approval binding. When True and the row carries
    # no binding, the verifier returns ``APPROVAL_LINKAGE_MISSING``
    # (valid=false, consumed=true). Use this when the action's
    # human-approval requirement isn't covered by the server-side
    # action_type-prefix heuristic.
    require_approval: bool | None = Field(default=None)
    # P1-1: Environment of the permit being verified. Source priority:
    #   context["environment"] → top-level environment → "production".
    # Required by the server for production permits as of 2026-05-14.
    environment: str | None = Field(default=None)
    # P1-5: SHA-256 hex digest of the recursively key-sorted canonical JSON
    # of the original evaluate payload. Required by the server for production
    # permits as of 2026-05-14.
    execution_hash: str | None = Field(default=None)
    # atlasent-api#3915: the permit actor's ``actor_identity.v1``, forwarded
    # unchanged. Required by /v1-verify-permit when the action class is
    # classified ``verified_actor`` (a server-owned mode) and verified against
    # the PERMIT's actor; ignored in every other mode, so always safe to send.
    actor_identity: dict[str, Any] | None = Field(default=None)
    # Legacy fields, excluded from wire serialization.
    context: dict[str, Any] = Field(default_factory=dict, exclude=True)
    api_key: str = Field(default="", exclude=True)

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def _warn_on_legacy_input(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "decision_id" in data and "permit_token" not in data:
            _warn_legacy("VerifyRequest field", "decision_id= -> permit_token=")
        if "action" in data and "action_type" not in data:
            _warn_legacy("VerifyRequest field", "action= -> action_type=")
        if "agent" in data and "actor_id" not in data:
            _warn_legacy("VerifyRequest field", "agent= -> actor_id=")
        if data.get("api_key"):
            _warn_legacy(
                "VerifyRequest field",
                "api_key= (request body) -> Authorization header (handled by client)",
            )
        if data.get("context"):
            _warn_legacy(
                "VerifyRequest field",
                "context= (request body) is no longer cross-checked by the server",
            )
        return data

    @field_validator("context", mode="after")
    @classmethod
    def _check_context_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _warn_oversize_context(value)


class VerifyResult(BaseModel):
    """Response from ``POST /v1-verify-permit``.

    Parses both the canonical handler.ts shape
    (``{valid, outcome, verify_error_code, reason}``) and the legacy
    shape (``{verified, outcome, permit_hash, timestamp}``); legacy
    responses are translated by ``_accept_legacy_response``.

    Canonical attributes:
        valid: ``True`` iff the permit is still valid, un-expired,
            un-revoked, and un-consumed.
        outcome: Server-side ``"allow"`` or ``"deny"``.
        verify_error_code: Stable code populated when ``outcome=="deny"``
            (e.g. ``"PERMIT_EXPIRED"``, ``"PERMIT_ALREADY_USED"``).
        reason: Human-readable explanation. Safe to surface to operators.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*``
            headers. ``None`` when the server didn't emit them.

    Legacy attributes:
        verified: Alias for :attr:`valid`.
        permit_hash: Legacy verification hash. Empty under canonical wire.
        timestamp: Legacy timestamp. Empty under canonical wire.
    """

    valid: bool = False
    outcome: str = ""
    verify_error_code: str | None = None
    reason: str = ""
    consumed: bool | None = None
    """``True`` iff the atomic verify-and-consume burned the permit
    row. Critically, ``APPROVAL_LINKAGE_MISSING`` returns
    ``valid=False`` BUT ``consumed=True`` — the permit cannot be
    reused; do not retry."""
    approval: PermitApprovalBinding | None = None
    """Persisted permit ↔ approval-artifact binding. ``None`` when the
    permit was minted without an approval requirement. Lets executors
    prove which signed approval authorized this consume."""
    rate_limit: RateLimitState | None = None

    # Legacy passthrough.
    verified: bool = False
    permit_hash: str = ""
    timestamp: str = ""

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_response(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        out = dict(data)

        # Legacy server shape: {verified, outcome, permit_hash, timestamp}.
        if "valid" not in out and isinstance(out.get("verified"), bool):
            out["valid"] = out["verified"]
        # Mirror canonical → legacy so existing `result.verified` keeps working.
        if "verified" not in out and isinstance(out.get("valid"), bool):
            out["verified"] = out["valid"]

        return out


# ── Key self-introspection ────────────────────────────────────────────


class ApiKeySelfResult(BaseModel):
    """Successful response from ``GET /v1-api-key-self``.

    Self-introspection of the API key this client was constructed with.
    Never includes the raw key or its hash — introspection is
    intentionally read-only and safe to surface in operator dashboards.

    Useful for:
        * ``IP_NOT_ALLOWED`` debugging — :attr:`client_ip` is the IP the
          server observed (first hop of X-Forwarded-For).
        * Proactive expiry warnings — :attr:`expires_at` is the
          server-stored expiry (``None`` means the key does not
          auto-expire).
        * Verifying scopes before attempting a scope-gated action.
        * "Which key am I?" in multi-tenant dashboards.

    Attributes:
        key_id: Server-side UUID of the ``api_keys`` row for this key.
        org_id: Organization the key belongs to.
        environment: ``"live"`` / ``"test"`` (or any future environment
            label the server introduces).
        scopes: Granted scopes (e.g. ``["evaluate", "audit.read"]``).
        allowed_cidrs: Per-key IP allowlist as CIDR strings, or
            ``None`` when the key is unrestricted.
        rate_limit_per_minute: Server-enforced per-minute rate limit.
        client_ip: Client IP as the server observed it.
        expires_at: Server-stored expiry; ``None`` means no auto-expire.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*``
            headers on this response. ``None`` when the server didn't
            emit them.
    """

    key_id: str
    org_id: str
    environment: str
    scopes: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] | None = None
    rate_limit_per_minute: int
    client_ip: str | None = None
    expires_at: str | None = None
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


# ── Compliance read endpoints ─────────────────────────────────────────


ComplianceControlStatus = Literal[
    "enforced", "partial", "not_enforced", "no_data", "attested"
]


class ComplianceWindow(BaseModel):
    """Resolved evaluation window echoed back on compliance read endpoints."""

    from_: str | None = Field(default=None, alias="from")
    to: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class ComplianceSummary(BaseModel):
    """Status roll-up shared by both compliance read endpoints."""

    enforced: int = 0
    partial: int = 0
    not_enforced: int = 0
    no_data: int = 0
    attested: int = 0
    total: int = 0


class ComplianceControl(BaseModel):
    """A single resolved control row from ``GET /v1-compliance-controls``."""

    clause_id: str
    framework_code: str
    section: str
    title: str
    requirement: str
    atlasent_primitive: str
    status_query: str
    evidence_source: str
    doc_ref: str | None = None
    display_order: int
    status: ComplianceControlStatus
    metric: Any = None

    model_config = ConfigDict(populate_by_name=True)


class ComplianceControlsResult(BaseModel):
    """Successful response from ``GET /v1-compliance-controls``.

    Resolves the compliance control catalog into live enforcement status
    per regulatory clause. Read-only; requires the ``compliance:read``
    scope.

    Attributes:
        framework: Framework code filtered to, or ``None`` when all
            frameworks are returned.
        window: Resolved evaluation window the aggregates were computed
            over.
        generated_at: ISO 8601 timestamp the server resolved the catalog.
        summary: Roll-up of control statuses across the returned set.
        controls: One row per regulatory clause, resolved to a live
            enforcement status.
        truncated: ``True`` when the catalog set was capped server-side.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*``
            headers; ``None`` when the server didn't emit them.
    """

    framework: str | None = None
    window: ComplianceWindow = Field(default_factory=ComplianceWindow)
    generated_at: str
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    controls: list[ComplianceControl] = Field(default_factory=list)
    truncated: bool = False
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class ComplianceEvidenceControl(BaseModel):
    """A single control row inside an evidence-pack ``bundle``."""

    clause_id: str
    framework_code: str
    section: str
    title: str
    requirement: str
    atlasent_primitive: str
    status_query: str
    evidence_source: str
    status: ComplianceControlStatus
    metric: Any = None

    model_config = ConfigDict(populate_by_name=True)


class ComplianceEvidenceBundle(BaseModel):
    """The self-contained, hashable evidence payload.

    ``ComplianceEvidencePackResult.sha256`` is computed over this object.
    """

    schema_: str = Field(alias="schema")
    framework: str
    window: ComplianceWindow = Field(default_factory=ComplianceWindow)
    org_id: str
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    controls: list[ComplianceEvidenceControl] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class ComplianceEvidencePackResult(BaseModel):
    """Successful response from ``GET /v1-compliance-evidence-pack``.

    A signed, self-contained evidence bundle for one regulatory
    framework. Read-only; requires the ``compliance:read`` scope.
    ``framework`` is REQUIRED on the request.

    Attributes:
        framework: Framework code the pack covers.
        window: Resolved evaluation window the pack was computed over.
        generated_at: ISO 8601 timestamp the server generated the pack.
        summary: Roll-up of control statuses across the bundle.
        sha256: SHA-256 hex digest of the canonical ``bundle`` payload.
        signature: Detached signature over the bundle / digest.
        signing_status: Whether the pack was signed and with what key
            state (e.g. ``"signed"`` / ``"unsigned"``).
        key_id: Identifier of the signing key, or ``None`` when unsigned.
        bundle: The self-contained, hashable evidence payload.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*``
            headers; ``None`` when the server didn't emit them.
    """

    framework: str
    window: ComplianceWindow = Field(default_factory=ComplianceWindow)
    generated_at: str
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    sha256: str
    signature: str
    signing_status: str
    key_id: str | None = None
    bundle: ComplianceEvidenceBundle
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


# ── Gate (convenience) ────────────────────────────────────────────────


class GateResult(BaseModel):
    """Combined result from :meth:`AtlaSentClient.gate`.

    Contains both the evaluation and verification results so callers
    have full audit context in one object.
    """

    evaluation: EvaluateResult
    verification: VerifyResult


# ── Authorize (public top-level API) ─────────────────────────────────


@dataclass(frozen=True)
class Permit:
    """Successful return value from :func:`atlasent.protect` — the
    action is authorized end-to-end (evaluate passed AND the resulting
    permit verified).

    Attributes:
        permit_id: Opaque permit / decision identifier.
        permit_hash: Verification hash bound to the permit.
        audit_hash: Hash-chained audit-trail entry (21 CFR Part 11).
        reason: Human-readable explanation from the policy engine.
        timestamp: ISO 8601 timestamp of the verification.
        permit_expires_at: ISO 8601 expiration timestamp of the permit.
            ``None`` on pre-rollout servers that don't emit ``expires_at``.
            Mirrors TypeScript SDK's ``permitExpiresAt``.
    """

    permit_id: str
    permit_hash: str
    audit_hash: str
    reason: str = ""
    timestamp: str = ""
    permit_expires_at: str | None = None


@dataclass
class AuthorizationResult:
    """Result of an :func:`atlasent.authorize` call.

    Check :attr:`permitted` to decide whether to proceed.

    Attributes:
        permitted: ``True`` if the action is authorized and verified.
        agent: The agent identifier passed to ``authorize``.
        action: The action name passed to ``authorize``.
        context: The context dict passed to ``authorize``.
        reason: Human-readable explanation from the policy engine.
        permit_token: Opaque decision identifier for audit lookup.
        audit_hash: Hash-chained audit trail entry.
        permit_hash: Verification hash bound to the permit.
        verified: ``True`` if the permit was server-verified end-to-end.
        timestamp: ISO 8601 timestamp.
        raw: The raw JSON response body from the API.
    """

    permitted: bool
    agent: str = ""
    action: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    permit_token: str = ""
    audit_hash: str = ""
    permit_hash: str = ""
    verified: bool = False
    timestamp: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.permitted


# ── Revoke permit ─────────────────────────────────────────────────────


class RevokePermitResult(BaseModel):
    """Result of :meth:`AtlaSentClient.revoke_permit`."""

    revoked: bool
    permit_id: str = Field(alias="decision_id")
    revoked_at: str | None = None
    audit_hash: str | None = None
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(populate_by_name=True)


# ── Permit lifecycle (canonical REST shapes) ──────────────────────────


class PermitRecord(BaseModel):
    """Wire shape of a Permit row, returned by
    :meth:`AtlaSentClient.get_permit` and embedded in
    :class:`ListPermitsResult`.

    Mirrors the openapi `Permit` schema. Revocation fields
    (``revoked_at``, ``revoked_by``, ``revoke_reason``) are populated
    only when ``status == 'revoked'``.

    Field names are snake_case to match the wire — no rename layer.
    """

    id: str
    org_id: str
    actor_id: str
    action_id: str
    target_id: str | None = None
    environment: str | None = None
    status: Literal["issued", "verified", "consumed", "expired", "revoked"]
    issued_at: str
    expires_at: str
    consumed_at: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None
    signature: str | None = None
    payload_hash: str | None = None
    decision_id: str | None = None

    model_config = ConfigDict(extra="allow")


class GetPermitResult(BaseModel):
    """Result of :meth:`AtlaSentClient.get_permit`."""

    permit: PermitRecord
    rate_limit: RateLimitState | None = None


class ListPermitsResult(BaseModel):
    """Result of :meth:`AtlaSentClient.list_permits`."""

    permits: list[PermitRecord]
    total: int
    next_cursor: str | None = None
    rate_limit: RateLimitState | None = None


# ── Canonical revoke / verify (REST) ──────────────────────────────────


class RevokePermitByIdResult(BaseModel):
    """Result of :meth:`AtlaSentClient.revoke_permit_by_id`.

    Returns the full updated :class:`PermitRecord` with
    ``status == 'revoked'`` and ``revoked_at`` / ``revoked_by`` /
    ``revoke_reason`` populated. After revocation, subsequent verify
    calls return ``410 PERMIT_REVOKED``.
    """

    permit: PermitRecord
    rate_limit: RateLimitState | None = None


class PermitVerifyEvidence(BaseModel):
    """Type-specific evidence body returned by
    :meth:`AtlaSentClient.verify_permit_by_id`.

    Mirrors the openapi ``PermitVerifyEvidence`` schema.
    """

    permit_id: str
    status: Literal["issued", "verified", "consumed", "expired", "revoked"]
    actor_id: str | None = None
    action_id: str | None = None
    expires_at: str | None = None
    payload_hash: str | None = None
    decision_id: str | None = None

    model_config = ConfigDict(extra="allow")


class VerifyPermitByIdResult(BaseModel):
    """Result of :meth:`AtlaSentClient.verify_permit_by_id`.

    The unified verification envelope (``valid``,
    ``verification_type``, ``reason``, ``verified_at``, ``evidence``)
    plus the full :class:`PermitRecord` preserved at ``permit`` for
    backward compatibility. Pin to ``valid`` for new code.
    """

    valid: bool
    verification_type: Literal["permit"] = "permit"
    reason: str | None = None
    verified_at: str
    evidence: PermitVerifyEvidence
    permit: PermitRecord
    rate_limit: RateLimitState | None = None


# ── Authority Intelligence ─────────────────────────────────────────────


class AuthorityExplanationPath(BaseModel):
    """One explicit authority path for a single mechanism, returned by
    :meth:`AtlaSentClient.explain_authority`.

    ``direct_grant`` / ``delegation`` / ``role_capability`` are never
    collapsed into one generic edge type, because the runtime treats
    them differently.
    """

    mechanism: Literal["direct_grant", "delegation", "role_capability"]
    matched: bool
    edges: list[dict[str, Any]] = Field(default_factory=list)
    """Ordered edge chain for this path. Shape varies by mechanism —
    treated as an open object, never over-typed per field."""

    model_config = ConfigDict(extra="allow")


class AuthorityUnresolvedFinding(BaseModel):
    """An excluded or ambiguous authority relationship reported as an
    explicit, named finding (e.g. an expired or unacknowledged
    delegation, a revoked grant, a coarse role whose capability
    mapping can't be expanded in SQL) — never a silent gap.

    ``finding_type`` is a plain string, not a hardcoded enum: the
    server may add new finding types (e.g.
    ``AUTHORITY_GRANT_REVOKED``, ``DELEGATION_EXPIRED``,
    ``DELEGATOR_ROLE_LOST``, ``NO_AUTHORITY_PATH_FOUND``) without a
    wire-breaking change.
    """

    finding_type: str
    reason: str | None = None

    model_config = ConfigDict(extra="allow")


class ExplainAuthorityResult(BaseModel):
    """Result of :meth:`AtlaSentClient.explain_authority` /
    :meth:`AtlaSentAsyncClient.explain_authority`.

    Passed through verbatim from
    ``authority_intelligence_explain_authority_v1`` — answers "why may
    principal P exercise scope/action A in organization O right now?"
    Read-only and additive; the SDK performs no interpretation of
    ``paths`` / ``unresolved`` / ``authority_found`` beyond parsing
    the JSON response.

    Field names are snake_case to match the wire — no rename layer.
    """

    organization_id: str
    principal_id: str
    requested_scope: str
    resource_id: str | None = None
    authority_found: bool
    paths: list[AuthorityExplanationPath] = Field(default_factory=list)
    unresolved: list[AuthorityUnresolvedFinding] = Field(default_factory=list)
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(extra="allow")


# ── Streaming evaluate events ─────────────────────────────────────────


class StreamDecisionEvent(BaseModel):
    """A policy decision emitted mid-stream by ``/v1-evaluate-stream``."""

    type: Literal["decision"] = "decision"
    decision: str
    permit_id: str = Field(alias="decision_id", default="")
    reason: str = ""
    audit_hash: str = ""
    timestamp: str = ""
    is_final: bool = False

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> StreamDecisionEvent:  # noqa: D401
        permitted = data.get("permitted", True)
        # Normalise to lowercase for parity with the TypeScript SDK and the
        # four-value decision literals used everywhere else in the SDK.
        raw_decision = data.get("decision", "allow" if permitted else "deny")
        decision = (
            raw_decision.lower()
            if isinstance(raw_decision, str)
            else ("allow" if permitted else "deny")
        )
        # The real /v1-evaluate-stream `event: decision` frame is
        # `{index, ...<v1-evaluate response>}` — i.e. the same canonical
        # {decision, permit_token, ...} shape evaluate() tolerates, not a
        # stream-specific {permitted, decision_id, is_final} shape. Prefer
        # the canonical `permit_token`; fall back to legacy `decision_id`
        # for older/mocked wire shapes.
        permit_id = data.get("permit_token") or data.get("decision_id", "")
        return cls(
            decision=decision,
            decision_id=permit_id,
            reason=data.get("reason", ""),
            audit_hash=data.get("audit_hash", ""),
            timestamp=data.get("timestamp", ""),
            is_final=bool(data.get("is_final", False)),
        )

    model_config = ConfigDict(populate_by_name=True)


class StreamProgressEvent(BaseModel):
    """An intermediate progress hint emitted before the final decision."""

    type: Literal["progress"] = "progress"
    stage: str = ""
    model_config = ConfigDict(extra="allow", populate_by_name=True)


StreamEvent = Annotated[
    StreamDecisionEvent | StreamProgressEvent,
    Field(discriminator="type"),
]


# ── Phase 7 typed models (provisional) ────────────────────────────────────────
#
# These shapes are SDK-side projections of cross-endpoint concepts:
#   - GovernanceDecision: a uniform decision envelope across
#     /v1-evaluate, governance webhooks, and enforcement helpers.
#   - AuthError: the Phase 4 ErrorEnvelope (`{error, code?, message?,
#     request_id?, status?}`) parsed off any 4xx/5xx response.
#   - EnforcementOutcome: the result of running a governance gate
#     against a decision (raised? passed-through? logged-only?).
#
# Wire contract for the error envelope is being finalized in
# atlasent-api (Phase 4 ErrorEnvelope, see PR #563). Until that lands
# in production the SDK keeps the legacy fallback chain
# (`error → message → reason`) in `_server_message`. Don't pin
# downstream code to these classes until `python-v2.4.0` is tagged.


class GovernanceDecision(BaseModel):
    """Uniform decision envelope across evaluate / webhook / enforcement.

    Mirrors the canonical fields the API emits on /v1-evaluate, plus
    `policy_id` and `evaluated_at` which governance webhooks include
    for deep-linking back to the audit trail.
    """

    decision: Literal["allow", "deny", "hold", "escalate"]
    reason: str | None = None
    code: str | None = None
    policy_id: str | None = None
    request_id: str | None = None
    evaluated_at: str | None = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> GovernanceDecision:
        denial = data.get("denial") or {}
        return cls(
            decision=data.get("decision", "deny"),
            reason=data.get("reason") or denial.get("reason"),
            code=data.get("code") or denial.get("code"),
            policy_id=data.get("policy_id"),
            request_id=data.get("request_id"),
            evaluated_at=data.get("evaluated_at") or data.get("timestamp"),
        )


class AuthError(BaseModel):
    """Parsed Phase 4 ErrorEnvelope.

    `error` is the canonical machine-readable identifier (e.g.
    ``"phi_scope_required"``). `message` is the human-readable string
    on legacy responses. `code` is a server-emitted slug; SDKs surface
    it via :class:`atlasent.exceptions.AtlaSentError.code` already.
    """

    error: str
    message: str | None = None
    code: str | None = None
    request_id: str | None = None
    status: int | None = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    @classmethod
    def from_body(
        cls,
        body: dict[str, Any] | None,
        *,
        status: int | None = None,
        request_id: str | None = None,
    ) -> AuthError | None:
        if not isinstance(body, dict):
            return None
        err = body.get("error")
        msg = body.get("message") or body.get("reason")
        if not isinstance(err, str) or not err:
            # No canonical error; synthesize from message if we have one,
            # otherwise this isn't an envelope we can type.
            if not isinstance(msg, str) or not msg:
                return None
            err = msg
        return cls(
            error=err,
            message=msg if isinstance(msg, str) else None,
            code=body.get("code") if isinstance(body.get("code"), str) else None,
            request_id=request_id or body.get("request_id"),
            status=status,
        )


class EnforcementOutcome(BaseModel):
    """Result of a governance enforcement check.

    Emitted by helpers in :mod:`atlasent.governance.enforcement` when
    a decision is gated through the enforcement layer. ``enforced``
    indicates whether the helper would raise (or did raise, depending
    on the call site); ``enforcement_action`` records what was done.
    """

    enforced: bool
    decision: Literal["allow", "deny", "hold", "escalate"]
    permit_token: str | None = None
    expires_at: str | None = None
    outcome: Literal["allow", "deny"] | None = None
    enforcement_action: (
        Literal["raised", "logged_only", "passthrough", "skipped"] | None
    ) = None
    reason: str | None = None
    code: str | None = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ── Decision replay (ADR-015 Phase C parity runtime) ────────────────────
#
# Restored 2026-05-24: PR #275 added the async client.replay() method
# and the dependent imports in async_client.py, but its squash merge
# dropped python/atlasent/models.py from the changeset — breaking
# `from atlasent import async_client` with an ImportError. This block
# closes that gap and also provides the type surface needed by the
# sync client.replay() in client.py.
#
# Wire alignment notes:
#   - The 7-value union is a deliberate superset of the raw server
#     wire values (NONE / DECISION_CHANGED / ENVELOPE_DRIFT) and the
#     SDK-canonical mapping the client performs (DECISION_CHANGED →
#     POLICY_DRIFT, plus 409 → ENGINE_DRIFT / BUNDLE_MISSING, plus
#     CHAIN_TAMPER for the audit-chain-v5 detector landing in a
#     parallel session). Server can emit any of the wire values; the
#     SDK never round-trips a POLICY_DRIFT string back to the server,
#     so the union being a superset is safe.
#   - `original_decision` and `replayed_decision` are lowercased on
#     ingest to match the canonical evaluate response convention.


ReplayVarianceKind = Literal[
    "NONE",
    "POLICY_DRIFT",
    "DECISION_CHANGED",
    "ENVELOPE_DRIFT",
    "CHAIN_TAMPER",
    "ENGINE_DRIFT",
    "BUNDLE_MISSING",
]


class ReplayResponse(BaseModel):
    """Result of replaying a recorded decision.

    Wire shape mirrors ``POST /v1/decisions/{id}/replay`` on the API
    (atlasent-api ``supabase/functions/v1-decisions-replay``).
    Side-effect-free server-side: replaying does not write to the audit
    chain or mint a permit (ADR-016 ``mode: "replay"`` sentinel).

    Variance interpretation:
        - ``NONE``: replay agrees with the original decision.
        - ``POLICY_DRIFT`` / ``DECISION_CHANGED``: same envelope, same
          bundle, different decision — typically rule non-determinism.
          The SDK normalizes ``DECISION_CHANGED`` (raw wire) to
          ``POLICY_DRIFT`` (canonical); both literals are accepted in
          the union to keep adapters that pass the raw wire string
          through working.
        - ``ENVELOPE_DRIFT``: recorded envelope hash no longer matches
          the recomputed canonical hash; replay short-circuited
          without re-evaluating.
        - ``CHAIN_TAMPER``: audit chain entry binding the engine
          version was tampered (audit chain v5 detector).
        - ``ENGINE_DRIFT``: original engine version is retired beyond
          its archival window, or absent from the registry.
        - ``BUNDLE_MISSING``: original policy bundle was not pinned
          on the recorded evaluation, so replay cannot be made
          deterministic.
    """

    decision_id: str
    variance_kind: ReplayVarianceKind
    original_decision: Literal["allow", "deny", "hold", "escalate"]
    original_deny_code: str | None = None
    replayed_decision: Literal["allow", "deny", "hold", "escalate"] | None = None
    replayed_deny_code: str | None = None
    engine_version: str | None = None
    engine_version_kind: Literal["active", "retired", "archival", "unknown"] | None = (
        None
    )
    accepts_replay: bool = True
    envelope_verification: (
        Literal["verified", "drift", "absent", "envelope_missing"] | None
    ) = None
    replayed_at: str
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(
        extra="allow", populate_by_name=True, arbitrary_types_allowed=True
    )


# ── License verification (self-hosted / air-gapped) ────────────────────────────


class LicenseStatus(BaseModel):
    """License status for a self-hosted or air-gapped AtlaSent deployment.

    Returned by ``GET /v1/license``. Describes the current validity, posture,
    enabled features, and optional capacity limits for the license key installed
    on this instance.

    Callers should check :attr:`status` ``== "active"`` before relying on
    :attr:`features`. A ``"grace"`` status means the license has expired but the
    grace period (:attr:`grace_until`) has not yet elapsed — enforcement is not
    yet suspended, but the license must be renewed immediately.

    Mirrors the TypeScript SDK's ``LicenseStatus`` interface.

    Attributes:
        status: Current validity state — ``"active"``, ``"grace"``,
            ``"expired"``, or ``"revoked"``.
        org_slug: Slug of the organization the license was issued to.
        posture: Deployment posture — ``"self_hosted"`` or ``"air_gapped"``.
        expires_at: ISO 8601 timestamp when the license expires.
        grace_until: ISO 8601 timestamp when the grace period ends.
            Present only when ``status == "grace"``.
        features: Feature flags enabled by this license
            (e.g. ``["governance", "bvs", "federation"]``).
        eval_limit: Maximum evaluations per day; ``None`` means unlimited.
        seat_limit: Maximum active seats (API key holders); ``None`` means
            unlimited.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*`` headers.
            ``None`` when the server didn't emit them.
    """

    status: Literal["active", "grace", "expired", "revoked"]
    org_slug: str
    posture: Literal["self_hosted", "air_gapped"]
    expires_at: str
    grace_until: str | None = None
    features: list[str] = Field(default_factory=list)
    eval_limit: int | None = None
    seat_limit: int | None = None
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(
        extra="allow", populate_by_name=True, arbitrary_types_allowed=True
    )


class LicenseVerifyResult(BaseModel):
    """Result of submitting a signed license blob to ``POST /v1/license/verify``.

    ``valid`` is the contract field — pin to it. When ``valid`` is ``False``,
    :attr:`error` carries a machine-readable reason code such as
    ``"SIGNATURE_INVALID"``, ``"ORG_MISMATCH"``, ``"LICENSE_EXPIRED"``, or
    ``"LICENSE_REVOKED"``.

    Mirrors the TypeScript SDK's ``LicenseVerifyResult`` interface.

    Attributes:
        valid: ``True`` when the submitted blob passes all verification checks.
        org_slug: Slug of the organization the submitted license was issued to.
            Present when ``valid`` is ``True``.
        expires_at: ISO 8601 expiry of the submitted license.
            Present when ``valid`` is ``True``.
        error: Machine-readable error code when ``valid`` is ``False``.
        rate_limit: Per-key rate-limit state from ``X-RateLimit-*`` headers.
            ``None`` when the server didn't emit them.
    """

    valid: bool
    org_slug: str | None = None
    expires_at: str | None = None
    error: str | None = None
    rate_limit: RateLimitState | None = None

    model_config = ConfigDict(
        extra="allow", populate_by_name=True, arbitrary_types_allowed=True
    )
