"""Synchronous AtlaSent API client (httpx-based)."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
import warnings
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

import httpx

from . import evidence_exports as _evx
from . import scim as _scim
from . import siem as _siem
from ._function_region import UNSET, _Unset, function_region_headers
from ._version import __version__
from .access_governance_log import AccessGovernanceLogClient
from .approval_artifact import ApprovalReference
from .audit import AuditEventsResult, AuditExportResult
from .authority_intelligence import AuthorityIntelligenceClient
from .clinical_client import ClinicalTrialsClient
from .evidence_bundle import EvidenceBundlesClient
from .exceptions import (
    PERMIT_MINT_FAILURE_ERROR_CODES,
    AtlaSentDenied,
    AtlaSentDeniedError,
    AtlaSentError,
    AtlaSentErrorCode,
    AtlaSentPermitMintFailedError,
    BundleVerificationError,
    PermissionDeniedError,
    RateLimitError,
    _normalize_permit_outcome,
)
from .governance_agents import (
    GovernanceAgent,
    GovernanceAgentEvaluation,
    GovernanceAgentFinding,
    ListGovernanceAgentsResult,
    ListGovernanceEvaluationsResult,
    ListGovernanceFindingsResult,
)
from .hitl import (
    HitlApprovalsResult,
    HitlChainResult,
    HitlCreateRequest,
    HitlEscalation,
    HitlEscalationResult,
    HitlStatus,
    ListHitlEscalationsResult,
)
from .models import (
    ApiKeySelfResult,
    AuthorizationResult,
    ComplianceControlsResult,
    ComplianceEvidencePackResult,
    ConstraintTrace,
    EvaluatePreflightResult,
    EvaluateRequest,
    EvaluateResult,
    ExplainAuthorityResult,
    GateResult,
    GetPermitResult,
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
    VerifyPermitByIdResult,
    VerifyRequest,
    VerifyResult,
)
from .payload_hash import (
    normalize_caller_payload_hash,
    server_payload_hash,
)
from .sso_client import SsoClient

if TYPE_CHECKING:
    from .cache import TTLCache

logger = logging.getLogger("atlasent")

DEFAULT_BASE_URL = "https://api.atlasent.io"
DEFAULT_TIMEOUT = 10
# Retry schedule parity with the TypeScript SDK:
#   4 total attempts (1 initial + 3 retries), delays 2 s → 4 s → 8 s
#   (capped at 16 s) via the exponential formula:
#   delay = min(16, retry_backoff * 2**attempt)
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 2.0
_RETRY_MAX_DELAY = 16.0


def _compute_execution_hash(payload: dict) -> str:
    """The server's fallback payload binding for ``payload``.

    Thin alias for :func:`atlasent.payload_hash.server_payload_hash`, kept
    because this private name is imported by ``async_client`` and covered by
    existing tests.

    CORRECTED: this used to return BARE hex. The value it is compared against
    — ``execution_evaluations.payload_hash`` / the permit's
    ``execution_hash_expected`` — is written by the server's ``hashPayload``,
    which PREFIXES ``sha256:``. ``/v1-verify-permit`` folds case and normalizes
    nothing else, so bare hex could never compare equal: a deterministic
    ``PAYLOAD_MISMATCH`` on every ``protect()`` / ``with_permit()`` call.

    The canonical BYTES were always right — see
    ``tests/test_payload_hash_parity.py``, which pins all eight applicable
    vectors against digests generated from the real server source. Only the
    scheme prefix was missing.
    """
    # v1-evaluate removes these three from the body before hashing it. The
    # strip belongs HERE and not inside server_payload_hash, which is a
    # faithful port of the server's hashPayload — hashPayload does not strip;
    # its caller does. None of the three is reachable from protect() today
    # (tests/test_protect_payload_binding.py compares against a reference that
    # strips them, so a newly-emitted `explain: false` fails there rather than
    # silently), but the server contract is the contract. Mutation testing
    # found this exact gap on the TypeScript side, where `explain` IS
    # reachable.
    core = (
        {
            k: v
            for k, v in payload.items()
            if k not in ("traceparent", "shadow", "explain")
        }
        if isinstance(payload, dict)
        else payload
    )
    return server_payload_hash(core)


# API-key prefix contract per atlasent-api/supabase/functions/_shared/auth.ts:
#   "ask_live_<entropy>" — production keys
#   "ask_test_<entropy>" — non-production keys
# Validated client-side so a mis-pasted key (with whitespace, quotes,
# or a leftover wrapping char) trips loudly at construction rather
# than yielding a 401 mid-conversation. The character class matches
# what atlasent-api accepts; widen here only if the server widens
# first.
_API_KEY_PATTERN = re.compile(r"^ask_(?:live|test)_[A-Za-z0-9_-]+$")
_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")


def _validate_api_key(api_key: str) -> str:
    """Reject obviously-malformed API keys at client init.

    Returns the trimmed key on accept; raises ``ValueError`` on
    reject. Never echoes the key into the error message — only the
    first 8 characters of any non-matching value, so a paste accident
    that copies the right side of the key doesn't surface in stderr.
    """
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("AtlaSent api_key is required")
    if not _API_KEY_PATTERN.match(api_key):
        head = api_key[:8] if api_key else ""
        raise ValueError(
            f"AtlaSent api_key does not match expected shape "
            f"`ask_(live|test)_<entropy>` (got prefix={head!r}). "
            "Check for whitespace, quotes, or trailing characters."
        )
    return api_key


def _redact_token(token: str) -> str:
    """Render a permit/decision token safe to log.

    Returns ``"…<last 6>"`` so log lines correlate against the
    server-side audit trail without leaking enough material to replay
    a permit. ``""`` and short strings render as ``"…"``.
    """
    if not token:
        return "…"
    return "…" + token[-6:]


def _enforce_tls(base_url: str) -> str:
    """Reject non-TLS base URLs unless the dev escape hatch is set.

    `ATLASENT_ALLOW_INSECURE_HTTP=1` permits ``http://`` for local
    fixtures and unit tests that mock httpx — production callers never
    set this. Returns the URL unchanged on accept; raises ``ValueError``
    on reject.
    """
    if os.getenv("ATLASENT_ALLOW_INSECURE_HTTP") == "1":
        return base_url
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.scheme != "https":
        raise ValueError(
            f"AtlaSent base_url must use https:// (got scheme={parsed.scheme!r}). "
            "For local development, set ATLASENT_ALLOW_INSECURE_HTTP=1."
        )
    return base_url


class AtlaSentClient:
    """Synchronous client for the AtlaSent authorization API.

    The client is **fail-closed**: any failure to confirm authorization
    raises an exception, so no action can proceed without an explicit
    permit.

    Args:
        api_key: Your AtlaSent API key (required).
        anon_key: An anonymous / public key for client-side contexts.
        base_url: Override the API base URL.
        timeout: HTTP request timeout in seconds.
        max_retries: Retries on transient errors (5xx, timeouts).
        retry_backoff: Base backoff in seconds (doubles each retry).
        cache: Optional :class:`~atlasent.cache.TTLCache` for caching
            evaluate results and avoiding redundant API calls.
        function_region: Edge-function region for runtime calls, sent as
            the region-pinning header. Omit to use ATLASENT_FUNCTION_REGION,
            then us-west-1 (the database's region) for the hosted runtime and
            no pinning otherwise. ``"auto"`` or ``None``: no pinning. A
            malformed value raises ``FunctionRegionConfigError``.

    Usage::

        from atlasent import AtlaSentClient

        client = AtlaSentClient(api_key="ask_live_...")
        result = client.gate("modify_patient_record", "agent-1",
                             {"patient_id": "PT-001"})
        print(result.verification.permit_hash)

    Supports the context-manager protocol::

        with AtlaSentClient(api_key="ask_live_...") as client:
            result = client.evaluate("read_data", "agent-1")
    """

    def __init__(
        self,
        api_key: str,
        *,
        anon_key: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        cache: TTLCache | None = None,
        function_region: str | None | _Unset = UNSET,
    ) -> None:
        self._api_key = _validate_api_key(api_key)
        self._anon_key = anon_key
        self._base_url = _enforce_tls(base_url).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff
        self._cache = cache
        # Edge-function region (see ._function_region); resolved once, sent on
        # every request through this client's default headers.
        self._region_headers = function_region_headers(self._base_url, function_region)
        self._client = httpx.Client(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": f"atlasent-python/{__version__}",
                **self._region_headers,
                # ADR-025: declare the wire-protocol version we were
                # built against. Runtime serves this version's response
                # shape; older versions outside the compatibility window
                # get 426 Upgrade Required.
                "X-AtlaSent-Protocol-Version": "1",
            },
            timeout=self._timeout,
        )
        self.sso = SsoClient(self)
        self.access_governance_log = AccessGovernanceLogClient(self)
        self.evidence_bundles = EvidenceBundlesClient(self)
        self.clinical_trials = ClinicalTrialsClient(self)
        self.authority_intelligence = AuthorityIntelligenceClient(self)

    # ── properties ────────────────────────────────────────────

    @property
    def api_key(self) -> str:
        return self._api_key

    @property
    def base_url(self) -> str:
        return self._base_url

    # ── public API ───────────────────────────────────────────

    def evaluate(
        self,
        action_type: str,
        actor_id: str,
        context: dict[str, Any] | None = None,
        *,
        resource_id: str | None = None,
        amount: float | None = None,
        approval: ApprovalReference | dict[str, Any] | None = None,
        require_approval: bool | None = None,
        environment: str | None = None,
        resource: dict[str, Any] | None = None,
        current_state: dict[str, Any] | None = None,
        proposed_state: dict[str, Any] | None = None,
        execution_binding: dict[str, Any] | None = None,
        state_snapshot: dict[str, Any] | None = None,
        execution_payload_hash: str | None = None,
        actor_identity: dict[str, Any] | None = None,
    ) -> EvaluateResult:
        ctx = context or {}
        if isinstance(approval, dict):
            approval = ApprovalReference.model_validate(approval)

        if self._cache is not None:
            from .cache import TTLCache

            cache_key = TTLCache.make_key(action_type, actor_id, ctx)
            cached = self._cache.get(cache_key)
            if cached is not None:
                logger.debug("evaluate cache hit for %s", cache_key)
                return cached

        req = EvaluateRequest(
            action_type=action_type,
            actor_id=actor_id,
            context=ctx,
            resource_id=resource_id,
            amount=amount,
            approval=approval,
            require_approval=require_approval,
            environment=environment,
            resource=resource,
            current_state=current_state,
            proposed_state=proposed_state,
            execution_binding=execution_binding,
            state_snapshot=state_snapshot,
            execution_payload_hash=execution_payload_hash,
            actor_identity=actor_identity,
        )
        logger.debug("evaluate action=%r actor=%r", action_type, actor_id)
        data, rate_limit, request_id = self._post(
            "/v1-evaluate", req.model_dump(by_alias=True, exclude_none=True)
        )

        decision = data.get("decision")
        if decision is None and isinstance(data.get("permitted"), bool):
            decision = "allow" if data["permitted"] else "deny"
        permit_token_raw = data.get("permit_token") or data.get("decision_id")
        if decision not in ("allow", "deny", "hold", "escalate") or not isinstance(
            permit_token_raw, (str, type(None))
        ):
            raise AtlaSentError(
                "Malformed /v1-evaluate response: missing or invalid "
                "`decision` (or legacy `permitted`/`decision_id`)",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        if decision != "allow":
            denial = data.get("denial") if isinstance(data.get("denial"), dict) else {}
            # Canonical handler.ts emits top-level deny_reason / deny_code;
            # the contract/legacy shape nests them under `denial`. Read both.
            reason = (
                data.get("deny_reason")
                or (denial.get("reason") if denial else None)
                or data.get("reason", "")
            )
            deny_code = data.get("deny_code") or (
                denial.get("code") if denial else None
            )
            raise AtlaSentDenied(
                decision=decision,
                permit_token=permit_token_raw or "",
                reason=reason or "",
                deny_code=deny_code,
                request_id=request_id,
                response_body=data,
            )

        if not permit_token_raw:
            # #1634: a 2xx allow response missing permit_token is the same
            # "allow, but no executable authority" outcome as the
            # documented permit_signing_unavailable envelope the _request()
            # layer already handles below — defensive fallback in case a
            # future response shape ever resolves this way over a 2xx
            # status. Same distinct error class either way.
            raise AtlaSentPermitMintFailedError(
                "Malformed /v1-evaluate response: decision='allow' "
                "but no permit_token (or legacy decision_id)",
                request_id=request_id,
                response_body=data,
            )

        result = EvaluateResult.model_validate(data)
        result.rate_limit = rate_limit
        logger.info(
            "evaluate permitted action=%r actor=%r token=%s",
            action_type,
            actor_id,
            _redact_token(result.permit_token),
        )

        if self._cache is not None:
            self._cache.put(cache_key, result)

        return result

    def evaluate_preflight(
        self,
        action_type: str,
        actor_id: str,
        context: dict[str, Any] | None = None,
    ) -> EvaluatePreflightResult:
        ctx = context or {}
        req = EvaluateRequest(
            action_type=action_type,
            actor_id=actor_id,
            context=ctx,
        )
        logger.debug("evaluate_preflight action=%r actor=%r", action_type, actor_id)
        data, rate_limit, request_id = self._post(
            "/v1-evaluate",
            req.model_dump(by_alias=True, exclude_none=True),
            params={"include": "constraint_trace"},
        )

        decision = data.get("decision")
        if decision is None and isinstance(data.get("permitted"), bool):
            decision = "allow" if data["permitted"] else "deny"
        if decision not in ("allow", "deny", "hold", "escalate"):
            raise AtlaSentError(
                "Malformed /v1-evaluate response: missing or invalid "
                "`decision` (or legacy `permitted`)",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        evaluation = EvaluateResult.model_validate(data)
        evaluation.rate_limit = rate_limit

        trace_raw = data.get("constraint_trace")
        constraint_trace: ConstraintTrace | None = None
        if isinstance(trace_raw, dict):
            constraint_trace = ConstraintTrace.model_validate(trace_raw)

        logger.info(
            "evaluate_preflight decision=%s action=%r actor=%r trace=%s",
            evaluation.decision,
            action_type,
            actor_id,
            "present" if constraint_trace is not None else "absent",
        )
        return EvaluatePreflightResult(
            evaluation=evaluation, constraint_trace=constraint_trace
        )

    def verify(
        self,
        permit_token: str,
        action_type: str = "",
        actor_id: str = "",
        context: dict[str, Any] | None = None,
        *,
        require_approval: bool | None = None,
        environment: str | None = None,
        execution_hash: str | None = None,
        actor_identity: dict[str, Any] | None = None,
    ) -> VerifyResult:
        warnings.warn(
            "AtlaSentClient.verify() is deprecated. Use verify_permit_by_id() "
            "for the canonical REST surface; it returns the unified "
            "verification envelope (valid/verification_type/reason/verified_at/"
            "evidence) plus the full PermitRecord. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        del context
        req = VerifyRequest(
            permit_token=permit_token,
            action_type=action_type,
            actor_id=actor_id,
            require_approval=require_approval,
            environment=environment,
            execution_hash=execution_hash if execution_hash else None,
            actor_identity=actor_identity,
        )
        logger.debug("verify token=%s", _redact_token(permit_token))
        data, rate_limit, request_id = self._post(
            "/v1-verify-permit", req.model_dump(by_alias=True, exclude_none=True)
        )
        if not isinstance(data.get("valid"), bool) and not isinstance(
            data.get("verified"), bool
        ):
            raise AtlaSentError(
                "Malformed /v1-verify-permit response: missing `valid` "
                "(or legacy `verified`)",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        result = VerifyResult.model_validate(data)
        result.rate_limit = rate_limit
        logger.info(
            "verify token=%s valid=%s", _redact_token(permit_token), result.valid
        )
        return result

    def protect(
        self,
        *,
        agent: str,
        action: str,
        context: dict[str, Any] | None = None,
        state_snapshot: dict[str, Any] | None = None,
        execution_payload_hash: str | None = None,
        actor_identity: dict[str, Any] | None = None,
    ) -> Permit:
        """Authorize an action end-to-end — the fail-closed execution primitive.

        Mirrors the TypeScript SDK's ``atlasent.protect()``. On allow, returns
        a verified :class:`Permit`. On policy denial, permit verification
        failure, or server unavailability raises :class:`AtlaSentDeniedError`.
        On transport / auth / rate-limit errors raises :class:`AtlaSentError`.

        ADR-005 D3: The trust snapshot expiry is checked before ``evaluate()``.
        When the snapshot is expired this raises :class:`BundleVerificationError`
        (a subclass of :class:`AtlaSentDeniedError`) unless the global manager
        was constructed with ``allow_expired_snapshot=True``.

        P1-5: ``execution_hash`` is computed over the canonical evaluate payload
        and sent on the ``/v1-verify-permit`` call so the server can validate
        the payload was not tampered with between evaluate and verify.

        ``verify_unavailable``: if the verify step raises a 5xx
        :class:`AtlaSentError`, the action is denied with
        ``outcome="verify_unavailable"`` rather than propagating the raw server
        error — callers get a typed denial they can branch on.
        """
        if not _ACTION_TYPE_RE.match(action):
            raise AtlaSentError(
                (
                    "action must be in dot-notation format "
                    '(e.g. "production.deploy"). '
                    f"Got: {action!r}"
                ),
                code="bad_request",
            )

        # ADR-005 D3: fail-closed on expired trust snapshot.
        # checkExpiry() also emits the one-time half-life warning when
        # >50% of the validity window has elapsed — mirrors TS protect.ts.
        from .trust_root import get_global_trust_root_manager  # noqa: PLC0415

        trust_mgr = get_global_trust_root_manager()
        if trust_mgr.check_expiry() == "expired":
            snap = trust_mgr.get_snapshot()
            raise BundleVerificationError(
                bundle_reason="trust_snapshot_expired",
                snapshot_valid_until=snap.valid_until,
                snapshot_fetched_at=snap.issued_at,
            )

        ctx = context or {}
        # Normalize BEFORE the evaluate call. A malformed digest is DROPPED by
        # the runtime, not rejected -- allow, permit, 200, no error -- which
        # mints a permit the caller wrongly believes is bound to its payload.
        # Refusing here turns silent non-enforcement into a loud caller error.
        _caller_hash = (
            normalize_caller_payload_hash(execution_payload_hash)
            if execution_payload_hash is not None
            else None
        )
        try:
            eval_result = self.evaluate(
                action,
                agent,
                ctx,
                state_snapshot=state_snapshot,
                execution_payload_hash=_caller_hash,
                actor_identity=actor_identity,
            )
        except AtlaSentDenied as exc:
            audit_hash = ""
            if exc.response_body is not None:
                candidate = exc.response_body.get("audit_hash")
                if isinstance(candidate, str):
                    audit_hash = candidate
            raise AtlaSentDeniedError(
                decision="deny",
                evaluation_id=exc.permit_token,
                reason=exc.reason,
                deny_code=exc.deny_code,
                audit_hash=audit_hash,
            ) from None

        _ctx_env = (
            ctx.get("environment") if isinstance(ctx.get("environment"), str) else None
        )
        if not _ctx_env:
            raise AtlaSentError(
                "context.environment is required. Pass the environment where this "
                "action executes (for example, 'production' or 'staging').",
                code="bad_request",
            )

        # Hash the body that was ACTUALLY POSTED, not a hand-written mirror of
        # it. The server hashes the whole evaluate body (minus traceparent /
        # shadow / explain), so any field that reaches the wire without
        # appearing here yields a digest that cannot match — which is exactly
        # what happened: the old three-key literal omitted `state_snapshot`,
        # so every protect(state_snapshot=...) call was a guaranteed
        # PAYLOAD_MISMATCH independently of the scheme-prefix defect.
        #
        # Reconstructed through the same EvaluateRequest model and the same
        # model_dump options evaluate() uses, so a field added to that model is
        # picked up automatically instead of silently dropped here.
        # `tests/test_protect_payload_binding.py` asserts this equals the body
        # the transport actually saw.
        # Which digest to present depends on which binding the permit carries,
        # and presenting the wrong FORM is a denial rather than a no-op:
        #
        #   caller digest supplied -> the server signed THAT bare hex into
        #     execution_hash_expected. Present it unchanged.
        #   none supplied -> the permit is bound to the server's own
        #     sha256:-prefixed hash of the whole evaluate body. Reproduce it.
        if _caller_hash is not None:
            _execution_hash = _caller_hash
        else:
            _eval_payload: dict[str, Any] = EvaluateRequest(
                action_type=action,
                actor_id=agent,
                context=ctx,
                state_snapshot=state_snapshot,
                actor_identity=actor_identity,
            ).model_dump(by_alias=True, exclude_none=True)
            _execution_hash = _compute_execution_hash(_eval_payload)

        # verify_unavailable: if the verify step returns 5xx, surface a typed
        # denial rather than propagating a raw AtlaSentError — fail-closed.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                verify_result = self.verify(
                    eval_result.permit_token,
                    action,
                    agent,
                    ctx,
                    environment=_ctx_env,
                    execution_hash=_execution_hash,
                    actor_identity=actor_identity,
                )
        except AtlaSentError as verify_err:
            if (
                verify_err.status_code is not None and verify_err.status_code >= 500
            ) or verify_err.code in ("server_error", "timeout", "network"):
                raise AtlaSentDeniedError(
                    decision="deny",
                    evaluation_id=eval_result.permit_token,
                    reason=f"Permit verification unavailable: {verify_err.message}",
                    audit_hash=eval_result.audit_hash,
                    outcome="verify_unavailable",
                ) from verify_err
            raise

        if not verify_result.valid:
            raise AtlaSentDeniedError(
                decision="deny",
                evaluation_id=eval_result.permit_token,
                reason=f"Permit failed verification ({verify_result.outcome})",
                audit_hash=eval_result.audit_hash,
                outcome=_normalize_permit_outcome(verify_result.outcome),
            )

        return Permit(
            permit_id=eval_result.permit_token,
            permit_hash=verify_result.permit_hash,
            audit_hash=eval_result.audit_hash,
            reason=eval_result.reason,
            timestamp=verify_result.timestamp,
            permit_expires_at=eval_result.expires_at or None,
        )

    def gate(
        self,
        action_type: str,
        actor_id: str,
        context: dict[str, Any] | None = None,
    ) -> GateResult:
        warnings.warn(
            "AtlaSentClient.gate() is deprecated. Use protect() for "
            "fail-closed execution or evaluate() + verify() to inspect "
            "the decision and verify separately. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        ctx = context or {}
        eval_result = self.evaluate(action_type, actor_id, ctx)
        verify_result = self.verify(
            eval_result.permit_token, action_type, actor_id, ctx
        )
        return GateResult(evaluation=eval_result, verification=verify_result)

    def authorize(
        self,
        *,
        agent: str,
        action: str,
        context: dict[str, Any] | None = None,
        verify: bool = True,
        raise_on_deny: bool = False,
    ) -> AuthorizationResult:
        warnings.warn(
            "AtlaSentClient.authorize() is deprecated. Use protect() for "
            "fail-closed execution (recommended) or evaluate() to inspect "
            "the four-value decision. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        ctx = context or {}
        try:
            eval_result = self.evaluate(action, agent, ctx)
        except AtlaSentDenied as exc:
            if raise_on_deny:
                raise PermissionDeniedError(
                    decision=exc.decision,
                    permit_token=exc.permit_token,
                    reason=exc.reason,
                    response_body=exc.response_body,
                ) from None
            return AuthorizationResult(
                permitted=False,
                agent=agent,
                action=action,
                context=dict(ctx),
                reason=exc.reason,
                permit_token=exc.permit_token,
                raw=exc.response_body or {},
            )

        permit_hash = ""
        verified = False
        if verify:
            verify_result = self.verify(eval_result.permit_token, action, agent, ctx)
            permit_hash = verify_result.permit_hash
            verified = verify_result.valid

        return AuthorizationResult(
            permitted=True,
            agent=agent,
            action=action,
            context=dict(ctx),
            reason=eval_result.reason,
            permit_token=eval_result.permit_token,
            audit_hash=eval_result.audit_hash,
            permit_hash=permit_hash,
            verified=verified,
            timestamp=eval_result.timestamp,
            raw=eval_result.model_dump(by_alias=True),
        )

    # ── lifecycle ────────────────────────────────────────────

    def close(self) -> None:
        self._client.close()
        logger.debug("AtlaSentClient closed")

    def __enter__(self) -> AtlaSentClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()

    # ── SCIM 2.0 ─────────────────────────────────────────────────────────
    # Method-level parity with AsyncAtlaSentClient's async_scim_* methods.
    # These delegate to the verified flat functions in atlasent.scim so the
    # endpoints/payloads stay single-sourced; sync callers get
    # ``client.scim_list_users(...)`` instead of importing module functions.

    def scim_list_users(
        self,
        org_id: str,
        *,
        filter: str | None = None,  # noqa: A002
        start_index: int | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Users`` — list provisioned users."""
        return _scim.scim_list_users(
            self, org_id, filter=filter, start_index=start_index, count=count
        )

    def scim_create_user(self, org_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """``POST /v1/scim/v2/{orgId}/Users`` — provision a new user."""
        return _scim.scim_create_user(self, org_id, user)

    def scim_get_user(self, org_id: str, user_id: str) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Users/{userId}`` — fetch a user by ID."""
        return _scim.scim_get_user(self, org_id, user_id)

    def scim_replace_user(
        self, org_id: str, user_id: str, user: dict[str, Any]
    ) -> dict[str, Any]:
        """``PUT /v1/scim/v2/{orgId}/Users/{userId}`` — full replacement."""
        return _scim.scim_replace_user(self, org_id, user_id, user)

    def scim_patch_user(
        self, org_id: str, user_id: str, operations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """``PATCH /v1/scim/v2/{orgId}/Users/{userId}`` — partial update."""
        return _scim.scim_patch_user(self, org_id, user_id, operations)

    def scim_delete_user(self, org_id: str, user_id: str) -> None:
        """``DELETE /v1/scim/v2/{orgId}/Users/{userId}`` — deprovision a user."""
        return _scim.scim_delete_user(self, org_id, user_id)

    def scim_list_groups(
        self,
        org_id: str,
        *,
        filter: str | None = None,  # noqa: A002
        start_index: int | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Groups`` — list provisioned groups."""
        return _scim.scim_list_groups(
            self, org_id, filter=filter, start_index=start_index, count=count
        )

    def scim_create_group(self, org_id: str, group: dict[str, Any]) -> dict[str, Any]:
        """``POST /v1/scim/v2/{orgId}/Groups`` — create a group."""
        return _scim.scim_create_group(self, org_id, group)

    def scim_get_group(self, org_id: str, group_id: str) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Groups/{groupId}`` — fetch a group by ID."""
        return _scim.scim_get_group(self, org_id, group_id)

    def scim_replace_group(
        self, org_id: str, group_id: str, group: dict[str, Any]
    ) -> dict[str, Any]:
        """``PUT /v1/scim/v2/{orgId}/Groups/{groupId}`` — full replacement."""
        return _scim.scim_replace_group(self, org_id, group_id, group)

    def scim_patch_group(
        self, org_id: str, group_id: str, operations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """``PATCH /v1/scim/v2/{orgId}/Groups/{groupId}`` — add/remove members."""
        return _scim.scim_patch_group(self, org_id, group_id, operations)

    def scim_delete_group(self, org_id: str, group_id: str) -> None:
        """``DELETE /v1/scim/v2/{orgId}/Groups/{groupId}`` — delete a group."""
        return _scim.scim_delete_group(self, org_id, group_id)

    # ── SIEM ─────────────────────────────────────────────────────────────

    def get_siem_config(self, org_id: str) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/siem-config`` — fetch current SIEM config."""
        return _siem.get_siem_config(self, org_id)

    def upsert_siem_config(
        self,
        org_id: str,
        *,
        destination_url: str,
        format: str = "json",  # noqa: A002
        auth_type: str = "none",
        credential: str | None = None,
        enabled: bool = True,
        included_event_types: list[str] | None = None,
        batch_size: int = 100,
        retry_count: int = 3,
    ) -> dict[str, Any]:
        """``PATCH /v1/orgs/{orgId}/siem-config`` — create or update SIEM config."""
        return _siem.upsert_siem_config(
            self,
            org_id,
            destination_url=destination_url,
            format=format,
            auth_type=auth_type,
            credential=credential,
            enabled=enabled,
            included_event_types=included_event_types,
            batch_size=batch_size,
            retry_count=retry_count,
        )

    def siem_test_delivery(self, org_id: str) -> dict[str, Any]:
        """``POST /v1/orgs/{orgId}/siem-exports/test`` — send a test event."""
        return _siem.siem_test_delivery(self, org_id)

    # ── Evidence exports ─────────────────────────────────────────────────

    def list_evidence_exports(
        self, org_id: str, *, regime: str | None = None
    ) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/evidence-exports`` — list past evidence exports."""
        return _evx.list_evidence_exports(self, org_id, regime=regime)

    def get_evidence_export(self, org_id: str, export_id: str) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/evidence-exports/{exportId}`` — fetch one export."""
        return _evx.get_evidence_export(self, org_id, export_id)

    def create_evidence_export(
        self,
        org_id: str,
        *,
        regime: str,
        window: dict[str, str] | None = None,
        bundle_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/orgs/{orgId}/evidence-exports`` — build & persist a bundle."""
        return _evx.create_evidence_export(
            self,
            org_id,
            regime=regime,
            window=window,
            bundle_id=bundle_id,
            evidence=evidence,
        )

    def key_self(self) -> ApiKeySelfResult:
        logger.debug("key_self")
        data, rate_limit, request_id = self._get("/v1-api-key-self")

        if not isinstance(data.get("key_id"), str) or not isinstance(
            data.get("org_id"), str
        ):
            raise AtlaSentError(
                "Malformed /v1-api-key-self response: missing " "`key_id` or `org_id`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        return ApiKeySelfResult.model_validate({**data, "rate_limit": rate_limit})

    # ── Compliance read endpoints ────────────────────────────────────────────

    def compliance_controls(
        self,
        *,
        framework: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> ComplianceControlsResult:
        """Resolve the compliance control catalog into live enforcement status
        (``GET /v1-compliance-controls``).

        Each regulatory clause is mapped to an AtlaSent enforcement
        primitive and resolved to a live status — ``enforced`` /
        ``partial`` / ``not_enforced`` / ``no_data`` / ``attested``.

        Read-only — requires the ``compliance:read`` scope.

        Args:
            framework: Filter to one framework code (e.g. ``"cfr_part_11"``).
                Omit for every framework.
            from_: Inclusive lower bound on the evaluation window (ISO 8601).
                Maps to the ``from`` query key.
            to: Inclusive upper bound on the evaluation window (ISO 8601).

        Raises:
            AtlaSentError: Network error, timeout, or malformed payload.
        """
        params: dict[str, str] = {}
        if framework is not None:
            params["framework"] = framework
        if from_ is not None:
            params["from"] = from_
        if to is not None:
            params["to"] = to

        logger.debug("compliance_controls framework=%r", framework)
        data, rate_limit, request_id = self._get(
            "/v1-compliance-controls", params=params or None
        )

        if not isinstance(data.get("controls"), list) or not isinstance(
            data.get("generated_at"), str
        ):
            raise AtlaSentError(
                "Malformed /v1-compliance-controls response: missing "
                "`controls` or `generated_at`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        return ComplianceControlsResult.model_validate(
            {**data, "rate_limit": rate_limit}
        )

    def compliance_evidence_pack(
        self,
        *,
        framework: str,
        from_: str | None = None,
        to: str | None = None,
    ) -> ComplianceEvidencePackResult:
        """Produce a signed, self-contained compliance evidence pack for one
        regulatory framework (``GET /v1-compliance-evidence-pack``).

        The returned ``bundle`` is hashable offline: recompute SHA-256 over
        it and compare to ``sha256``, then check ``signature`` against the
        trust root.

        Read-only — requires the ``compliance:read`` scope.

        Args:
            framework: Framework code the pack covers (e.g. ``"cfr_part_11"``).
                REQUIRED — the server rejects the call without it.
            from_: Inclusive lower bound on the evaluation window (ISO 8601).
                Maps to the ``from`` query key.
            to: Inclusive upper bound on the evaluation window (ISO 8601).

        Raises:
            AtlaSentError: Missing ``framework``, network error, timeout, or
                malformed payload.
        """
        if not framework:
            raise AtlaSentError("framework is required", code="bad_request")
        params: dict[str, str] = {"framework": framework}
        if from_ is not None:
            params["from"] = from_
        if to is not None:
            params["to"] = to

        logger.debug("compliance_evidence_pack framework=%r", framework)
        data, rate_limit, request_id = self._get(
            "/v1-compliance-evidence-pack", params=params
        )

        if not isinstance(data.get("sha256"), str) or not isinstance(
            data.get("bundle"), dict
        ):
            raise AtlaSentError(
                "Malformed /v1-compliance-evidence-pack response: missing "
                "`sha256` or `bundle`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        return ComplianceEvidencePackResult.model_validate(
            {**data, "rate_limit": rate_limit}
        )

    # ── License verification (self-hosted / air-gapped) ──────────────────────

    def get_license(self) -> LicenseStatus:
        """Retrieve the license status of this self-hosted or air-gapped deployment.

        Calls ``GET /v1/license``. Returns the current validity state, expiry,
        enabled feature flags, and optional capacity limits for the installed
        license key.

        Callers should check ``result.status == "active"`` before proceeding.
        A ``"grace"`` status means the license has lapsed but a grace window
        (``grace_until``) is still open — the deployment continues to function
        but the license should be renewed immediately.

        Returns:
            :class:`LicenseStatus` — license validity and metadata.

        Raises:
            :class:`AtlaSentError` on transport or authentication failures.
        """
        logger.debug("get_license")
        data, rate_limit, _ = self._get("/v1/license")
        return LicenseStatus.model_validate({**data, "rate_limit": rate_limit})

    def verify_license(self, blob: str) -> LicenseVerifyResult:
        """Validate a signed license blob against this deployment's public key.

        Calls ``POST /v1/license/verify``. Use this when onboarding a new
        license key or rotating an expiring one — submit the blob received from
        AtlaSent and check ``result.valid`` before applying the new license.

        A ``valid=False`` response is **not** raised — inspect the returned
        object. Only transport / server errors raise :class:`AtlaSentError`.

        Args:
            blob: The signed license blob string provided by AtlaSent.

        Returns:
            :class:`LicenseVerifyResult` — ``valid`` flag plus optional
            ``org_slug``, ``expires_at``, and ``error`` fields.

        Raises:
            :class:`AtlaSentError` on transport or authentication failures.
        """
        if not blob or not isinstance(blob, str):
            raise AtlaSentError("blob is required", code="bad_request")
        logger.debug("verify_license")
        data, rate_limit, _ = self._post("/v1/license/verify", {"blob": blob})
        return LicenseVerifyResult.model_validate({**data, "rate_limit": rate_limit})

    def revoke_permit(
        self,
        permit_id: str,
        *,
        reason: str | None = None,
    ) -> RevokePermitResult:
        warnings.warn(
            "AtlaSentClient.revoke_permit() is deprecated. Use "
            "revoke_permit_by_id() for the canonical REST surface; it "
            "returns the full updated PermitRecord with revoked_at / "
            "revoked_by / revoke_reason populated. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        payload = {
            "decision_id": permit_id,
            "reason": reason or "",
            "api_key": self._api_key,
        }
        logger.debug("revoke_permit permit_id=%s", _redact_token(permit_id))
        data, rate_limit, request_id = self._post("/v1-revoke-permit", payload)

        if not isinstance(data.get("revoked"), bool) or not isinstance(
            data.get("decision_id"), str
        ):
            raise AtlaSentError(
                "Malformed /v1-revoke-permit response: "
                "missing `revoked` or `decision_id`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        result = RevokePermitResult.model_validate(data)
        result.rate_limit = rate_limit
        return result

    def revoke_permit_by_id(
        self,
        permit_id: str,
        *,
        reason: str | None = None,
    ) -> RevokePermitByIdResult:
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        path = f"/v1/permits/{quote(permit_id, safe='')}/revoke"
        data, rate_limit, _ = self._post(path, body)
        return RevokePermitByIdResult(
            permit=PermitRecord.model_validate(data),
            rate_limit=rate_limit,
        )

    def verify_permit_by_id(self, permit_id: str) -> VerifyPermitByIdResult:
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        path = f"/v1/permits/{quote(permit_id, safe='')}/verify"
        data, rate_limit, request_id = self._post(path, {})
        envelope_keys = {
            "valid",
            "verification_type",
            "reason",
            "verified_at",
            "evidence",
        }
        permit_row = {k: v for k, v in data.items() if k not in envelope_keys}
        if "valid" not in data or "evidence" not in data:
            raise AtlaSentError(
                (
                    "Malformed /v1/permits/{id}/verify response: "
                    "missing canonical envelope fields"
                ),
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        return VerifyPermitByIdResult(
            valid=bool(data["valid"]),
            verification_type="permit",
            reason=data.get("reason"),
            verified_at=str(data["verified_at"]),
            evidence=PermitVerifyEvidence.model_validate(data["evidence"]),
            permit=PermitRecord.model_validate(permit_row),
            rate_limit=rate_limit,
        )

    def get_permit(self, permit_id: str) -> GetPermitResult:
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        path = f"/v1/permits/{quote(permit_id, safe='')}"
        data, rate_limit, _ = self._get(path)
        return GetPermitResult(
            permit=PermitRecord.model_validate(data),
            rate_limit=rate_limit,
        )

    def explain_authority(
        self,
        principal_id: str,
        requested_scope: str,
        resource_id: str | None = None,
    ) -> ExplainAuthorityResult:
        """Explain why (or why not) ``principal_id`` currently has
        authority for ``requested_scope`` in the caller's org.

        Calls ``GET /v1-authority-intelligence/explain-authority``.
        Strictly read-only and additive — it explains the same facts
        ``/v1-evaluate`` and ``/v1-verify-permit`` already read, and
        never changes any deny/hold/allow semantics. Requires the
        ``authority_intelligence:read`` API key scope.
        """
        if not principal_id:
            raise AtlaSentError("principal_id is required", code="bad_request")
        if not requested_scope:
            raise AtlaSentError("requested_scope is required", code="bad_request")
        params: dict[str, str] = {
            "principal_id": principal_id,
            "requested_scope": requested_scope,
        }
        if resource_id:
            params["resource_id"] = resource_id
        data, rate_limit, _ = self._get(
            "/v1-authority-intelligence/explain-authority", params=params
        )
        return ExplainAuthorityResult.model_validate({**data, "rate_limit": rate_limit})

    def list_permits(
        self,
        *,
        status: str | None = None,
        actor_id: str | None = None,
        action_type: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ListPermitsResult:
        params: dict[str, str] = {}
        if status is not None:
            params["status"] = status
        if actor_id is not None:
            params["actor_id"] = actor_id
        if action_type is not None:
            params["action_type"] = action_type
        if from_ is not None:
            params["from"] = from_
        if to is not None:
            params["to"] = to
        if limit is not None:
            params["limit"] = str(limit)
        if cursor is not None:
            params["cursor"] = cursor

        data, rate_limit, request_id = self._get("/v1/permits", params=params or None)
        permits_raw = data.get("permits")
        if not isinstance(permits_raw, list):
            raise AtlaSentError(
                "Malformed /v1/permits response: missing `permits` array",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        permits = [PermitRecord.model_validate(p) for p in permits_raw]
        total = data.get("total")
        return ListPermitsResult(
            permits=permits,
            total=total if isinstance(total, int) else len(permits),
            next_cursor=data.get("next_cursor"),
            rate_limit=rate_limit,
        )

    def list_audit_events(
        self,
        *,
        types: str | None = None,
        actor_id: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> AuditEventsResult:
        params: dict[str, str] = {}
        if types:
            params["types"] = types
        if actor_id:
            params["actor_id"] = actor_id
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        if limit is not None:
            params["limit"] = str(limit)
        if cursor:
            params["cursor"] = cursor

        logger.debug("list_audit_events params=%r", params)
        data, rate_limit, request_id = self._request(
            "GET", "/v1-audit/events", None, params=params
        )

        if not isinstance(data.get("events"), list) or not isinstance(
            data.get("total"), int
        ):
            raise AtlaSentError(
                "Malformed /v1-audit/events response: missing `events` or `total`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        return AuditEventsResult.model_validate({**data, "rate_limit": rate_limit})

    def create_audit_export(
        self,
        *,
        types: str | None = None,
        actor_id: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> AuditExportResult:
        payload: dict[str, Any] = {}
        if types:
            payload["types"] = types
        if actor_id:
            payload["actor_id"] = actor_id
        if from_:
            payload["from"] = from_
        if to:
            payload["to"] = to

        logger.debug("create_audit_export filter=%r", payload)
        data, rate_limit, request_id = self._post("/v1-audit/exports", payload)

        if (
            not isinstance(data.get("export_id"), str)
            or not isinstance(data.get("chain_head_hash"), str)
            or not isinstance(data.get("events"), list)
        ):
            raise AtlaSentError(
                "Malformed /v1-audit/exports response: missing "
                "`export_id`, `chain_head_hash`, or `events`",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )

        return AuditExportResult(bundle=data, rate_limit=rate_limit)

    def list_governance_agents(self) -> ListGovernanceAgentsResult:
        """List advisory governance agents registered for this org
        (``GET /v1/governance/agents``).

        Every returned agent has ``authority_class == "advisory"`` and
        ``can_authorize == False`` -- structural invariants enforced by the
        runtime DB, not just convention.

        Raises:
            AtlaSentError: Network error, timeout, or malformed payload.
            RateLimitError: HTTP 429.
        """
        logger.debug("list_governance_agents")
        data, rate_limit, request_id = self._get("/v1/governance/agents")

        agents_raw = data.get("agents")
        if not isinstance(agents_raw, list):
            raise AtlaSentError(
                "Malformed /v1/governance/agents response: missing `agents` array",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        return ListGovernanceAgentsResult(
            agents=[GovernanceAgent.model_validate(a) for a in agents_raw],
            rate_limit=rate_limit,
        )

    def list_governance_findings(
        self,
        *,
        change_id: str,
        agent_slug: str | None = None,
    ) -> ListGovernanceFindingsResult:
        """List advisory findings produced against one governed change
        (``GET /v1/governance/findings?change_id=...``).

        All returned findings have ``can_authorize == False`` -- enforced
        by a CHECK constraint on the runtime DB; no finding can ever
        satisfy a gate.

        Args:
            change_id: The governed-change UUID to query against.
            agent_slug: Optional filter to a single agent's findings.

        Raises:
            AtlaSentError: Network error, timeout, or malformed payload.
            RateLimitError: HTTP 429.
        """
        if not change_id:
            raise AtlaSentError("change_id is required", code="bad_request")
        params: dict[str, str] = {"change_id": change_id}
        if agent_slug is not None:
            params["agent_slug"] = agent_slug

        logger.debug("list_governance_findings change_id=%r", change_id)
        data, rate_limit, request_id = self._get(
            "/v1/governance/findings", params=params
        )

        findings_raw = data.get("findings")
        if not isinstance(findings_raw, list):
            raise AtlaSentError(
                "Malformed /v1/governance/findings response: missing `findings` array",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        return ListGovernanceFindingsResult(
            findings=[GovernanceAgentFinding.model_validate(f) for f in findings_raw],
            rate_limit=rate_limit,
        )

    def list_governance_evaluations(
        self,
        *,
        change_id: str,
        agent_slug: str | None = None,
    ) -> ListGovernanceEvaluationsResult:
        """List agent run records for a governed change
        (``GET /v1/governance/evaluations?change_id=...``).

        Includes completed, failed, and timed-out runs. The same
        (agent_slug, agent_version, input_hash) combination may produce
        multiple rows -- the runtime DB does not dedupe.

        Args:
            change_id: The governed-change UUID to query against.
            agent_slug: Optional filter to one agent's runs.

        Raises:
            AtlaSentError: Network error, timeout, or malformed payload.
            RateLimitError: HTTP 429.
        """
        if not change_id:
            raise AtlaSentError("change_id is required", code="bad_request")
        params: dict[str, str] = {"change_id": change_id}
        if agent_slug is not None:
            params["agent_slug"] = agent_slug

        logger.debug("list_governance_evaluations change_id=%r", change_id)
        data, rate_limit, request_id = self._get(
            "/v1/governance/evaluations", params=params
        )

        evals_raw = data.get("evaluations")
        if not isinstance(evals_raw, list):
            raise AtlaSentError(
                "Malformed /v1/governance/evaluations response: "
                "missing `evaluations` array",
                code="bad_response",
                request_id=request_id,
                response_body=data,
            )
        return ListGovernanceEvaluationsResult(
            evaluations=[
                GovernanceAgentEvaluation.model_validate(e) for e in evals_raw
            ],
            rate_limit=rate_limit,
        )

    # ── Decision replay (ADR-015 Phase C parity runtime) ────────────────────
    #
    # Sync mirror of AsyncAtlaSentClient.replay(). Side-effect-free
    # server-side: replaying does not write to the audit chain or mint
    # a permit (ADR-016 ``mode: "replay"`` sentinel).
    #
    # Wire-variance → SDK-canonical mapping is kept identical to the
    # async client to keep contract conformance vectors valid against
    # both runtimes. See ``ReplayResponse`` in ``models`` for the
    # 7-value variance union and its interpretation.

    def replay(self, *, evaluation_id: str) -> ReplayResponse:
        """Re-evaluate a recorded decision against its originally-pinned
        bundle and engine version. Side-effect-free server-side.

        ``409 replay_not_eligible`` responses are surfaced as a
        ``ReplayResponse`` with ``variance_kind`` of ``ENGINE_DRIFT``
        or ``BUNDLE_MISSING`` rather than raising — callers can branch
        on the variance kind without try/except plumbing.

        Args:
            evaluation_id: The UUID of the recorded decision to replay.

        Raises:
            AtlaSentError: Network / transport failure, non-409 HTTP
                error, or malformed response payload.
        """
        path = f"/v1/decisions/{quote(evaluation_id, safe='')}/replay"
        try:
            data, rate_limit, _ = self._post(path, {})
        except AtlaSentError as err:
            if err.status_code == 409:
                msg = str(err).lower()
                variance_kind: ReplayVarianceKind = (
                    "BUNDLE_MISSING" if "bundle" in msg else "ENGINE_DRIFT"
                )
                return ReplayResponse(
                    decision_id=evaluation_id,
                    variance_kind=variance_kind,
                    original_decision="deny",
                    accepts_replay=False,
                    replayed_at=datetime.now(timezone.utc).isoformat(),
                    rate_limit=None,
                )
            raise
        variance_map: dict[str, str] = {
            "NONE": "NONE",
            "DECISION_CHANGED": "POLICY_DRIFT",
            "ENVELOPE_DRIFT": "ENVELOPE_DRIFT",
            "CHAIN_TAMPER": "CHAIN_TAMPER",
            "BUNDLE_MISSING": "BUNDLE_MISSING",
            "ENGINE_DRIFT": "ENGINE_DRIFT",
        }
        raw_variance = data.get("variance", "")
        vk: ReplayVarianceKind = variance_map.get(raw_variance, "NONE")
        replay_dec = data.get("replay_decision")
        return ReplayResponse(
            decision_id=data.get("decision_id", evaluation_id),
            variance_kind=vk,
            original_decision=(data.get("original_decision") or "deny").lower(),
            original_deny_code=data.get("original_deny_code"),
            replayed_decision=replay_dec.lower() if replay_dec else None,
            replayed_deny_code=data.get("replay_deny_code"),
            engine_version=data.get("engine_version"),
            engine_version_kind=data.get("engine_version_kind"),
            accepts_replay=bool(data.get("accepts_replay", True)),
            envelope_verification=data.get("envelope_verification"),
            replayed_at=data.get("replayed_at")
            or datetime.now(timezone.utc).isoformat(),
            rate_limit=rate_limit,
        )

    # ── internals ─────────────────────────────────────────────────────

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        return self._request("POST", path, payload, params=params)

    def _get(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        return self._request("GET", path, None, params=params)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        url = f"{self._base_url}{path}"
        request_id = uuid.uuid4().hex[:12]
        headers = {"X-Request-ID": request_id}

        for attempt in range(1 + self._max_retries):
            try:
                if method == "POST":
                    response = self._client.post(
                        url, json=payload, headers=headers, params=params
                    )
                else:
                    response = self._client.get(url, headers=headers, params=params)
            except httpx.TimeoutException as exc:
                logger.warning(
                    "%s timeout (attempt %d/%d)",
                    path,
                    attempt + 1,
                    1 + self._max_retries,
                )
                if attempt < self._max_retries:
                    self._backoff(attempt)
                    continue
                raise AtlaSentError(
                    f"Request to {path} timed out after "
                    f"{1 + self._max_retries} attempts",
                    code="timeout",
                    request_id=request_id,
                ) from exc
            except httpx.ConnectError as exc:
                logger.warning(
                    "%s connection failed (attempt %d/%d)",
                    self._base_url,
                    attempt + 1,
                    1 + self._max_retries,
                )
                if attempt < self._max_retries:
                    self._backoff(attempt)
                    continue
                raise AtlaSentError(
                    f"Failed to connect to AtlaSent API at "
                    f"{self._base_url} after {1 + self._max_retries} attempts",
                    code="network",
                    request_id=request_id,
                ) from exc
            except httpx.HTTPError as exc:
                raise AtlaSentError(
                    f"Request failed: {exc}",
                    code="network",
                    request_id=request_id,
                ) from exc

            if response.status_code == 429:
                retry_after = _parse_retry_after(response)
                raise RateLimitError(
                    retry_after=retry_after,
                    request_id=request_id,
                )
            if response.status_code == 401:
                raise AtlaSentError(
                    _server_message(response) or "Invalid API key",
                    status_code=401,
                    code="invalid_api_key",
                    request_id=request_id,
                )
            if response.status_code == 403:
                raise AtlaSentError(
                    _server_message(response)
                    or "Access forbidden — check your API key permissions",
                    status_code=403,
                    code="forbidden",
                    request_id=request_id,
                )
            if response.status_code >= 500:
                logger.warning(
                    "Server %d on %s (attempt %d/%d)",
                    response.status_code,
                    path,
                    attempt + 1,
                    1 + self._max_retries,
                )
                if attempt < self._max_retries:
                    self._backoff(attempt)
                    continue
                # #1634: the wire envelope for a permit-mint/signing failure
                # is a non-2xx status (503 recoverable / 500 invariant)
                # carrying `{"error": "permit_signing_unavailable", ...}`.
                # Surface it as a distinct, structurally recognizable error
                # class rather than the generic AtlaSentError every other
                # non-2xx response gets, so application code can tell
                # "AtlaSent could not materialize executable authority"
                # apart from an ordinary transport/auth/rate-limit failure.
                mint_failure_code = _parse_mint_failure_code(response)
                if mint_failure_code is not None:
                    raise AtlaSentPermitMintFailedError(
                        f"API error {response.status_code}: {response.text[:500]}",
                        code=mint_failure_code,
                        status_code=response.status_code,
                        request_id=request_id,
                    )
                raise AtlaSentError(
                    f"API error {response.status_code}: {response.text[:500]}",
                    status_code=response.status_code,
                    code="server_error",
                    request_id=request_id,
                )
            if response.status_code >= 400:
                raise AtlaSentError(
                    f"API error {response.status_code}: {response.text[:500]}",
                    status_code=response.status_code,
                    code="bad_request",
                    request_id=request_id,
                )

            try:
                return (
                    response.json(),
                    _parse_rate_limit_headers(response),
                    request_id,
                )
            except ValueError as exc:
                raise AtlaSentError(
                    "Invalid JSON response from AtlaSent API",
                    code="bad_response",
                    request_id=request_id,
                ) from exc

        raise AtlaSentError(  # pragma: no cover
            f"Request to {path} failed after {1 + self._max_retries} attempts",
            code="network",
            request_id=request_id,
        )

    def _backoff(self, attempt: int) -> None:
        delay = min(_RETRY_MAX_DELAY, self._retry_backoff * (2**attempt))
        logger.debug("Retrying in %.1fs…", delay)
        time.sleep(delay)

    # ── HITL orchestration (path-routed /v1/hitl/*) ───────────────────────

    def create_hitl_escalation(
        self,
        request: HitlCreateRequest,
    ) -> HitlEscalationResult:
        body = request.model_dump(exclude_none=True)
        data, rate_limit, _ = self._post("/v1/hitl", body)
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )

    def list_hitl_escalations(
        self,
        *,
        status: HitlStatus | None = None,
        agent_id: str | None = None,
        assigned_to_user_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ListHitlEscalationsResult:
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        if agent_id:
            params["agent_id"] = agent_id
        if assigned_to_user_id:
            params["assigned_to_user_id"] = assigned_to_user_id
        if limit is not None:
            params["limit"] = str(limit)
        if cursor:
            params["cursor"] = cursor
        data, rate_limit, _ = self._get("/v1/hitl", params=params or None)
        return ListHitlEscalationsResult(**data, rate_limit=rate_limit)

    def get_hitl_escalation(self, escalation_id: str) -> HitlEscalationResult:
        if not escalation_id:
            raise AtlaSentError("escalation_id is required", code="bad_request")
        path = f"/v1/hitl/{quote(escalation_id, safe='')}"
        data, rate_limit, _ = self._get(path)
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )

    def list_hitl_approvals(self, escalation_id: str) -> HitlApprovalsResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/approvals"
        data, rate_limit, _ = self._get(path)
        return HitlApprovalsResult(**data, rate_limit=rate_limit)

    def get_hitl_chain(self, escalation_id: str) -> HitlChainResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/chain"
        data, rate_limit, _ = self._get(path)
        return HitlChainResult(**data, rate_limit=rate_limit)

    def approve_hitl_escalation(
        self,
        escalation_id: str,
        *,
        note: str | None = None,
    ) -> HitlEscalationResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/approve"
        body: dict[str, Any] = {}
        if note is not None:
            body["note"] = note
        data, rate_limit, _ = self._post(path, body)
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )

    def reject_hitl_escalation(
        self,
        escalation_id: str,
        *,
        note: str | None = None,
    ) -> HitlEscalationResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/reject"
        body: dict[str, Any] = {}
        if note is not None:
            body["note"] = note
        data, rate_limit, _ = self._post(path, body)
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )

    def escalate_hitl_escalation(
        self,
        escalation_id: str,
        *,
        to_role: str | None = None,
        to_user_id: str | None = None,
        reason: str | None = None,
    ) -> HitlEscalationResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/escalate"
        body: dict[str, Any] = {}
        if to_role is not None:
            body["to_role"] = to_role
        if to_user_id is not None:
            body["to_user_id"] = to_user_id
        if reason is not None:
            body["reason"] = reason
        data, rate_limit, _ = self._post(path, body)
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )

    def timeout_hitl_escalation(
        self,
        escalation_id: str,
    ) -> HitlEscalationResult:
        path = f"/v1/hitl/{quote(escalation_id, safe='')}/timeout"
        data, rate_limit, _ = self._post(path, {})
        return HitlEscalationResult(
            escalation=HitlEscalation.model_validate(data),
            rate_limit=rate_limit,
        )


def _server_message(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        for key in ("error", "message", "reason"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _parse_mint_failure_code(response: httpx.Response) -> AtlaSentErrorCode | None:
    """Return the wire ``error`` code when it's in the permit-mint
    operational-error taxonomy (#1634), else ``None``.

    Parses ``response.text`` directly (not ``response.json()``) so a
    non-JSON error body (e.g. a gateway timeout page) falls through to the
    generic ``AtlaSentAPIError``-equivalent path unchanged, same as before
    this taxonomy existed.
    """
    try:
        body = json.loads(response.text)
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    error_code = body.get("error")
    if isinstance(error_code, str) and error_code in PERMIT_MINT_FAILURE_ERROR_CODES:
        # mypy: the membership check above narrows to the allowlisted
        # AtlaSentErrorCode literal (mirrors _normalize_permit_outcome's
        # identical narrowing comment in exceptions.py).
        return error_code  # type: ignore[return-value]
    return None


def _parse_retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        pass
    try:
        parsed = parsedate_to_datetime(value)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:  # pragma: no cover
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = (parsed - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


def _parse_rate_limit_headers(response: httpx.Response) -> RateLimitState | None:
    raw_limit = response.headers.get("x-ratelimit-limit")
    raw_remaining = response.headers.get("x-ratelimit-remaining")
    raw_reset = response.headers.get("x-ratelimit-reset")
    if raw_limit is None or raw_remaining is None or raw_reset is None:
        return None
    try:
        limit = int(raw_limit)
        remaining = int(raw_remaining)
    except (ValueError, TypeError):
        return None
    reset_at = _parse_reset_header(raw_reset)
    if reset_at is None:
        return None
    return RateLimitState(limit=limit, remaining=remaining, reset_at=reset_at)


def _parse_reset_header(raw: str) -> datetime | None:
    try:
        seconds = float(raw)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
