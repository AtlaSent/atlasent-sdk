"""Asynchronous AtlaSent API client (httpx.AsyncClient-based)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
import warnings
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from ._function_region import UNSET, _Unset, function_region_headers
from ._version import __version__
from .approval_artifact import ApprovalReference
from .audit import AuditEventsResult, AuditExportResult
from .client import (
    _ACTION_TYPE_RE,
    _compute_execution_hash,
    _enforce_tls,
    _parse_mint_failure_code,
    _parse_rate_limit_headers,
    _parse_retry_after,
    _redact_token,
    _server_message,
    _validate_api_key,
)
from .config import get_api_key as _get_api_key
from .config import get_base_url as _get_base_url
from .evidence_exports import (
    _VALID_REGIMES,
)
from .evidence_exports import (
    _enc as _ev_enc,
)
from .exceptions import (
    AtlaSentDenied,
    AtlaSentDeniedError,
    AtlaSentError,
    AtlaSentPermitMintFailedError,
    BundleVerificationError,
    PermissionDeniedError,
    RateLimitError,
    StreamParseError,
    StreamTimeoutError,
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
    StreamProgressEvent,
    VerifyPermitByIdResult,
    VerifyRequest,
    VerifyResult,
)
from .payload_hash import normalize_caller_payload_hash
from .scim import (
    SCIM_GROUP_SCHEMA,
    SCIM_PATCH_OP_SCHEMA,
    SCIM_USER_SCHEMA,
    _scim_qs,
)
from .scim import (
    _enc as _scim_enc,
)
from .siem import (
    _VALID_AUTH_TYPES,
    _VALID_FORMATS,
)
from .siem import (
    _enc as _siem_enc,
)
from .trust_root import get_global_trust_root_manager

if TYPE_CHECKING:
    from .cache import TTLCache

logger = logging.getLogger("atlasent")

DEFAULT_BASE_URL = "https://api.atlasent.io"
DEFAULT_TIMEOUT = 10
# Retry schedule parity with the TypeScript SDK:
#   4 total attempts (1 initial + 3 retries), delays 2 s -> 4 s -> 8 s
#   (capped at 16 s) via the exponential formula:
#   delay = min(16, retry_backoff * 2**attempt)
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 2.0
_RETRY_MAX_DELAY = 16.0


class AsyncAtlaSentClient:
    """Async client for the AtlaSent authorization API.

    Mirrors :class:`AtlaSentClient` but with ``async``/``await``.
    Uses ``httpx.AsyncClient`` under the hood.

    Args:
        api_key: Your AtlaSent API key (required).
        anon_key: An anonymous / public key for client-side contexts.
        base_url: Override the API base URL.
        timeout: HTTP request timeout in seconds.
        max_retries: Retries on transient errors (5xx, timeouts).
        retry_backoff: Base backoff in seconds (doubles each retry).

    Usage::

        async with AsyncAtlaSentClient(api_key="ask_live_...") as client:
            result = await client.gate("read_data", "agent-1")
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        anon_key: str = "",
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        cache: TTLCache | None = None,
        function_region: str | None | _Unset = UNSET,
    ) -> None:
        resolved_api_key = api_key or _get_api_key()
        resolved_base_url = base_url or _get_base_url()
        self._api_key = _validate_api_key(resolved_api_key)
        self._anon_key = anon_key
        self._base_url = _enforce_tls(resolved_base_url).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff
        self._cache = cache
        # Edge-function region (see ._function_region); resolved once, sent on
        # every request through this client's default headers.
        self._region_headers = function_region_headers(self._base_url, function_region)
        self._client = httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {resolved_api_key}",
                "User-Agent": f"atlasent-python/{__version__}",
                **self._region_headers,
            },
            timeout=self._timeout,
        )

    # ── public API ─────────────────────────────────────────────────

    async def evaluate(
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
    ) -> EvaluateResult:
        """Evaluate whether an action is authorized.

        Returns an :class:`EvaluateResult` on permit.
        Raises :class:`AtlaSentDenied` on deny (fail-closed).

        See :meth:`AtlaSentClient.evaluate` for full kwarg semantics.
        """
        ctx = context or {}
        if isinstance(approval, dict):
            approval = ApprovalReference.model_validate(approval)

        # Check cache
        if self._cache is not None:
            from .cache import TTLCache

            cache_key = TTLCache.make_key(action_type, actor_id, ctx)
            cached = self._cache.get(cache_key)
            if cached is not None:
                logger.debug("evaluate cache hit for %s (async)", cache_key)
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
        )
        logger.debug("evaluate action=%r actor=%r (async)", action_type, actor_id)
        data, rate_limit, request_id = await self._post(
            "/v1-evaluate", req.model_dump(by_alias=True, exclude_none=True)
        )

        # Tolerate both canonical {decision, permit_token} and legacy
        # {permitted, decision_id}.
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

        # Store in cache
        if self._cache is not None:
            self._cache.put(cache_key, result)

        return result

    async def evaluate_preflight(
        self,
        action_type: str,
        actor_id: str,
        context: dict[str, Any] | None = None,
    ) -> EvaluatePreflightResult:
        """Pre-flight evaluation that always returns the constraint trace.

        Async mirror of :meth:`AtlaSentClient.evaluate_preflight`. Wraps
        ``POST /v1-evaluate?include=constraint_trace`` so a workflow's
        submission step can surface trivial defects (missing fields,
        wrong roles) BEFORE pushing the request to an approval queue.

        Returns an :class:`EvaluatePreflightResult` carrying the
        regular :class:`EvaluateResult` plus the
        :class:`ConstraintTrace`. Does NOT raise on a non-allow
        decision: the caller branches on
        ``result.evaluation.decision`` and renders failing stages from
        ``result.constraint_trace``.

        On older atlasent-api deployments that omit the trace,
        ``constraint_trace`` is ``None`` rather than raising —
        forward-compatible degradation.

        Performance: one extra round-trip on submission, latency
        comparable to :meth:`evaluate` with a fuller response body.
        Prefer :meth:`evaluate` if the caller does not need the trace.
        """
        ctx = context or {}
        req = EvaluateRequest(
            action_type=action_type,
            actor_id=actor_id,
            context=ctx,
        )
        logger.debug(
            "evaluate_preflight action=%r actor=%r (async)", action_type, actor_id
        )
        data, rate_limit, request_id = await self._post(
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

    async def verify(
        self,
        permit_token: str,
        action_type: str = "",
        actor_id: str = "",
        context: dict[str, Any] | None = None,
        *,
        require_approval: bool | None = None,
        environment: str | None = None,
        execution_hash: str | None = None,
    ) -> VerifyResult:
        """Verify a previously issued permit token.

        .. deprecated::
           Use :meth:`verify_permit_by_id` — the canonical REST surface
           returns the unified verification envelope plus the full
           PermitRecord. Will be removed in ``atlasent`` v3.

        See :meth:`AtlaSentClient.verify` for full kwarg semantics.
        """
        warnings.warn(
            "AsyncAtlaSentClient.verify() is deprecated. Use "
            "verify_permit_by_id() for the canonical REST surface; it "
            "returns the unified verification envelope (valid / "
            "verification_type / reason / verified_at / evidence) plus "
            "the full PermitRecord. Will be removed in v3.",
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
        )
        logger.debug("verify token=%s (async)", _redact_token(permit_token))
        data, rate_limit, request_id = await self._post(
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

    async def protect(
        self,
        *,
        agent: str,
        action: str,
        context: dict[str, Any] | None = None,
        state_snapshot: dict[str, Any] | None = None,
        execution_payload_hash: str | None = None,
    ) -> Permit:
        """Authorize an action end-to-end (async). The category primitive.

        Async mirror of :meth:`AtlaSentClient.protect`. On allow,
        returns a verified :class:`Permit`; on deny or verification
        failure raises :class:`AtlaSentDeniedError`; on transport /
        auth / rate-limit / server error raises :class:`AtlaSentError`.

        Example::

            from atlasent import AsyncAtlaSentClient

            async with AsyncAtlaSentClient(api_key="ask_live_...") as client:
                permit = await client.protect(
                    agent="deploy-bot",
                    action="production.deploy",
                    context={"commit": commit},
                )
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
        # ADR-005 D3: fail-closed if trust snapshot has expired
        expiry = get_global_trust_root_manager().check_expiry()
        if expiry == "expired":
            snap = get_global_trust_root_manager().get_snapshot()
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
            eval_result = await self.evaluate(
                action,
                agent,
                ctx,
                state_snapshot=state_snapshot,
                execution_payload_hash=_caller_hash,
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
            ).model_dump(by_alias=True, exclude_none=True)
            _execution_hash = _compute_execution_hash(_eval_payload)

        # Suppress the DeprecationWarning from the public verify() method:
        # protect() is the canonical API and should not surface deprecation
        # noise from its own internal implementation.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                verify_result = await self.verify(
                    eval_result.permit_token,
                    action,
                    agent,
                    ctx,
                    environment=_ctx_env,
                    execution_hash=_execution_hash,
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
        )

    async def protect_stream(
        self,
        agent: str,
        action: str,
        context: dict[str, Any] | None = None,
        *,
        stream_timeout_s: float = 30.0,
        max_retries: int = 3,
    ) -> AsyncIterator[StreamDecisionEvent | StreamProgressEvent]:
        """Open a streaming evaluation session against ``POST /v1-evaluate-stream``.

        Sends a single-item V2-D4 batch (``{items: [{action_type, actor_id,
        context}]}``) and yields :class:`StreamDecisionEvent` /
        :class:`StreamProgressEvent` objects as the server emits them. The
        iterator ends cleanly when the server sends the terminal
        ``event: complete`` frame (or the legacy/generic ``event: done``); it
        raises :class:`AtlaSentError` on transport errors or when the server
        sends ``event: error``.

        Hardening:

        - Raises :class:`StreamTimeoutError` when no event arrives within
          ``stream_timeout_s`` seconds (default 30 s). Pass ``0`` to disable.
        - Retries up to ``max_retries`` times (default 3) with 1 s / 2 s / 4 s
          delays on ``httpx.ConnectError`` or ``asyncio.TimeoutError``. Sends
          ``Last-Event-ID`` on reconnect when the server emitted event IDs.
        - Raises :class:`StreamParseError` on partial / malformed JSON rather
          than letting ``json.JSONDecodeError`` escape.
        - Closes cleanly on ``event: complete``, ``event: done``, or a
          decision event with ``done: true`` / ``is_final: true``.

        Usage::

            async for event in client.protect_stream("my-agent", "my-action"):
                if event.type == "decision":
                    break
        """
        url = f"{self._base_url}/v1-evaluate-stream"
        # Wire contract (V2-D4, atlasent-api supabase/functions/v1-evaluate-stream/
        # handler.ts): the endpoint is body-compatible with /v1/evaluate/batch —
        # `{batch_id?, items: [{action_type, actor_id, context, ...}]}` — NOT a
        # flat {action, agent, context, api_key} body. `agent`/`action` are this
        # SDK's public parameter names; `action_type`/`actor_id` are the real wire
        # fields, matching how evaluate()/EvaluateRequest and
        # v2_endpoints.authorize_stream() already build their payloads. Auth is
        # carried by the Authorization header below, never a body `api_key` field.
        payload = {
            "items": [
                {
                    "action_type": action,
                    "actor_id": agent,
                    "context": context or {},
                }
            ],
        }
        request_id = uuid.uuid4().hex[:12]

        last_event_id: str | None = None
        retry_count = 0

        while True:
            headers: dict[str, str] = {
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "User-Agent": f"atlasent-python/{__version__}",
                "X-Request-ID": request_id,
            }
            if last_event_id is not None:
                headers["Last-Event-ID"] = last_event_id

            stream_done = False
            network_drop = False

            try:
                async with self._client.stream(
                    "POST",
                    url,
                    content=json.dumps(payload).encode(),
                    headers=headers,
                ) as response:
                    if response.status_code != 200:
                        await response.aread()
                        raise AtlaSentError(
                            "AtlaSent stream request failed with status "
                            f"{response.status_code}",
                            code="server_error",
                            status_code=response.status_code,
                            request_id=request_id,
                        )

                    last_event_id_container: list[str | None] = [last_event_id]

                    def _on_event_id(eid: str) -> None:
                        last_event_id_container[0] = eid

                    async for event in _parse_sse(
                        response.aiter_lines(),
                        request_id,
                        stream_timeout_s,
                        _on_event_id,
                    ):
                        yield event
                        if isinstance(event, StreamDecisionEvent) and event.is_final:
                            stream_done = True

                    last_event_id = last_event_id_container[0]
                    stream_done = True

            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                if retry_count < max_retries:
                    network_drop = True
                else:
                    raise AtlaSentError(
                        f"AtlaSent stream failed after {retry_count} retries: {exc}",
                        code="network",
                        request_id=request_id,
                    ) from exc
            except asyncio.TimeoutError as exc:
                if retry_count < max_retries:
                    network_drop = True
                else:
                    raise StreamTimeoutError(stream_timeout_s) from exc

            if stream_done:
                break

            if network_drop:
                retry_count += 1
                delay = 1.0 * (2 ** (retry_count - 1))  # 1s, 2s, 4s
                await asyncio.sleep(delay)
                continue

            break

    async def gate(
        self,
        action_type: str,
        actor_id: str,
        context: dict[str, Any] | None = None,
    ) -> GateResult:
        """Evaluate then verify in one call — the happy-path shortcut.

        .. deprecated::
           Use :meth:`protect` for fail-closed execution, or
           :meth:`evaluate` + :meth:`verify` to inspect the decision
           and verify separately. Will be removed in ``atlasent`` v3.
        """
        warnings.warn(
            "AsyncAtlaSentClient.gate() is deprecated. Use protect() for "
            "fail-closed execution or evaluate() + verify() to inspect "
            "the decision and verify separately. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        ctx = context or {}
        eval_result = await self.evaluate(action_type, actor_id, ctx)
        verify_result = await self.verify(
            eval_result.permit_token, action_type, actor_id, ctx
        )
        return GateResult(evaluation=eval_result, verification=verify_result)

    async def authorize(
        self,
        *,
        agent: str,
        action: str,
        context: dict[str, Any] | None = None,
        verify: bool = True,
        raise_on_deny: bool = False,
    ) -> AuthorizationResult:
        """Authorize an agent action — async version of
        :meth:`AtlaSentClient.authorize`.

        .. deprecated::
           Use :meth:`protect` for fail-closed execution
           (recommended — no ``permitted=False`` return path to forget),
           or :meth:`evaluate` to inspect the four-value decision.
           Will be removed in ``atlasent`` v3.
        """
        warnings.warn(
            "AsyncAtlaSentClient.authorize() is deprecated. Use protect() for "
            "fail-closed execution (recommended) or evaluate() to inspect "
            "the four-value decision. Will be removed in v3.",
            DeprecationWarning,
            stacklevel=2,
        )
        ctx = context or {}
        try:
            eval_result = await self.evaluate(action, agent, ctx)
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
            verify_result = await self.verify(
                eval_result.permit_token, action, agent, ctx
            )
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

    # ── lifecycle ───────────────────────────────────────────────

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        await self._client.aclose()
        logger.debug("AsyncAtlaSentClient closed")

    async def __aenter__(self) -> AsyncAtlaSentClient:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        await self.close()

    async def key_self(self) -> ApiKeySelfResult:
        """Self-introspection of the API key this client was constructed with.

        Calls ``GET /v1-api-key-self``. Never returns the raw key or its
        hash — safe to surface in operator dashboards. Useful for
        ``IP_NOT_ALLOWED`` debugging (the server tells you exactly which
        client IP it saw), proactive expiry warnings, and scope
        introspection before attempting a scope-gated action.

        Response also includes ``rate_limit`` so key-introspection
        doubles as a cheap rate-limit probe without consuming a permit.

        Raises:
            AtlaSentError: Network error, timeout, unexpected response,
                or malformed payload.
            RateLimitError: HTTP 429.
        """
        logger.debug("key_self")
        data, rate_limit, request_id = await self._get("/v1-api-key-self")

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

    async def compliance_controls(
        self,
        *,
        framework: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> ComplianceControlsResult:
        """Resolve the compliance control catalog into live enforcement status
        (``GET /v1-compliance-controls``). Async mirror of
        :meth:`AtlaSentClient.compliance_controls`.

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
        data, rate_limit, request_id = await self._get(
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

    async def compliance_evidence_pack(
        self,
        *,
        framework: str,
        from_: str | None = None,
        to: str | None = None,
    ) -> ComplianceEvidencePackResult:
        """Produce a signed compliance evidence pack for one framework
        (``GET /v1-compliance-evidence-pack``). Async mirror of
        :meth:`AtlaSentClient.compliance_evidence_pack`.

        Read-only — requires the ``compliance:read`` scope. ``framework``
        is REQUIRED.

        Args:
            framework: Framework code the pack covers. REQUIRED.
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
        data, rate_limit, request_id = await self._get(
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

    async def revoke_permit(
        self,
        permit_id: str,
        *,
        reason: str | None = None,
    ) -> RevokePermitResult:
        """Revoke a previously-issued permit (``POST /v1-revoke-permit``).

        .. deprecated::
           Use :meth:`revoke_permit_by_id` — the canonical REST surface
           returns the full updated PermitRecord with revoked_at /
           revoked_by / revoke_reason populated. Will be removed in
           ``atlasent`` v3.

        Once revoked the permit will no longer pass :meth:`verify`.
        The revocation is recorded in the audit log with the optional *reason*.
        """
        warnings.warn(
            "AsyncAtlaSentClient.revoke_permit() is deprecated. Use "
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
        logger.debug("revoke_permit permit_id=%s (async)", _redact_token(permit_id))
        data, rate_limit, request_id = await self._post("/v1-revoke-permit", payload)

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

    # ── Canonical REST surface (parity with sync client) ────────────────────────

    async def get_permit(self, permit_id: str) -> GetPermitResult:
        """Get a single permit's full lifecycle state
        (``GET /v1/permits/{permit_id}``).

        Async parity for :meth:`AtlaSentClient.get_permit`. See the
        sync version for full semantics.
        """
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        path = f"/v1/permits/{quote(permit_id, safe='')}"
        data, rate_limit, _ = await self._get(path)
        return GetPermitResult(
            permit=PermitRecord.model_validate(data),
            rate_limit=rate_limit,
        )

    async def explain_authority(
        self,
        principal_id: str,
        requested_scope: str,
        resource_id: str | None = None,
    ) -> ExplainAuthorityResult:
        """Explain why (or why not) ``principal_id`` currently has
        authority for ``requested_scope`` in the caller's org.

        Async parity for :meth:`AtlaSentClient.explain_authority`. See
        the sync version for full semantics. Calls ``GET
        /v1-authority-intelligence/explain-authority``; requires the
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
        data, rate_limit, _ = await self._get(
            "/v1-authority-intelligence/explain-authority", params=params
        )
        return ExplainAuthorityResult.model_validate({**data, "rate_limit": rate_limit})

    async def list_permits(
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
        """List permits issued to the calling org
        (``GET /v1/permits``).

        Async parity for :meth:`AtlaSentClient.list_permits`. See the
        sync version for full kwarg semantics.
        """
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

        data, rate_limit, request_id = await self._get(
            "/v1/permits", params=params or None
        )
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

    async def revoke_permit_by_id(
        self,
        permit_id: str,
        *,
        reason: str | None = None,
    ) -> RevokePermitByIdResult:
        """Revoke a permit through the canonical REST surface
        (``POST /v1/permits/{permit_id}/revoke``).

        Async parity for :meth:`AtlaSentClient.revoke_permit_by_id`.
        """
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        path = f"/v1/permits/{quote(permit_id, safe='')}/revoke"
        data, rate_limit, _ = await self._post(path, body)
        return RevokePermitByIdResult(
            permit=PermitRecord.model_validate(data),
            rate_limit=rate_limit,
        )

    async def verify_permit_by_id(self, permit_id: str) -> VerifyPermitByIdResult:
        """Verify a permit through the canonical REST surface
        (``POST /v1/permits/{permit_id}/verify``).

        Async parity for :meth:`AtlaSentClient.verify_permit_by_id`.
        """
        if not permit_id:
            raise AtlaSentError("permit_id is required", code="bad_request")
        path = f"/v1/permits/{quote(permit_id, safe='')}/verify"
        data, rate_limit, request_id = await self._post(path, {})
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

    async def list_audit_events(
        self,
        *,
        types: str | None = None,
        actor_id: str | None = None,
        from_: str | None = None,
        to: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> AuditEventsResult:
        """List persisted audit events (``GET /v1-audit/events``).

        Async mirror of :meth:`AtlaSentClient.list_audit_events`. See
        that method for argument semantics.
        """
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

        logger.debug("list_audit_events params=%r (async)", params)
        data, rate_limit, request_id = await self._request(
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

    async def create_audit_export(
        self,
        *,
        types: str | None = None,
        actor_id: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> AuditExportResult:
        """Request a signed audit-export bundle
        (``POST /v1-audit/exports``).

        Async mirror of :meth:`AtlaSentClient.create_audit_export`.
        See that method for verification-workflow notes.
        """
        payload: dict[str, Any] = {}
        if types:
            payload["types"] = types
        if actor_id:
            payload["actor_id"] = actor_id
        if from_:
            payload["from"] = from_
        if to:
            payload["to"] = to

        logger.debug("create_audit_export filter=%r (async)", payload)
        data, rate_limit, request_id = await self._post("/v1-audit/exports", payload)

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

    async def list_governance_agents(self) -> ListGovernanceAgentsResult:
        """List advisory governance agents registered for this org
        (``GET /v1/governance/agents``).

        Every returned agent has ``authority_class == "advisory"`` and
        ``can_authorize == False`` -- structural invariants enforced by the
        runtime DB, not just convention.

        Raises:
            AtlaSentError: Network error, timeout, or malformed payload.
            RateLimitError: HTTP 429.
        """
        logger.debug("list_governance_agents (async)")
        data, rate_limit, request_id = await self._get("/v1/governance/agents")

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

    async def list_governance_findings(
        self,
        *,
        change_id: str,
        agent_slug: str | None = None,
    ) -> ListGovernanceFindingsResult:
        """List advisory findings produced against one governed change
        (``GET /v1/governance/findings?change_id=...").

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

        logger.debug("list_governance_findings change_id=%r (async)", change_id)
        data, rate_limit, request_id = await self._get(
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

    async def list_governance_evaluations(
        self,
        *,
        change_id: str,
        agent_slug: str | None = None,
    ) -> ListGovernanceEvaluationsResult:
        """List agent run records for a governed change
        (``GET /v1/governance/evaluations?change_id=...").

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

        logger.debug("list_governance_evaluations change_id=%r (async)", change_id)
        data, rate_limit, request_id = await self._get(
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

    # ── Decision replay (ADR-015 §Replay, parity v2) ─────────────────────────────

    async def replay(self, *, evaluation_id: str) -> ReplayResponse:
        path = f"/v1/decisions/{quote(evaluation_id, safe='')}/replay"
        try:
            data, rate_limit, _ = await self._post(path, {})
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

    # ── SCIM 2.0 (async) ─────────────────────────────────────────────────────────────

    async def async_scim_list_users(
        self,
        org_id: str,
        *,
        filter: str | None = None,
        start_index: int | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Users`` — list provisioned users (async)."""
        qs = _scim_qs(filter=filter, start_index=start_index, count=count)
        return await self._do_scim("GET", f"/v1/scim/v2/{_scim_enc(org_id)}/Users{qs}")

    async def async_scim_create_user(
        self,
        org_id: str,
        user: dict[str, Any],
    ) -> dict[str, Any]:
        """``POST /v1/scim/v2/{orgId}/Users`` — provision a new user (async)."""
        if "schemas" not in user:
            user = {**user, "schemas": [SCIM_USER_SCHEMA]}
        return await self._do_scim(
            "POST", f"/v1/scim/v2/{_scim_enc(org_id)}/Users", user
        )

    async def async_scim_get_user(
        self,
        org_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Users/{userId}`` — fetch a user by ID (async)."""
        return await self._do_scim(
            "GET", f"/v1/scim/v2/{_scim_enc(org_id)}/Users/{_scim_enc(user_id)}"
        )

    async def async_scim_replace_user(
        self,
        org_id: str,
        user_id: str,
        user: dict[str, Any],
    ) -> dict[str, Any]:
        """``PUT /v1/scim/v2/{orgId}/Users/{userId}`` — full replacement (async)."""
        if "schemas" not in user:
            user = {**user, "schemas": [SCIM_USER_SCHEMA]}
        return await self._do_scim(
            "PUT",
            f"/v1/scim/v2/{_scim_enc(org_id)}/Users/{_scim_enc(user_id)}",
            user,
        )

    async def async_scim_patch_user(
        self,
        org_id: str,
        user_id: str,
        operations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """``PATCH /v1/scim/v2/{orgId}/Users/{userId}`` — partial update (async)."""
        body = {"schemas": [SCIM_PATCH_OP_SCHEMA], "Operations": operations}
        return await self._do_scim(
            "PATCH",
            f"/v1/scim/v2/{_scim_enc(org_id)}/Users/{_scim_enc(user_id)}",
            body,
        )

    async def async_scim_delete_user(
        self,
        org_id: str,
        user_id: str,
    ) -> None:
        """``DELETE /v1/scim/v2/{orgId}/Users/{userId}`` — deprovision a
        user (async).
        """
        await self._do_scim(
            "DELETE", f"/v1/scim/v2/{_scim_enc(org_id)}/Users/{_scim_enc(user_id)}"
        )

    async def async_scim_list_groups(
        self,
        org_id: str,
        *,
        filter: str | None = None,
        start_index: int | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Groups`` — list provisioned groups (async)."""
        qs = _scim_qs(filter=filter, start_index=start_index, count=count)
        return await self._do_scim("GET", f"/v1/scim/v2/{_scim_enc(org_id)}/Groups{qs}")

    async def async_scim_create_group(
        self,
        org_id: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """``POST /v1/scim/v2/{orgId}/Groups`` — create a group (async)."""
        if "schemas" not in group:
            group = {**group, "schemas": [SCIM_GROUP_SCHEMA]}
        return await self._do_scim(
            "POST", f"/v1/scim/v2/{_scim_enc(org_id)}/Groups", group
        )

    async def async_scim_get_group(
        self,
        org_id: str,
        group_id: str,
    ) -> dict[str, Any]:
        """``GET /v1/scim/v2/{orgId}/Groups/{groupId}`` — fetch a group by
        ID (async).
        """
        return await self._do_scim(
            "GET", f"/v1/scim/v2/{_scim_enc(org_id)}/Groups/{_scim_enc(group_id)}"
        )

    async def async_scim_replace_group(
        self,
        org_id: str,
        group_id: str,
        group: dict[str, Any],
    ) -> dict[str, Any]:
        """``PUT /v1/scim/v2/{orgId}/Groups/{groupId}`` — full replacement (async)."""
        if "schemas" not in group:
            group = {**group, "schemas": [SCIM_GROUP_SCHEMA]}
        return await self._do_scim(
            "PUT",
            f"/v1/scim/v2/{_scim_enc(org_id)}/Groups/{_scim_enc(group_id)}",
            group,
        )

    async def async_scim_patch_group(
        self,
        org_id: str,
        group_id: str,
        operations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """``PATCH /v1/scim/v2/{orgId}/Groups/{groupId}`` — add/remove
        members (async).
        """
        body = {"schemas": [SCIM_PATCH_OP_SCHEMA], "Operations": operations}
        return await self._do_scim(
            "PATCH",
            f"/v1/scim/v2/{_scim_enc(org_id)}/Groups/{_scim_enc(group_id)}",
            body,
        )

    async def async_scim_delete_group(
        self,
        org_id: str,
        group_id: str,
    ) -> None:
        """``DELETE /v1/scim/v2/{orgId}/Groups/{groupId}`` — delete a group (async)."""
        await self._do_scim(
            "DELETE", f"/v1/scim/v2/{_scim_enc(org_id)}/Groups/{_scim_enc(group_id)}"
        )

    # ── SIEM (async) ───────────────────────────────────────────────────

    async def async_get_siem_config(self, org_id: str) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/siem-config`` — fetch current SIEM config (async)."""
        return await self._do_scim("GET", f"/v1/orgs/{_siem_enc(org_id)}/siem-config")

    async def async_upsert_siem_config(
        self,
        org_id: str,
        *,
        destination_url: str,
        format: str = "json",
        auth_type: str = "none",
        credential: str | None = None,
        enabled: bool = True,
        included_event_types: list[str] | None = None,
        batch_size: int = 100,
        retry_count: int = 3,
    ) -> dict[str, Any]:
        """``PATCH /v1/orgs/{orgId}/siem-config`` — create or update SIEM
        config (async).

        Args:
            org_id: AtlaSent organisation ID.
            destination_url: HTTPS endpoint that will receive events.
                Must start with ``https://``.
            format: Wire format — ``"splunk_hec"``, ``"elastic_ecs"``,
                ``"qradar_cef"``, or ``"json"``.
            auth_type: Auth method — ``"bearer"``, ``"basic"``,
                ``"api_key"``, or ``"none"``.
            credential: Write-only auth secret. Omit to keep existing value.
            enabled: Whether to stream events (default ``True``).
            included_event_types: Event types to stream.
            batch_size: Events per delivery batch (1–1000, default 100).
            retry_count: Retry attempts on delivery failure (0–10, default 3).

        Raises:
            ValueError: On invalid ``format``, ``auth_type``,
                ``destination_url``, or out-of-range numeric bounds.
        """
        if not destination_url.startswith("https://"):
            raise ValueError("destination_url must be an HTTPS URL")
        if format not in _VALID_FORMATS:
            raise ValueError(
                f"format must be one of: {', '.join(sorted(_VALID_FORMATS))}"
            )
        if auth_type not in _VALID_AUTH_TYPES:
            raise ValueError(
                f"auth_type must be one of: {', '.join(sorted(_VALID_AUTH_TYPES))}"
            )
        if not 1 <= batch_size <= 1000:
            raise ValueError(f"batch_size must be between 1 and 1000, got {batch_size}")
        if not 0 <= retry_count <= 10:
            raise ValueError(f"retry_count must be between 0 and 10, got {retry_count}")

        body: dict[str, Any] = {
            "destinationUrl": destination_url,
            "format": format,
            "authType": auth_type,
            "enabled": enabled,
            "includedEventTypes": included_event_types
            or ["permit", "deny", "override", "governance"],
            "batchSize": batch_size,
            "retryCount": retry_count,
        }
        if credential is not None:
            body["credential"] = credential

        return await self._do_scim(
            "PATCH", f"/v1/orgs/{_siem_enc(org_id)}/siem-config", body
        )

    async def async_siem_test_delivery(self, org_id: str) -> dict[str, Any]:
        """``POST /v1/orgs/{orgId}/siem-exports/test`` — send a test event (async)."""
        return await self._do_scim(
            "POST", f"/v1/orgs/{_siem_enc(org_id)}/siem-exports/test", {}
        )

    # ── Evidence exports (async) ──────────────────────────────────────────────────

    async def async_list_evidence_exports(
        self,
        org_id: str,
        *,
        regime: str | None = None,
    ) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/evidence-exports`` — list past evidence
        exports (async).

        Raises:
            ValueError: When ``regime`` is not a recognised value.
        """
        if regime is not None and regime not in _VALID_REGIMES:
            raise ValueError(
                f"regime must be one of: {', '.join(sorted(_VALID_REGIMES))}"
            )
        path = f"/v1/orgs/{_ev_enc(org_id)}/evidence-exports"
        if regime is not None:
            path = f"{path}?regime={_ev_enc(regime)}"
        return await self._do_scim("GET", path)

    async def async_get_evidence_export(
        self,
        org_id: str,
        export_id: str,
    ) -> dict[str, Any]:
        """``GET /v1/orgs/{orgId}/evidence-exports/{exportId}`` — fetch one
        export (async).
        """
        return await self._do_scim(
            "GET",
            f"/v1/orgs/{_ev_enc(org_id)}/evidence-exports/{_ev_enc(export_id)}",
        )

    async def async_create_evidence_export(
        self,
        org_id: str,
        *,
        regime: str,
        window: dict[str, str] | None = None,
        bundle_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """``POST /v1/orgs/{orgId}/evidence-exports`` — build and persist an
        evidence bundle (async).

        Args:
            org_id: AtlaSent organisation ID.
            regime: Compliance framework — ``"soc2_type_ii"``, ``"hipaa"``,
                or ``"gdpr"``.
            window: Optional time window dict with ``"from"`` and/or ``"to"``
                ISO-8601 timestamp strings.
            bundle_id: Optional deterministic bundle UUID.
            evidence: Optional free-form supplementary evidence dict.

        Raises:
            ValueError: When ``regime`` is not a recognised value.
        """
        if regime not in _VALID_REGIMES:
            raise ValueError(
                f"regime must be one of: {', '.join(sorted(_VALID_REGIMES))}"
            )

        body: dict[str, Any] = {"regime": regime}
        if window is not None:
            body["window"] = window
        if bundle_id is not None:
            body["bundle_id"] = bundle_id
        if evidence is not None:
            body.update(evidence)

        return await self._do_scim(
            "POST", f"/v1/orgs/{_ev_enc(org_id)}/evidence-exports", body
        )

    # ── internals ──────────────────────────────────────────────

    async def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        """POST with retry on transient failures.

        Returns ``(body, rate_limit, request_id)``. ``rate_limit`` is
        parsed from ``X-RateLimit-*`` headers on the response or
        ``None`` when the server doesn't emit them. Callers use
        ``request_id`` to attach the ``X-Request-ID`` we sent to any
        exception they raise while interpreting the body, so call
        sites see the same correlation id whether the request failed
        at transport / HTTP status time (raised inside ``_post``) or
        at body-shape time (raised by the caller after ``_post``
        returns).

        ``params`` is appended as a URL query string (e.g.
        ``?include=constraint_trace`` for the preflight helper). The
        request body is unchanged.
        """
        return await self._request("POST", path, payload, params=params)

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        """GET with retry on transient failures.

        Same ``(body, rate_limit, request_id)`` shape as :meth:`_post`
        so response-parsing code is shared.

        ``params`` is appended as a URL query string when present.
        """
        return await self._request("GET", path, None, params=params)

    async def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], RateLimitState | None, str]:
        """Shared retry + error-mapping core for POST / GET.

        ``params`` is only honored for GET and is serialized as URL
        query parameters.
        """
        url = f"{self._base_url}{path}"
        request_id = uuid.uuid4().hex[:12]
        headers = {"X-Request-ID": request_id}

        for attempt in range(1 + self._max_retries):
            try:
                if method == "POST":
                    response = await self._client.post(
                        url, json=payload, headers=headers, params=params
                    )
                else:
                    response = await self._client.get(
                        url, headers=headers, params=params
                    )
            except httpx.TimeoutException as exc:
                logger.warning(
                    "%s timeout (attempt %d/%d)",
                    path,
                    attempt + 1,
                    1 + self._max_retries,
                )
                if attempt < self._max_retries:
                    await self._backoff(attempt)
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
                    await self._backoff(attempt)
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
                    await self._backoff(attempt)
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

    async def _backoff(self, attempt: int) -> None:
        delay = min(_RETRY_MAX_DELAY, self._retry_backoff * (2**attempt))
        logger.debug("Retrying in %.1fs… (async)", delay)
        await asyncio.sleep(delay)

    async def _do_scim(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Async helper for SCIM/SIEM/evidence-export calls.

        Supports all HTTP verbs (GET, POST, PUT, PATCH, DELETE).
        Returns parsed JSON or ``None`` for 204 No Content.
        """
        import json as _json

        url = f"{self._base_url}{path}"
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["content"] = _json.dumps(body, separators=(",", ":")).encode()
            kwargs["headers"] = {"Content-Type": "application/json"}

        response = await self._client.request(method, url, **kwargs)
        request_id = response.headers.get("X-Request-ID")
        if response.status_code == 204:
            return None
        if response.status_code >= 400:
            msg = None
            try:
                err = response.json()
                msg = err.get("error") or err.get("message")
            except (ValueError, AttributeError):
                pass
            raise AtlaSentError(
                msg or f"{method} {path} returned {response.status_code}",
                status_code=response.status_code,
                code="server_error" if response.status_code >= 500 else "bad_request",
                request_id=request_id,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise AtlaSentError(
                f"{method} {path}: malformed JSON response",
                status_code=response.status_code,
                code="bad_response",
                request_id=request_id,
            ) from exc


# ── SSE parser ────────────────────────────────────────────────────────────────────────


async def _parse_sse(
    lines: AsyncIterator[str],
    request_id: str,
    timeout_s: float = 0.0,
    on_event_id: Any = None,
) -> AsyncIterator[StreamDecisionEvent | StreamProgressEvent]:
    """Parse server-sent events from an async line iterator.

    Yields :class:`StreamDecisionEvent` and :class:`StreamProgressEvent`.
    Raises :class:`AtlaSentError` on ``event: error``.
    Returns (stops iterating) on ``event: done`` or ``done: true`` payload.
    Unknown event types are silently skipped for forward compatibility.

    Hardening additions:
    - Per-event timeout via ``timeout_s`` (0 = disabled): raises
      :class:`StreamTimeoutError` if no line arrives in time.
    - JSON parse failures raise :class:`StreamParseError`.
    - Calls ``on_event_id(id)`` when an ``id:`` field is seen.
    """
    event_type = "message"
    data_lines: list[str] = []
    event_id: str | None = None

    async def _next_line(it: AsyncIterator[str], timeout: float) -> str | None:
        """Fetch the next line, applying a timeout when timeout > 0.

        Returns ``None`` when the iterator is exhausted.
        Raises :class:`StreamTimeoutError` on timeout.
        """
        if timeout <= 0:
            try:
                return await it.__anext__()
            except StopAsyncIteration:
                return None
        try:
            return await asyncio.wait_for(it.__anext__(), timeout=timeout)
        except StopAsyncIteration:
            return None
        except asyncio.TimeoutError as exc:
            raise StreamTimeoutError(timeout) from exc

    while True:
        line = await _next_line(lines, timeout_s)
        if line is None:
            # Stream ended without an explicit done event.
            # If there's partial data accumulated, surface it as a parse error.
            if data_lines:
                raise StreamParseError("\n".join(data_lines))
            return

        if line == "":
            # Blank line: dispatch accumulated event
            if data_lines:
                data = "\n".join(data_lines)
                data_lines = []

                if event_id is not None and on_event_id is not None:
                    on_event_id(event_id)

                if event_type in ("done", "complete"):
                    # "done" is the legacy/generic terminal marker; "complete"
                    # is the real V2-D4 wire terminal frame emitted by
                    # /v1-evaluate-stream (`{batch_id, count, partial}`) once
                    # every item in the request's `items` array has been
                    # evaluated. Neither payload carries information this
                    # generator's callers currently consume, so both simply
                    # end the stream cleanly rather than falling through to
                    # "unknown event types skipped".
                    return

                try:
                    parsed: dict[str, Any] = json.loads(data)
                except json.JSONDecodeError as exc:
                    raise StreamParseError(data, exc) from exc
                except (ValueError, TypeError) as exc:
                    raise StreamParseError(data, exc) from exc

                if event_type == "error":
                    # The real wire frame (`event: error\ndata: {error_code,
                    # message, index}`) uses `error_code`; `code` is kept as a
                    # fallback for the legacy/generic shape some older mocks
                    # and tests still use.
                    raise AtlaSentError(
                        parsed.get("message", "Stream error from AtlaSent API"),
                        code=parsed.get("error_code")
                        or parsed.get("code", "server_error"),
                        request_id=parsed.get("request_id", request_id),
                    )

                if event_type == "decision":
                    ev = StreamDecisionEvent.from_wire(parsed)
                    yield ev
                    # Terminal: final decision (or inline done: true) closes stream.
                    if ev.is_final or parsed.get("done") is True:
                        return
                elif event_type == "progress":
                    extra = {
                        k: v for k, v in parsed.items() if k not in ("type", "stage")
                    }
                    yield StreamProgressEvent(
                        stage=str(parsed.get("stage", "")),
                        **extra,
                    )
                    # Check done: true on progress events too.
                    if isinstance(parsed, dict) and parsed.get("done") is True:
                        return
                # unknown event types skipped

            event_type = "message"
            event_id = None
        elif line.startswith("event: "):
            event_type = line[7:].strip()
        elif line.startswith("data: "):
            data_lines.append(line[6:])
        elif line.startswith("id: ") or line.startswith("id:"):
            event_id = line.split(":", 1)[1].strip()
