"""AtlaSent SDK exceptions.

The SDK follows a **fail-closed** design: any failure to confirm
authorization raises an exception, ensuring no action proceeds
without an explicit permit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .approval_artifact import EvaluateSigningHint

AtlaSentDecision = Literal["deny", "hold", "escalate"]
"""Policy decision outcomes on a denial.

``"deny"`` is what the current ``/v1-evaluate`` API returns. ``"hold"``
and ``"escalate"`` are reserved for forthcoming API decisions that
put a permit into a pending state requiring human review; the union
is declared now so call sites can ``match`` exhaustively from the
start and adopt new decisions without a breaking change.
"""

AtlaSentErrorCode = Literal[
    "invalid_api_key",
    "forbidden",
    "rate_limited",
    "timeout",
    "network",
    "bad_response",
    "bad_request",
    "server_error",
    "feature_disabled",
    "claim_evidence_incomplete",
    # atlasent-api #1634 (permit-mint operational-error taxonomy): policy
    # evaluation resolved ALLOW but AtlaSent could not materialize
    # executable authority (permit mint/signing failed). Distinct from
    # every other code above — none of those describe an ALLOW outcome.
    "permit_signing_unavailable",
]
"""Coarse error category — shared across AtlaSent SDKs.

Call sites MAY ``switch`` / ``match`` on this field. The set is
defined by ``contract/vectors/errors.json`` in the SDK repo; any new
code MUST be added there first.
"""

PermitOutcome = Literal[
    "permit_consumed",
    "permit_expired",
    "permit_revoked",
    "permit_not_found",
    "permit_signing_key_revoked",
    "verify_unavailable",
]
"""Reason an already-issued permit failed verification.

Surfaced on :class:`AtlaSentDeniedError.outcome` so operators can
distinguish replay (``permit_consumed``) from revocation
(``permit_revoked``) from natural expiry (``permit_expired``) without
parsing :attr:`AtlaSentDeniedError.reason`. The set is defined by
``contract/vectors/permit_outcomes.json``; any new outcome MUST be
added there first.

Values:
    permit_consumed: The permit was already consumed by a prior verify
        (v1 single-use replay protection).
    permit_expired: The permit's TTL passed before verification.
    permit_revoked: The permit was explicitly revoked (D3 endpoint).
    permit_not_found: The permit id wasn't recognized server-side
        (typo, cross-tenant lookup, or pre-issuance race).
    permit_signing_key_revoked: The permit's signing key KID appears in
        the trust-root revocation list (ADR-005 D3 R2/R3 key rotation).
    verify_unavailable: The verification endpoint returned a 5xx error
        (server unavailable, overloaded, or network partition). Fail-
        closed: the action MUST NOT proceed when this outcome is set.
        Surface as a distinct outcome so callers can distinguish
        infra failures from policy denials without parsing error codes.

See ``docs/REVOCATION_RUNBOOK.md`` (atlasent meta) for the operator-
facing matrix this discriminator drives.
"""

_KNOWN_PERMIT_OUTCOMES: frozenset[str] = frozenset(
    {
        "permit_consumed",
        "permit_expired",
        "permit_revoked",
        "permit_not_found",
        "permit_signing_key_revoked",
        "verify_unavailable",
    }
)


def _normalize_permit_outcome(raw: str | None) -> PermitOutcome | None:
    """Map a server-supplied ``outcome`` string to :data:`PermitOutcome`.

    Returns ``None`` for ``None``, ``""``, ``"verified"``, or any
    unrecognized value. Used at the SDK's deny boundary so we don't
    raise mis-typed outcomes — when the server adds a new outcome
    string, callers branching on :attr:`AtlaSentDeniedError.outcome`
    see ``None`` and fall through to their generic deny path rather
    than match an unknown literal.
    """
    if raw in _KNOWN_PERMIT_OUTCOMES:
        # mypy: the membership check above narrows to PermitOutcome.
        return raw  # type: ignore[return-value]
    return None


class AtlaSentError(Exception):
    """Base exception for all AtlaSent SDK errors.

    Raised on network failures, timeouts, malformed responses,
    configuration errors, and any other unexpected condition.
    Because the SDK is fail-closed, an ``AtlaSentError`` means
    the action must NOT proceed.

    Attributes:
        message: Human-readable error message.
        status_code: HTTP status code when the error originated from
            an API response. ``None`` for transport errors.
        code: Coarse category from :data:`AtlaSentErrorCode`.
            ``None`` only on the deprecated legacy construction path;
            every raise site inside the SDK sets it.
        request_id: Value of the ``X-Request-ID`` header the SDK sent
            with the failing request. Paste this into support tickets
            so the server-side log entry can be correlated. ``None``
            if the error was raised before the request was dispatched
            (e.g. a :class:`ConfigurationError`).
        response_body: Decoded JSON body when available.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: AtlaSentErrorCode | None = None,
        request_id: str | None = None,
        response_body: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.code: AtlaSentErrorCode | None = code
        self.request_id = request_id
        self.response_body = response_body
        super().__init__(self.message)


class AtlaSentDenied(AtlaSentError):
    """Raised when the AtlaSent API explicitly denies an action.

    This is the normal "not permitted" path.  Callers should catch
    this to handle denied actions gracefully (e.g., log an audit
    event, return a 403 to the user).

    Attributes:
        decision: The decision string returned by the API (e.g. ``"deny"``).
        permit_token: The token associated with this evaluation, if any.
        reason: Human-readable explanation, when provided by the API.
        deny_code: Stable machine code naming *why* the action was denied
            (e.g. ``"SNAPSHOT_REQUIRED"``). ``None`` when the server did not
            return one. Branch on this, not on the human-readable ``reason``.
    """

    def __init__(
        self,
        decision: str,
        *,
        permit_token: str = "",
        reason: str = "",
        deny_code: str | None = None,
        request_id: str | None = None,
        response_body: dict[str, Any] | None = None,
    ) -> None:
        self.decision = decision
        self.permit_token = permit_token
        self.reason = reason
        self.deny_code = deny_code
        msg = f"Action denied: {decision}"
        if deny_code:
            msg += f" [{deny_code}]"
        if reason:
            msg += f" — {reason}"
        super().__init__(
            msg,
            request_id=request_id,
            response_body=response_body,
        )

    @property
    def is_human_approval_required(self) -> bool:
        """True when the denial is ``INSUFFICIENT_APPROVALS``.

        Lets callers route the action into an approval queue instead of
        treating it as a hard refusal. See :mod:`atlasent.deny_codes`.
        """
        from .deny_codes import requires_human_approval

        return requires_human_approval(self.deny_code)

    @property
    def signing_hint(self) -> EvaluateSigningHint | None:
        """The binding a signed approval for this exact request must
        reproduce (ADR-055), from the denial's ``signing_hint``.

        ``bind.action_hash`` is what the approver signs into an
        ``approval_artifact.v1``; retry the same evaluate with that
        artifact as ``approval=``. ``None`` when the runtime sent no
        hint (it is disclosure-gated) or a malformed one.
        """
        if not isinstance(self.response_body, dict):
            return None
        from .approval_artifact import parse_signing_hint

        return parse_signing_hint(self.response_body.get("signing_hint"))


class ConfigurationError(AtlaSentError):
    """Raised when the SDK is misconfigured (e.g., missing API key)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PermissionDeniedError(AtlaSentDenied):
    """Raised when ``authorize(..., raise_on_deny=True)`` is denied.

    Alias-style subclass of :class:`AtlaSentDenied` that reads more
    naturally in authorization-centric code paths.
    """


class AtlaSentDeniedError(AtlaSentDenied):
    """Raised by :func:`atlasent.protect` when the policy engine
    refuses the action, or when the resulting permit fails
    end-to-end verification.

    This is the **fail-closed boundary** of ``protect()``: every
    code path that short-circuits an action because authorization
    was not confirmed raises ``AtlaSentDeniedError``. Callers cannot
    silently proceed on a denial by forgetting to branch on a
    return value.

    Shape mirrors the TypeScript SDK's ``AtlaSentDeniedError`` for
    cross-language parity. Subclasses :class:`AtlaSentDenied` so
    existing ``except AtlaSentDenied:`` catches ``protect()``
    denials too; use ``except AtlaSentDeniedError:`` to distinguish
    a policy denial from the older ``authorize()`` /
    ``evaluate()`` denial surface.

    Attributes:
        decision: Policy outcome — ``"deny"`` today; ``"hold"`` /
            ``"escalate"`` reserved for forthcoming API responses.
        evaluation_id: Opaque permit / decision identifier (echo of
            the inherited ``permit_token`` field, named for parity
            with the TypeScript SDK).
        reason: Human-readable explanation from the policy engine.
        deny_code: Stable machine code naming *why* the action was
            denied (e.g. ``"SNAPSHOT_REQUIRED"``). ``None`` when the
            server did not return one. Inherited from
            :class:`AtlaSentDenied`. Branch on this, not on ``reason``.
        audit_hash: Hash-chained audit-trail entry associated with
            the decision, if present on the server response.
        outcome: When the denial came from permit verification (not
            policy evaluation), the discriminator that distinguishes
            replay (``"permit_consumed"``), expiry
            (``"permit_expired"``), revocation (``"permit_revoked"``),
            missing-record (``"permit_not_found"``), signing-key
            revocation (``"permit_signing_key_revoked"``), and server
            unavailability (``"verify_unavailable"``). ``None`` for
            evaluate-time denials. See :data:`PermitOutcome`.
    """

    def __init__(
        self,
        *,
        decision: AtlaSentDecision = "deny",
        evaluation_id: str,
        reason: str = "",
        deny_code: str | None = None,
        audit_hash: str = "",
        outcome: PermitOutcome | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            decision=decision,
            permit_token=evaluation_id,
            reason=reason,
            deny_code=deny_code,
        )
        self.evaluation_id = evaluation_id
        self.audit_hash = audit_hash
        self.outcome: PermitOutcome | None = outcome
        # `request_id` lives on `AtlaSentError` in the TS SDK; Python's
        # AtlaSentError doesn't have a first-class request_id attribute
        # yet (that's a separate parity change — see finish-work), so
        # store it on this subclass for now.
        self.request_id = request_id

    # ── Outcome discriminators ──────────────────────────────────
    # Convenience predicates that mirror the operator runbook's matrix.
    # Callers can branch directly on the outcome strings; these are
    # sugar so the common cases are explicit at the call site.

    @property
    def is_revoked(self) -> bool:
        """``True`` when the permit was explicitly revoked (D3 endpoint)."""
        return self.outcome == "permit_revoked"

    @property
    def is_expired(self) -> bool:
        """``True`` when the permit's TTL passed before verification."""
        return self.outcome == "permit_expired"

    @property
    def is_consumed(self) -> bool:
        """``True`` when the permit was already consumed by a prior verify
        (v1 single-use replay protection).
        """
        return self.outcome == "permit_consumed"

    @property
    def is_not_found(self) -> bool:
        """``True`` when the permit id wasn't recognized server-side
        (typo, cross-tenant lookup, or pre-issuance race).
        """
        return self.outcome == "permit_not_found"

    @property
    def is_signing_key_revoked(self) -> bool:
        """``True`` when the permit's signing key KID appears in the
        trust-root revocation list (ADR-005 D3 R2/R3 key rotation).
        """
        return self.outcome == "permit_signing_key_revoked"

    @property
    def is_verify_unavailable(self) -> bool:
        """``True`` when the verification endpoint returned a 5xx error.

        The action MUST NOT proceed — fail-closed. Callers should
        treat this the same as any other denial but may choose to
        surface a distinct user-facing message (e.g. "authorization
        service temporarily unavailable") or trigger an alerting path.
        """
        return self.outcome == "verify_unavailable"


BundleVerificationReason = Literal[
    "trust_snapshot_expired",
    "key_revoked",
    "key_role_mismatch",
]
"""Discriminator for :class:`BundleVerificationError` failures."""


class BundleVerificationError(AtlaSentDeniedError):
    """Raised when bundle or permit verification fails due to a trust-root
    condition: expired snapshot, revoked signing key, or key role mismatch.

    Extends :class:`AtlaSentDeniedError` so ``isinstance(e, AtlaSentDeniedError)``
    catches these failures alongside policy denials; use
    ``isinstance(e, BundleVerificationError)`` to branch specifically.

    Attributes:
        bundle_reason: Discriminator — ``"trust_snapshot_expired"``,
            ``"key_revoked"``, or ``"key_role_mismatch"``.
        snapshot_valid_until: ``valid_until`` of the expired snapshot, if applicable.
        snapshot_fetched_at: ``issued_at`` of the snapshot (proxy for fetch time).
        snapshot_source: Whether the snapshot came from the pinned vendor file
            or a live refresh.
        kid: Which key id was revoked or role-mismatched, when applicable.
    """

    def __init__(
        self,
        *,
        bundle_reason: BundleVerificationReason,
        evaluation_id: str = "",
        snapshot_valid_until: str | None = None,
        snapshot_fetched_at: str | None = None,
        snapshot_source: Literal["pinned", "live"] | None = None,
        kid: str | None = None,
    ) -> None:
        super().__init__(
            decision="deny",
            evaluation_id=evaluation_id,
            reason=bundle_reason,
        )
        self.bundle_reason = bundle_reason
        self.snapshot_valid_until = snapshot_valid_until
        self.snapshot_fetched_at = snapshot_fetched_at
        self.snapshot_source = snapshot_source
        self.kid = kid


class StreamTimeoutError(AtlaSentError):
    """Raised when no SSE event arrives within the configured timeout window.

    Callers can catch this specifically to distinguish a stalled stream
    from other network or parse failures::

        except StreamTimeoutError:
            # reconnect or alert

    Attributes:
        timeout_s: The timeout in seconds that was exceeded.
    """

    def __init__(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s
        super().__init__(
            f"AtlaSent stream timed out after {timeout_s}s with no event",
            code="timeout",
        )


class StreamParseError(AtlaSentError):
    """Raised when the SSE stream closes with a partial / malformed JSON payload.

    Callers can catch this specifically to distinguish a parse failure
    from a timeout or network error::

        except StreamParseError as e:
            logger.error("bad SSE data: %s", e.raw_data[:200])

    Attributes:
        raw_data: The raw data string that failed to parse.
    """

    def __init__(self, raw_data: str, cause: Exception | None = None) -> None:
        self.raw_data = raw_data
        super().__init__(
            f"AtlaSent stream received malformed JSON: {raw_data[:200]}",
            code="bad_response",
        )
        if cause is not None:
            self.__cause__ = cause


class RateLimitError(AtlaSentError):
    """Raised when the API returns HTTP 429 (Too Many Requests).

    Attributes:
        retry_after: Seconds to wait before retrying, parsed from the
            ``Retry-After`` header. ``None`` if the header was absent
            or unparseable. Both numeric (``"30"``) and HTTP-date
            (``"Wed, 21 Oct 2026 07:28:00 GMT"``) forms are supported
            per RFC 9110 §10.2.3.
        request_id: ``X-Request-ID`` the SDK sent with the throttled
            request. See :class:`AtlaSentError.request_id`.
    """

    def __init__(
        self,
        retry_after: float | None = None,
        *,
        request_id: str | None = None,
    ) -> None:
        self.retry_after = retry_after
        msg = "Rate limited by AtlaSent API"
        if retry_after is not None:
            msg += f" — retry after {retry_after}s"
        super().__init__(
            msg,
            status_code=429,
            code="rate_limited",
            request_id=request_id,
        )


class AtlaSentPermitMintFailedError(AtlaSentError):
    """Raised when policy evaluation resolved ``ALLOW`` but AtlaSent could
    not materialize executable authority — the permit could not be
    minted/signed.

    This is the permit-mint **operational-error taxonomy** (architecture
    decision, ``atlasent-api`` #1634). It is a distinct
    operational/infrastructure failure, NOT an authorization decision: it
    must never be confused with :class:`AtlaSentDenied` /
    :class:`AtlaSentDeniedError` (this class extends neither, and neither
    extends this class), even though, like them, the practical outcome for
    the caller is the same — no permit, do not proceed.

    :attr:`decision` is fixed to ``"allow"`` because that is the policy
    result that actually occurred; callers must branch on
    ``isinstance(e, AtlaSentPermitMintFailedError)`` (or :attr:`code`), not
    on ``decision``, to learn *why* nothing is executable.

    Two wire shapes both raise this class:

    1. A non-2xx response (503 for a recoverable signer/config
       unavailability, 500 for an invariant failure) carrying
       ``{"error": "permit_signing_unavailable", ...}``.
    2. A defensive fallback: a 2xx response with ``decision: "allow"`` but
       no ``permit_token`` — the same "allow, but no executable authority"
       outcome, in case a future response shape ever resolves this way
       over a 2xx status instead of the documented non-2xx envelope above.

    Mirrors the TypeScript SDK's ``AtlaSentPermitMintFailedError``
    (``atlasent-api`` ``packages/sdk/src/errors.ts``) for cross-language
    parity, adapted to this SDK's existing :class:`AtlaSentError`
    attributes (``status_code``, ``code``, ``request_id``,
    ``response_body``) rather than introducing a new hierarchy.

    Attributes:
        decision: Always ``"allow"`` — the policy result that actually
            occurred, never ``deny``/``hold``/``escalate``.
    """

    decision: Literal["allow"] = "allow"

    def __init__(
        self,
        message: str,
        *,
        code: AtlaSentErrorCode = "permit_signing_unavailable",
        status_code: int | None = None,
        request_id: str | None = None,
        response_body: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            code=code,
            request_id=request_id,
            response_body=response_body,
        )


#: Wire-level error codes belonging to the permit-mint operational-error
#: taxonomy (atlasent-api #1634). Kept as an explicit allowlist (currently
#: one entry) rather than a prefix/heuristic match — mirrors the TypeScript
#: SDK's ``PERMIT_MINT_FAILURE_ERROR_CODES``: "preserve
#: ``permit_signing_unavailable`` unless a separately reviewed
#: compatibility migration renames it" per the architecture decision. Add
#: to this set only alongside such a migration.
PERMIT_MINT_FAILURE_ERROR_CODES: frozenset[str] = frozenset(
    {"permit_signing_unavailable"}
)


# ── Bundle verification error (ADR-005 D3 fail-closed expiry / revocation) ───
