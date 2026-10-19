"""Send-time authorization gate for the Gmail API.

The Python counterpart of ``@atlasent/gmail``. It implements CANON-000047 /
ACT-0050 (``communication.external.send``) as a send-time API gate. AtlaSent
evaluates the send, then verifies and consumes the permit, *before* the
caller's Gmail API call is made. A denied, held or unverified request never
reaches Gmail::

    1. evaluate  -- check the policy engine (communication.external.send)
    2. verify    -- confirm and consume the permit for THIS message
    3. send      -- call Gmail ONLY if both pass, with the bytes that were authorized

WHAT THE PERMIT AND THE APPROVAL ARE BOUND TO. The guard snapshots the exact
request Gmail will receive: ``userId``, the base64url ``raw`` RFC 2822 message
(recipients, headers, body and attachments) and ``threadId``. It hashes that
snapshot (:func:`compute_gmail_send_digest`) and sends the digest to evaluate
twice:

- as top-level ``execution_payload_hash``, which the runtime signs into the
  permit and which the guard re-presents at verify; and
- as top-level ``resource_id``, which the runtime folds into the
  ``action_hash`` a human ``approval_artifact.v1`` signs, so an approval for
  one message cannot authorize another.

Gmail is called with a request built from the snapshot, never with the
caller's own mapping, so changing that mapping while the send is being
authorized changes nothing that is sent.

The digest is byte-identical to ``@atlasent/gmail``'s for the same snapshot,
so an approval desk shows the same value whichever SDK prepared the send
(``tests/test_gmail_guard.py`` pins both against shared vectors).

The :class:`GmailExternalSendFacts` remain caller-asserted classification
inputs. This module does not parse MIME, so it does not check them against
the bytes; a human approval covers the bytes and the facts together.

``gmail`` is a ``googleapiclient`` Gmail service (``build("gmail", "v1",
...)``) or anything with the same ``users().messages().send(...)`` /
``users().drafts().get(...)`` / ``users().drafts().send(...)`` shape. This
module never imports or configures Google credentials.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from .exceptions import AtlaSentDenied, AtlaSentError

if TYPE_CHECKING:
    from .approval_artifact import ApprovalArtifactV1, EvaluateSigningHint
    from .client import AtlaSentClient

#: ACT-0050 / CANON-000047 canonical action type.
COMMUNICATION_EXTERNAL_SEND = "communication.external.send"

#: Version tag folded into the message digest. Changing the digest input bumps it.
GMAIL_SEND_BINDING_VERSION = "gmail_send_binding.v1"


@dataclass(frozen=True)
class GmailExternalSendFacts:
    """Classification facts for one outbound send: policy inputs the caller asserts.

    The permit and any approval are also bound to the exact message bytes,
    not to these alone.
    """

    recipient: str
    """Exact recipient address, or a stable joined form for several.

    For several recipients, sort and comma-join them.
    """
    recipient_known: bool
    """Whether the recipient is a previously known correspondent."""
    sensitive_attachment: bool
    """Whether the send carries a flagged-sensitive attachment or body."""
    attachment_sha256: str = ""
    """SHA-256 hex of the sensitive content, when there is any."""
    recipient_domain: str | None = None
    """Sent as ``context.recipient_domain``. Derived from ``recipient`` when omitted."""
    actor_origin: Literal["human", "ai_agent"] | None = None
    """Policy context and audit evidence only; no runtime branch reads it."""


@dataclass(frozen=True)
class GmailSendSnapshot:
    """The exact request Gmail will receive, frozen before evaluate."""

    kind: Literal["message", "draft"]
    user_id: str
    raw: str
    """base64url RFC 2822 message: recipients, headers, body and attachments."""
    thread_id: str | None
    draft_id: str | None
    """The draft sent, for ``kind="draft"``."""


@dataclass(frozen=True)
class GmailSendDenial:
    """The send was blocked. Gmail was not called."""

    decision: str
    """One of ``deny``, ``hold``, ``escalate``, ``verify_failed``,
    ``invalid_request``, ``content_changed`` or ``error``."""
    reason: str
    deny_code: str | None = None
    """Stable code from an evaluate-time denial, e.g. ``INSUFFICIENT_APPROVALS``."""
    evaluation_id: str | None = None
    audit_hash: str | None = None
    message_digest: str | None = None
    """Digest of the message the guard would have sent, when it got that far."""
    sent: Literal[False] = False


@dataclass(frozen=True)
class GmailSendSuccess:
    """The send happened, after the permit was verified and consumed."""

    message: Any
    """The Gmail API response."""
    permit_id: str
    audit_hash: str
    message_digest: str
    """Digest of the exact request sent; the value the permit was bound to."""
    sent: Literal[True] = True


GmailSendResult = GmailSendSuccess | GmailSendDenial


@dataclass(frozen=True)
class GmailSendApprovalRequest:
    """What a human approval for one message must bind.

    When ``ok`` is true, sign ``signing_hint.bind.action_hash`` into an
    ``approval_artifact.v1`` and pass it to the send as ``approval_artifact``.
    """

    ok: bool
    signing_hint: EvaluateSigningHint | None = None
    message_digest: str | None = None
    reason: str = ""
    decision: str | None = None
    deny_code: str | None = None


class GmailSendDeniedError(AtlaSentError):
    """Raised instead of returning a denial when ``on_deny="throw"``."""

    def __init__(self, denial: GmailSendDenial) -> None:
        super().__init__(f"Gmail send blocked: {denial.decision} — {denial.reason}")
        self.denial = denial


class _InvalidSendRequest(ValueError):
    pass


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _json(value: Any, *, sort_keys: bool) -> str:
    # The serialization JavaScript's JSON.stringify produces, so the digests
    # equal @atlasent/gmail's: no whitespace, non-ASCII left as is.
    return json.dumps(
        value, sort_keys=sort_keys, separators=(",", ":"), ensure_ascii=False
    )


def compute_gmail_send_digest(snapshot: GmailSendSnapshot) -> str:
    """Bare 64-hex SHA-256 over the canonical snapshot.

    The value sent as ``execution_payload_hash`` and ``resource_id``. Exposed so
    an approval UI can show which message an approval covers.
    """
    return _sha256_hex(
        _json(
            {
                "binding_version": GMAIL_SEND_BINDING_VERSION,
                "kind": snapshot.kind,
                "userId": snapshot.user_id,
                "raw": snapshot.raw,
                "threadId": snapshot.thread_id,
                "draftId": snapshot.draft_id,
            },
            sort_keys=True,
        )
    )


def compute_external_send_target_id(facts: GmailExternalSendFacts) -> str:
    """SHA-256 hex over the recipient, attachment and sensitivity facts.

    Sent as ``context.target.id``.
    """
    # Insertion order, not sorted: it matches @atlasent/gmail's serialization.
    return _sha256_hex(
        _json(
            {
                "recipient": facts.recipient,
                "attachment_sha256": facts.attachment_sha256 or "",
                "sensitive_attachment": facts.sensitive_attachment,
            },
            sort_keys=False,
        )
    )


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _body(request: Mapping[str, Any]) -> Mapping[str, Any]:
    body = request.get("body")
    if body is None:
        return {}
    if not isinstance(body, Mapping):
        raise _InvalidSendRequest("body must be a mapping")
    return body


def _refuse_media(request: Mapping[str, Any]) -> None:
    if (
        request.get("media_body") is not None
        or request.get("media_mime_type") is not None
    ):
        # A media upload is sent instead of body["raw"]; the guard cannot bind it.
        raise _InvalidSendRequest(
            "media uploads are not supported: pass the message as body['raw']"
        )


def _snapshot_message_request(request: Mapping[str, Any]) -> GmailSendSnapshot:
    user_id = request.get("userId")
    if not _non_empty(user_id):
        raise _InvalidSendRequest("userId is required")
    _refuse_media(request)
    body = _body(request)
    raw = body.get("raw")
    if not _non_empty(raw):
        raise _InvalidSendRequest("body['raw'] is required")
    thread_id = body.get("threadId")
    return GmailSendSnapshot(
        kind="message",
        user_id=user_id,
        raw=raw,
        thread_id=thread_id if _non_empty(thread_id) else None,
        draft_id=None,
    )


def _draft_id_of(request: Mapping[str, Any]) -> tuple[str, str]:
    user_id = request.get("userId")
    if not _non_empty(user_id):
        raise _InvalidSendRequest("userId is required")
    _refuse_media(request)
    body = _body(request)
    if body.get("message") is not None:
        # It would replace the draft's content at send time with bytes the
        # guard never bound.
        raise _InvalidSendRequest(
            "drafts.send with replacement content is not supported: "
            "update the draft, then send it by id"
        )
    draft_id = body.get("id")
    if not _non_empty(draft_id):
        raise _InvalidSendRequest("body['id'] (the draft id) is required")
    return user_id, draft_id


def _snapshot_draft(gmail: Any, user_id: str, draft_id: str) -> GmailSendSnapshot:
    """Read the draft as Gmail holds it.

    ``drafts.send`` sends that, not what the caller passes.
    """
    draft = (
        gmail.users().drafts().get(userId=user_id, id=draft_id, format="raw").execute()
    )
    message = draft.get("message") if isinstance(draft, Mapping) else None
    message = message if isinstance(message, Mapping) else {}
    raw = message.get("raw")
    if not _non_empty(raw):
        raise _InvalidSendRequest(f"draft {draft_id} has no raw content")
    thread_id = message.get("threadId")
    return GmailSendSnapshot(
        kind="draft",
        user_id=user_id,
        raw=raw,
        thread_id=thread_id if _non_empty(thread_id) else None,
        draft_id=draft_id,
    )


def _recipient_domain(facts: GmailExternalSendFacts) -> str | None:
    if facts.recipient_domain:
        return facts.recipient_domain
    at = facts.recipient.rfind("@")
    return None if at == -1 else facts.recipient[at + 1 :]


def _context(
    facts: GmailExternalSendFacts,
    extra_context: Mapping[str, Any] | None,
    approvals_claimed: int,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        **(extra_context or {}),
        "recipient_known": facts.recipient_known,
        "sensitive_attachment": facts.sensitive_attachment,
        "approvals": approvals_claimed,
        "target": {"id": compute_external_send_target_id(facts)},
    }
    domain = _recipient_domain(facts)
    if domain is not None:
        context["recipient_domain"] = domain
    if facts.actor_origin is not None:
        context["actor_origin"] = facts.actor_origin
    return context


def _evaluate_send(
    atlasent: AtlaSentClient,
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str,
    extra_context: Mapping[str, Any] | None,
    digest: str,
    approvals_claimed: int,
    approval_artifact: ApprovalArtifactV1 | Mapping[str, Any] | None,
) -> Any:
    """The single place the evaluate request is composed.

    Shared by the approval request and the send, so both present the same
    ``action_hash`` inputs and differ only in ``approval``.
    """
    return atlasent.evaluate(
        COMMUNICATION_EXTERNAL_SEND,
        agent,
        _context(facts, extra_context, approvals_claimed),
        environment=environment,
        resource_id=digest,
        execution_payload_hash=digest,
        approval=(
            {"artifact": approval_artifact} if approval_artifact is not None else None
        ),
    )


def _evaluation_id(body: Mapping[str, Any] | None) -> str | None:
    for key in ("evaluation_id", "request_id"):
        value = (body or {}).get(key)
        if _non_empty(value):
            return value
    return None


def _blocked(on_deny: str, denial: GmailSendDenial) -> GmailSendDenial:
    if on_deny == "throw":
        raise GmailSendDeniedError(denial)
    return denial


def _run_guarded_send(
    atlasent: AtlaSentClient,
    facts: GmailExternalSendFacts,
    snapshot: GmailSendSnapshot,
    *,
    agent: str,
    environment: str,
    extra_context: Mapping[str, Any] | None,
    approval_artifact: ApprovalArtifactV1 | Mapping[str, Any] | None,
    on_deny: str,
    reread_digest: Callable[[], str] | None,
    perform_send: Callable[[], Any],
) -> GmailSendResult:
    digest = compute_gmail_send_digest(snapshot)
    if getattr(atlasent, "_cache", None) is not None:
        # The evaluate cache keys on action, actor and context only, so it would
        # hand this send a permit minted for another message (or one already
        # consumed). Verify would then refuse it; say why up front instead.
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="invalid_request",
                reason="the AtlaSentClient has an evaluate cache; a send needs a "
                "fresh permit, "
                "so use a client without one",
                message_digest=digest,
            ),
        )
    try:
        # Report an approval only when one is attached for the runtime to verify.
        evaluation = _evaluate_send(
            atlasent,
            facts,
            agent=agent,
            environment=environment,
            extra_context=extra_context,
            digest=digest,
            approvals_claimed=1 if approval_artifact is not None else 0,
            approval_artifact=approval_artifact,
        )
    except AtlaSentDenied as err:
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision=err.decision,
                reason=err.reason or f"blocked by decision={err.decision}",
                deny_code=err.deny_code,
                evaluation_id=_evaluation_id(err.response_body),
                message_digest=digest,
            ),
        )
    except Exception as err:  # noqa: BLE001 - every failure blocks the send
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="error",
                reason=f"evaluate failed: {err}",
                message_digest=digest,
            ),
        )

    permit_id = evaluation.permit_token
    evidence = {
        "evaluation_id": evaluation.request_id or None,
        "audit_hash": evaluation.audit_hash or None,
        "message_digest": digest,
    }
    try:
        # Re-present the digest the runtime signed into the permit
        # (execution_hash_expected); anything else is a PAYLOAD_MISMATCH.
        verification = atlasent.verify(
            permit_id,
            COMMUNICATION_EXTERNAL_SEND,
            agent,
            environment=environment,
            execution_hash=digest,
        )
    except Exception as err:  # noqa: BLE001 - every failure blocks the send
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="error", reason=f"verify failed: {err}", **evidence
            ),
        )
    if verification.valid is not True:
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="verify_failed",
                reason=f"permit verification failed: outcome={verification.outcome}",
                **evidence,
            ),
        )
    if verification.consumed is not True:
        # Verified but not burned: the permit could be presented again, so it
        # cannot authorize a send that must happen once.
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="verify_failed",
                reason="permit verified but was not reported consumed",
                **evidence,
            ),
        )

    if reread_digest is not None:
        try:
            current = reread_digest()
        except Exception as err:  # noqa: BLE001 - every failure blocks the send
            return _blocked(
                on_deny,
                GmailSendDenial(
                    decision="error",
                    reason=f"could not re-read the draft: {err}",
                    **evidence,
                ),
            )
        if current != digest:
            return _blocked(
                on_deny,
                GmailSendDenial(
                    decision="content_changed",
                    reason="the draft changed after it was authorized",
                    **evidence,
                ),
            )

    # ONLY reachable once evaluate allowed AND verify confirmed and consumed
    # the permit. The single call site of the Gmail send endpoints.
    message = perform_send()
    return GmailSendSuccess(
        message=message,
        permit_id=permit_id,
        audit_hash=evaluation.audit_hash,
        message_digest=digest,
    )


def guarded_gmail_send(
    gmail: Any,
    atlasent: AtlaSentClient,
    request: Mapping[str, Any],
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str = "production",
    approval_artifact: ApprovalArtifactV1 | Mapping[str, Any] | None = None,
    extra_context: Mapping[str, Any] | None = None,
    on_deny: Literal["result", "throw"] = "result",
) -> GmailSendResult:
    """Authorize, then send with ``users().messages().send``.

    ``request`` holds what you would pass to ``messages().send(**request)``:
    ``userId`` and ``body`` with ``raw`` (and optionally ``threadId``). Only
    those are sent. A media upload is refused.

    Gmail is called only when the permit was verified and consumed, with
    exactly the ``userId``, ``raw`` and ``threadId`` the permit is bound to.
    Obtain ``approval_artifact`` with :func:`request_gmail_send_approval`.
    """
    try:
        snapshot = _snapshot_message_request(request)
    except _InvalidSendRequest as err:
        return _blocked(
            on_deny, GmailSendDenial(decision="invalid_request", reason=str(err))
        )
    outbound_body: dict[str, Any] = {"raw": snapshot.raw}
    if snapshot.thread_id is not None:
        outbound_body["threadId"] = snapshot.thread_id

    def send() -> Any:
        return (
            gmail.users()
            .messages()
            .send(userId=snapshot.user_id, body=outbound_body)
            .execute()
        )

    return _run_guarded_send(
        atlasent,
        facts,
        snapshot,
        agent=agent,
        environment=environment,
        extra_context=extra_context,
        approval_artifact=approval_artifact,
        on_deny=on_deny,
        reread_digest=None,
        perform_send=send,
    )


def guarded_gmail_send_draft(
    gmail: Any,
    atlasent: AtlaSentClient,
    request: Mapping[str, Any],
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str = "production",
    approval_artifact: ApprovalArtifactV1 | Mapping[str, Any] | None = None,
    extra_context: Mapping[str, Any] | None = None,
    on_deny: Literal["result", "throw"] = "result",
) -> GmailSendResult:
    """Authorize, then send an existing draft with ``users().drafts().send``.

    ``request`` is ``{"userId": ..., "body": {"id": draft_id}}``. Gmail sends
    the draft as Gmail holds it, so the guard reads it (``drafts().get``,
    ``format="raw"``), binds those bytes, and reads it again just before
    sending: an edit after authorization refuses the send
    (``content_changed``). A change in the instant between that read and
    Gmail's own send cannot be observed from a client. ``drafts().create``
    is not wrapped: it delivers no mail.
    """
    try:
        user_id, draft_id = _draft_id_of(request)
        snapshot = _snapshot_draft(gmail, user_id, draft_id)
    except _InvalidSendRequest as err:
        return _blocked(
            on_deny, GmailSendDenial(decision="invalid_request", reason=str(err))
        )
    except Exception as err:  # noqa: BLE001 - every failure blocks the send
        return _blocked(
            on_deny,
            GmailSendDenial(
                decision="error", reason=f"could not read the draft: {err}"
            ),
        )

    def reread() -> str:
        return compute_gmail_send_digest(_snapshot_draft(gmail, user_id, draft_id))

    def send() -> Any:
        return (
            gmail.users().drafts().send(userId=user_id, body={"id": draft_id}).execute()
        )

    return _run_guarded_send(
        atlasent,
        facts,
        snapshot,
        agent=agent,
        environment=environment,
        extra_context=extra_context,
        approval_artifact=approval_artifact,
        on_deny=on_deny,
        reread_digest=reread,
        perform_send=send,
    )


def _request_approval(
    atlasent: AtlaSentClient,
    snapshot: GmailSendSnapshot,
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str,
    extra_context: Mapping[str, Any] | None,
) -> GmailSendApprovalRequest:
    digest = compute_gmail_send_digest(snapshot)
    try:
        # approvals: 1 with no artifact: the same request the send makes once
        # the artifact is attached, so the runtime hands out the action_hash
        # that send will be checked against (ADR-055 two-step).
        _evaluate_send(
            atlasent,
            facts,
            agent=agent,
            environment=environment,
            extra_context=extra_context,
            digest=digest,
            approvals_claimed=1,
            approval_artifact=None,
        )
    except AtlaSentDenied as err:
        hint = err.signing_hint
        if hint is None:
            return GmailSendApprovalRequest(
                ok=False,
                decision=err.decision,
                deny_code=err.deny_code,
                reason=err.reason
                or "the runtime returned no signing hint for this request",
                message_digest=digest,
            )
        return GmailSendApprovalRequest(
            ok=True, signing_hint=hint, message_digest=digest
        )
    except Exception as err:  # noqa: BLE001 - reported, never sent
        return GmailSendApprovalRequest(
            ok=False, reason=f"evaluate failed: {err}", message_digest=digest
        )
    # The permit minted here is never verified or used; it expires.
    return GmailSendApprovalRequest(
        ok=False,
        decision="allow",
        reason=(
            "the runtime allowed this request without an approval artifact, "
            "so there is no approval to request"
        ),
        message_digest=digest,
    )


def request_gmail_send_approval(
    atlasent: AtlaSentClient,
    request: Mapping[str, Any],
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str = "production",
    extra_context: Mapping[str, Any] | None = None,
) -> GmailSendApprovalRequest:
    """Step one of the ADR-055 two-step approval for :func:`guarded_gmail_send`.

    Returns the ``action_hash`` a human approval for exactly this message must
    sign. Sends nothing. Then call :func:`guarded_gmail_send` with the same
    ``request``, ``facts``, ``agent``, ``environment`` and ``extra_context``,
    plus ``approval_artifact``.
    """
    try:
        snapshot = _snapshot_message_request(request)
    except _InvalidSendRequest as err:
        return GmailSendApprovalRequest(ok=False, reason=str(err))
    return _request_approval(
        atlasent,
        snapshot,
        facts,
        agent=agent,
        environment=environment,
        extra_context=extra_context,
    )


def request_gmail_send_draft_approval(
    gmail: Any,
    atlasent: AtlaSentClient,
    request: Mapping[str, Any],
    facts: GmailExternalSendFacts,
    *,
    agent: str,
    environment: str = "production",
    extra_context: Mapping[str, Any] | None = None,
) -> GmailSendApprovalRequest:
    """:func:`request_gmail_send_approval` for :func:`guarded_gmail_send_draft`.

    Binds the draft's current content.
    """
    try:
        user_id, draft_id = _draft_id_of(request)
        snapshot = _snapshot_draft(gmail, user_id, draft_id)
    except Exception as err:  # noqa: BLE001 - reported, never sent
        return GmailSendApprovalRequest(ok=False, reason=str(err))
    return _request_approval(
        atlasent,
        snapshot,
        facts,
        agent=agent,
        environment=environment,
        extra_context=extra_context,
    )


__all__ = [
    "COMMUNICATION_EXTERNAL_SEND",
    "GMAIL_SEND_BINDING_VERSION",
    "GmailExternalSendFacts",
    "GmailSendApprovalRequest",
    "GmailSendDenial",
    "GmailSendDeniedError",
    "GmailSendResult",
    "GmailSendSnapshot",
    "GmailSendSuccess",
    "compute_external_send_target_id",
    "compute_gmail_send_digest",
    "guarded_gmail_send",
    "guarded_gmail_send_draft",
    "request_gmail_send_approval",
    "request_gmail_send_draft_approval",
]
