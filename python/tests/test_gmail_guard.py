"""``atlasent.gmail`` against a fake runtime that enforces what the real one does.

Every test drives the real ``AtlaSentClient`` over a fake transport that
applies the runtime's rules, as ``typescript/packages/gmail/test`` does:

- the permit binds top-level ``execution_payload_hash`` when it is bare hex;
- verify compares the presented ``payload_hash`` / ``execution_hash`` with it
  and burns the permit (``consumed: true``) on success;
- a human approval verifies only if ``approval.artifact.action_hash`` equals
  the hash of {action_type, actor_id, resource_id, context, environment},
  once per nonce; with no artifact the deny carries that hash as
  ``signing_hint``.

No test touches a real Gmail account: ``gmail`` is a recording fake.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import httpx
import pytest

from atlasent import AtlaSentClient
from atlasent.cache import TTLCache
from atlasent.gmail import (
    COMMUNICATION_EXTERNAL_SEND,
    GmailExternalSendFacts,
    GmailSendDeniedError,
    GmailSendSnapshot,
    compute_external_send_target_id,
    compute_gmail_send_digest,
    guarded_gmail_send,
    guarded_gmail_send_draft,
    request_gmail_send_approval,
    request_gmail_send_draft_approval,
)

# ── parity with @atlasent/gmail ─────────────────────────────────────────────

# Produced by @atlasent/gmail's computeGmailSendDigest / computeExternalSendTargetId
# (typescript/packages/gmail, built from main at c74082b). The TypeScript suite
# pins the same values, so a change to either serialization fails one of them.
DIGEST_VECTORS = [
    (
        GmailSendSnapshot(
            "message",
            "me",
            "VG86IGJvYXJkQGV4YW1wbGUuY29tDQpTdWJqZWN0OiBRMw0KDQpEcmFmdA",
            None,
            None,
        ),
        "e0348537ec616f8d51a59ef95fc10c563ce576cd3507abd3c1a0d48aed101660",
    ),
    (
        GmailSendSnapshot(
            "message",
            "founder@example.com",
            "VG86IGNmb0BleGFtcGxlLmNvbQ0KDQpoaQ",
            "18c2f0a1b2c3d4e5",
            None,
        ),
        "5ee70358999964889bb3efe9e533b87c8809e71fad72430b178540535f9bf2a3",
    ),
    (
        GmailSendSnapshot(
            "draft",
            "me",
            "VG86IGJvYXJkQGV4YW1wbGUuY29tDQoNCkRyYWZ0IG9ubHk",
            None,
            "r-4815162342",
        ),
        "9a443373dc4ff153cf2a6b783d7078a6751b4e26a6d83dd599fbf49d87153696",
    ),
    (
        GmailSendSnapshot("message", "josé@exämple.com", "eA", None, None),
        "3a6d95f5779e323e04d0fe7873f16688556d40a496f6bcdb95aa7a8528519d7e",
    ),
]
TARGET_VECTORS = [
    (
        GmailExternalSendFacts("board@example.com", False, True, "3b" * 32),
        "c20d7c236a4dfac7def7ba35e08e98a365991dc1faf5a4b2bf2227abb3fc9553",
    ),
    (
        GmailExternalSendFacts("cfo@example.com", True, False),
        "521c91f2b7887268fe8bee8d4de123ddebc2c4632e67e121a24e4a1862fb4f48",
    ),
]


@pytest.mark.parametrize(("snapshot", "expected"), DIGEST_VECTORS)
def test_message_digest_equals_the_typescript_sdk(snapshot, expected) -> None:
    assert compute_gmail_send_digest(snapshot) == expected


@pytest.mark.parametrize(("facts", "expected"), TARGET_VECTORS)
def test_target_id_equals_the_typescript_sdk(facts, expected) -> None:
    assert compute_external_send_target_id(facts) == expected


# ── fake runtime ────────────────────────────────────────────────────────────


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class FakeRuntime:
    def __init__(
        self,
        *,
        require_artifact: bool = True,
        consumed: bool | None = True,
        evaluate_raises: bool = False,
        verify_raises: bool = False,
        force_decision: str | None = None,
        hint: bool = True,
        after_evaluate=None,
        after_verify=None,
    ) -> None:
        self.require_artifact = require_artifact
        self.consumed = consumed
        self.evaluate_raises = evaluate_raises
        self.verify_raises = verify_raises
        self.force_decision = force_decision
        self.hint = hint
        self.after_evaluate = after_evaluate
        self.after_verify = after_verify
        self.evaluate_bodies: list[dict[str, Any]] = []
        self.verify_bodies: list[dict[str, Any]] = []
        self.permits: dict[str, dict[str, Any]] = {}
        self.used_nonces: set[str] = set()
        self.seq = 0

    @staticmethod
    def action_hash(body: dict[str, Any]) -> str:
        return _sha256(
            _canonical(
                {
                    "action_type": body.get("action_type"),
                    "actor_id": body.get("actor_id"),
                    "resource_id": body.get("resource_id") or "",
                    "context": body.get("context") or {},
                    "environment": body.get("environment"),
                }
            )
        )

    def evaluate(self, body: dict[str, Any]) -> dict[str, Any]:
        self.evaluate_bodies.append(body)
        if self.evaluate_raises:
            raise httpx.ConnectError("connection refused")
        self.seq += 1
        if self.force_decision:
            return {
                "decision": self.force_decision,
                "deny_reason": "forced",
                "request_id": f"req-{self.seq}",
            }
        expected = self.action_hash(body)
        artifact = (body.get("approval") or {}).get("artifact")
        approved = False
        if artifact is not None:
            if artifact.get("action_hash") != expected:
                return {
                    "decision": "deny",
                    "deny_code": "APPROVAL_INVALID",
                    "deny_reason": "approval does not match this action",
                }
            if artifact["nonce"] in self.used_nonces:
                return {
                    "decision": "deny",
                    "deny_code": "APPROVAL_REPLAYED",
                    "deny_reason": "approval already used",
                }
            self.used_nonces.add(artifact["nonce"])
            approved = True
        approvals = body["context"]["approvals"]
        allowed = approvals >= 1 if not self.require_artifact else approved
        if not allowed:
            reply: dict[str, Any] = {
                "decision": "deny",
                "deny_code": "INSUFFICIENT_APPROVALS",
                "deny_reason": "a human approval is required",
                "request_id": f"req-{self.seq}",
            }
            if artifact is None and self.hint:
                reply["signing_hint"] = {
                    "assertion_type": "approval_artifact.v1",
                    "bind": {
                        "action_hash": expected,
                        "tenant_id": "org-1",
                        "environment": body.get("environment"),
                    },
                }
            return reply
        ep = body.get("execution_payload_hash")
        bound = (
            ep.lower()
            if isinstance(ep, str) and re.fullmatch(r"[0-9a-fA-F]{64}", ep)
            else "sha256:" + _sha256(_canonical(body))
        )
        token = f"pt.v3.fake-{self.seq}"
        self.permits[token] = {"bound": bound, "consumed": False}
        return {
            "decision": "allow",
            "permit_token": token,
            "request_id": f"req-{self.seq}",
            "audit_hash": f"audit-{self.seq}",
        }

    def verify(self, body: dict[str, Any]) -> dict[str, Any]:
        self.verify_bodies.append(body)
        if self.verify_raises:
            raise httpx.ReadError("socket hang up")
        permit = self.permits.get(body.get("permit_token"))
        if permit is None:
            return {
                "valid": False,
                "outcome": "deny",
                "verify_error_code": "PERMIT_NOT_FOUND",
            }
        if permit["consumed"]:
            return {
                "valid": False,
                "outcome": "deny",
                "verify_error_code": "PERMIT_ALREADY_USED",
                "consumed": False,
            }
        presented = body.get("payload_hash") or body.get("execution_hash")
        if presented != permit["bound"]:
            return {
                "valid": False,
                "outcome": "deny",
                "verify_error_code": "PAYLOAD_MISMATCH",
                "consumed": False,
            }
        permit["consumed"] = True
        reply: dict[str, Any] = {"valid": True, "outcome": "allow"}
        if self.consumed is not None:
            reply["consumed"] = self.consumed
        return reply

    def post(self, url: str, json: Any = None, headers: Any = None, params: Any = None):
        body = json if isinstance(json, dict) else {}
        if url.endswith("/v1-evaluate"):
            reply = self.evaluate(body)
            if self.after_evaluate:
                self.after_evaluate()
        elif url.endswith("/v1-verify-permit"):
            reply = self.verify(body)
            if self.after_verify:
                self.after_verify()
        else:  # pragma: no cover - a failing test names the stray request
            raise AssertionError(f"unexpected request {url}")
        return httpx.Response(200, json=reply, request=httpx.Request("POST", url))


def _client(runtime: FakeRuntime, mocker, **kwargs) -> AtlaSentClient:
    client = AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0, **kwargs)
    mocker.patch.object(client._client, "post", side_effect=runtime.post)
    return client


# ── fake Gmail ──────────────────────────────────────────────────────────────


class _Call:
    def __init__(self, fn, kwargs) -> None:
        self._fn, self._kwargs = fn, kwargs

    def execute(self):
        return self._fn(**self._kwargs)


class FakeGmail:
    """The part of a googleapiclient Gmail service the guard uses; records calls."""

    def __init__(self, drafts: dict[str, dict[str, Any]] | None = None) -> None:
        self.store = drafts or {}
        self.sent: list[dict[str, Any]] = []
        self.draft_sends: list[dict[str, Any]] = []
        self.draft_reads: list[str] = []
        self.fail_draft_read_after: int | None = None

    def users(self):
        return self

    def messages(self):
        return _Messages(self)

    def drafts(self):
        return _Drafts(self)


class _Messages:
    def __init__(self, gmail: FakeGmail) -> None:
        self.gmail = gmail

    def send(self, **kwargs):
        def run(userId, body):  # noqa: N803 - googleapiclient's keyword
            self.gmail.sent.append(
                {"userId": userId, "body": json.loads(json.dumps(body))}
            )
            return {"id": "m-1", "threadId": body.get("threadId", "t-new")}

        return _Call(run, kwargs)


class _Drafts:
    def __init__(self, gmail: FakeGmail) -> None:
        self.gmail = gmail

    def get(self, **kwargs):
        def run(userId, id, format):  # noqa: N803 - googleapiclient's keyword
            assert format == "raw"
            self.gmail.draft_reads.append(id)
            limit = self.gmail.fail_draft_read_after
            if limit is not None and len(self.gmail.draft_reads) > limit:
                raise RuntimeError("draft read failed")
            if id not in self.gmail.store:
                raise RuntimeError(f"draft {id} not found")
            return {"id": id, "message": dict(self.gmail.store[id])}

        return _Call(run, kwargs)

    def send(self, **kwargs):
        def run(userId, body):  # noqa: N803 - googleapiclient's keyword
            self.gmail.draft_sends.append({"userId": userId, "body": dict(body)})
            return {"id": "m-d", "threadId": "t-d"}

        return _Call(run, kwargs)


# ── fixtures ────────────────────────────────────────────────────────────────

AGENT = "agent:outreach-assistant"
RAW = "VG86IGJvYXJkQGV4YW1wbGUuY29tDQpTdWJqZWN0OiBRMw0KDQpEcmFmdA"
REQUEST = {"userId": "me", "body": {"raw": RAW}}
FACTS = GmailExternalSendFacts(
    recipient="board@example.com", recipient_known=False, sensitive_attachment=False
)


def _artifact(hint, nonce: str = "nonce-0001") -> dict[str, Any]:
    """What an approval desk produces once a person has reviewed the message."""
    return {
        "version": "approval_artifact.v1",
        "approval_id": f"apr-{nonce}",
        "tenant_id": hint.bind.tenant_id,
        "action_type": COMMUNICATION_EXTERNAL_SEND,
        "resource_id": "message",
        "action_hash": hint.bind.action_hash,
        "reviewer": {
            "principal_id": "11111111-1111-4111-8111-111111111111",
            "principal_kind": "human",
        },
        "issuer": {
            "type": "approval_service",
            "issuer_id": "atlasent-console",
            "kid": "kid-1",
        },
        "issued_at": "2026-10-19T00:00:00Z",
        "expires_at": "2026-10-19T00:05:00Z",
        "nonce": nonce,
        "signature": "deadbeef",
    }


def _approved_send(runtime, mocker, request=REQUEST, gmail=None, **kwargs):
    client = _client(runtime, mocker)
    gmail = gmail or FakeGmail()
    approval = request_gmail_send_approval(client, request, FACTS, agent=AGENT)
    assert approval.ok, approval.reason
    result = guarded_gmail_send(
        gmail,
        client,
        request,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
        **kwargs,
    )
    return result, gmail, approval


# ── message sends ───────────────────────────────────────────────────────────


def test_an_approved_send_reaches_gmail_once_with_the_bound_bytes(mocker) -> None:
    runtime = FakeRuntime()
    result, gmail, approval = _approved_send(runtime, mocker)
    digest = compute_gmail_send_digest(
        GmailSendSnapshot("message", "me", RAW, None, None)
    )
    assert result.sent is True
    assert result.message_digest == digest == approval.message_digest
    assert result.permit_id.startswith("pt.v3.fake-") and result.audit_hash.startswith(
        "audit-"
    )
    assert gmail.sent == [{"userId": "me", "body": {"raw": RAW}}]
    send_body = runtime.evaluate_bodies[-1]
    assert (
        send_body["resource_id"] == digest
        and send_body["execution_payload_hash"] == digest
    )
    assert (
        send_body["action_type"] == COMMUNICATION_EXTERNAL_SEND
        and send_body["environment"] == "production"
    )
    assert runtime.verify_bodies[-1]["execution_hash"] == digest


def test_the_approval_request_and_the_send_present_the_same_action(mocker) -> None:
    runtime = FakeRuntime()
    _approved_send(runtime, mocker)
    harvest, submit = runtime.evaluate_bodies
    assert "approval" not in harvest and "approval" in submit
    assert {k: v for k, v in submit.items() if k != "approval"} == harvest
    assert harvest["context"]["approvals"] == 1


def test_without_an_approval_nothing_is_sent_and_none_is_claimed(mocker) -> None:
    runtime = FakeRuntime()
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail, _client(runtime, mocker), REQUEST, FACTS, agent=AGENT
    )
    assert (
        result.sent is False
        and result.decision == "deny"
        and result.deny_code == "INSUFFICIENT_APPROVALS"
    )
    assert result.evaluation_id == "req-1" and result.message_digest
    assert runtime.evaluate_bodies[0]["context"]["approvals"] == 0
    assert gmail.sent == [] and runtime.verify_bodies == []


def test_a_class_that_accepts_a_count_still_gets_no_claim_from_the_guard(
    mocker,
) -> None:
    runtime = FakeRuntime(require_artifact=False)
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail, _client(runtime, mocker), REQUEST, FACTS, agent=AGENT
    )
    assert result.sent is False and gmail.sent == []


def test_an_approval_for_one_message_cannot_send_another(mocker) -> None:
    runtime = FakeRuntime()
    client = _client(runtime, mocker)
    gmail = FakeGmail()
    approval = request_gmail_send_approval(client, REQUEST, FACTS, agent=AGENT)
    other = {"userId": "me", "body": {"raw": "VG86IGV2ZXJ5b25lQGV4YW1wbGUuY29t"}}
    result = guarded_gmail_send(
        gmail,
        client,
        other,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert (
        result.sent is False
        and result.deny_code == "APPROVAL_INVALID"
        and gmail.sent == []
    )


def test_an_approval_sends_once(mocker) -> None:
    runtime = FakeRuntime()
    result, gmail, approval = _approved_send(runtime, mocker)
    assert result.sent is True
    client = _client(runtime, mocker)
    again = guarded_gmail_send(
        gmail,
        client,
        REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert (
        again.sent is False
        and again.deny_code == "APPROVAL_REPLAYED"
        and len(gmail.sent) == 1
    )


def test_changing_the_callers_request_after_authorization_changes_nothing_sent(
    mocker,
) -> None:
    request = {"userId": "me", "body": {"raw": RAW, "threadId": "t-1"}}

    def tamper() -> None:
        request["body"]["raw"] = "VG86IGV2ZXJ5b25lQGV4YW1wbGUuY29t"
        request["userId"] = "someone-else"

    runtime = FakeRuntime()
    client = _client(runtime, mocker)
    approval = request_gmail_send_approval(client, request, FACTS, agent=AGENT)
    runtime.after_verify = tamper
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail,
        client,
        request,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert result.sent is True
    assert gmail.sent == [{"userId": "me", "body": {"raw": RAW, "threadId": "t-1"}}]


def test_only_userid_raw_and_threadid_are_sent(mocker) -> None:
    request = {
        "userId": "me",
        "body": {"raw": RAW, "threadId": "t-1", "labelIds": ["SENT"], "id": "x"},
    }
    result, gmail, _ = _approved_send(FakeRuntime(), mocker, request=request)
    assert result.sent is True and gmail.sent == [
        {"userId": "me", "body": {"raw": RAW, "threadId": "t-1"}}
    ]


@pytest.mark.parametrize(
    ("request_", "reason"),
    [
        ({"body": {"raw": RAW}}, "userId"),
        ({"userId": "", "body": {"raw": RAW}}, "userId"),
        ({"userId": "me"}, "raw"),
        ({"userId": "me", "body": {"raw": ""}}, "raw"),
        ({"userId": "me", "body": "raw"}, "mapping"),
        ({"userId": "me", "body": {"raw": RAW}, "media_body": object()}, "media"),
        ({"userId": "me", "body": {}, "media_mime_type": "message/rfc822"}, "media"),
    ],
)
def test_a_request_it_cannot_bind_is_refused_before_evaluate(
    mocker, request_, reason
) -> None:
    runtime = FakeRuntime()
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail, _client(runtime, mocker), request_, FACTS, agent=AGENT
    )
    assert (
        result.sent is False
        and result.decision == "invalid_request"
        and reason in result.reason
    )
    assert runtime.evaluate_bodies == [] and gmail.sent == []
    assert (
        request_gmail_send_approval(
            _client(runtime, mocker), request_, FACTS, agent=AGENT
        ).ok
        is False
    )


@pytest.mark.parametrize(("consumed", "label"), [(False, "false"), (None, "absent")])
def test_a_permit_that_was_not_consumed_sends_nothing(mocker, consumed, label) -> None:
    result, gmail, _ = _approved_send(FakeRuntime(consumed=consumed), mocker)
    assert result.sent is False and result.decision == "verify_failed", label
    assert "consumed" in result.reason and gmail.sent == []


def test_a_permit_that_does_not_verify_sends_nothing(mocker) -> None:
    runtime = FakeRuntime()
    client = _client(runtime, mocker)
    approval = request_gmail_send_approval(client, REQUEST, FACTS, agent=AGENT)
    real_verify = runtime.verify

    def mismatch(body):
        body = dict(body, execution_hash="0" * 64)
        return real_verify(body)

    runtime.verify = mismatch  # type: ignore[method-assign]
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail,
        client,
        REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert (
        result.sent is False
        and result.decision == "verify_failed"
        and "outcome=deny" in result.reason
    )
    assert result.evaluation_id and result.audit_hash and gmail.sent == []


def test_evaluate_and_verify_failures_send_nothing(mocker) -> None:
    gmail = FakeGmail()
    failed = guarded_gmail_send(
        gmail,
        _client(FakeRuntime(evaluate_raises=True), mocker),
        REQUEST,
        FACTS,
        agent=AGENT,
    )
    assert failed.decision == "error" and failed.reason.startswith("evaluate failed")
    runtime = FakeRuntime()
    client = _client(runtime, mocker)
    approval = request_gmail_send_approval(client, REQUEST, FACTS, agent=AGENT)
    runtime.verify_raises = True
    gmail2 = FakeGmail()
    result = guarded_gmail_send(
        gmail2,
        client,
        REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert result.decision == "error" and result.reason.startswith("verify failed")
    assert gmail.sent == [] and gmail2.sent == []


def test_a_hold_sends_nothing(mocker) -> None:
    gmail = FakeGmail()
    result = guarded_gmail_send(
        gmail,
        _client(FakeRuntime(force_decision="hold"), mocker),
        REQUEST,
        FACTS,
        agent=AGENT,
    )
    assert result.sent is False and result.decision == "hold" and gmail.sent == []


def test_on_deny_throw_raises_with_the_denial(mocker) -> None:
    gmail = FakeGmail()
    with pytest.raises(GmailSendDeniedError) as info:
        guarded_gmail_send(
            gmail,
            _client(FakeRuntime(), mocker),
            REQUEST,
            FACTS,
            agent=AGENT,
            on_deny="throw",
        )
    assert info.value.denial.deny_code == "INSUFFICIENT_APPROVALS" and gmail.sent == []
    with pytest.raises(GmailSendDeniedError):
        guarded_gmail_send(
            gmail,
            _client(FakeRuntime(), mocker),
            {"userId": "me"},
            FACTS,
            agent=AGENT,
            on_deny="throw",
        )


def test_a_client_with_an_evaluate_cache_is_refused(mocker) -> None:
    runtime = FakeRuntime()
    gmail = FakeGmail()
    client = _client(runtime, mocker, cache=TTLCache(ttl=60))
    result = guarded_gmail_send(gmail, client, REQUEST, FACTS, agent=AGENT)
    assert result.decision == "invalid_request" and "cache" in result.reason
    assert runtime.evaluate_bodies == [] and gmail.sent == []


def test_the_context_carries_the_facts_and_the_guard_fields_win(mocker) -> None:
    runtime = FakeRuntime()
    facts = GmailExternalSendFacts(
        "cfo@example.com", True, True, "ab" * 32, actor_origin="ai_agent"
    )
    extra = {"approvals": 99, "target": "spoofed", "campaign": "q3"}
    guarded_gmail_send(
        FakeGmail(),
        _client(runtime, mocker),
        REQUEST,
        facts,
        agent=AGENT,
        extra_context=extra,
        environment="staging",
    )
    body = runtime.evaluate_bodies[0]
    assert body["environment"] == "staging"
    assert body["context"] == {
        "campaign": "q3",
        "recipient_known": True,
        "sensitive_attachment": True,
        "approvals": 0,
        "target": {"id": compute_external_send_target_id(facts)},
        "recipient_domain": "example.com",
        "actor_origin": "ai_agent",
    }
    explicit = GmailExternalSendFacts(
        "a,b", False, False, recipient_domain="corp.example"
    )
    guarded_gmail_send(
        FakeGmail(), _client(runtime, mocker), REQUEST, explicit, agent=AGENT
    )
    assert runtime.evaluate_bodies[-1]["context"]["recipient_domain"] == "corp.example"
    no_domain = GmailExternalSendFacts("internal-list", False, False)
    guarded_gmail_send(
        FakeGmail(), _client(runtime, mocker), REQUEST, no_domain, agent=AGENT
    )
    assert "recipient_domain" not in runtime.evaluate_bodies[-1]["context"]


# ── approval requests ───────────────────────────────────────────────────────


def test_an_approval_request_when_the_runtime_needs_none(mocker) -> None:
    runtime = FakeRuntime(require_artifact=False)
    approval = request_gmail_send_approval(
        _client(runtime, mocker), REQUEST, FACTS, agent=AGENT
    )
    assert (
        approval.ok is False
        and approval.decision == "allow"
        and approval.message_digest
    )
    assert runtime.verify_bodies == []


def test_an_approval_request_without_a_hint_reports_why(mocker) -> None:
    approval = request_gmail_send_approval(
        _client(FakeRuntime(hint=False), mocker), REQUEST, FACTS, agent=AGENT
    )
    assert (
        approval.ok is False
        and approval.deny_code == "INSUFFICIENT_APPROVALS"
        and approval.signing_hint is None
    )


def test_an_approval_request_that_fails_reports_why(mocker) -> None:
    approval = request_gmail_send_approval(
        _client(FakeRuntime(evaluate_raises=True), mocker), REQUEST, FACTS, agent=AGENT
    )
    assert approval.ok is False and approval.reason.startswith("evaluate failed")


# ── drafts ──────────────────────────────────────────────────────────────────

DRAFT_RAW = "VG86IGJvYXJkQGV4YW1wbGUuY29tDQoNCkRyYWZ0IG9ubHk"
DRAFT_REQUEST = {"userId": "me", "body": {"id": "r-1"}}


def _draft_gmail() -> FakeGmail:
    return FakeGmail(drafts={"r-1": {"raw": DRAFT_RAW, "threadId": "t-9"}})


def _approved_draft(runtime, mocker, gmail):
    client = _client(runtime, mocker)
    approval = request_gmail_send_draft_approval(
        gmail, client, DRAFT_REQUEST, FACTS, agent=AGENT
    )
    assert approval.ok, approval.reason
    return client, approval


def test_an_approved_draft_is_sent_by_id_after_reading_it_twice(mocker) -> None:
    runtime = FakeRuntime()
    gmail = _draft_gmail()
    client, approval = _approved_draft(runtime, mocker, gmail)
    result = guarded_gmail_send_draft(
        gmail,
        client,
        DRAFT_REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert result.sent is True
    assert result.message_digest == compute_gmail_send_digest(
        GmailSendSnapshot("draft", "me", DRAFT_RAW, "t-9", "r-1")
    )
    assert gmail.draft_sends == [{"userId": "me", "body": {"id": "r-1"}}]
    assert gmail.draft_reads == [
        "r-1",
        "r-1",
        "r-1",
    ]  # approval, authorize, just before send
    assert gmail.sent == []


def test_a_draft_edited_after_authorization_is_not_sent(mocker) -> None:
    runtime = FakeRuntime()
    gmail = _draft_gmail()
    client, approval = _approved_draft(runtime, mocker, gmail)
    runtime.after_verify = lambda: gmail.store["r-1"].update(
        raw="VG86IGV2ZXJ5b25lQGV4YW1wbGUuY29t"
    )
    result = guarded_gmail_send_draft(
        gmail,
        client,
        DRAFT_REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert (
        result.sent is False
        and result.decision == "content_changed"
        and gmail.draft_sends == []
    )


def test_a_draft_that_cannot_be_reread_is_not_sent(mocker) -> None:
    runtime = FakeRuntime()
    gmail = _draft_gmail()
    client, approval = _approved_draft(runtime, mocker, gmail)
    gmail.fail_draft_read_after = 2
    result = guarded_gmail_send_draft(
        gmail,
        client,
        DRAFT_REQUEST,
        FACTS,
        agent=AGENT,
        approval_artifact=_artifact(approval.signing_hint),
    )
    assert (
        result.sent is False
        and result.decision == "error"
        and "re-read" in result.reason
        and gmail.draft_sends == []
    )


@pytest.mark.parametrize(
    ("request_", "decision", "reason"),
    [
        (
            {"userId": "me", "body": {"id": "r-1", "message": {"raw": "eA"}}},
            "invalid_request",
            "replacement",
        ),
        (
            {"userId": "me", "body": {"id": "r-1"}, "media_body": object()},
            "invalid_request",
            "media",
        ),
        ({"userId": "me", "body": {}}, "invalid_request", "draft id"),
        ({"body": {"id": "r-1"}}, "invalid_request", "userId"),
        (
            {"userId": "me", "body": {"id": "missing"}},
            "error",
            "could not read the draft",
        ),
        (
            {"userId": "me", "body": {"id": "empty"}},
            "invalid_request",
            "no raw content",
        ),
    ],
)
def test_a_draft_it_cannot_bind_is_refused(mocker, request_, decision, reason) -> None:
    runtime = FakeRuntime()
    gmail = FakeGmail(drafts={"r-1": {"raw": DRAFT_RAW}, "empty": {"raw": ""}})
    result = guarded_gmail_send_draft(
        gmail, _client(runtime, mocker), request_, FACTS, agent=AGENT
    )
    assert (
        result.sent is False and result.decision == decision and reason in result.reason
    )
    assert runtime.evaluate_bodies == [] and gmail.draft_sends == []
    assert (
        request_gmail_send_draft_approval(
            gmail, _client(runtime, mocker), request_, FACTS, agent=AGENT
        ).ok
        is False
    )


def test_a_draft_without_an_approval_is_not_sent(mocker) -> None:
    gmail = _draft_gmail()
    result = guarded_gmail_send_draft(
        gmail, _client(FakeRuntime(), mocker), DRAFT_REQUEST, FACTS, agent=AGENT
    )
    assert (
        result.sent is False
        and result.deny_code == "INSUFFICIENT_APPROVALS"
        and gmail.draft_sends == []
    )
