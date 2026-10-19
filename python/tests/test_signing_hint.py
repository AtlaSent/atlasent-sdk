"""``signing_hint`` on an ``INSUFFICIENT_APPROVALS`` denial (ADR-055).

The runtime's ``action_hash`` covers the context it enriched server-side,
so a caller cannot recompute what an approver must sign. The denial
carries it as ``signing_hint``; ``AtlaSentDenied.signing_hint`` surfaces
it, shape-checked the same way as the TypeScript SDK's ``signingHint``.
"""

from __future__ import annotations

import pytest

from atlasent import (
    AsyncAtlaSentClient,
    AtlaSentClient,
    AtlaSentDenied,
    AtlaSentDeniedError,
    EvaluateSigningHint,
)

from .test_protect_payload_binding import _mock_resp

HINT = {
    "assertion_type": "approval_artifact.v1",
    "bind": {
        "action_hash": "b" * 64,
        "tenant_id": "org-1",
        "environment": "production",
        "required_role": "email_send_approver",
    },
}


def _deny(hint):
    body = {
        "decision": "deny",
        "deny_code": "INSUFFICIENT_APPROVALS",
        "deny_reason": "a verified approval is required",
        "request_id": "req-1",
    }
    if hint is not _ABSENT:
        body["signing_hint"] = hint
    return body


_ABSENT = object()


def _denial(mocker, hint) -> AtlaSentDenied:
    client = AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)
    mocker.patch.object(
        client._client, "post", return_value=_mock_resp(mocker, _deny(hint))
    )
    with pytest.raises(AtlaSentDenied) as info:
        client.evaluate(
            "communication.external.send", "agent:a1", {"environment": "production"}
        )
    return info.value


def test_surfaces_a_well_formed_hint(mocker) -> None:
    err = _denial(mocker, HINT)
    assert err.is_human_approval_required
    hint = err.signing_hint
    assert isinstance(hint, EvaluateSigningHint)
    assert hint.bind.action_hash == "b" * 64
    assert hint.bind.required_role == "email_send_approver"
    assert hint.model_dump(exclude_none=True) == HINT


def test_surfaces_a_role_list_and_keeps_fields_it_does_not_know(mocker) -> None:
    hint = {
        **HINT,
        "bind": {
            **HINT["bind"],
            "required_roles": ["email_send_approver", "compliance"],
            "future_field": "x",
        },
    }
    got = _denial(mocker, hint).signing_hint
    assert got is not None
    assert got.bind.required_roles == ["email_send_approver", "compliance"]
    # A binding field this SDK predates still reaches the signer.
    assert got.model_dump(exclude_none=True) == hint


@pytest.mark.parametrize(
    ("label", "hint"),
    [
        ("absent", _ABSENT),
        ("null", None),
        ("a string", "b" * 64),
        ("a list", [HINT]),
        ("no assertion_type", {"bind": HINT["bind"]}),
        ("no bind", {"assertion_type": "approval_artifact.v1"}),
        ("bind is a list", {**HINT, "bind": [HINT["bind"]]}),
        ("bind is a string naming a role field", {**HINT, "bind": "required_role"}),
        (
            "a short action_hash",
            {**HINT, "bind": {**HINT["bind"], "action_hash": "b" * 63}},
        ),
        (
            "an uppercase action_hash",
            {**HINT, "bind": {**HINT["bind"], "action_hash": "B" * 64}},
        ),
        (
            "no tenant_id",
            {**HINT, "bind": {"action_hash": "b" * 64, "environment": "production"}},
        ),
        ("a numeric tenant_id", {**HINT, "bind": {**HINT["bind"], "tenant_id": 1}}),
        (
            "no environment",
            {**HINT, "bind": {"action_hash": "b" * 64, "tenant_id": "org-1"}},
        ),
        (
            "a non-string required_role",
            {**HINT, "bind": {**HINT["bind"], "required_role": 7}},
        ),
        (
            "a null required_role",
            {**HINT, "bind": {**HINT["bind"], "required_role": None}},
        ),
        (
            "required_roles as a string",
            {**HINT, "bind": {**HINT["bind"], "required_roles": "email_send_approver"}},
        ),
        (
            "required_roles with a non-string entry",
            {**HINT, "bind": {**HINT["bind"], "required_roles": ["a", 1]}},
        ),
        (
            "a null required_roles",
            {**HINT, "bind": {**HINT["bind"], "required_roles": None}},
        ),
    ],
)
def test_omits_a_hint_that_is(mocker, label, hint) -> None:
    err = _denial(mocker, hint)
    assert err.deny_code == "INSUFFICIENT_APPROVALS", label
    assert err.signing_hint is None, label


@pytest.mark.asyncio
async def test_async_client_surfaces_it_too(mocker) -> None:
    client = AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)

    async def _post(*args, **kwargs):
        return _mock_resp(mocker, _deny(HINT))

    mocker.patch.object(client._client, "post", side_effect=_post)
    with pytest.raises(AtlaSentDenied) as info:
        await client.evaluate(
            "communication.external.send", "agent:a1", {"environment": "production"}
        )
    assert info.value.signing_hint is not None
    assert info.value.signing_hint.bind.action_hash == "b" * 64


def test_a_denial_without_a_body_has_no_hint() -> None:
    assert (
        AtlaSentDenied("deny", deny_code="INSUFFICIENT_APPROVALS").signing_hint is None
    )


def test_protect_denial_carries_no_hint(mocker) -> None:
    # protect() takes no approval, so there is nothing to sign the hint
    # into; its AtlaSentDeniedError deliberately does not carry one.
    client = AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)
    mocker.patch.object(
        client._client, "post", return_value=_mock_resp(mocker, _deny(HINT))
    )
    with pytest.raises(AtlaSentDeniedError) as info:
        client.protect(
            agent="agent:a1",
            action="communication.external.send",
            context={"environment": "production"},
        )
    assert info.value.deny_code == "INSUFFICIENT_APPROVALS"
    assert info.value.signing_hint is None
