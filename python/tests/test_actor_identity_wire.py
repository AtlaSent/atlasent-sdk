"""``actor_identity`` on the wire (atlasent-api#3915).

The runtime requires an ``actor_identity.v1`` at evaluate for the mandatory
change-control action types, and at verify when the action class is
classified ``verified_actor``. Both read it from the TOP LEVEL of the body.
The SDK forwards it unchanged and never mints or inspects it. These tests
assert the posted BODIES, as ``test_protect_payload_binding.py`` does.
"""

from __future__ import annotations

import warnings

import pytest

from atlasent import AsyncAtlaSentClient, AtlaSentClient

from .test_protect_payload_binding import (
    EVALUATE_PERMIT,
    VERIFY_OK,
    _mock_resp,
    _posted_bodies,
    _server_bound_hash_of,
)

IDENTITY = {
    "version": "actor_identity.v1",
    "subject": {"principal_id": "agent:a1", "principal_kind": "agent", "role": "agent"},
    "binding": {
        "action_type": "production.deploy",
        "tenant_id": "org-1",
        "environment": "production",
    },
    "signature": "ab" * 64,
}

CONTEXT = {"environment": "production", "service": "api"}


def _sync_protect(mocker, **kwargs):
    client = AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)
    post = mocker.patch.object(
        client._client,
        "post",
        side_effect=[
            _mock_resp(mocker, EVALUATE_PERMIT),
            _mock_resp(mocker, VERIFY_OK),
        ],
    )
    client.protect(
        agent="agent:a1", action="production.deploy", context=CONTEXT, **kwargs
    )
    return _posted_bodies(post)


class TestProtect:
    def test_presents_it_top_level_at_evaluate_and_verify(self, mocker) -> None:
        evaluate_body, verify_body = _sync_protect(mocker, actor_identity=IDENTITY)
        assert evaluate_body["actor_identity"] == IDENTITY
        assert verify_body["actor_identity"] == IDENTITY
        assert "actor_identity" not in evaluate_body["context"]

    def test_fallback_digest_covers_the_identity_that_was_posted(self, mocker) -> None:
        # The server hashes the whole evaluate body, identity included, so the
        # reconstruction protect() presents must include it too.
        evaluate_body, verify_body = _sync_protect(mocker, actor_identity=IDENTITY)
        assert verify_body["execution_hash"] == _server_bound_hash_of(evaluate_body)

    def test_without_one_neither_body_carries_the_field(self, mocker) -> None:
        evaluate_body, verify_body = _sync_protect(mocker)
        assert "actor_identity" not in evaluate_body
        assert "actor_identity" not in verify_body

    @pytest.mark.asyncio
    async def test_async_presents_it_at_both_boundaries(self, mocker) -> None:
        client = AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)

        async def _post(*args, **kwargs):
            return _mock_resp(mocker, _post.queue.pop(0))

        _post.queue = [EVALUATE_PERMIT, VERIFY_OK]
        post = mocker.patch.object(client._client, "post", side_effect=_post)
        await client.protect(
            agent="agent:a1",
            action="production.deploy",
            context=CONTEXT,
            actor_identity=IDENTITY,
        )
        evaluate_body, verify_body = _posted_bodies(post)
        assert evaluate_body["actor_identity"] == IDENTITY
        assert verify_body["actor_identity"] == IDENTITY
        assert verify_body["execution_hash"] == _server_bound_hash_of(evaluate_body)


class TestClientMethods:
    def test_evaluate_and_verify_forward_it(self, mocker) -> None:
        client = AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)
        post = mocker.patch.object(
            client._client,
            "post",
            side_effect=[
                _mock_resp(mocker, EVALUATE_PERMIT),
                _mock_resp(mocker, VERIFY_OK),
                _mock_resp(mocker, VERIFY_OK),
            ],
        )
        client.evaluate("production.deploy", "agent:a1", {}, actor_identity=IDENTITY)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            client.verify("pt.v4.x", actor_identity=IDENTITY)
            client.verify("pt.v4.x")
        evaluate_body, verify_body, bare_verify = _posted_bodies(post)
        assert evaluate_body["actor_identity"] == IDENTITY
        assert verify_body["actor_identity"] == IDENTITY
        assert "actor_identity" not in bare_verify
