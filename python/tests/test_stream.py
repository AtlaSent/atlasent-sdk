"""Tests for AsyncAtlaSentClient.protect_stream (SSE streaming evaluate).

`protect_stream()` talks to the real V2-D4 `/v1-evaluate-stream` contract
(`atlasent-api` `supabase/functions/v1-evaluate-stream/handler.ts`):

    request:  {batch_id?, items: [{action_type, actor_id, context, ...}]}
    response: SSE frames — `event: decision` (one per item, carrying the
              same canonical shape as a /v1-evaluate response, prefixed
              with `index`), `event: error` (per-item RPC failure,
              `{index, error_code, message}`), terminating in
              `event: complete` (`{batch_id, count, partial}`).

Every test below either asserts the *outgoing* request body matches this
contract (`TestProtectStreamRequestShape`) or drives the mocked transport
with response frames shaped exactly like the real handler emits them
(`TestProtectStream`) — not a stream-specific shape this SDK invented on
its own. See atlasent-sdk#498 for the bug this replaced: the previous
payload was a flat `{action, agent, context, api_key}` body the real
handler's `!Array.isArray(body.items)` check rejects outright, and the
previous tests could not have caught it because they only exercised the
response-parsing side against a self-consistent (but wrong) fixture.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from atlasent import AsyncAtlaSentClient, StreamDecisionEvent, StreamProgressEvent

API_KEY = "ask_test_stream"
BASE_URL = "https://api.atlasent.io/functions/v1"


# ── SSE helpers — shaped like the REAL /v1-evaluate-stream wire frames ───────
#
# A `decision` frame is `{index, ...<v1-evaluate response>}`: the same
# canonical {decision, permit_token, reason, audit_hash, timestamp} shape
# `evaluate()` parses, never a stream-specific {permitted, decision_id,
# is_final} shape. There is no `is_final` field on the wire at all — the
# stream's true terminal signal is the `complete` frame below.


def _decision_wire(
    *,
    index: int = 0,
    decision: str = "allow",
    permit_token: str = "pt.v4.stream-token",
    reason: str = "ok",
    audit_hash: str = "h1",
    timestamp: str = "2026-04-30T00:00:00Z",
) -> str:
    data = json.dumps(
        dict(
            index=index,
            decision=decision,
            permit_token=permit_token,
            reason=reason,
            audit_hash=audit_hash,
            timestamp=timestamp,
        )
    )
    return f"event: decision\ndata: {data}\n"


def _error_wire(
    *, index: int = 0, error_code: str = "item_failed", message: str = "boom"
) -> str:
    data = json.dumps(dict(index=index, error_code=error_code, message=message))
    return f"event: error\ndata: {data}\n"


def _complete_wire(
    *, batch_id: str = "b1", count: int = 1, partial: bool = False
) -> str:
    data = json.dumps(dict(batch_id=batch_id, count=count, partial=partial))
    return f"event: complete\ndata: {data}\n"


def _progress(stage: str = "policy_loading") -> str:
    return f"event: progress\ndata: {json.dumps({'stage': stage})}\n"


# ── Legacy/generic shapes — kept to prove the SDK still tolerates them ──────


def _decision_legacy(
    *,
    permitted: bool = True,
    decision_id: str = "dec_s1",
    reason: str = "ok",
    audit_hash: str = "h1",
    timestamp: str = "2026-04-30T00:00:00Z",
    is_final: bool = True,
) -> str:
    data = json.dumps(
        dict(
            permitted=permitted,
            decision_id=decision_id,
            reason=reason,
            audit_hash=audit_hash,
            timestamp=timestamp,
            is_final=is_final,
        )
    )
    return f"event: decision\ndata: {data}\n"


def _done() -> str:
    return "event: done\ndata: {}\n"


def _error_legacy(code: str = "server_error", message: str = "oops") -> str:
    return f"event: error\ndata: {json.dumps({'code': code, 'message': message})}\n"


async def _lines_from(*blocks: str):
    """Async generator that yields each line from the blocks, inserting a blank
    line (event separator) between blocks as the SSE spec requires."""
    for block in blocks:
        for line in block.splitlines():
            yield line
        yield ""  # event separator blank line


def _make_mock_response(lines_gen, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.aiter_lines = MagicMock(return_value=lines_gen)
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=None)
    return response


def _patched_client() -> AsyncAtlaSentClient:
    return AsyncAtlaSentClient(api_key=API_KEY, base_url=BASE_URL)


# ── collect helper ────────────────────────────────────────────────────────────


async def collect(client: AsyncAtlaSentClient, **kwargs: Any) -> list[Any]:
    events = []
    async for event in client.protect_stream(**kwargs):
        events.append(event)
    return events


# ── request-shape tests (the actual regression coverage for #498) ──────────


class TestProtectStreamRequestShape:
    """Asserts the *outgoing* request body, not just that some request was
    sent and some mocked response handled — this is exactly the gap
    atlasent-sdk#498 identified: the old test suite would have passed even
    though the real payload was structurally rejected by the handler's
    `!Array.isArray(body.items)` check.
    """

    async def test_request_body_matches_v2_d4_items_contract(self) -> None:
        lines = _lines_from(_decision_wire(), _complete_wire())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        await collect(
            client,
            agent="deploy-bot",
            action="production.deploy",
            context={"commit": "abc123"},
        )

        assert client._client.stream.call_count == 1
        call = client._client.stream.call_args
        method, url = call.args
        assert method == "POST"
        assert url == f"{BASE_URL}/v1-evaluate-stream"

        sent_body = json.loads(call.kwargs["content"])

        # The bug: this used to be a flat {action, agent, context, api_key}
        # body. The real handler requires `items` to be an array at all —
        # asserting the exact contract, not merely "a body was sent".
        assert set(sent_body.keys()) == {"items"}
        assert isinstance(sent_body["items"], list)
        assert len(sent_body["items"]) == 1

        item = sent_body["items"][0]
        assert item == {
            "action_type": "production.deploy",
            "actor_id": "deploy-bot",
            "context": {"commit": "abc123"},
        }
        # Field names the old buggy payload used instead — must be absent.
        assert "action" not in sent_body
        assert "agent" not in sent_body
        assert "api_key" not in sent_body
        assert "context" not in sent_body  # context belongs inside the item

    async def test_request_body_defaults_context_to_empty_dict(self) -> None:
        lines = _lines_from(_decision_wire(), _complete_wire())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        await collect(client, agent="bot", action="read")

        sent_body = json.loads(client._client.stream.call_args.kwargs["content"])
        assert sent_body["items"][0]["context"] == {}

    async def test_request_uses_bearer_auth_header_not_body_api_key(self) -> None:
        lines = _lines_from(_decision_wire(), _complete_wire())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        await collect(client, agent="bot", action="read")

        headers = client._client.stream.call_args.kwargs["headers"]
        assert headers["Authorization"] == f"Bearer {API_KEY}"
        sent_body = json.loads(client._client.stream.call_args.kwargs["content"])
        assert "api_key" not in sent_body


# ── response-parsing tests, against the REAL wire response shape ───────────


class TestProtectStream:
    async def test_yields_decision_then_completes_on_complete_frame(self) -> None:
        lines = _lines_from(
            _decision_wire(permit_token="pt.v4.final"), _complete_wire()
        )
        response = _make_mock_response(lines)

        with patch.object(
            _patched_client()._client, "stream", return_value=response
        ) as mock_stream:
            client = _patched_client()
            mock_stream.return_value = response
            client._client.stream = MagicMock(return_value=response)
            events = await collect(client, agent="bot", action="read")

        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, StreamDecisionEvent)
        assert ev.decision == "allow"
        # permit_id resolves from the canonical `permit_token` field.
        assert ev.permit_id == "pt.v4.final"

    async def test_yields_deny_decision(self) -> None:
        lines = _lines_from(
            _decision_wire(decision="deny", permit_token=""), _complete_wire()
        )
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="delete")

        assert len(events) == 1
        assert isinstance(events[0], StreamDecisionEvent)
        assert events[0].decision == "deny"

    async def test_yields_progress_then_decision(self) -> None:
        lines = _lines_from(
            _progress("context_enrichment"),
            _decision_wire(),
            _complete_wire(),
        )
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="write")

        assert len(events) == 2
        assert isinstance(events[0], StreamProgressEvent)
        assert events[0].stage == "context_enrichment"
        assert isinstance(events[1], StreamDecisionEvent)

    async def test_raises_on_error_event_using_error_code_field(self) -> None:
        from atlasent.exceptions import AtlaSentError

        # Real wire shape uses `error_code`, not `code`.
        lines = _lines_from(
            _error_wire(error_code="item_failed", message="upstream timeout")
        )
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        with pytest.raises(AtlaSentError, match="upstream timeout") as exc_info:
            await collect(client, agent="bot", action="read")
        assert exc_info.value.code == "item_failed"

    async def test_raises_on_non_200_status(self) -> None:
        from atlasent.exceptions import AtlaSentError

        response = MagicMock()
        response.status_code = 403
        response.aread = AsyncMock(return_value=b'{"error":"forbidden"}')
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=None)

        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        with pytest.raises(AtlaSentError):
            await collect(client, agent="bot", action="read")

    async def test_skips_unknown_event_types(self) -> None:
        unknown = 'event: future_hint\ndata: {"x": 1}\n'
        lines = _lines_from(unknown, _decision_wire(), _complete_wire())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="read")

        assert len(events) == 1
        assert isinstance(events[0], StreamDecisionEvent)

    async def test_stops_at_complete_before_further_events(self) -> None:
        # A decision frame arriving after `complete` is ignored — `complete`
        # is the real terminal frame, same as `done` was for the legacy shape.
        lines = _lines_from(_complete_wire(), _decision_wire())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="read")

        assert events == []


# ── legacy/generic-shape backward compatibility ─────────────────────────────
#
# The parser also tolerates the older {permitted, decision_id, is_final}
# decision shape and the generic `event: done` terminal marker, in case any
# caller's mocked transport or an older server build still emits them.


class TestProtectStreamLegacyShapeCompat:
    async def test_yields_final_decision_event_legacy_shape(self) -> None:
        lines = _lines_from(_decision_legacy(decision_id="dec_final"), _done())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="read")

        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, StreamDecisionEvent)
        assert ev.decision == "allow"
        assert ev.permit_id == "dec_final"
        assert ev.is_final is True

    async def test_yields_interim_then_final_decision_legacy_shape(self) -> None:
        lines = _lines_from(
            _decision_legacy(decision_id="dec_interim", is_final=False),
            _decision_legacy(decision_id="dec_final", is_final=True),
            _done(),
        )
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="read")

        assert len(events) == 2
        assert events[0].is_final is False  # type: ignore[union-attr]
        assert events[1].is_final is True  # type: ignore[union-attr]

    async def test_raises_on_legacy_error_event(self) -> None:
        from atlasent.exceptions import AtlaSentError

        lines = _lines_from(
            _error_legacy(code="server_error", message="upstream timeout")
        )
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        with pytest.raises(AtlaSentError, match="upstream timeout"):
            await collect(client, agent="bot", action="read")

    async def test_stops_at_done_before_further_events(self) -> None:
        # decision after done is ignored
        lines = _lines_from(_done(), _decision_legacy())
        response = _make_mock_response(lines)
        client = _patched_client()
        client._client.stream = MagicMock(return_value=response)

        events = await collect(client, agent="bot", action="read")

        assert events == []
