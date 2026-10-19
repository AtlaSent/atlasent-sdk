"""Tests for atlasent.v2_endpoints — V2-D3/D4/D8 wire methods."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from atlasent import AtlaSentClient
from atlasent.exceptions import AtlaSentError
from atlasent.v2_endpoints import (
    BATCH_PATH,
    GRAPHQL_PATH,
    MAX_BATCH_ITEMS,
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

API_KEY = "ask_test_v2wave"
BASE_URL = "https://api.atlasent.io/functions/v1"
VALID_BATCH_ID = "12345678-1234-5678-1234-567812345678"


def _client() -> AtlaSentClient:
    return AtlaSentClient(api_key=API_KEY, base_url=BASE_URL)


def _mock_response(
    *,
    status: int = 200,
    body: Any = None,
    request_id: str | None = "req_v2_test",
) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.headers = {"X-Request-ID": request_id} if request_id else {}
    response.json = MagicMock(return_value=body)
    if body is None:
        response.json.side_effect = ValueError("no body")
    response.text = json.dumps(body) if body is not None else ""
    return response


def _mock_stream_response(
    lines: list[str],
    *,
    status: int = 200,
    request_id: str | None = "req_v2_stream",
) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.headers = {"X-Request-ID": request_id} if request_id else {}
    response.iter_lines = MagicMock(return_value=iter(lines))
    response.__enter__ = MagicMock(return_value=response)
    response.__exit__ = MagicMock(return_value=None)
    return response


# ── FeatureNotEnabledError ─────────────────────────────────────────────


class TestFeatureNotEnabledError:
    def test_exposes_feature_and_endpoint(self) -> None:
        err = FeatureNotEnabledError("batch", "/v1/evaluate/batch")
        assert err.feature == "batch"
        assert err.endpoint == "/v1/evaluate/batch"
        assert err.status_code == 404
        assert err.code == "feature_disabled"
        assert "batch" in err.message
        assert "/v1/evaluate/batch" in err.message
        assert "v2_batch" in err.message

    def test_subclass_of_atlasent_error(self) -> None:
        err = FeatureNotEnabledError("streaming", "/v1/evaluate/stream")
        assert isinstance(err, AtlaSentError)

    def test_forwards_request_id(self) -> None:
        err = FeatureNotEnabledError("graphql", "/v1/graphql", request_id="req_abc")
        assert err.request_id == "req_abc"


# ── evaluate_many ───────────────────────────────────────────────────


class TestEvaluateMany:
    def test_returns_parsed_response(self) -> None:
        client = _client()
        body = {
            "batch_id": VALID_BATCH_ID,
            "items": [
                {
                    "index": 0,
                    "decision": "allow",
                    "decision_id": "dec_0",
                    "permit_token": "pt_0",
                },
                {
                    "index": 1,
                    "decision": "deny",
                    "decision_id": "dec_1",
                    "reason": "policy_violation",
                },
            ],
            "partial": False,
        }
        client._client.post = MagicMock(return_value=_mock_response(body=body))

        result = evaluate_many(
            client,
            [
                {"action_type": "read", "actor_id": "a1"},
                {"action_type": "write", "actor_id": "a2"},
            ],
            batch_id=VALID_BATCH_ID,
        )

        assert isinstance(result, EvaluateBatchResponse)
        assert result.batch_id == VALID_BATCH_ID
        assert result.partial is False
        assert len(result.items) == 2
        assert result.items[0] == EvaluateBatchItem(
            index=0,
            decision="allow",
            decision_id="dec_0",
            permit_token="pt_0",
        )
        assert result.items[1].decision == "deny"
        assert result.items[1].reason == "policy_violation"

        call = client._client.post.call_args
        assert call.args[0] == f"{BASE_URL}{BATCH_PATH}"
        # body sent as raw bytes
        sent = json.loads(call.kwargs["content"])
        assert sent["items"][0]["action_type"] == "read"
        assert sent["batch_id"] == VALID_BATCH_ID

    def test_omits_batch_id_when_not_provided(self) -> None:
        client = _client()
        body = {"batch_id": "auto", "items": [], "partial": False}
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        sent = json.loads(client._client.post.call_args.kwargs["content"])
        assert "batch_id" not in sent

    def test_propagates_per_item_error_fields(self) -> None:
        client = _client()
        body = {
            "batch_id": VALID_BATCH_ID,
            "items": [
                {
                    "index": 0,
                    "decision": None,
                    "error_code": "upstream_timeout",
                    "error_message": "policy engine timed out",
                }
            ],
            "partial": True,
        }
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        result = evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert result.partial is True
        assert result.items[0].decision is None
        assert result.items[0].error_code == "upstream_timeout"
        assert result.items[0].error_message == "policy engine timed out"

    def test_404_raises_feature_not_enabled(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=404, body={"error": "not found"})
        )
        with pytest.raises(FeatureNotEnabledError) as ei:
            evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.feature == "batch"
        assert ei.value.endpoint == BATCH_PATH
        assert ei.value.request_id == "req_v2_test"

    def test_500_raises_atlasent_error_server_error(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=500, body={"error": "boom"})
        )
        with pytest.raises(AtlaSentError) as ei:
            evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.status_code == 500
        assert ei.value.code == "server_error"

    def test_400_raises_atlasent_error_bad_request(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=400, body={"error": "bad"})
        )
        with pytest.raises(AtlaSentError) as ei:
            evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.code == "bad_request"

    def test_malformed_json_raises_bad_response(self) -> None:
        client = _client()
        bad = _mock_response(status=200, body=None)
        client._client.post = MagicMock(return_value=bad)
        with pytest.raises(AtlaSentError) as ei:
            evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.code == "bad_response"

    def test_rejects_empty_items(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="non-empty"):
            evaluate_many(client, [])

    def test_rejects_oversized_items(self) -> None:
        client = _client()
        too_many = [{"action_type": "x", "actor_id": "y"}] * (MAX_BATCH_ITEMS + 1)
        with pytest.raises(ValueError, match="exceeds maximum"):
            evaluate_many(client, too_many)

    def test_rejects_non_uuid_batch_id(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="valid UUID"):
            evaluate_many(
                client,
                [{"action_type": "x", "actor_id": "y"}],
                batch_id="not-a-uuid",
            )

    def test_rejects_oversize_body(self) -> None:
        client = _client()
        huge = "z" * 1_100_000
        with pytest.raises(ValueError, match="exceeds maximum"):
            evaluate_many(client, [{"action_type": "x", "ctx": huge}])

    def test_handles_response_with_missing_items_key(self) -> None:
        client = _client()
        body = {"batch_id": "b1"}  # no items, no partial
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        result = evaluate_many(client, [{"action_type": "x", "actor_id": "y"}])
        assert result.items == ()
        assert result.partial is False


# ── authorize_stream ────────────────────────────────────────────────


class TestAuthorizeStream:
    def _make_stream_lines(self, *frames: tuple[str, dict[str, Any]]) -> list[str]:
        """Build SSE line stream from (event_name, data) pairs."""
        lines: list[str] = []
        for event_name, data in frames:
            lines.append(f"event: {event_name}")
            lines.append(f"data: {json.dumps(data)}")
            lines.append("")
        return lines

    def test_dispatches_decision_and_complete(self) -> None:
        client = _client()
        lines = self._make_stream_lines(
            (
                "decision",
                {
                    "index": 0,
                    "decision": "allow",
                    "decision_id": "dec_0",
                    "permit_token": "pt_0",
                },
            ),
            (
                "decision",
                {"index": 1, "decision": "deny", "reason": "policy"},
            ),
            (
                "complete",
                {"batch_id": VALID_BATCH_ID, "count": 2, "partial": False},
            ),
        )
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))

        decisions: list[StreamDecision] = []
        errors: list[StreamErrorFrame] = []
        result = authorize_stream(
            client,
            [
                {"action_type": "read", "actor_id": "a"},
                {"action_type": "delete", "actor_id": "b"},
            ],
            batch_id=VALID_BATCH_ID,
            on_decision=decisions.append,
            on_error=errors.append,
        )

        assert isinstance(result, StreamComplete)
        assert result.batch_id == VALID_BATCH_ID
        assert result.count == 2
        assert result.partial is False
        assert len(decisions) == 2
        assert decisions[0].decision == "allow"
        assert decisions[0].decision_id == "dec_0"
        assert decisions[1].decision == "deny"
        assert errors == []

    def test_dispatches_error_frame_and_continues(self) -> None:
        client = _client()
        lines = self._make_stream_lines(
            (
                "decision",
                {"index": 0, "decision": "allow"},
            ),
            (
                "error",
                {
                    "index": 1,
                    "error_code": "upstream_timeout",
                    "message": "policy engine timeout",
                },
            ),
            (
                "decision",
                {"index": 2, "decision": "allow"},
            ),
            (
                "complete",
                {"batch_id": VALID_BATCH_ID, "count": 3, "partial": True},
            ),
        )
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))

        decisions: list[StreamDecision] = []
        errors: list[StreamErrorFrame] = []
        result = authorize_stream(
            client,
            [{"action_type": "x", "actor_id": "y"}] * 3,
            on_decision=decisions.append,
            on_error=errors.append,
        )

        assert result.partial is True
        assert len(decisions) == 2
        assert len(errors) == 1
        assert errors[0].index == 1
        assert errors[0].error_code == "upstream_timeout"

    def test_ignores_keep_alive_comment_lines(self) -> None:
        client = _client()
        lines = [
            ": heartbeat",
            "",
            "event: complete",
            f"data: {json.dumps({'batch_id': 'b', 'count': 0, 'partial': False})}",
            "",
        ]
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))

        result = authorize_stream(
            client,
            [{"action_type": "x", "actor_id": "y"}],
        )
        assert result.count == 0

    def test_ignores_malformed_data_frame(self) -> None:
        client = _client()
        lines = [
            "event: decision",
            "data: not-json-at-all",
            "",
            "event: complete",
            f"data: {json.dumps({'batch_id': 'b', 'count': 1, 'partial': False})}",
            "",
        ]
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))
        result = authorize_stream(client, [{"action_type": "x", "actor_id": "y"}])
        assert result.count == 1

    def test_ignores_non_dict_payload(self) -> None:
        client = _client()
        lines = [
            "event: decision",
            "data: [1, 2, 3]",
            "",
            "event: complete",
            f"data: {json.dumps({'batch_id': 'b', 'count': 0, 'partial': False})}",
            "",
        ]
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))
        result = authorize_stream(client, [{"action_type": "x", "actor_id": "y"}])
        assert result.batch_id == "b"

    def test_handles_bytes_lines(self) -> None:
        client = _client()
        lines: list[Any] = [
            b"event: complete",
            b'data: {"batch_id": "b", "count": 0, "partial": false}',
            b"",
        ]
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))
        result = authorize_stream(client, [{"action_type": "x", "actor_id": "y"}])
        assert result.batch_id == "b"

    def test_404_raises_feature_not_enabled(self) -> None:
        client = _client()
        client._client.stream = MagicMock(
            return_value=_mock_stream_response([], status=404)
        )
        with pytest.raises(FeatureNotEnabledError) as ei:
            authorize_stream(
                client,
                [{"action_type": "x", "actor_id": "y"}],
            )
        assert ei.value.feature == "streaming"

    def test_500_raises_atlasent_error(self) -> None:
        client = _client()
        client._client.stream = MagicMock(
            return_value=_mock_stream_response([], status=500)
        )
        with pytest.raises(AtlaSentError) as ei:
            authorize_stream(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.code == "server_error"

    def test_400_raises_atlasent_error_bad_request(self) -> None:
        client = _client()
        client._client.stream = MagicMock(
            return_value=_mock_stream_response([], status=400)
        )
        with pytest.raises(AtlaSentError) as ei:
            authorize_stream(client, [{"action_type": "x", "actor_id": "y"}])
        assert ei.value.code == "bad_request"

    def test_stream_without_complete_raises(self) -> None:
        client = _client()
        lines = self._make_stream_lines(
            ("decision", {"index": 0, "decision": "allow"}),
        )
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))
        with pytest.raises(AtlaSentError, match="without a `complete`"):
            authorize_stream(
                client,
                [{"action_type": "x", "actor_id": "y"}],
                on_decision=lambda d: None,
            )

    def test_skips_decision_when_no_callback(self) -> None:
        # Coverage for the on_decision=None branch.
        client = _client()
        lines = self._make_stream_lines(
            ("decision", {"index": 0, "decision": "allow"}),
            ("error", {"index": 1, "error_code": "x", "message": "y"}),
            ("complete", {"batch_id": "b", "count": 2, "partial": True}),
        )
        client._client.stream = MagicMock(return_value=_mock_stream_response(lines))
        result = authorize_stream(client, [{"action_type": "x", "actor_id": "y"}] * 2)
        assert result.partial is True

    def test_rejects_empty_items(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="non-empty"):
            authorize_stream(client, [])

    def test_rejects_oversized_items(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="exceeds maximum"):
            authorize_stream(
                client,
                [{"action_type": "x", "actor_id": "y"}] * (MAX_BATCH_ITEMS + 1),
            )

    def test_rejects_invalid_batch_id(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="valid UUID"):
            authorize_stream(
                client,
                [{"action_type": "x", "actor_id": "y"}],
                batch_id="nope",
            )


# ── graphql ───────────────────────────────────────────────────────────


class TestGraphQL:
    def test_returns_data_on_success(self) -> None:
        client = _client()
        body = {
            "data": {
                "recentEvaluations": [{"decisionId": "dec_1", "decision": "allow"}]
            }
        }
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        result = graphql(
            client,
            "query Q { recentEvaluations(limit: 10) { decisionId decision } }",
            variables={"x": 1},
            operation_name="Q",
        )
        assert isinstance(result, GraphQLResponse)
        assert result.data == body["data"]
        assert result.errors == ()
        sent = json.loads(client._client.post.call_args.kwargs["content"])
        assert sent["query"].startswith("query Q")
        assert sent["variables"] == {"x": 1}
        assert sent["operationName"] == "Q"

    def test_surfaces_errors_field(self) -> None:
        client = _client()
        body = {
            "data": None,
            "errors": [{"message": "Field 'forbidden' requires policy:read scope."}],
        }
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        result = graphql(client, "{ forbidden }")
        assert result.data is None
        assert len(result.errors) == 1
        assert "policy:read" in result.errors[0]["message"]

    def test_omits_variables_and_operation_name_when_not_provided(self) -> None:
        client = _client()
        body = {"data": {"activeBundle": {"id": "b_1"}}}
        client._client.post = MagicMock(return_value=_mock_response(body=body))
        graphql(client, "{ activeBundle { id } }")
        sent = json.loads(client._client.post.call_args.kwargs["content"])
        assert "variables" not in sent
        assert "operationName" not in sent

    def test_404_raises_feature_not_enabled(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=404, body={"error": "off"})
        )
        with pytest.raises(FeatureNotEnabledError) as ei:
            graphql(client, "{ activeBundle { id } }")
        assert ei.value.feature == "graphql"
        assert ei.value.endpoint == GRAPHQL_PATH

    def test_500_raises_atlasent_error(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=500, body={"error": "boom"})
        )
        with pytest.raises(AtlaSentError) as ei:
            graphql(client, "{ activeBundle { id } }")
        assert ei.value.code == "server_error"

    def test_400_raises_atlasent_error_bad_request(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=400, body={"error": "bad"})
        )
        with pytest.raises(AtlaSentError) as ei:
            graphql(client, "{ x }")
        assert ei.value.code == "bad_request"

    def test_malformed_json_raises_bad_response(self) -> None:
        client = _client()
        client._client.post = MagicMock(
            return_value=_mock_response(status=200, body=None)
        )
        with pytest.raises(AtlaSentError) as ei:
            graphql(client, "{ activeBundle { id } }")
        assert ei.value.code == "bad_response"

    def test_rejects_empty_query(self) -> None:
        client = _client()
        with pytest.raises(ValueError, match="non-empty"):
            graphql(client, "")
        with pytest.raises(ValueError, match="non-empty"):
            graphql(client, "   ")

    def test_rejects_oversize_body(self) -> None:
        client = _client()
        huge_query = "query { activeBundle { id } } # " + ("a" * 1_100_000)
        with pytest.raises(ValueError, match="exceeds maximum"):
            graphql(client, huge_query)
