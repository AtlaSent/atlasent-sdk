"""Tests for the synchronous AtlaSentClient."""

import httpx
import pytest

from atlasent.audit import AuditEventsResult, AuditExportResult
from atlasent.client import AtlaSentClient
from atlasent.exceptions import AtlaSentDenied, AtlaSentError, RateLimitError
from atlasent.models import (
    ApiKeySelfResult,
    ComplianceControlsResult,
    ComplianceEvidencePackResult,
    ConstraintTrace,
    EvaluatePreflightResult,
    EvaluateResult,
    GateResult,
    VerifyResult,
)


@pytest.fixture
def client():
    return AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)


@pytest.fixture
def client_retry():
    return AtlaSentClient(
        api_key="ask_test_xxxxxxxx", max_retries=2, retry_backoff=0.01
    )


EVALUATE_PERMIT = {
    "permitted": True,
    "decision_id": "dec_100",
    "reason": "Action complies with policy",
    "audit_hash": "hash_abc",
    "timestamp": "2025-01-15T12:00:00Z",
}

EVALUATE_DENY = {
    "permitted": False,
    "decision_id": "dec_101",
    "reason": "Missing required context",
    "audit_hash": "hash_def",
    "timestamp": "2025-01-15T12:01:00Z",
}

VERIFY_OK = {
    "verified": True,
    "permit_hash": "permit_xyz",
    "timestamp": "2025-01-15T12:05:00Z",
}


def _mock_resp(mocker, status_code=200, json_data=None, headers=None):
    resp = mocker.Mock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = ""
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ── Init ──────────────────────────────────────────────────────


class TestInit:
    def test_defaults(self):
        c = AtlaSentClient(api_key="ask_test_xxxxxxxx")
        assert c._api_key == "ask_test_xxxxxxxx"
        assert c._anon_key == ""
        assert c._base_url == "https://api.atlasent.io/functions/v1"
        assert c._timeout == 10
        assert c._max_retries == 3

    def test_custom(self):
        c = AtlaSentClient(
            api_key="ask_test_xxxxxxxx",
            anon_key="anon",
            base_url="https://staging.atlasent.io/",
            timeout=30,
            max_retries=5,
        )
        assert c._anon_key == "anon"
        assert c._base_url == "https://staging.atlasent.io"
        assert c._timeout == 30

    def test_rejects_http_base_url(self):
        with pytest.raises(ValueError, match="https"):
            AtlaSentClient(
                api_key="ask_test_xxxxxxxx", base_url="http://api.atlasent.io"
            )

    def test_dev_escape_hatch_allows_http(self, monkeypatch):
        monkeypatch.setenv("ATLASENT_ALLOW_INSECURE_HTTP", "1")
        c = AtlaSentClient(
            api_key="ask_test_xxxxxxxx", base_url="http://localhost:8000"
        )
        assert c._base_url == "http://localhost:8000"

    def test_rejects_malformed_api_key(self):
        with pytest.raises(ValueError, match="ask_"):
            AtlaSentClient(api_key="not_a_real_key")

    def test_rejects_whitespace_padded_api_key(self):
        # Common paste accident — wrapping whitespace.
        with pytest.raises(ValueError, match="ask_"):
            AtlaSentClient(api_key=" ask_test_xxxxxxxx ")

    def test_rejects_empty_api_key(self):
        with pytest.raises(ValueError, match="required"):
            AtlaSentClient(api_key="")

    def test_accepts_live_and_test_prefixes(self):
        AtlaSentClient(api_key="ask_live_abc123")
        AtlaSentClient(api_key="ask_test_abc123")

    def test_user_agent(self):
        c = AtlaSentClient(api_key="ask_test_xxxxxxxx")
        assert "atlasent-python/" in c._client.headers["user-agent"]

    def test_authorization_header(self):
        c = AtlaSentClient(api_key="ask_live_xyz")
        assert c._client.headers["authorization"] == "Bearer ask_live_xyz"

    def test_accept_header(self):
        c = AtlaSentClient(api_key="ask_test_xxxxxxxx")
        assert c._client.headers["accept"] == "application/json"


# ── Evaluate ─────────────────────────────────────────────────


class TestEvaluate:
    def test_permit(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.evaluate("read_data", "agent-1", {"study": "S001"})

        assert isinstance(result, EvaluateResult)
        assert result.permitted is True  # legacy attr (canonical: result.decision)
        assert result.permit_token == "dec_100"
        assert result.reason == "Action complies with policy"

    def test_deny_raises(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_DENY)
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentDenied) as exc_info:
            client.evaluate("write_data", "agent-1")

        err = exc_info.value
        # Canonical four-value enum (was "False" when decision was bool-stringified).
        assert err.decision == "deny"
        assert err.permit_token == "dec_101"
        assert err.reason == "Missing required context"
        assert err.response_body == EVALUATE_DENY

    def test_payload_shape(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        client.evaluate("action", "actor", {"k": "v"})

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["action_type"] == "action"
        assert payload["actor_id"] == "actor"
        assert payload["context"] == {"k": "v"}
        # api_key is sent via Authorization header, never echoed in the body.
        assert "api_key" not in payload

    def test_timeout_raises(self, client, mocker):
        mocker.patch.object(
            client._client, "post", side_effect=httpx.TimeoutException("timeout")
        )
        with pytest.raises(AtlaSentError, match="timed out"):
            client.evaluate("a", "b")

    def test_connection_error(self, client, mocker):
        mocker.patch.object(
            client._client, "post", side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(AtlaSentError, match="Failed to connect"):
            client.evaluate("a", "b")

    def test_401(self, client, mocker):
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, status_code=401)
        )
        with pytest.raises(AtlaSentError, match="Invalid API key") as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.status_code == 401

    def test_500(self, client, mocker):
        resp = _mock_resp(mocker, status_code=500)
        resp.text = "Internal Server Error"
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError, match="API error 500"):
            client.evaluate("a", "b")


# ── Evaluate preflight (?include=constraint_trace) ───────────


CONSTRAINT_TRACE_WIRE = {
    "rules_evaluated": [
        {
            "policy_id": "pol_close_window_v3",
            "decision": "deny",
            "fingerprint": "fp_abc123",
            "stages": [
                {
                    "stage": "role_check",
                    "rule": "preparer_required",
                    "matched": True,
                    "order": 0,
                },
                {
                    "stage": "context",
                    "rule": "change_reason_required",
                    "matched": False,
                    "detail": "context.change_reason missing",
                    "order": 1,
                },
            ],
        },
    ],
    "matching_policy_id": "pol_close_window_v3",
}

EVALUATE_PREFLIGHT_DENY_WITH_TRACE = {
    "decision": "deny",
    "permit_token": "",
    "denial": {"reason": "preflight: change_reason missing", "code": "MISSING_FIELD"},
    "constraint_trace": CONSTRAINT_TRACE_WIRE,
}

EVALUATE_PREFLIGHT_ALLOW_NO_TRACE = {
    # Older atlasent-api version that does not echo `constraint_trace`
    # — the helper must degrade gracefully (trace=None).
    "decision": "allow",
    "permit_token": "dec_pf_42",
    "request_id": "req_pf",
}


class TestEvaluatePreflight:
    def test_appends_include_constraint_trace_query(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PREFLIGHT_DENY_WITH_TRACE)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        client.evaluate_preflight("close_period", "agent-1", {"period": "2025-12"})

        # The whole point of the helper is that it always sets the
        # `?include=constraint_trace` query — never optional, never
        # silently dropped.
        assert mock_post.call_args.kwargs["params"] == {"include": "constraint_trace"}
        # The request body shape is identical to evaluate(): the trace
        # is requested via the URL, not the body.
        body = mock_post.call_args.kwargs["json"]
        assert body == {
            "action_type": "close_period",
            "actor_id": "agent-1",
            "context": {"period": "2025-12"},
        }

    def test_parses_constraint_trace_into_typed_shape(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PREFLIGHT_DENY_WITH_TRACE)
        mocker.patch.object(client._client, "post", return_value=resp)

        result = client.evaluate_preflight("close_period", "agent-1")

        assert isinstance(result, EvaluatePreflightResult)
        # Does NOT raise on deny — preflight returns the outcome so
        # callers can inspect the trace alongside it.
        assert isinstance(result.evaluation, EvaluateResult)
        assert result.evaluation.decision == "deny"
        assert isinstance(result.constraint_trace, ConstraintTrace)
        assert result.constraint_trace.matching_policy_id == "pol_close_window_v3"
        assert len(result.constraint_trace.rules_evaluated) == 1
        policy = result.constraint_trace.rules_evaluated[0]
        assert policy.policy_id == "pol_close_window_v3"
        assert policy.decision == "deny"
        assert len(policy.stages) == 2
        assert policy.stages[0].matched is True
        assert policy.stages[1].matched is False
        assert policy.stages[1].detail == "context.change_reason missing"
        assert policy.stages[1].order == 1

    def test_missing_trace_is_none_not_raises(self, client, mocker):
        # Forward-compat: an older atlasent-api version that does not
        # populate `constraint_trace` in the response must not break
        # the helper. The method returns the result with trace=None.
        resp = _mock_resp(mocker, json_data=EVALUATE_PREFLIGHT_ALLOW_NO_TRACE)
        mocker.patch.object(client._client, "post", return_value=resp)

        result = client.evaluate_preflight("close_period", "agent-1")

        assert isinstance(result, EvaluatePreflightResult)
        assert result.evaluation.decision == "allow"
        assert result.evaluation.permit_token == "dec_pf_42"
        assert result.constraint_trace is None

    def test_unknown_trace_keys_do_not_crash(self, client, mocker):
        # The trace types are forward-compatible: an unknown engine-
        # side key on a stage / policy / envelope must not raise.
        wire = {
            "decision": "allow",
            "permit_token": "dec_x",
            "constraint_trace": {
                "rules_evaluated": [
                    {
                        "policy_id": "p1",
                        "decision": "allow",
                        "fingerprint": "fp_1",
                        "stages": [
                            {
                                "stage": "s1",
                                "matched": True,
                                "order": 0,
                                "future_field": "yo",  # unknown
                            },
                        ],
                        "next_field_we_haven_t_seen": 42,  # unknown
                    },
                ],
                "future_top_level_field": True,  # unknown
            },
        }
        resp = _mock_resp(mocker, json_data=wire)
        mocker.patch.object(client._client, "post", return_value=resp)

        result = client.evaluate_preflight("act", "actor")
        assert result.constraint_trace is not None
        assert result.constraint_trace.rules_evaluated[0].stages[0].matched is True

    def test_malformed_response_raises(self, client, mocker):
        # Same fail-closed contract as evaluate(): if the response has
        # neither canonical `decision` nor legacy `permitted`, raise.
        resp = _mock_resp(mocker, json_data={"unrelated": True})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError, match="Malformed"):
            client.evaluate_preflight("a", "b")


# ── Verify ──────────────────────────────────────────────────


class TestVerify:
    def test_valid(self, client, mocker):
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=VERIFY_OK)
        )
        result = client.verify("dec_100", "read_data", "agent-1")

        assert isinstance(result, VerifyResult)
        assert result.valid is True
        assert result.permit_hash == "permit_xyz"

    def test_payload_shape(self, client, mocker):
        resp = _mock_resp(mocker, json_data=VERIFY_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        client.verify("dec_100", "read_data", "agent-1", {"k": "v"})

        payload = mock_post.call_args[1]["json"]
        assert payload["permit_token"] == "dec_100"
        assert payload["action_type"] == "read_data"
        assert payload["actor_id"] == "agent-1"
        # The verify handler does not consult context; SDK omits it from
        # the wire to avoid round-tripping unread fields.
        assert "context" not in payload
        assert "api_key" not in payload


# ── Gate ────────────────────────────────────────────────────


class TestGate:
    def test_permit_and_verify(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            side_effect=[
                _mock_resp(mocker, json_data=EVALUATE_PERMIT),
                _mock_resp(mocker, json_data=VERIFY_OK),
            ],
        )
        result = client.gate("read_data", "agent-1", {"study": "S001"})

        assert isinstance(result, GateResult)
        assert result.evaluation.permit_token == "dec_100"
        assert result.verification.valid is True
        assert client._client.post.call_count == 2

    def test_deny_at_evaluate(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_DENY),
        )
        with pytest.raises(AtlaSentDenied):
            client.gate("write_data", "agent-1")

        # verify should NOT have been called
        assert client._client.post.call_count == 1


# ── Retry ───────────────────────────────────────────────────


class TestRetry:
    def test_retries_on_timeout(self, client_retry, mocker):
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(
            client_retry._client,
            "post",
            side_effect=[httpx.TimeoutException("t"), ok],
        )
        result = client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"
        assert client_retry._client.post.call_count == 2

    def test_retries_on_5xx(self, client_retry, mocker):
        err = _mock_resp(mocker, status_code=502)
        err.text = "Bad Gateway"
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(client_retry._client, "post", side_effect=[err, ok])
        result = client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"

    def test_exhausted(self, client_retry, mocker):
        mocker.patch.object(
            client_retry._client,
            "post",
            side_effect=httpx.TimeoutException("t"),
        )
        with pytest.raises(AtlaSentError, match="3 attempts"):
            client_retry.evaluate("a", "b")
        assert client_retry._client.post.call_count == 3

    def test_no_retry_on_4xx(self, client_retry, mocker):
        resp = _mock_resp(mocker, status_code=422)
        resp.text = "Unprocessable"
        mocker.patch.object(client_retry._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError, match="422"):
            client_retry.evaluate("a", "b")
        assert client_retry._client.post.call_count == 1


# ── Rate Limiting ─────────────────────────────────────────────


class TestRateLimit:
    def test_429(self, client, mocker):
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": "30"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.retry_after == 30.0

    def test_429_no_header(self, client, mocker):
        resp = _mock_resp(mocker, status_code=429)
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.retry_after is None


# ── Error codes (SDK-PY-002 / SDK-PY-003) ────────────────────


class TestErrorCodes:
    def test_401_has_invalid_api_key_code(self, client, mocker):
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, status_code=401)
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "invalid_api_key"
        assert exc_info.value.status_code == 401

    def test_403_has_forbidden_code(self, client, mocker):
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, status_code=403)
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "forbidden"

    def test_500_has_server_error_code(self, client, mocker):
        resp = _mock_resp(mocker, status_code=500)
        resp.text = "boom"
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "server_error"

    def test_422_has_bad_request_code(self, client, mocker):
        resp = _mock_resp(mocker, status_code=422)
        resp.text = "bad field"
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "bad_request"

    def test_timeout_has_timeout_code(self, client, mocker):
        mocker.patch.object(
            client._client, "post", side_effect=httpx.TimeoutException("t")
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "timeout"

    def test_connection_error_has_network_code(self, client, mocker):
        mocker.patch.object(
            client._client, "post", side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "network"

    def test_malformed_evaluate_body_is_bad_response(self, client, mocker):
        # Valid JSON, but missing `permitted` and `decision_id`.
        resp = _mock_resp(mocker, json_data={"foo": "bar"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "bad_response"
        assert exc_info.value.response_body == {"foo": "bar"}
        assert "permitted" in exc_info.value.message

    def test_malformed_verify_body_is_bad_response(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"outcome": "ok"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.verify("dec_100")
        assert exc_info.value.code == "bad_response"
        assert "verified" in exc_info.value.message

    def test_invalid_json_is_bad_response(self, client, mocker):
        resp = _mock_resp(mocker, status_code=200)
        resp.json.side_effect = ValueError("not json")
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "bad_response"


# ── Resource Management ─────────────────────────────────────────


class TestLifecycle:
    def test_close(self, client, mocker):
        mock_close = mocker.patch.object(client._client, "close")
        client.close()
        mock_close.assert_called_once()

    def test_context_manager(self, mocker):
        with AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0) as c:
            mock_close = mocker.patch.object(c._client, "close")
        mock_close.assert_called_once()


# ── Edge Cases ────────────────────────────────────────────────


class TestEdgeCases:
    def test_malformed_json_response(self, client, mocker):
        """Server returns 200 but invalid JSON."""
        resp = mocker.Mock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.side_effect = ValueError("No JSON")
        mocker.patch.object(client._client, "post", return_value=resp)

        with pytest.raises(AtlaSentError, match="Invalid JSON"):
            client.evaluate("a", "b")

    def test_partial_evaluate_response(self, client, mocker):
        """Server returns 200 but missing required fields.

        Both shapes covered: legacy ``{permitted: True}`` without a
        ``decision_id`` and canonical ``{decision: "allow"}`` without
        a ``permit_token`` are fail-closed by the client.
        """
        # Legacy shape, no decision_id.
        resp = _mock_resp(mocker, json_data={"permitted": True})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(Exception):
            client.evaluate("a", "b")

        # Canonical shape, no permit_token.
        resp = _mock_resp(mocker, json_data={"decision": "allow"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(Exception):
            client.evaluate("a", "b")

    def test_none_context_treated_as_empty(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        client.evaluate("action", "actor", None)

        payload = mock_post.call_args[1]["json"]
        assert payload["context"] == {}

    def test_empty_context_dict(self, client, mocker):
        resp = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        client.evaluate("action", "actor", {})

        payload = mock_post.call_args[1]["json"]
        assert payload["context"] == {}

    def test_gate_does_not_call_verify_on_deny(self, client, mocker):
        """gate() should stop after evaluate if denied."""
        resp = _mock_resp(mocker, json_data=EVALUATE_DENY)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        with pytest.raises(AtlaSentDenied):
            client.gate("a", "b")

        assert mock_post.call_count == 1

    def test_denied_response_body_preserved(self, client, mocker):
        """AtlaSentDenied should carry the full response body."""
        deny_data = {
            "permitted": False,
            "decision_id": "dec_999",
            "reason": "policy violation",
            "audit_hash": "h",
            "timestamp": "t",
            "extra_field": "preserved",
        }
        resp = _mock_resp(mocker, json_data=deny_data)
        mocker.patch.object(client._client, "post", return_value=resp)

        with pytest.raises(AtlaSentDenied) as exc_info:
            client.evaluate("a", "b")

        assert exc_info.value.response_body["extra_field"] == "preserved"

    def test_large_error_body_truncated(self, client, mocker):
        resp = _mock_resp(mocker, status_code=400)
        resp.text = "x" * 1000
        mocker.patch.object(client._client, "post", return_value=resp)

        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")

        assert len(exc_info.value.message) < 600

    def test_verify_with_minimal_params(self, client, mocker):
        """verify() works with just permit_token."""
        resp = _mock_resp(mocker, json_data=VERIFY_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)

        result = client.verify("dec_100")

        assert result.valid is True
        payload = mock_post.call_args[1]["json"]
        assert payload["permit_token"] == "dec_100"
        assert payload["action_type"] == ""
        assert payload["actor_id"] == ""


class TestSyncRetryPaths:
    def test_connect_error_retries_then_succeeds(self, client_retry, mocker):
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(
            client_retry._client,
            "post",
            side_effect=[httpx.ConnectError("refused"), ok],
        )
        result = client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"

    def test_generic_httpx_error_maps_to_network_code(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            side_effect=httpx.ReadError("connection reset"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "network"

    def test_403_surfaces_server_message_from_json(self, client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"reason": "key is read-only"}
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert "key is read-only" in str(exc_info.value)
        assert exc_info.value.code == "forbidden"

    def test_403_prefers_error_field_over_message(self, client, mocker):
        # Phase 4 ErrorEnvelope: body.error is canonical and must win
        # over the legacy `message` / `reason` keys.
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {
            "error": "phi_scope_required",
            "message": "fallback should not appear",
        }
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert "phi_scope_required" in str(exc_info.value)
        assert "fallback should not appear" not in str(exc_info.value)

    def test_401_with_non_json_body_uses_default_message(self, client, mocker):
        resp = _mock_resp(mocker, status_code=401)
        resp.json.side_effect = ValueError("not json")
        resp.text = "<html>unauthorized</html>"
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "invalid_api_key"
        assert "Invalid API key" in str(exc_info.value)

    def test_429_with_non_numeric_retry_after_falls_back_to_none(self, client, mocker):
        resp = _mock_resp(
            mocker, status_code=429, headers={"retry-after": "not-a-number"}
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.retry_after is None

    def test_429_with_http_date_retry_after(self, client, mocker):
        from datetime import datetime, timedelta, timezone

        future = datetime.now(timezone.utc) + timedelta(seconds=45)
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": http_date})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.retry_after is not None
        assert 30.0 <= exc_info.value.retry_after <= 45.0

    def test_429_with_http_date_in_the_past_clamps_to_zero(self, client, mocker):
        from datetime import datetime, timedelta, timezone

        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        http_date = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": http_date})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.retry_after == 0.0

    def test_all_retries_exhausted_raises_network(self, client_retry, mocker):
        mocker.patch.object(
            client_retry._client,
            "post",
            side_effect=httpx.ConnectError("refused"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client_retry.evaluate("a", "b")
        assert exc_info.value.code == "network"
        assert "attempts" in exc_info.value.message

    def test_403_body_with_no_message_or_reason_key(self, client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"error": "forbidden"}
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        assert exc_info.value.code == "forbidden"

    def test_parse_reset_header_naive_iso8601_gets_utc(self, client, mocker):
        from atlasent.client import _parse_reset_header

        naive_iso = "2026-05-01T00:00:00"
        result = _parse_reset_header(naive_iso)
        assert result is not None
        from datetime import timezone as tz

        assert result.tzinfo == tz.utc


class TestSyncRequestIdOnExceptions:
    """Every SDK-raised exception must carry the X-Request-ID we sent."""

    def test_401_surfaces_request_id(self, client, mocker):
        mock_post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=401),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    def test_429_surfaces_request_id(self, client, mocker):
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": "1"})
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    def test_deny_surfaces_request_id(self, client, mocker):
        mock_post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_DENY),
        )
        with pytest.raises(AtlaSentDenied) as exc_info:
            client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    def test_malformed_body_surfaces_request_id(self, client, mocker):
        mock_post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data={"foo": "bar"}),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.code == "bad_response"
        assert exc_info.value.request_id == sent

    def test_timeout_surfaces_request_id(self, client, mocker):
        mock_post = mocker.patch.object(
            client._client,
            "post",
            side_effect=httpx.TimeoutException("t"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent


# ── Rate-limit header parsing ────────────────────────────────────


class TestRateLimitHeaders:
    """Parse ``X-RateLimit-*`` on every authed response and expose as
    ``result.rate_limit``. None on older deployments / partial headers.
    """

    RESET_SECONDS = 1_714_068_060
    RESET_ISO = "2024-04-25T17:21:00+00:00"

    def _headers(self, **kwargs: str) -> dict[str, str]:
        return {k.replace("_", "-"): v for k, v in kwargs.items()}

    def test_evaluate_exposes_rate_limit_when_all_three_headers_present(
        self, client, mocker
    ):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=EVALUATE_PERMIT,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "1000",
                        "x_ratelimit_remaining": "762",
                        "x_ratelimit_reset": str(self.RESET_SECONDS),
                    }
                ),
            ),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 1000
        assert result.rate_limit.remaining == 762
        assert result.rate_limit.reset_at.timestamp() == float(self.RESET_SECONDS)

    def test_verify_exposes_rate_limit(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=VERIFY_OK,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "600",
                        "x_ratelimit_remaining": "0",
                        "x_ratelimit_reset": str(self.RESET_SECONDS),
                    }
                ),
            ),
        )
        result = client.verify("tok_xyz")
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 600
        assert result.rate_limit.remaining == 0

    def test_iso8601_reset_accepted(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=EVALUATE_PERMIT,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "100",
                        "x_ratelimit_remaining": "50",
                        "x_ratelimit_reset": self.RESET_ISO,
                    }
                ),
            ),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is not None
        assert result.rate_limit.reset_at.isoformat() == self.RESET_ISO

    def test_no_headers_yields_none(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_PERMIT),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is None

    def test_missing_one_header_yields_none(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=EVALUATE_PERMIT,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "100",
                        "x_ratelimit_remaining": "50",
                        # reset intentionally missing
                    }
                ),
            ),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is None

    def test_non_numeric_count_yields_none(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=EVALUATE_PERMIT,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "not-a-number",
                        "x_ratelimit_remaining": "50",
                        "x_ratelimit_reset": str(self.RESET_SECONDS),
                    }
                ),
            ),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is None

    def test_unparseable_reset_yields_none(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=EVALUATE_PERMIT,
                headers=self._headers(
                    **{
                        "x_ratelimit_limit": "100",
                        "x_ratelimit_remaining": "50",
                        "x_ratelimit_reset": "whenever",
                    }
                ),
            ),
        )
        result = client.evaluate("a", "b")
        assert result.rate_limit is None


# ── key_self ──────────────────────────────────────────────────


KEY_SELF_PAYLOAD = {
    "key_id": "550e8400-e29b-41d4-a716-446655440000",
    "org_id": "123e4567-e89b-12d3-a456-426614174000",
    "environment": "live",
    "scopes": ["evaluate", "audit.read"],
    "allowed_cidrs": ["10.0.0.0/8"],
    "rate_limit_per_minute": 1000,
    "client_ip": "10.2.3.4",
    "expires_at": "2026-12-31T23:59:59Z",
}


class TestKeySelf:
    def test_returns_typed_result(self, client, mocker):
        resp = _mock_resp(mocker, json_data=KEY_SELF_PAYLOAD)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.key_self()
        assert isinstance(result, ApiKeySelfResult)
        assert result.key_id == KEY_SELF_PAYLOAD["key_id"]
        assert result.org_id == KEY_SELF_PAYLOAD["org_id"]
        assert result.environment == "live"
        assert result.scopes == ["evaluate", "audit.read"]
        assert result.allowed_cidrs == ["10.0.0.0/8"]
        assert result.rate_limit_per_minute == 1000
        assert result.client_ip == "10.2.3.4"
        assert result.expires_at == "2026-12-31T23:59:59Z"
        assert result.rate_limit is None  # no X-RateLimit-* headers in mock

    def test_issues_get_not_post(self, client, mocker):
        """Pins the method — regression guard against future `request`
        refactors accidentally switching to POST."""
        resp = _mock_resp(mocker, json_data=KEY_SELF_PAYLOAD)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        post_mock = mocker.patch.object(client._client, "post")
        client.key_self()
        assert get_mock.call_count == 1
        assert post_mock.call_count == 0
        assert "/v1-api-key-self" in get_mock.call_args[0][0]

    def test_surfaces_rate_limit_headers(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data=KEY_SELF_PAYLOAD,
            headers={
                "x-ratelimit-limit": "1000",
                "x-ratelimit-remaining": "987",
                "x-ratelimit-reset": "1714068060",
            },
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.key_self()
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 1000
        assert result.rate_limit.remaining == 987

    def test_runtime_body_with_no_stored_rate_limit(self, client, mocker):
        # The body atlasent-api's v1-api-key-self returns for a key with no
        # stored limit: rate_limit_per_minute is null, never a made-up number,
        # and organization_id rides along beside org_id.
        body = {
            "key_id": "0f0e0d0c-0000-4000-8000-0000000000b1",
            "org_id": "0f0e0d0c-0000-4000-8000-0000000000a1",
            "organization_id": "0f0e0d0c-0000-4000-8000-0000000000a1",
            "environment": "test",
            "scopes": ["evaluate:write", "verify:execute"],
            "allowed_cidrs": None,
            "rate_limit_per_minute": None,
            "client_ip": "203.0.113.5",
            "expires_at": None,
        }
        resp = _mock_resp(mocker, json_data=body)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.key_self()
        assert result.rate_limit_per_minute is None
        assert result.org_id == body["org_id"]
        assert result.scopes == ["evaluate:write", "verify:execute"]

    def test_defaults_optional_fields(self, client, mocker):
        minimal = {
            "key_id": "k",
            "org_id": "o",
            "environment": "test",
            "rate_limit_per_minute": 60,
        }
        resp = _mock_resp(mocker, json_data=minimal)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.key_self()
        assert result.scopes == []
        assert result.allowed_cidrs is None
        assert result.client_ip is None
        assert result.expires_at is None

    def test_bad_response_on_missing_key_id(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data={
                "org_id": "o",
                "environment": "live",
                "rate_limit_per_minute": 60,
            },
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.key_self()
        assert excinfo.value.code == "bad_response"

    def test_401_propagates_as_atlasent_error(self, client, mocker):
        resp = _mock_resp(mocker, status_code=401, json_data={"message": "bad key"})
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.key_self()
        assert excinfo.value.code == "invalid_api_key"

    def test_429_raises_rate_limit_error(self, client, mocker):
        resp = _mock_resp(
            mocker,
            status_code=429,
            json_data={},
            headers={"retry-after": "30"},
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(RateLimitError):
            client.key_self()


# ── compliance_controls / compliance_evidence_pack ───────────────


COMPLIANCE_CONTROLS_PAYLOAD = {
    "framework": "cfr_part_11",
    "window": {"from": "2026-05-01T00:00:00Z", "to": "2026-06-01T00:00:00Z"},
    "generated_at": "2026-06-19T00:00:00Z",
    "summary": {
        "enforced": 8,
        "partial": 2,
        "not_enforced": 1,
        "no_data": 1,
        "attested": 0,
        "total": 12,
    },
    "controls": [
        {
            "clause_id": "11.10(a)",
            "framework_code": "cfr_part_11",
            "section": "11.10",
            "title": "Validation of systems",
            "requirement": "Validation of systems to ensure accuracy.",
            "atlasent_primitive": "execution_evaluations",
            "status_query": "evaluations_present_30d",
            "evidence_source": "execution_evaluations",
            "doc_ref": "https://docs/cfr-11-10a",
            "display_order": 1,
            "status": "enforced",
            "metric": {"count": 42},
        }
    ],
    "truncated": False,
}


class TestComplianceControls:
    def test_returns_typed_result(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_CONTROLS_PAYLOAD)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.compliance_controls(framework="cfr_part_11")
        assert isinstance(result, ComplianceControlsResult)
        assert result.framework == "cfr_part_11"
        assert result.window.from_ == "2026-05-01T00:00:00Z"
        assert result.window.to == "2026-06-01T00:00:00Z"
        assert result.generated_at == "2026-06-19T00:00:00Z"
        assert result.summary.total == 12
        assert len(result.controls) == 1
        assert result.controls[0].status == "enforced"
        assert result.controls[0].metric == {"count": 42}
        assert result.truncated is False
        assert result.rate_limit is None

    def test_passes_query_params(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_CONTROLS_PAYLOAD)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        client.compliance_controls(
            framework="cfr_part_11", from_="2026-05-01", to="2026-06-01"
        )
        assert "/v1-compliance-controls" in get_mock.call_args[0][0]
        params = get_mock.call_args.kwargs["params"]
        assert params == {
            "framework": "cfr_part_11",
            "from": "2026-05-01",
            "to": "2026-06-01",
        }

    def test_no_params_when_no_args(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_CONTROLS_PAYLOAD)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        client.compliance_controls()
        assert get_mock.call_args.kwargs["params"] is None

    def test_issues_get_not_post(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_CONTROLS_PAYLOAD)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        post_mock = mocker.patch.object(client._client, "post")
        client.compliance_controls()
        assert get_mock.call_count == 1
        assert post_mock.call_count == 0

    def test_bad_response_on_missing_controls(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"generated_at": "2026-06-19T00:00:00Z"})
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.compliance_controls()
        assert excinfo.value.code == "bad_response"


COMPLIANCE_PACK_PAYLOAD = {
    "framework": "cfr_part_11",
    "window": {"from": "2026-05-01T00:00:00Z", "to": "2026-06-01T00:00:00Z"},
    "generated_at": "2026-06-19T00:00:00Z",
    "summary": {
        "enforced": 8,
        "partial": 2,
        "not_enforced": 1,
        "no_data": 1,
        "attested": 0,
        "total": 12,
    },
    "sha256": "a" * 64,
    "signature": "ed25519:abc",
    "signing_status": "signed",
    "key_id": "v1",
    "bundle": {
        "schema": "atlasent.compliance.evidence_pack.v1",
        "framework": "cfr_part_11",
        "window": {"from": "2026-05-01T00:00:00Z", "to": "2026-06-01T00:00:00Z"},
        "org_id": "123e4567-e89b-12d3-a456-426614174000",
        "summary": {
            "enforced": 8,
            "partial": 2,
            "not_enforced": 1,
            "no_data": 1,
            "attested": 0,
            "total": 12,
        },
        "controls": [],
    },
}


class TestComplianceEvidencePack:
    def test_returns_typed_result(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_PACK_PAYLOAD)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.compliance_evidence_pack(framework="cfr_part_11")
        assert isinstance(result, ComplianceEvidencePackResult)
        assert result.framework == "cfr_part_11"
        assert result.sha256 == "a" * 64
        assert result.signature == "ed25519:abc"
        assert result.signing_status == "signed"
        assert result.key_id == "v1"
        assert result.bundle.schema_ == "atlasent.compliance.evidence_pack.v1"
        assert result.bundle.org_id == "123e4567-e89b-12d3-a456-426614174000"
        assert result.rate_limit is None

    def test_passes_query_params(self, client, mocker):
        resp = _mock_resp(mocker, json_data=COMPLIANCE_PACK_PAYLOAD)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        client.compliance_evidence_pack(
            framework="cfr_part_11", from_="2026-05-01", to="2026-06-01"
        )
        assert "/v1-compliance-evidence-pack" in get_mock.call_args[0][0]
        params = get_mock.call_args.kwargs["params"]
        assert params == {
            "framework": "cfr_part_11",
            "from": "2026-05-01",
            "to": "2026-06-01",
        }

    def test_framework_required(self, client, mocker):
        get_mock = mocker.patch.object(client._client, "get")
        with pytest.raises(AtlaSentError) as excinfo:
            client.compliance_evidence_pack(framework="")
        assert excinfo.value.code == "bad_request"
        assert get_mock.call_count == 0

    def test_bad_response_on_missing_bundle(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data={"framework": "cfr_part_11", "sha256": "a" * 64},
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.compliance_evidence_pack(framework="cfr_part_11")
        assert excinfo.value.code == "bad_response"


# ── list_audit_events / create_audit_export ──────────────────────


AUDIT_EVENT_ALPHA = {
    "id": "evt-1",
    "org_id": "org-1",
    "sequence": 1,
    "type": "evaluate.allow",
    "decision": "allow",
    "actor_id": "agent-1",
    "resource_type": None,
    "resource_id": None,
    "payload": {"action": "read_data"},
    "hash": "a" * 64,
    "previous_hash": "0" * 64,
    "occurred_at": "2026-04-21T00:00:00Z",
    "created_at": "2026-04-21T00:00:01Z",
}


AUDIT_EVENTS_PAGE = {
    "events": [AUDIT_EVENT_ALPHA],
    "total": 1,
    "next_cursor": "cursor_beta",
}


AUDIT_EXPORT_BUNDLE = {
    "export_id": "export-1",
    "org_id": "org-1",
    "events": [AUDIT_EVENT_ALPHA],
    "chain_head_hash": "a" * 64,
    "chain_integrity_ok": True,
    "tampered_event_ids": [],
    "signature": "sig_bytes_base64url",
    "signature_status": "signed",
    "signing_key_id": "test-key",
    "signed_at": "2026-04-21T00:00:00Z",
    "event_count": 1,
}


class TestRevokePermit:
    REVOKE_OK = {
        "revoked": True,
        "decision_id": "dec_to_revoke",
        "revoked_at": "2026-04-30T01:00:00Z",
        "audit_hash": "hash_revoked",
    }

    def test_revoke_returns_result(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKE_OK)
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.revoke_permit("dec_to_revoke", reason="policy violation")
        assert result.revoked is True
        assert result.permit_id == "dec_to_revoke"
        assert result.revoked_at == "2026-04-30T01:00:00Z"

    def test_revoke_sends_correct_payload(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKE_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        client.revoke_permit("dec_to_revoke", reason="audit")
        payload = mock_post.call_args[1]["json"]
        # /v1-revoke-permit is out of scope for the v1-evaluate /
        # v1-verify-permit contract reconciliation — it still uses the
        # legacy decision_id / api_key body fields.
        assert payload["decision_id"] == "dec_to_revoke"
        assert payload["reason"] == "audit"
        assert payload["api_key"] == "ask_test_xxxxxxxx"

    def test_revoke_defaults_reason_to_empty_string(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKE_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        client.revoke_permit("dec_to_revoke")
        assert mock_post.call_args[1]["json"]["reason"] == ""

    def test_revoke_bad_response_missing_revoked(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"decision_id": "dec_x"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.revoke_permit("dec_x")
        assert exc_info.value.code == "bad_response"

    def test_revoke_bad_response_missing_decision_id(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"revoked": True})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.revoke_permit("dec_x")
        assert exc_info.value.code == "bad_response"

    def test_revoke_surfaces_rate_limit(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data=self.REVOKE_OK,
            headers={
                "x-ratelimit-limit": "100",
                "x-ratelimit-remaining": "50",
                "x-ratelimit-reset": "9999999999",
            },
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.revoke_permit("dec_to_revoke")
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 100


class TestListAuditEvents:
    def test_issues_get_to_v1_audit_events_with_snake_case_body(self, client, mocker):
        resp = _mock_resp(mocker, json_data=AUDIT_EVENTS_PAGE)
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        result = client.list_audit_events()

        assert isinstance(result, AuditEventsResult)
        assert result.total == 1
        assert result.next_cursor == "cursor_beta"
        assert result.events[0].id == "evt-1"
        assert result.events[0].previous_hash == "0" * 64
        assert result.events[0].decision == "allow"
        assert result.rate_limit is None

        url = get_mock.call_args[0][0]
        assert "/v1-audit/events" in url
        assert get_mock.call_args.kwargs.get("params") == {}

    def test_forwards_every_filter_as_snake_case_params(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"events": [], "total": 0})
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        client.list_audit_events(
            types="evaluate.allow,policy.updated",
            actor_id="agent-1",
            from_="2026-04-20T00:00:00Z",
            to="2026-04-22T00:00:00Z",
            limit=25,
            cursor="abc",
        )
        assert get_mock.call_args.kwargs["params"] == {
            "types": "evaluate.allow,policy.updated",
            "actor_id": "agent-1",
            "from": "2026-04-20T00:00:00Z",
            "to": "2026-04-22T00:00:00Z",
            "limit": "25",
            "cursor": "abc",
        }

    def test_omits_unset_filter_fields(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"events": [], "total": 0})
        get_mock = mocker.patch.object(client._client, "get", return_value=resp)
        client.list_audit_events(types="evaluate.allow")
        assert get_mock.call_args.kwargs["params"] == {"types": "evaluate.allow"}

    def test_surfaces_rate_limit_headers(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data=AUDIT_EVENTS_PAGE,
            headers={
                "x-ratelimit-limit": "500",
                "x-ratelimit-remaining": "499",
                "x-ratelimit-reset": "1714070000",
            },
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.list_audit_events()
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 500
        assert result.rate_limit.remaining == 499

    def test_bad_response_on_missing_events(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"total": 0})
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.list_audit_events()
        assert excinfo.value.code == "bad_response"

    def test_bad_response_on_missing_total(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"events": []})
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.list_audit_events()
        assert excinfo.value.code == "bad_response"


class TestCreateAuditExport:
    def test_posts_empty_filter_by_default_and_preserves_bundle(self, client, mocker):
        resp = _mock_resp(mocker, json_data=AUDIT_EXPORT_BUNDLE)
        post_mock = mocker.patch.object(client._client, "post", return_value=resp)
        result = client.create_audit_export()

        assert isinstance(result, AuditExportResult)
        # bundle is the server's raw dict — identity matters for signature verification.
        assert result.bundle is AUDIT_EXPORT_BUNDLE
        assert result.export_id == "export-1"
        assert result.org_id == "org-1"
        assert result.chain_head_hash == "a" * 64
        assert result.signature == "sig_bytes_base64url"
        assert result.signature_status == "signed"
        assert result.signing_key_id == "test-key"
        assert result.event_count == 1
        assert result.rate_limit is None

        assert "/v1-audit/exports" in post_mock.call_args[0][0]
        assert post_mock.call_args.kwargs["json"] == {}

    def test_forwards_filter_fields_as_json_body(self, client, mocker):
        resp = _mock_resp(mocker, json_data=AUDIT_EXPORT_BUNDLE)
        post_mock = mocker.patch.object(client._client, "post", return_value=resp)
        client.create_audit_export(
            types="evaluate.allow",
            actor_id="agent-1",
            from_="2026-04-20T00:00:00Z",
            to="2026-04-22T00:00:00Z",
        )
        assert post_mock.call_args.kwargs["json"] == {
            "types": "evaluate.allow",
            "actor_id": "agent-1",
            "from": "2026-04-20T00:00:00Z",
            "to": "2026-04-22T00:00:00Z",
        }

    def test_bundle_round_trips_through_offline_verifier(self, client, mocker):
        """Byte-identical round-trip: the bundle dict returned by
        create_audit_export should flow straight into verify_audit_bundle
        without reshaping or key-reorder."""
        import atlasent

        resp = _mock_resp(mocker, json_data=AUDIT_EXPORT_BUNDLE)
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.create_audit_export()
        # No signing keys configured — signature check is skipped, but
        # the chain-integrity check exercises the bundle structure.
        outcome = atlasent.verify_audit_bundle(result.bundle, keys=[])
        # The fixture's hash fields are synthetic so the chain check
        # will fail — the assertion we care about is that the call
        # completes without raising, proving dict compatibility.
        assert outcome is not None

    def test_surfaces_rate_limit_headers(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data=AUDIT_EXPORT_BUNDLE,
            headers={
                "x-ratelimit-limit": "10",
                "x-ratelimit-remaining": "9",
                "x-ratelimit-reset": "1714070000",
            },
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.create_audit_export()
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 10

    def test_bad_response_on_missing_export_id(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data={"chain_head_hash": "x", "events": []},
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.create_audit_export()
        assert excinfo.value.code == "bad_response"

    def test_bad_response_on_non_array_events(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data={"export_id": "e", "chain_head_hash": "x", "events": "nope"},
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as excinfo:
            client.create_audit_export()
        assert excinfo.value.code == "bad_response"

    def test_empty_bundle_exposes_defaults(self, client, mocker):
        resp = _mock_resp(
            mocker,
            json_data={
                "export_id": "e",
                "org_id": "o",
                "events": [],
                "chain_head_hash": "0" * 64,
            },
        )
        mocker.patch.object(client._client, "post", return_value=resp)
        result = client.create_audit_export()
        assert result.events == []
        assert result.tampered_event_ids == []
        assert result.signature == ""
        # signature_status falls through to 'unsigned' when the server omitted it.
        assert result.signature_status == "unsigned"
        assert result.signing_key_id is None
        assert result.signed_at == ""
        assert result.event_count == 0  # len(events) fallback when count missing
        assert result.chain_integrity_ok is False


class TestContextSizeWarning:
    """Phase B.3 — soft cap on context properties surfaces as a warning,
    not a hard error. The hosted API enforces the hard cap in
    contract/openapi.yaml; the SDK adds a developer-visible nudge
    without breaking production traffic on the day this ships.
    """

    def test_oversize_context_logs_warning(self, caplog):
        import logging

        from atlasent.models import EvaluateRequest

        oversize = {f"k{i}": i for i in range(70)}
        with caplog.at_level(logging.WARNING, logger="atlasent"):
            req = EvaluateRequest(action="a", agent="b", context=oversize)

        assert req.context == oversize
        assert any(
            "soft cap" in record.message and "70 top-level" in record.message
            for record in caplog.records
        )

    def test_in_bounds_context_does_not_warn(self, caplog):
        import logging

        from atlasent.models import EvaluateRequest

        ctx = {f"k{i}": i for i in range(10)}
        with caplog.at_level(logging.WARNING, logger="atlasent"):
            EvaluateRequest(action="a", agent="b", context=ctx)

        assert not any("soft cap" in record.message for record in caplog.records)


class TestGetPermit:
    PERMIT = {
        "id": "pt_alpha",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "verified",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
        "consumed_at": None,
        "revoked_at": None,
        "revoked_by": None,
        "revoke_reason": None,
        "payload_hash": "sha256:deadbeef",
        "decision_id": "eval_a",
    }

    def test_returns_permit(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.PERMIT)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        result = client.get_permit("pt_alpha")
        assert result.permit.id == "pt_alpha"
        assert result.permit.status == "verified"
        url = mock_get.call_args[0][0]
        assert url.endswith("/v1-permits/pt_alpha")

    def test_url_encodes_id(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.PERMIT)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        client.get_permit("pt with spaces")
        url = mock_get.call_args[0][0]
        assert url.endswith("/v1-permits/pt%20with%20spaces")

    def test_empty_id_raises(self, client):
        with pytest.raises(AtlaSentError) as exc_info:
            client.get_permit("")
        assert exc_info.value.code == "bad_request"

    def test_surfaces_revocation(self, client, mocker):
        revoked = dict(
            self.PERMIT,
            status="revoked",
            revoked_at="2026-05-07T01:10:00Z",
            revoked_by="user_admin",
            revoke_reason="approval rescinded",
        )
        resp = _mock_resp(mocker, json_data=revoked)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.get_permit("pt_alpha")
        assert result.permit.status == "revoked"
        assert result.permit.revoked_at == "2026-05-07T01:10:00Z"
        assert result.permit.revoked_by == "user_admin"
        assert result.permit.revoke_reason == "approval rescinded"


class TestExplainAuthority:
    EXPLANATION = {
        "organization_id": "org_1",
        "principal_id": "principal_1",
        "requested_scope": "production:deployment.production.approve",
        "resource_id": None,
        "authority_found": True,
        "paths": [
            {
                "mechanism": "role_capability",
                "matched": True,
                "edges": [
                    {
                        "source_table": "user_roles",
                        "evidence_posture": "direct",
                        "authority_basis": "role_grant",
                        "role": "deployer",
                    }
                ],
            }
        ],
        "unresolved": [],
    }

    def test_returns_explanation(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.EXPLANATION)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        result = client.explain_authority(
            "principal_1",
            "production:deployment.production.approve",
            resource_id="res_1",
        )
        assert result.organization_id == "org_1"
        assert result.principal_id == "principal_1"
        assert result.authority_found is True
        assert len(result.paths) == 1
        assert result.paths[0].mechanism == "role_capability"
        assert result.unresolved == []

        url = mock_get.call_args[0][0]
        # Hyphenated (edge-function-name) form — the real handler strips
        # `/v1-authority-intelligence/` as a literal prefix; the slash form
        # from the committed OpenAPI docs never matches and 404s.
        assert url.endswith("/v1-authority-intelligence/explain-authority")
        params = mock_get.call_args.kwargs["params"]
        assert params == {
            "principal_id": "principal_1",
            "requested_scope": "production:deployment.production.approve",
            "resource_id": "res_1",
        }

    def test_omits_resource_id_when_not_supplied(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.EXPLANATION)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        client.explain_authority(
            "principal_1", "production:deployment.production.approve"
        )
        params = mock_get.call_args.kwargs["params"]
        assert "resource_id" not in params

    def test_surfaces_unresolved_finding_when_not_found(self, client, mocker):
        not_found = dict(
            self.EXPLANATION,
            authority_found=False,
            paths=[],
            unresolved=[
                {
                    "finding_type": "NO_AUTHORITY_PATH_FOUND",
                    "reason": "no matching grant, delegation, or role capability",
                }
            ],
        )
        resp = _mock_resp(mocker, json_data=not_found)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.explain_authority(
            "principal_1", "production:deployment.production.approve"
        )
        assert result.authority_found is False
        assert len(result.unresolved) == 1
        assert result.unresolved[0].finding_type == "NO_AUTHORITY_PATH_FOUND"

    def test_empty_principal_id_raises(self, client):
        with pytest.raises(AtlaSentError) as exc_info:
            client.explain_authority("", "production:deployment.production.approve")
        assert exc_info.value.code == "bad_request"

    def test_empty_requested_scope_raises(self, client):
        with pytest.raises(AtlaSentError) as exc_info:
            client.explain_authority("principal_1", "")
        assert exc_info.value.code == "bad_request"

    def test_validation_error_makes_no_request(self, client, mocker):
        mock_get = mocker.patch.object(client._client, "get")
        with pytest.raises(AtlaSentError):
            client.explain_authority("", "production:deployment.production.approve")
        mock_get.assert_not_called()

    def test_403_surfaces_as_forbidden(self, client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"reason": "missing authority_intelligence:read scope"}
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.explain_authority(
                "principal_1", "production:deployment.production.approve"
            )
        assert exc_info.value.code == "forbidden"


class TestListPermits:
    LIST = {
        "permits": [
            {
                "id": "pt_a",
                "org_id": "org_x",
                "actor_id": "a",
                "action_id": "x",
                "status": "issued",
                "issued_at": "2026-05-07T01:00:00Z",
                "expires_at": "2026-05-07T01:15:00Z",
            },
            {
                "id": "pt_b",
                "org_id": "org_x",
                "actor_id": "a",
                "action_id": "x",
                "status": "consumed",
                "issued_at": "2026-05-07T00:00:00Z",
                "expires_at": "2026-05-07T00:15:00Z",
                "consumed_at": "2026-05-07T00:10:00Z",
            },
        ],
        "total": 2,
    }

    def test_returns_list(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.LIST)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        result = client.list_permits()
        assert len(result.permits) == 2
        assert result.total == 2
        url = mock_get.call_args[0][0]
        assert url.endswith("/v1-permits")
        # No query params when no filters
        assert mock_get.call_args[1].get("params") is None

    def test_passes_filters_as_query_params(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.LIST)
        mock_get = mocker.patch.object(client._client, "get", return_value=resp)
        client.list_permits(
            status="revoked",
            actor_id="user_42",
            action_type="ehr.write",
            from_="2026-05-01T00:00:00Z",
            to="2026-05-07T00:00:00Z",
            limit=100,
            cursor="2026-05-06T00:00:00Z",
        )
        params = mock_get.call_args[1]["params"]
        assert params["status"] == "revoked"
        assert params["actor_id"] == "user_42"
        assert params["action_type"] == "ehr.write"
        assert params["from"] == "2026-05-01T00:00:00Z"
        assert params["to"] == "2026-05-07T00:00:00Z"
        assert params["limit"] == "100"
        assert params["cursor"] == "2026-05-06T00:00:00Z"

    def test_surfaces_next_cursor(self, client, mocker):
        resp = _mock_resp(
            mocker, json_data={**self.LIST, "next_cursor": "2026-05-06T23:00:00Z"}
        )
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.list_permits(limit=2)
        assert result.next_cursor == "2026-05-06T23:00:00Z"

    def test_bad_response_missing_permits(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"total": 0})
        mocker.patch.object(client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.list_permits()
        assert exc_info.value.code == "bad_response"

    def test_total_falls_back_to_permits_length(self, client, mocker):
        without_total = {"permits": self.LIST["permits"]}
        resp = _mock_resp(mocker, json_data=without_total)
        mocker.patch.object(client._client, "get", return_value=resp)
        result = client.list_permits()
        assert result.total == 2


class TestDeprecationWarnings:
    """Tier 3 of pilot-readiness: legacy entrypoints emit
    DeprecationWarning. Canonical surface is protect() / evaluate() /
    verify().
    """

    def test_client_authorize_emits_deprecation_warning(self, client, mocker):
        # Mock evaluate path so authorize() doesn't try to network.
        mocker.patch.object(
            client,
            "evaluate",
            side_effect=AtlaSentDenied(
                "deny",
                permit_token="dec_x",
                reason="policy denied",
                response_body={},
            ),
        )
        with pytest.warns(DeprecationWarning, match="authorize"):
            client.authorize(agent="a", action="b")

    def test_client_gate_emits_deprecation_warning(self, client, mocker):
        mocker.patch.object(
            client,
            "evaluate",
            return_value=EvaluateResult(decision="allow", permit_token="t"),
        )
        mocker.patch.object(
            client,
            "verify",
            return_value=VerifyResult(
                valid=True, outcome="allow", permit_hash="h", timestamp="t"
            ),
        )
        with pytest.warns(DeprecationWarning, match="gate"):
            client.gate("act", "actor")

    def test_protect_does_not_emit_deprecation_warning(self, client, mocker):
        # Canonical surface — must not emit.
        mocker.patch.object(
            client,
            "evaluate",
            return_value=EvaluateResult(decision="allow", permit_token="t"),
        )
        mocker.patch.object(
            client,
            "verify",
            return_value=VerifyResult(
                valid=True, outcome="allow", permit_hash="h", timestamp="t"
            ),
        )
        import warnings as _warnings

        with _warnings.catch_warnings():
            _warnings.simplefilter("error", DeprecationWarning)
            client.protect(
                agent="a",
                action="production.deploy",
                context={"environment": "production"},
            )  # must not raise

    def test_evaluate_does_not_emit_deprecation_warning(self, client, mocker):
        # Canonical surface — must not emit.
        resp = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(client._client, "post", return_value=resp)
        import warnings as _warnings

        with _warnings.catch_warnings():
            _warnings.simplefilter("error", DeprecationWarning)
            client.evaluate("act", "actor")  # must not raise


class TestRevokePermitById:
    REVOKED = {
        "id": "pt_alpha",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "revoked",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
        "revoked_at": "2026-05-07T01:10:00Z",
        "revoked_by": "user_admin",
        "revoke_reason": "approval rescinded",
    }

    def test_returns_updated_permit(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKED)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        result = client.revoke_permit_by_id("pt_alpha", reason="approval rescinded")
        url = mock_post.call_args[0][0]
        body = mock_post.call_args[1]["json"]
        assert url.endswith("/v1-permits/pt_alpha/revoke")
        assert body == {"reason": "approval rescinded"}
        assert result.permit.status == "revoked"
        assert result.permit.revoked_at == "2026-05-07T01:10:00Z"
        assert result.permit.revoked_by == "user_admin"
        assert result.permit.revoke_reason == "approval rescinded"

    def test_omits_reason_when_not_supplied(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKED)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        client.revoke_permit_by_id("pt_alpha")
        body = mock_post.call_args[1]["json"]
        assert body == {}

    def test_url_encodes_id(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKED)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        client.revoke_permit_by_id("pt with spaces")
        url = mock_post.call_args[0][0]
        assert url.endswith("/v1-permits/pt%20with%20spaces/revoke")

    def test_empty_id_raises(self, client):
        with pytest.raises(AtlaSentError) as exc_info:
            client.revoke_permit_by_id("")
        assert exc_info.value.code == "bad_request"


class TestVerifyPermitById:
    VERIFY_OK = {
        "valid": True,
        "verification_type": "permit",
        "reason": None,
        "verified_at": "2026-05-07T01:00:00.214Z",
        "evidence": {
            "permit_id": "pt_alpha",
            "status": "verified",
            "actor_id": "agent-1",
            "action_id": "ehr.write",
            "expires_at": "2026-05-07T01:15:00Z",
            "payload_hash": "sha256:deadbeef",
            "decision_id": "eval_a",
        },
        # legacy fields preserved at top level (allOf in openapi)
        "id": "pt_alpha",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "verified",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
        "payload_hash": "sha256:deadbeef",
        "decision_id": "eval_a",
    }

    def test_returns_canonical_envelope(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.VERIFY_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        result = client.verify_permit_by_id("pt_alpha")
        url = mock_post.call_args[0][0]
        assert url.endswith("/v1-permits/pt_alpha/verify")
        assert result.valid is True
        assert result.verification_type == "permit"
        assert result.reason is None
        assert result.verified_at == "2026-05-07T01:00:00.214Z"
        assert result.evidence.permit_id == "pt_alpha"
        assert result.evidence.status == "verified"
        assert result.permit.id == "pt_alpha"
        assert result.permit.status == "verified"

    def test_url_encodes_id(self, client, mocker):
        resp = _mock_resp(mocker, json_data=self.VERIFY_OK)
        mock_post = mocker.patch.object(client._client, "post", return_value=resp)
        client.verify_permit_by_id("pt with spaces")
        url = mock_post.call_args[0][0]
        assert url.endswith("/v1-permits/pt%20with%20spaces/verify")

    def test_empty_id_raises(self, client):
        with pytest.raises(AtlaSentError) as exc_info:
            client.verify_permit_by_id("")
        assert exc_info.value.code == "bad_request"

    def test_bad_response_missing_envelope_raises(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"id": "pt_alpha", "status": "verified"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            client.verify_permit_by_id("pt_alpha")
        assert exc_info.value.code == "bad_response"


class TestLegacyRevokeVerifyDeprecated:
    """Legacy revoke_permit() is deprecated; verify() is NOT.

    verify() calls /v1-verify-permit, the execution-boundary verifier
    (signature, binding and replay checks). verify_permit_by_id() is a
    lifecycle/status operation and is not a substitute, so verify() must
    not warn.
    """

    def test_legacy_revoke_permit_emits_warning(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"revoked": True, "decision_id": "dec_x"})
        mocker.patch.object(client._client, "post", return_value=resp)
        with pytest.warns(DeprecationWarning, match="revoke_permit"):
            client.revoke_permit("dec_x")

    def test_verify_does_not_warn(self, client, mocker):
        resp = _mock_resp(mocker, json_data={"valid": True, "outcome": "allow"})
        post = mocker.patch.object(client._client, "post", return_value=resp)
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            client.verify("pt_x")
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []
        assert post.call_args[0][0].endswith("/v1-verify-permit")

    def test_verify_docstring_not_deprecated(self):
        doc = AtlaSentClient.verify.__doc__ or ""
        assert ".. deprecated::" not in doc
        assert "it is not deprecated" in doc
        assert "execution boundary" in doc
        by_id = AtlaSentClient.verify_permit_by_id.__doc__ or ""
        assert "lifecycle/status operation" in by_id
        assert ":meth:`verify`" in by_id


class TestPermitFunctionRoutes:
    """Per-permit calls address the ``v1-permits`` function, id encoded.

    Under the hosted functions root the first path segment is the
    function name, so ``/v1/permits/...`` reaches no function.
    """

    NASTY = "pt/a b?c"
    ENC = "pt%2Fa%20b%3Fc"
    ROW = {
        "id": "pt_alpha",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "verified",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
    }

    def _verify_wire(self):
        return {
            "valid": True,
            "verification_type": "permit",
            "reason": None,
            "verified_at": "2026-05-07T01:00:00Z",
            "evidence": {"permit_id": "pt_alpha", "status": "verified"},
            **self.ROW,
        }

    def test_get_permit(self, client, mocker):
        get = mocker.patch.object(
            client._client, "get", return_value=_mock_resp(mocker, json_data=self.ROW)
        )
        client.get_permit(self.NASTY)
        assert get.call_args[0][0].endswith(f"/functions/v1/v1-permits/{self.ENC}")

    def test_list_permits(self, client, mocker):
        get = mocker.patch.object(
            client._client,
            "get",
            return_value=_mock_resp(mocker, json_data={"permits": [self.ROW]}),
        )
        client.list_permits(status="verified")
        assert get.call_args[0][0].endswith("/functions/v1/v1-permits")

    def test_verify_permit_by_id(self, client, mocker):
        post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=self._verify_wire()),
        )
        client.verify_permit_by_id(self.NASTY)
        assert post.call_args[0][0].endswith(
            f"/functions/v1/v1-permits/{self.ENC}/verify"
        )
        assert post.call_args.kwargs["json"] == {}

    def test_revoke_permit_by_id(self, client, mocker):
        post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data={**self.ROW, "status": "revoked"}
            ),
        )
        client.revoke_permit_by_id(self.NASTY, reason="superseded")
        assert post.call_args[0][0].endswith(
            f"/functions/v1/v1-permits/{self.ENC}/revoke"
        )
        assert post.call_args.kwargs["json"] == {"reason": "superseded"}
