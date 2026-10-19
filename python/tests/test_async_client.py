"""Tests for AsyncAtlaSentClient."""

import httpx
import pytest

from atlasent.async_client import AsyncAtlaSentClient
from atlasent.audit import AuditEventsResult, AuditExportResult
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

EVALUATE_PERMIT = {
    "permitted": True,
    "decision_id": "dec_100",
    "reason": "OK",
    "audit_hash": "hash_abc",
    "timestamp": "2025-01-15T12:00:00Z",
}

EVALUATE_DENY = {
    "permitted": False,
    "decision_id": "dec_101",
    "reason": "Denied",
    "audit_hash": "hash_def",
    "timestamp": "2025-01-15T12:01:00Z",
}

VERIFY_OK = {
    "verified": True,
    "permit_hash": "permit_xyz",
    "timestamp": "2025-01-15T12:05:00Z",
}


@pytest.fixture
def async_client():
    return AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)


@pytest.fixture
def async_client_retry():
    return AsyncAtlaSentClient(
        api_key="ask_test_xxxxxxxx", max_retries=2, retry_backoff=0.01
    )


def _mock_resp(mocker, status_code=200, json_data=None, headers=None):
    resp = mocker.Mock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = ""
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


class TestAsyncInit:
    def test_authorization_header(self):
        c = AsyncAtlaSentClient(api_key="ask_live_xyz")
        assert c._client.headers["authorization"] == "Bearer ask_live_xyz"

    def test_accept_header(self):
        c = AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx")
        assert c._client.headers["accept"] == "application/json"

    def test_user_agent_header(self):
        c = AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx")
        assert "atlasent-python/" in c._client.headers["user-agent"]


class TestAsyncEvaluate:
    @pytest.mark.asyncio
    async def test_permit(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_PERMIT),
        )
        result = await async_client.evaluate("read_data", "agent-1")
        assert isinstance(result, EvaluateResult)
        assert result.permitted is True  # legacy attr (canonical: result.decision)
        assert result.permit_token == "dec_100"

    @pytest.mark.asyncio
    async def test_deny_raises(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_DENY),
        )
        with pytest.raises(AtlaSentDenied) as exc_info:
            await async_client.evaluate("write_data", "agent-1")
        assert exc_info.value.reason == "Denied"

    @pytest.mark.asyncio
    async def test_timeout(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            side_effect=httpx.TimeoutException("t"),
        )
        with pytest.raises(AtlaSentError, match="timed out"):
            await async_client.evaluate("a", "b")

    @pytest.mark.asyncio
    async def test_connection_error(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            side_effect=httpx.ConnectError("refused"),
        )
        with pytest.raises(AtlaSentError, match="Failed to connect"):
            await async_client.evaluate("a", "b")


CONSTRAINT_TRACE_WIRE = {
    "rules_evaluated": [
        {
            "policy_id": "pol_close_window_v3",
            "decision": "deny",
            "fingerprint": "fp_abc123",
            "stages": [
                {
                    "stage": "context",
                    "rule": "change_reason_required",
                    "matched": False,
                    "detail": "context.change_reason missing",
                    "order": 0,
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
    # Older atlasent-api version that does not echo `constraint_trace`.
    "decision": "allow",
    "permit_token": "dec_pf_42",
    "request_id": "req_pf",
}


class TestAsyncEvaluatePreflight:
    @pytest.mark.asyncio
    async def test_appends_include_constraint_trace_query(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data=EVALUATE_PREFLIGHT_DENY_WITH_TRACE
            ),
        )
        await async_client.evaluate_preflight(
            "close_period", "agent-1", {"period": "2025-12"}
        )
        assert mock_post.call_args.kwargs["params"] == {"include": "constraint_trace"}
        body = mock_post.call_args.kwargs["json"]
        assert body == {
            "action_type": "close_period",
            "actor_id": "agent-1",
            "context": {"period": "2025-12"},
        }

    @pytest.mark.asyncio
    async def test_parses_typed_preflight_response(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data=EVALUATE_PREFLIGHT_DENY_WITH_TRACE
            ),
        )
        result = await async_client.evaluate_preflight("close_period", "agent-1")
        assert isinstance(result, EvaluatePreflightResult)
        assert result.evaluation.decision == "deny"
        assert isinstance(result.constraint_trace, ConstraintTrace)
        assert result.constraint_trace.matching_policy_id == "pol_close_window_v3"
        assert result.constraint_trace.rules_evaluated[0].stages[0].matched is False

    @pytest.mark.asyncio
    async def test_missing_trace_is_none_not_raises(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data=EVALUATE_PREFLIGHT_ALLOW_NO_TRACE
            ),
        )
        result = await async_client.evaluate_preflight("close_period", "agent-1")
        assert result.evaluation.decision == "allow"
        assert result.evaluation.permit_token == "dec_pf_42"
        assert result.constraint_trace is None


class TestAsyncVerify:
    @pytest.mark.asyncio
    async def test_valid(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=VERIFY_OK),
        )
        result = await async_client.verify("dec_100")
        assert isinstance(result, VerifyResult)
        assert result.valid is True


class TestAsyncGate:
    @pytest.mark.asyncio
    async def test_permit_and_verify(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            side_effect=[
                _mock_resp(mocker, json_data=EVALUATE_PERMIT),
                _mock_resp(mocker, json_data=VERIFY_OK),
            ],
        )
        result = await async_client.gate("read_data", "agent-1")
        assert isinstance(result, GateResult)
        assert result.evaluation.permit_token == "dec_100"
        assert result.verification.valid is True

    @pytest.mark.asyncio
    async def test_deny_at_evaluate(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_DENY),
        )
        with pytest.raises(AtlaSentDenied):
            await async_client.gate("write_data", "agent-1")
        assert async_client._client.post.call_count == 1


class TestAsyncRetry:
    @pytest.mark.asyncio
    async def test_retries_on_timeout(self, async_client_retry, mocker):
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(
            async_client_retry._client,
            "post",
            side_effect=[httpx.TimeoutException("t"), ok],
        )
        result = await async_client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"

    @pytest.mark.asyncio
    async def test_retries_on_5xx(self, async_client_retry, mocker):
        err = _mock_resp(mocker, status_code=502)
        err.text = "Bad Gateway"
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(async_client_retry._client, "post", side_effect=[err, ok])
        result = await async_client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"

    @pytest.mark.asyncio
    async def test_exhausted(self, async_client_retry, mocker):
        mocker.patch.object(
            async_client_retry._client,
            "post",
            side_effect=httpx.TimeoutException("t"),
        )
        with pytest.raises(AtlaSentError, match="3 attempts"):
            await async_client_retry.evaluate("a", "b")


class TestAsyncRateLimit:
    @pytest.mark.asyncio
    async def test_429(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": "5"})
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.retry_after == 5.0


class TestAsyncErrorCodes:
    @pytest.mark.asyncio
    async def test_401_has_invalid_api_key_code(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=401),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "invalid_api_key"

    @pytest.mark.asyncio
    async def test_timeout_has_timeout_code(self, async_client, mocker):
        mocker.patch.object(
            async_client._client, "post", side_effect=httpx.TimeoutException("t")
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "timeout"

    @pytest.mark.asyncio
    async def test_connection_error_has_network_code(self, async_client, mocker):
        mocker.patch.object(
            async_client._client, "post", side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "network"

    @pytest.mark.asyncio
    async def test_malformed_evaluate_body_is_bad_response(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data={"foo": "bar"})
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "bad_response"

    @pytest.mark.asyncio
    async def test_malformed_verify_body_is_bad_response(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data={"outcome": "ok"})
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.verify("dec_100")
        assert exc_info.value.code == "bad_response"


class TestAsyncLifecycle:
    @pytest.mark.asyncio
    async def test_context_manager(self, mocker):
        async with AsyncAtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0) as c:
            mock_close = mocker.patch.object(c._client, "aclose")
        mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close(self, async_client, mocker):
        mock_close = mocker.patch.object(async_client._client, "aclose")
        await async_client.close()
        mock_close.assert_called_once()


class TestAsyncCache:
    @pytest.mark.asyncio
    async def test_cache_hit_short_circuits_request(self, mocker):
        from atlasent.cache import TTLCache

        cache = TTLCache(ttl=60.0)
        client = AsyncAtlaSentClient(
            api_key="ask_test_xxxxxxxx", max_retries=0, cache=cache
        )
        post = mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_PERMIT),
        )
        first = await client.evaluate("read_data", "agent-1")
        second = await client.evaluate("read_data", "agent-1")
        assert first == second
        # Second call must come from the cache, not the network.
        assert post.call_count == 1


class TestAsyncRetryExhaustion:
    @pytest.mark.asyncio
    async def test_connect_error_retries_then_succeeds(
        self, async_client_retry, mocker
    ):
        ok = _mock_resp(mocker, json_data=EVALUATE_PERMIT)
        mocker.patch.object(
            async_client_retry._client,
            "post",
            side_effect=[httpx.ConnectError("refused"), ok],
        )
        result = await async_client_retry.evaluate("a", "b")
        assert result.permit_token == "dec_100"

    @pytest.mark.asyncio
    async def test_5xx_exhausted_raises_server_error(self, async_client_retry, mocker):
        err = _mock_resp(mocker, status_code=503)
        err.text = "Service Unavailable"
        mocker.patch.object(
            async_client_retry._client,
            "post",
            return_value=err,
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client_retry.evaluate("a", "b")
        assert exc_info.value.code == "server_error"
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_generic_httpx_error_maps_to_network_code(self, async_client, mocker):
        # httpx raises various HTTPError subclasses (ProtocolError,
        # ReadError, etc.) that aren't Timeout/ConnectError. They should
        # all surface as code="network".
        mocker.patch.object(
            async_client._client,
            "post",
            side_effect=httpx.ReadError("connection reset"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "network"


class TestAsyncHttpStatusCodes:
    @pytest.mark.asyncio
    async def test_403_has_forbidden_code(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=403),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "forbidden"
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_422_has_bad_request_code(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=422)
        resp.text = "validation failed"
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "bad_request"
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_403_surfaces_server_message_from_json(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"message": "key lacks phi:read scope"}
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert "key lacks phi:read scope" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_403_prefers_error_field_over_message(self, async_client, mocker):
        # Phase 4 ErrorEnvelope: body.error is canonical and must win
        # over the legacy `message` / `reason` keys.
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {
            "error": "phi_scope_required",
            "message": "fallback should not appear",
        }
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert "phi_scope_required" in str(exc_info.value)
        assert "fallback should not appear" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_200_with_invalid_json_is_bad_response(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=200)
        resp.json.side_effect = ValueError("not json")
        resp.text = "plaintext, not JSON"
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "bad_response"


class TestAsyncRetryAfter:
    @pytest.mark.asyncio
    async def test_429_with_non_numeric_retry_after_falls_back_to_none(
        self, async_client, mocker
    ):
        resp = _mock_resp(
            mocker, status_code=429, headers={"retry-after": "not-a-number"}
        )
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.retry_after is None

    @pytest.mark.asyncio
    async def test_429_without_retry_after_header(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=429)
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.retry_after is None

    @pytest.mark.asyncio
    async def test_429_with_http_date_retry_after(self, async_client, mocker):
        from datetime import datetime, timedelta, timezone

        future = datetime.now(timezone.utc) + timedelta(seconds=45)
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": http_date})
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        # Allow scheduling slack around the 45s encoded in the header.
        assert exc_info.value.retry_after is not None
        assert 30.0 <= exc_info.value.retry_after <= 45.0

    @pytest.mark.asyncio
    async def test_429_with_http_date_in_the_past_clamps_to_zero(
        self, async_client, mocker
    ):
        from datetime import datetime, timedelta, timezone

        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        http_date = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": http_date})
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.retry_after == 0.0


class TestAsyncRequestIdOnExceptions:
    """Every SDK-raised exception must carry the X-Request-ID we sent."""

    @pytest.mark.asyncio
    async def test_401_surfaces_request_id(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=401),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent
        assert exc_info.value.request_id  # non-empty

    @pytest.mark.asyncio
    async def test_429_surfaces_request_id(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=429, headers={"retry-after": "1"})
        mock_post = mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError) as exc_info:
            await async_client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    @pytest.mark.asyncio
    async def test_timeout_surfaces_request_id(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            side_effect=httpx.TimeoutException("t"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    @pytest.mark.asyncio
    async def test_deny_surfaces_request_id(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=EVALUATE_DENY),
        )
        with pytest.raises(AtlaSentDenied) as exc_info:
            await async_client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.request_id == sent

    @pytest.mark.asyncio
    async def test_malformed_body_surfaces_request_id(self, async_client, mocker):
        # Raised AFTER _post returns — catches that request_id is
        # threaded out of _post via its new (body, request_id) return.
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data={"foo": "bar"}),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        sent = mock_post.call_args[1]["headers"]["X-Request-ID"]
        assert exc_info.value.code == "bad_response"
        assert exc_info.value.request_id == sent


# ── key_self (async) ────────────────────────────────────────────────


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


class TestAsyncKeySelf:
    @pytest.mark.asyncio
    async def test_returns_typed_result(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=KEY_SELF_PAYLOAD),
        )
        result = await async_client.key_self()
        assert isinstance(result, ApiKeySelfResult)
        assert result.key_id == KEY_SELF_PAYLOAD["key_id"]
        assert result.environment == "live"
        assert result.scopes == ["evaluate", "audit.read"]
        assert result.expires_at == "2026-12-31T23:59:59Z"
        assert result.rate_limit is None

    @pytest.mark.asyncio
    async def test_issues_get_not_post(self, async_client, mocker):
        get_mock = mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=KEY_SELF_PAYLOAD),
        )
        post_mock = mocker.patch.object(async_client._client, "post")
        await async_client.key_self()
        assert get_mock.call_count == 1
        assert post_mock.call_count == 0
        assert "/v1-api-key-self" in get_mock.call_args[0][0]

    @pytest.mark.asyncio
    async def test_bad_response_on_missing_org_id(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(
                mocker,
                json_data={
                    "key_id": "k",
                    "environment": "live",
                    "rate_limit_per_minute": 60,
                },
            ),
        )
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.key_self()
        assert excinfo.value.code == "bad_response"

    @pytest.mark.asyncio
    async def test_surfaces_rate_limit_headers(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(
                mocker,
                json_data=KEY_SELF_PAYLOAD,
                headers={
                    "x-ratelimit-limit": "600",
                    "x-ratelimit-remaining": "0",
                    "x-ratelimit-reset": "1714068060",
                },
            ),
        )
        result = await async_client.key_self()
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 600
        assert result.rate_limit.remaining == 0


# ── compliance_controls / compliance_evidence_pack (async) ───────────


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
            "doc_ref": None,
            "display_order": 1,
            "status": "enforced",
            "metric": {"count": 42},
        }
    ],
    "truncated": False,
}

COMPLIANCE_PACK_PAYLOAD = {
    "framework": "cfr_part_11",
    "window": {"from": None, "to": None},
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
        "window": {"from": None, "to": None},
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


class TestAsyncCompliance:
    @pytest.mark.asyncio
    async def test_controls_returns_typed_result(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=COMPLIANCE_CONTROLS_PAYLOAD),
        )
        result = await async_client.compliance_controls(framework="cfr_part_11")
        assert isinstance(result, ComplianceControlsResult)
        assert result.framework == "cfr_part_11"
        assert len(result.controls) == 1
        assert result.controls[0].status == "enforced"

    @pytest.mark.asyncio
    async def test_controls_bad_response(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(
                mocker, json_data={"generated_at": "2026-06-19T00:00:00Z"}
            ),
        )
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.compliance_controls()
        assert excinfo.value.code == "bad_response"

    @pytest.mark.asyncio
    async def test_pack_returns_typed_result(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=COMPLIANCE_PACK_PAYLOAD),
        )
        result = await async_client.compliance_evidence_pack(framework="cfr_part_11")
        assert isinstance(result, ComplianceEvidencePackResult)
        assert result.sha256 == "a" * 64
        assert result.bundle.schema_ == "atlasent.compliance.evidence_pack.v1"

    @pytest.mark.asyncio
    async def test_pack_framework_required(self, async_client, mocker):
        get_mock = mocker.patch.object(async_client._client, "get")
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.compliance_evidence_pack(framework="")
        assert excinfo.value.code == "bad_request"
        assert get_mock.call_count == 0

    @pytest.mark.asyncio
    async def test_pack_bad_response(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(
                mocker, json_data={"framework": "cfr_part_11", "sha256": "a" * 64}
            ),
        )
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.compliance_evidence_pack(framework="cfr_part_11")
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


class TestAsyncListAuditEvents:
    @pytest.mark.asyncio
    async def test_issues_get_with_snake_case_params(self, async_client, mocker):
        get_mock = mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=AUDIT_EVENTS_PAGE),
        )
        result = await async_client.list_audit_events(
            types="evaluate.allow",
            actor_id="agent-1",
            from_="2026-04-20T00:00:00Z",
            to="2026-04-22T00:00:00Z",
            limit=25,
            cursor="abc",
        )

        assert isinstance(result, AuditEventsResult)
        assert result.total == 1
        assert result.next_cursor == "cursor_beta"
        assert result.events[0].id == "evt-1"
        assert "/v1-audit/events" in get_mock.call_args[0][0]
        assert get_mock.call_args.kwargs["params"] == {
            "types": "evaluate.allow",
            "actor_id": "agent-1",
            "from": "2026-04-20T00:00:00Z",
            "to": "2026-04-22T00:00:00Z",
            "limit": "25",
            "cursor": "abc",
        }

    @pytest.mark.asyncio
    async def test_omits_unset_params(self, async_client, mocker):
        get_mock = mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data={"events": [], "total": 0}),
        )
        await async_client.list_audit_events()
        assert get_mock.call_args.kwargs["params"] == {}

    @pytest.mark.asyncio
    async def test_surfaces_rate_limit_headers(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(
                mocker,
                json_data=AUDIT_EVENTS_PAGE,
                headers={
                    "x-ratelimit-limit": "500",
                    "x-ratelimit-remaining": "499",
                    "x-ratelimit-reset": "1714070000",
                },
            ),
        )
        result = await async_client.list_audit_events()
        assert result.rate_limit is not None
        assert result.rate_limit.remaining == 499

    @pytest.mark.asyncio
    async def test_bad_response_on_missing_events(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data={"total": 0}),
        )
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.list_audit_events()
        assert excinfo.value.code == "bad_response"


class TestAsyncCreateAuditExport:
    @pytest.mark.asyncio
    async def test_posts_empty_body_by_default_and_preserves_bundle(
        self, async_client, mocker
    ):
        post_mock = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=AUDIT_EXPORT_BUNDLE),
        )
        result = await async_client.create_audit_export()

        assert isinstance(result, AuditExportResult)
        assert result.bundle is AUDIT_EXPORT_BUNDLE
        assert result.export_id == "export-1"
        assert result.signature == "sig_bytes_base64url"
        assert result.signing_key_id == "test-key"
        assert "/v1-audit/exports" in post_mock.call_args[0][0]
        assert post_mock.call_args.kwargs["json"] == {}

    @pytest.mark.asyncio
    async def test_forwards_filter_fields(self, async_client, mocker):
        post_mock = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=AUDIT_EXPORT_BUNDLE),
        )
        await async_client.create_audit_export(
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

    @pytest.mark.asyncio
    async def test_surfaces_rate_limit_headers(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker,
                json_data=AUDIT_EXPORT_BUNDLE,
                headers={
                    "x-ratelimit-limit": "10",
                    "x-ratelimit-remaining": "9",
                    "x-ratelimit-reset": "1714070000",
                },
            ),
        )
        result = await async_client.create_audit_export()
        assert result.rate_limit is not None
        assert result.rate_limit.limit == 10

    @pytest.mark.asyncio
    async def test_bad_response_on_missing_fields(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data={"chain_head_hash": "x", "events": []}
            ),
        )
        with pytest.raises(AtlaSentError) as excinfo:
            await async_client.create_audit_export()
        assert excinfo.value.code == "bad_response"


REVOKE_OK_WIRE = {
    "revoked": True,
    "decision_id": "dec_to_revoke",
    "revoked_at": "2026-04-30T01:00:00Z",
    "audit_hash": "hash_revoked",
}


class TestAsyncRevokePermit:
    async def test_revoke_returns_result(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=REVOKE_OK_WIRE),
        )
        result = await async_client.revoke_permit("dec_to_revoke", reason="policy")
        assert result.revoked is True
        assert result.permit_id == "dec_to_revoke"

    async def test_revoke_sends_correct_payload(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=REVOKE_OK_WIRE),
        )
        await async_client.revoke_permit("dec_to_revoke", reason="audit")
        payload = mock_post.call_args[1]["json"]
        # /v1-revoke-permit is out of scope for this PR.
        assert payload["decision_id"] == "dec_to_revoke"
        assert payload["reason"] == "audit"

    async def test_revoke_defaults_reason_to_empty_string(self, async_client, mocker):
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=REVOKE_OK_WIRE),
        )
        await async_client.revoke_permit("dec_to_revoke")
        assert mock_post.call_args[1]["json"]["reason"] == ""

    async def test_revoke_bad_response_missing_revoked(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data={"decision_id": "dec_x"}),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.revoke_permit("dec_x")
        assert exc_info.value.code == "bad_response"

    async def test_revoke_bad_response_missing_decision_id(self, async_client, mocker):
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data={"revoked": True}),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.revoke_permit("dec_x")
        assert exc_info.value.code == "bad_response"


class TestAsyncRetryExhaustionNetwork:
    async def test_all_connect_retries_exhausted_raises_network(
        self, async_client_retry, mocker
    ):
        mocker.patch.object(
            async_client_retry._client,
            "post",
            side_effect=httpx.ConnectError("refused"),
        )
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client_retry.evaluate("a", "b")
        assert exc_info.value.code == "network"
        assert "attempts" in exc_info.value.message


class TestAsyncServerMessageEdgeCases:
    async def test_403_body_with_no_message_or_reason_key(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"error": "forbidden"}
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "forbidden"

    async def test_403_json_parse_failure_uses_default_message(
        self, async_client, mocker
    ):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.side_effect = ValueError("not json")
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(AtlaSentError) as exc_info:
            await async_client.evaluate("a", "b")
        assert exc_info.value.code == "forbidden"

    async def test_parse_retry_after_naive_http_date_gets_utc(
        self, async_client, mocker
    ):
        resp = _mock_resp(
            mocker, status_code=429, headers={"retry-after": "not-a-number"}
        )
        mocker.patch.object(async_client._client, "post", return_value=resp)
        with pytest.raises(RateLimitError):
            await async_client.evaluate("a", "b")


class TestParseSseEdgeCases:
    """Coverage for _parse_sse() paths not reached by test_stream.py."""

    async def test_blank_line_with_no_accumulated_data_is_ignored(self):
        from atlasent.async_client import _parse_sse

        async def lines():
            yield ""  # blank line with no prior data
            yield "event: decision"
            yield (
                'data: {"permitted":true,"decision_id":"d1","reason":"ok",'
                '"audit_hash":"h","timestamp":"2026-01-01T00:00:00Z","is_final":true}'
            )
            yield ""  # dispatch decision
            yield "data: {}"
            yield ""  # dispatch done → return

        events = [e async for e in _parse_sse(lines(), "rid_test")]
        assert len(events) == 1

    async def test_malformed_json_in_sse_data_raises(self):
        from atlasent.async_client import _parse_sse

        async def lines():
            yield "event: decision"
            yield "data: {not valid json"
            yield ""

        with pytest.raises(AtlaSentError) as exc_info:
            async for _ in _parse_sse(lines(), "rid_test"):
                pass
        assert exc_info.value.code == "bad_response"

    async def test_iterator_exhausts_without_done_returns_cleanly(self):
        from atlasent.async_client import _parse_sse

        async def lines():
            yield "event: decision"
            yield (
                'data: {"permitted":true,"decision_id":"d1","reason":"ok",'
                '"audit_hash":"h","timestamp":"2026-01-01T00:00:00Z","is_final":true}'
            )
            yield ""
            # no done event — iterator just ends

        events = [e async for e in _parse_sse(lines(), "rid_test")]
        assert len(events) == 1

    async def test_unknown_line_type_is_silently_skipped(self):
        from atlasent.async_client import _parse_sse

        async def lines():
            yield ": this is a comment"  # SSE comment, matches none of the conditions
            yield "event: decision"
            yield (
                'data: {"permitted":true,"decision_id":"d2","reason":"ok",'
                '"audit_hash":"h","timestamp":"2026-01-01T00:00:00Z","is_final":true}'
            )
            yield ""
            yield "event: done"
            yield "data: {}"
            yield ""

        events = [e async for e in _parse_sse(lines(), "rid_test")]
        assert len(events) == 1


class TestAsyncGetPermit:
    PERMIT = {
        "id": "pt_a",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "verified",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
    }

    @pytest.mark.asyncio
    async def test_returns_permit(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.PERMIT)
        mock_get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=resp,
        )
        result = await async_client.get_permit("pt_a")
        url = mock_get.call_args[0][0]
        assert url.endswith("/v1-permits/pt_a")
        assert result.permit.id == "pt_a"

    @pytest.mark.asyncio
    async def test_empty_id_raises(self, async_client):
        with pytest.raises(AtlaSentError) as exc:
            await async_client.get_permit("")
        assert exc.value.code == "bad_request"


class TestAsyncExplainAuthority:
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

    @pytest.mark.asyncio
    async def test_returns_explanation(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.EXPLANATION)
        mock_get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=resp,
        )
        result = await async_client.explain_authority(
            "principal_1",
            "production:deployment.production.approve",
            resource_id="res_1",
        )
        url = mock_get.call_args[0][0]
        # Hyphenated (edge-function-name) form — the real handler strips
        # `/v1-authority-intelligence/` as a literal prefix; the slash form
        # from the committed OpenAPI docs never matches and 404s.
        assert url.endswith("/v1-authority-intelligence/explain-authority")
        params = mock_get.call_args[1]["params"]
        assert params["resource_id"] == "res_1"
        assert result.organization_id == "org_1"
        assert result.authority_found is True
        assert len(result.paths) == 1

    @pytest.mark.asyncio
    async def test_omits_resource_id_when_not_supplied(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.EXPLANATION)
        mock_get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=resp,
        )
        await async_client.explain_authority(
            "principal_1", "production:deployment.production.approve"
        )
        params = mock_get.call_args[1]["params"]
        assert "resource_id" not in params

    @pytest.mark.asyncio
    async def test_surfaces_unresolved_finding_when_not_found(
        self, async_client, mocker
    ):
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
        mocker.patch.object(async_client._client, "get", return_value=resp)
        result = await async_client.explain_authority(
            "principal_1", "production:deployment.production.approve"
        )
        assert result.authority_found is False
        assert result.unresolved[0].finding_type == "NO_AUTHORITY_PATH_FOUND"

    @pytest.mark.asyncio
    async def test_empty_principal_id_raises(self, async_client):
        with pytest.raises(AtlaSentError) as exc:
            await async_client.explain_authority(
                "", "production:deployment.production.approve"
            )
        assert exc.value.code == "bad_request"

    @pytest.mark.asyncio
    async def test_empty_requested_scope_raises(self, async_client):
        with pytest.raises(AtlaSentError) as exc:
            await async_client.explain_authority("principal_1", "")
        assert exc.value.code == "bad_request"

    @pytest.mark.asyncio
    async def test_403_surfaces_as_forbidden(self, async_client, mocker):
        resp = _mock_resp(mocker, status_code=403)
        resp.json.return_value = {"reason": "missing authority_intelligence:read scope"}
        mocker.patch.object(async_client._client, "get", return_value=resp)
        with pytest.raises(AtlaSentError) as exc:
            await async_client.explain_authority(
                "principal_1", "production:deployment.production.approve"
            )
        assert exc.value.code == "forbidden"


class TestAsyncListPermits:
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
            }
        ],
        "total": 1,
    }

    @pytest.mark.asyncio
    async def test_returns_list(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.LIST)
        mock_get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=resp,
        )
        result = await async_client.list_permits()
        url = mock_get.call_args[0][0]
        assert url.endswith("/v1-permits")
        assert len(result.permits) == 1

    @pytest.mark.asyncio
    async def test_passes_filters(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.LIST)
        mock_get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=resp,
        )
        await async_client.list_permits(status="revoked", actor_id="u_42")
        params = mock_get.call_args[1]["params"]
        assert params["status"] == "revoked"
        assert params["actor_id"] == "u_42"


class TestAsyncRevokePermitById:
    REVOKED = {
        "id": "pt_a",
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

    @pytest.mark.asyncio
    async def test_returns_updated_permit(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.REVOKED)
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=resp,
        )
        result = await async_client.revoke_permit_by_id(
            "pt_a", reason="approval rescinded"
        )
        url = mock_post.call_args[0][0]
        body = mock_post.call_args[1]["json"]
        assert url.endswith("/v1-permits/pt_a/revoke")
        assert body == {"reason": "approval rescinded"}
        assert result.permit.status == "revoked"
        assert result.permit.revoke_reason == "approval rescinded"


class TestAsyncVerifyPermitById:
    VERIFY_OK = {
        "valid": True,
        "verification_type": "permit",
        "reason": None,
        "verified_at": "2026-05-07T01:00:00Z",
        "evidence": {
            "permit_id": "pt_a",
            "status": "verified",
            "actor_id": "agent-1",
            "action_id": "ehr.write",
            "expires_at": "2026-05-07T01:15:00Z",
        },
        "id": "pt_a",
        "org_id": "org_x",
        "actor_id": "agent-1",
        "action_id": "ehr.write",
        "status": "verified",
        "issued_at": "2026-05-07T01:00:00Z",
        "expires_at": "2026-05-07T01:15:00Z",
    }

    @pytest.mark.asyncio
    async def test_returns_canonical_envelope(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data=self.VERIFY_OK)
        mock_post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=resp,
        )
        result = await async_client.verify_permit_by_id("pt_a")
        url = mock_post.call_args[0][0]
        assert url.endswith("/v1-permits/pt_a/verify")
        assert result.valid is True
        assert result.verification_type == "permit"
        assert result.evidence.permit_id == "pt_a"
        assert result.permit.id == "pt_a"


class TestAsyncLegacyDeprecation:
    @pytest.mark.asyncio
    async def test_async_legacy_revoke_emits_warning(self, async_client, mocker):
        resp = _mock_resp(mocker, json_data={"revoked": True, "decision_id": "dec_x"})
        mocker.patch.object(
            async_client._client,
            "post",
            return_value=resp,
        )
        with pytest.warns(DeprecationWarning, match="revoke_permit"):
            await async_client.revoke_permit("dec_x")

    @pytest.mark.asyncio
    async def test_async_verify_does_not_warn(self, async_client, mocker):
        # verify() is the execution-boundary verifier (/v1-verify-permit);
        # it is not deprecated and must not warn.
        resp = _mock_resp(mocker, json_data={"valid": True, "outcome": "allow"})
        post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=resp,
        )
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            await async_client.verify("pt_x")
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []
        assert post.call_args[0][0].endswith("/v1-verify-permit")


class TestAsyncPermitFunctionRoutes:
    """Async per-permit calls address the ``v1-permits`` function, id encoded."""

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

    @pytest.mark.asyncio
    async def test_get_permit(self, async_client, mocker):
        get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data=self.ROW),
        )
        await async_client.get_permit(self.NASTY)
        assert get.call_args[0][0].endswith(f"/functions/v1/v1-permits/{self.ENC}")

    @pytest.mark.asyncio
    async def test_list_permits(self, async_client, mocker):
        get = mocker.patch.object(
            async_client._client,
            "get",
            return_value=_mock_resp(mocker, json_data={"permits": [self.ROW]}),
        )
        await async_client.list_permits()
        assert get.call_args[0][0].endswith("/functions/v1/v1-permits")

    @pytest.mark.asyncio
    async def test_verify_permit_by_id(self, async_client, mocker):
        wire = {
            "valid": True,
            "verification_type": "permit",
            "reason": None,
            "verified_at": "2026-05-07T01:00:00Z",
            "evidence": {"permit_id": "pt_alpha", "status": "verified"},
            **self.ROW,
        }
        post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(mocker, json_data=wire),
        )
        await async_client.verify_permit_by_id(self.NASTY)
        assert post.call_args[0][0].endswith(
            f"/functions/v1/v1-permits/{self.ENC}/verify"
        )
        assert post.call_args.kwargs["json"] == {}

    @pytest.mark.asyncio
    async def test_revoke_permit_by_id(self, async_client, mocker):
        post = mocker.patch.object(
            async_client._client,
            "post",
            return_value=_mock_resp(
                mocker, json_data={**self.ROW, "status": "revoked"}
            ),
        )
        await async_client.revoke_permit_by_id(self.NASTY, reason="superseded")
        assert post.call_args[0][0].endswith(
            f"/functions/v1/v1-permits/{self.ENC}/revoke"
        )
        assert post.call_args.kwargs["json"] == {"reason": "superseded"}
