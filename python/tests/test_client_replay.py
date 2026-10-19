"""Tests for AtlaSentClient.replay() — ADR-015 Phase C parity runtime.

Restores coverage that was supposed to land with PR #275 but was
dropped from its squash merge. The async path has its own coverage
in test_async_client.py once that suite is updated; this file pins
the sync surface.
"""

from __future__ import annotations

import httpx
import pytest

from atlasent.client import AtlaSentClient
from atlasent.exceptions import AtlaSentError, RateLimitError
from atlasent.models import ReplayResponse


@pytest.fixture
def client():
    return AtlaSentClient(api_key="ask_test_xxxxxxxx", max_retries=0)


def _mock_resp(mocker, status_code=200, json_data=None, headers=None, text=""):
    resp = mocker.Mock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ── 200 happy paths ──────────────────────────────────────────────────


class TestReplay200:
    def test_variance_none(self, client, mocker):
        wire = {
            "decision_id": "dec_abc",
            "original_decision": "allow",
            "replay_decision": "allow",
            "engine_version": "wire-v1@1.0.0",
            "engine_version_kind": "active",
            "accepts_replay": True,
            "variance": "NONE",
            "envelope_verification": "verified",
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        result = client.replay(evaluation_id="dec_abc")
        assert isinstance(result, ReplayResponse)
        assert result.variance_kind == "NONE"
        assert result.original_decision == "allow"
        assert result.replayed_decision == "allow"
        assert result.engine_version_kind == "active"
        assert result.envelope_verification == "verified"
        assert result.rate_limit is None

    def test_decision_changed_normalizes_to_policy_drift(self, client, mocker):
        wire = {
            "decision_id": "dec_abc",
            "original_decision": "allow",
            "replay_decision": "deny",
            "replay_deny_code": "policy.expired_consent",
            "engine_version_kind": "active",
            "accepts_replay": True,
            "variance": "DECISION_CHANGED",
            "envelope_verification": "verified",
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        result = client.replay(evaluation_id="dec_abc")
        # SDK-canonical normalization — DECISION_CHANGED wire → POLICY_DRIFT.
        assert result.variance_kind == "POLICY_DRIFT"
        assert result.replayed_decision == "deny"
        assert result.replayed_deny_code == "policy.expired_consent"

    def test_envelope_drift_passthrough(self, client, mocker):
        wire = {
            "decision_id": "dec_abc",
            "original_decision": "allow",
            "engine_version_kind": "active",
            "accepts_replay": True,
            "variance": "ENVELOPE_DRIFT",
            "envelope_verification": "drift",
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        result = client.replay(evaluation_id="dec_abc")
        assert result.variance_kind == "ENVELOPE_DRIFT"
        assert result.replayed_decision is None
        assert result.envelope_verification == "drift"

    def test_unknown_wire_variance_defaults_to_none(self, client, mocker):
        # Forward-compat: an unrecognized wire string normalizes to NONE
        # rather than throwing — the SDK is additive.
        wire = {
            "decision_id": "dec_abc",
            "original_decision": "allow",
            "engine_version_kind": "active",
            "accepts_replay": True,
            "variance": "SOMETHING_NEW",
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        result = client.replay(evaluation_id="dec_abc")
        assert result.variance_kind == "NONE"


# ── 409 replay_not_eligible — returned, not raised ─────────────────────


class TestReplay409:
    def test_engine_drift_message(self, client, mocker):
        # 409 with an "engine" hint → ENGINE_DRIFT variance.
        body = (
            '{"error":"replay_not_eligible",'
            '"message":"Engine version wire-v0@0.9.0 does not accept replay"}'
        )
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=409, text=body),
        )
        result = client.replay(evaluation_id="dec_abc")
        assert result.variance_kind == "ENGINE_DRIFT"
        assert result.accepts_replay is False
        # We synthesize a deny on the original decision since we
        # couldn't load the wire response.
        assert result.original_decision == "deny"

    def test_bundle_missing_message(self, client, mocker):
        body = (
            '{"error":"replay_not_eligible",'
            '"message":"No policy bundle recorded for this decision"}'
        )
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=409, text=body),
        )
        result = client.replay(evaluation_id="dec_abc")
        assert result.variance_kind == "BUNDLE_MISSING"
        assert result.accepts_replay is False


# ── Non-409 errors propagate ───────────────────────────────────────────


class TestReplayErrors:
    def test_500_raises(self, client, mocker):
        # 500 with retries=0 raises immediately.
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=500, text="boom"),
        )
        with pytest.raises(AtlaSentError) as exc:
            client.replay(evaluation_id="dec_abc")
        assert exc.value.status_code == 500

    def test_429_raises_rate_limit(self, client, mocker):
        mocker.patch.object(
            client._client,
            "post",
            return_value=_mock_resp(mocker, status_code=429),
        )
        with pytest.raises(RateLimitError):
            client.replay(evaluation_id="dec_abc")


# ── URL shape + method ─────────────────────────────────────────────────


class TestReplayWire:
    def test_posts_to_canonical_path(self, client, mocker):
        wire = {
            "decision_id": "dec_abc",
            "original_decision": "allow",
            "variance": "NONE",
            "accepts_replay": True,
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        post = mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        client.replay(evaluation_id="dec_abc")
        args, kwargs = post.call_args
        assert (
            args[0]
            == "https://api.atlasent.io/functions/v1/v1/decisions/dec_abc/replay"
        )
        assert kwargs["json"] == {}

    def test_url_encodes_evaluation_id(self, client, mocker):
        wire = {
            "decision_id": "odd:id",
            "original_decision": "allow",
            "variance": "NONE",
            "accepts_replay": True,
            "replayed_at": "2026-05-24T00:00:00Z",
        }
        post = mocker.patch.object(
            client._client, "post", return_value=_mock_resp(mocker, json_data=wire)
        )
        client.replay(evaluation_id="odd:id")
        url = post.call_args[0][0]
        # ':' must be %3A in the path component.
        assert "/v1/decisions/odd%3Aid/replay" in url
