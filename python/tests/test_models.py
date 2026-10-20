"""Tests for Pydantic models.

Covers BOTH the canonical handler.ts wire shape and the legacy
{action, agent, api_key} / {permitted, decision_id} shape that older
SDK callers and older atlasent-api deployments may still use. The
canonical shape is the source of truth; legacy shapes are accepted
with a DeprecationWarning on input and transparently translated on
response.
"""

import warnings

from atlasent.models import (
    AuthError,
    EnforcementOutcome,
    EvaluateRequest,
    EvaluateResult,
    EvaluateRiskEnvelope,
    GateResult,
    GovernanceDecision,
    VerifyRequest,
    VerifyResult,
)


class TestEvaluateRequest:
    def test_canonical_serializes_to_canonical_wire(self):
        req = EvaluateRequest(
            action_type="read_data",
            actor_id="agent-1",
            context={"study": "S001"},
        )
        data = req.model_dump(by_alias=True)
        assert data["action_type"] == "read_data"
        assert data["actor_id"] == "agent-1"
        assert data["context"] == {"study": "S001"}
        # api_key MUST NOT appear on the wire — server reads it from the
        # Authorization header.
        assert "api_key" not in data

    def test_legacy_input_translates_with_deprecation(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            req = EvaluateRequest(
                action="read_data", agent="agent-1", api_key="ask_test_xxxxxxxx"
            )
        assert req.action_type == "read_data"
        assert req.actor_id == "agent-1"
        # Wire is still canonical.
        data = req.model_dump(by_alias=True)
        assert data["action_type"] == "read_data"
        assert data["actor_id"] == "agent-1"
        assert "action" not in data
        assert "agent" not in data
        assert "api_key" not in data
        kinds = [
            str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)
        ]
        assert any("action= -> action_type=" in m for m in kinds)
        assert any("agent= -> actor_id=" in m for m in kinds)
        assert any("api_key=" in m for m in kinds)

    def test_default_context(self):
        req = EvaluateRequest(action_type="x", actor_id="y")
        assert req.context == {}


class TestEvaluateResult:
    def test_from_legacy_api_response(self):
        # Old-shaped server response (pre-handler.ts).
        result = EvaluateResult.model_validate(
            {
                "permitted": True,
                "decision_id": "dec_100",
                "reason": "OK",
                "audit_hash": "hash_abc",
                "timestamp": "2025-01-15T12:00:00Z",
            }
        )
        # Canonical attributes populated from legacy.
        assert result.decision == "allow"
        assert result.permit_token == "dec_100"
        # Legacy attributes also populated for backward-compat.
        assert result.permitted is True
        assert result.decision_id == "dec_100"
        assert result.reason == "OK"
        assert result.audit_hash == "hash_abc"
        assert result.timestamp == "2025-01-15T12:00:00Z"

    def test_from_canonical_api_response(self):
        result = EvaluateResult.model_validate(
            {
                "decision": "allow",
                "permit_token": "pt_xyz",
                "request_id": "req_1",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )
        assert result.decision == "allow"
        assert result.permit_token == "pt_xyz"
        assert result.request_id == "req_1"
        assert result.expires_at == "2026-01-01T01:00:00Z"
        # Legacy attrs mirrored.
        assert result.permitted is True
        assert result.decision_id == "pt_xyz"

    def test_canonical_deny_with_denial(self):
        result = EvaluateResult.model_validate(
            {
                "decision": "deny",
                "denial": {"reason": "no quorum", "code": "MISSING_APPROVAL"},
            }
        )
        assert result.decision == "deny"
        assert result.permitted is False
        assert result.denial == {"reason": "no quorum", "code": "MISSING_APPROVAL"}
        assert result.reason == "no quorum"  # legacy mirror

    def test_human_approval_fields_parsed_from_response(self):
        """Two-stage authorization lifecycle (#1617): human_approval_required
        and human_approval_status are parsed from the wire response."""
        result = EvaluateResult.model_validate(
            {
                "decision": "escalate",
                "human_approval_required": True,
                "human_approval_status": "pending",
            }
        )
        assert result.decision == "escalate"
        assert result.human_approval_required is True
        assert result.human_approval_status == "pending"

    def test_approval_request_id_parsed_from_response(self):
        result = EvaluateResult.model_validate(
            {"decision": "escalate", "approval_request_id": "apr_123"}
        )
        assert result.approval_request_id == "apr_123"
        assert EvaluateResult.model_validate({"decision": "allow", "permit_token": "pt"}).approval_request_id is None

    def test_human_approval_fields_none_when_absent(self):
        """Backward compat: a runtime response predating the lifecycle
        fields leaves both attributes None, never a fabricated default."""
        result = EvaluateResult.model_validate(
            {
                "decision": "allow",
                "permit_token": "pt_xyz",
            }
        )
        assert result.human_approval_required is None
        assert result.human_approval_status is None


class TestVerifyRequest:
    def test_canonical_serializes_to_canonical_wire(self):
        req = VerifyRequest(
            permit_token="pt_100",
            action_type="read_data",
            actor_id="agent-1",
        )
        data = req.model_dump(by_alias=True)
        assert data["permit_token"] == "pt_100"
        assert data["action_type"] == "read_data"
        assert data["actor_id"] == "agent-1"
        assert "context" not in data
        assert "api_key" not in data

    def test_legacy_input_translates_with_deprecation(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            req = VerifyRequest(
                decision_id="pt_100",
                action="read_data",
                agent="agent-1",
                api_key="ask_test_xxxxxxxx",
            )
        assert req.permit_token == "pt_100"
        assert req.action_type == "read_data"
        assert req.actor_id == "agent-1"
        data = req.model_dump(by_alias=True)
        assert data["permit_token"] == "pt_100"
        assert "decision_id" not in data
        assert "api_key" not in data
        kinds = [
            str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)
        ]
        assert any("decision_id= -> permit_token=" in m for m in kinds)


class TestVerifyResult:
    def test_from_legacy_api_response(self):
        result = VerifyResult.model_validate(
            {
                "verified": True,
                "permit_hash": "permit_xyz",
                "timestamp": "2025-01-15T12:05:00Z",
            }
        )
        assert result.valid is True
        assert result.verified is True
        assert result.permit_hash == "permit_xyz"
        assert result.timestamp == "2025-01-15T12:05:00Z"

    def test_from_canonical_api_response(self):
        result = VerifyResult.model_validate({"valid": True, "outcome": "allow"})
        assert result.valid is True
        assert result.outcome == "allow"
        assert result.verified is True  # legacy mirror

    def test_canonical_deny_with_error_code(self):
        result = VerifyResult.model_validate(
            {
                "valid": False,
                "outcome": "deny",
                "verify_error_code": "PERMIT_EXPIRED",
                "reason": "Permit expired at 2026-01-01T00:15:00Z",
            }
        )
        assert result.valid is False
        assert result.outcome == "deny"
        assert result.verify_error_code == "PERMIT_EXPIRED"
        assert result.reason.startswith("Permit expired")
        assert result.verified is False  # legacy mirror

    def test_outcome_default(self):
        result = VerifyResult.model_validate({"verified": False})
        assert result.valid is False
        assert result.outcome == ""


class TestGateResult:
    def test_combines_eval_and_verify(self):
        ev = EvaluateResult(decision="allow", permit_token="dec_1")
        vr = VerifyResult(valid=True)
        gate = GateResult(evaluation=ev, verification=vr)
        assert gate.evaluation.permit_token == "dec_1"
        assert gate.evaluation.decision == "allow"
        assert gate.verification.valid is True


class TestNoExtraneousWarnings:
    def test_canonical_construction_emits_no_deprecation(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            EvaluateRequest(action_type="x", actor_id="y", context={"k": "v"})
            VerifyRequest(permit_token="t", action_type="x", actor_id="y")
        deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert deprecations == []


class TestGovernanceDecision:
    def test_from_wire_canonical_shape(self):
        d = GovernanceDecision.from_wire(
            {
                "decision": "deny",
                "reason": "outside_change_window",
                "code": "change_window",
                "policy_id": "pol_42",
                "request_id": "req_abc",
                "evaluated_at": "2026-05-09T10:00:00Z",
            }
        )
        assert d.decision == "deny"
        assert d.code == "change_window"
        assert d.policy_id == "pol_42"
        assert d.evaluated_at == "2026-05-09T10:00:00Z"

    def test_from_wire_lifts_denial_substruct(self):
        # /v1-evaluate emits {decision: "deny", denial: {reason, code}}
        # — GovernanceDecision flattens that for downstream consumers.
        d = GovernanceDecision.from_wire(
            {"decision": "deny", "denial": {"reason": "no_quorum", "code": "qrm"}}
        )
        assert d.reason == "no_quorum"
        assert d.code == "qrm"

    def test_from_wire_defaults_to_deny_on_missing_decision(self):
        d = GovernanceDecision.from_wire({})
        assert d.decision == "deny"


class TestAuthError:
    def test_from_body_prefers_error_field(self):
        err = AuthError.from_body(
            {"error": "phi_scope_required", "message": "key lacks phi:read"},
            status=403,
            request_id="req_xyz",
        )
        assert err is not None
        assert err.error == "phi_scope_required"
        assert err.message == "key lacks phi:read"
        assert err.status == 403
        assert err.request_id == "req_xyz"

    def test_from_body_synthesizes_error_from_message(self):
        # Older servers without the Phase 4 envelope still produce a
        # usable AuthError so callers can rely on `.error` being set.
        err = AuthError.from_body({"message": "rate limit exceeded"}, status=429)
        assert err is not None
        assert err.error == "rate limit exceeded"
        assert err.status == 429

    def test_from_body_returns_none_for_empty_envelope(self):
        assert AuthError.from_body({}) is None
        assert AuthError.from_body(None) is None
        assert AuthError.from_body("not a dict") is None  # type: ignore[arg-type]


class TestEnforcementOutcome:
    def test_construct_minimal(self):
        out = EnforcementOutcome(enforced=False, decision="allow")
        assert out.enforced is False
        assert out.decision == "allow"
        assert out.enforcement_action is None

    def test_construct_with_enforcement(self):
        out = EnforcementOutcome(
            enforced=True,
            decision="deny",
            enforcement_action="raised",
            reason="quorum_failed",
            code="qrm",
        )
        assert out.enforced is True
        assert out.enforcement_action == "raised"
        assert out.reason == "quorum_failed"


class TestEvaluateRiskEnvelope:
    """Tests for EvaluateRiskEnvelope and EvaluateRiskEnvelopeFactor models."""

    def test_risk_envelope_without_factors(self):
        """risk_envelope present with no factors (explain not requested)."""
        envelope = EvaluateRiskEnvelope.model_validate(
            {
                "weighted_score": 0.42,
                "engine_decision": "allow",
                "envelope_decision": "allow",
                "promoted": False,
                "hard_blocks": [],
            }
        )
        assert envelope.weighted_score == 0.42
        assert envelope.engine_decision == "allow"
        assert envelope.envelope_decision == "allow"
        assert envelope.promoted is False
        assert envelope.hard_blocks == []
        assert envelope.factors == []

    def test_risk_envelope_with_factors(self):
        """risk_envelope present with factors populated via explain=True."""
        envelope = EvaluateRiskEnvelope.model_validate(
            {
                "weighted_score": 0.85,
                "engine_decision": "allow",
                "envelope_decision": "hold",
                "promoted": True,
                "hard_blocks": ["SANCTION_LIST"],
                "factors": [
                    {
                        "factor": "ACTION_SENSITIVITY",
                        "value": 0.9,
                        "weight": 0.5,
                        "reason": "action touches PII",
                    },
                    {
                        "factor": "ACTOR_TRUST",
                        "value": 0.7,
                        "weight": 0.5,
                        "reason": "actor has recent anomalies",
                    },
                ],
            }
        )
        assert envelope.weighted_score == 0.85
        assert envelope.promoted is True
        assert envelope.hard_blocks == ["SANCTION_LIST"]
        assert len(envelope.factors) == 2
        assert envelope.factors[0].factor == "ACTION_SENSITIVITY"
        assert envelope.factors[0].value == 0.9
        assert envelope.factors[0].weight == 0.5
        assert envelope.factors[0].reason == "action touches PII"
        assert envelope.factors[1].factor == "ACTOR_TRUST"

    def test_evaluate_result_risk_envelope_present(self):
        """EvaluateResult parses risk_envelope from the wire response."""
        result = EvaluateResult.model_validate(
            {
                "decision": "hold",
                "permit_token": "",
                "denial": {"reason": "high risk score", "code": "RISK_HOLD"},
                "risk_envelope": {
                    "weighted_score": 0.75,
                    "engine_decision": "allow",
                    "envelope_decision": "hold",
                    "promoted": True,
                    "hard_blocks": [],
                    "factors": [
                        {
                            "factor": "ACTION_SENSITIVITY",
                            "value": 0.8,
                            "weight": 1.0,
                            "reason": "high-sensitivity action",
                        }
                    ],
                },
            }
        )
        assert result.decision == "hold"
        assert result.risk_envelope is not None
        assert result.risk_envelope.weighted_score == 0.75
        assert result.risk_envelope.promoted is True
        assert len(result.risk_envelope.factors) == 1
        assert result.risk_envelope.factors[0].factor == "ACTION_SENSITIVITY"

    def test_evaluate_result_risk_envelope_absent(self):
        """EvaluateResult.risk_envelope is None when server omits the field."""
        result = EvaluateResult.model_validate(
            {
                "decision": "allow",
                "permit_token": "pt_no_envelope",
            }
        )
        assert result.risk_envelope is None

    def test_evaluate_request_explain_field(self):
        """EvaluateRequest serializes explain when set."""
        req = EvaluateRequest(action_type="read_data", actor_id="agent-1", explain=True)
        data = req.model_dump(exclude_none=True)
        assert data["explain"] is True

    def test_evaluate_request_explain_omitted_by_default(self):
        """EvaluateRequest omits explain from the wire when not set."""
        req = EvaluateRequest(action_type="read_data", actor_id="agent-1")
        data = req.model_dump(exclude_none=True)
        assert "explain" not in data
