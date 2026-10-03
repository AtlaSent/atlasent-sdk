"""Python contract-parity tests for the approval-artifact surface.

Mirrors the TypeScript SDK's approval-artifact vector tests
(``atlasent-sdk/typescript/test/approval-artifact-vectors.test.ts``).

Three responsibilities:

1. **Vector loading.** Every fixture JSON in
   ``contract/vectors/approval-artifact/`` parses cleanly into
   :class:`atlasent.ApprovalArtifactV1`. If a producer ever adds /
   renames a field, the schema, the TS types, the Python types, and
   the fixtures all have to be touched together — this test fails
   first when they fall out of sync.

2. **Wire-shape parity.** ``EvaluateRequest.approval`` round-trips
   through the canonical wire dump and re-parse without losing any
   field; the dumped dict matches what the verifier on the
   atlasent-console / atlasent-api Deno path expects.

3. **Result-model parity.** ``EvaluateResult`` populates
   ``permit_approval`` from BOTH wire shapes the server may emit
   (atlasent-console nests under ``permit.approval`` per PermitV2;
   atlasent-api exposes top-level ``permit_approval``).
   ``VerifyResult`` surfaces the persisted binding plus the
   ``APPROVAL_LINKAGE_MISSING`` downgrade fields.

No new behavior is introduced: this PR is contract parity only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from atlasent import (
    ApprovalArtifactV1,
    ApprovalIssuer,
    ApprovalReference,
    ApprovalReviewer,
    ApprovalTrustedIssuersConfig,
    EvaluateResult,
    PermitApprovalBinding,
    TrustedIssuerKey,
    VerifyResult,
)
from atlasent.models import EvaluateRequest, VerifyRequest

# ── Locate the cross-repo vectors. The Python SDK lives one level
# below the contract dir, so walk up two parents. We tolerate the
# vectors being absent in install layouts that ship the Python wheel
# without the contract dir — those environments skip these tests.
VECTORS_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "contract"
    / "vectors"
    / "approval-artifact"
)


def _load_vector(name: str) -> dict:
    path = VECTORS_DIR / f"{name}.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


pytestmark = pytest.mark.skipif(
    not VECTORS_DIR.exists(),
    reason="contract/vectors/approval-artifact not available in this layout",
)


# ── 1. Vector loading ────────────────────────────────────────────────

VECTOR_NAMES = [
    "valid",
    "expired",
    "wrong-hash",
    "agent-reviewer",
    "missing-role",
    "untrusted-issuer",
    "wrong-signature",
    "replay",
]


@pytest.mark.parametrize("name", VECTOR_NAMES)
def test_vector_artifact_parses_into_pydantic_model(name: str) -> None:
    """Every TS-SDK vector parses into the Python ApprovalArtifactV1.

    Drift detector: if a field is added/renamed in the schema (and the
    fixtures regenerated) but not mirrored in the Python model, this
    parametrized test fails immediately for the affected vector.
    """
    vector = _load_vector(name)
    artifact = ApprovalArtifactV1.model_validate(vector["artifact"])
    assert artifact.version == "approval_artifact.v1"
    assert artifact.approval_id == vector["artifact"]["approval_id"]
    # Round-trip preserves canonical wire shape.
    assert artifact.model_dump(exclude_none=True) == vector["artifact"]


def test_valid_vector_carries_human_reviewer() -> None:
    valid = _load_vector("valid")
    artifact = ApprovalArtifactV1.model_validate(valid["artifact"])
    assert artifact.reviewer.principal_kind == "human"
    assert "qa_reviewer" in (artifact.reviewer.roles or [])


def test_agent_reviewer_vector_carries_agent_kind() -> None:
    """The agent-reviewer fixture is structurally valid (the schema
    permits the enum value); the *verifier* is what rejects it. The
    Python model must not artificially block it — that would mask
    server-side denials in client-side tests.
    """
    agent = _load_vector("agent-reviewer")
    artifact = ApprovalArtifactV1.model_validate(agent["artifact"])
    assert artifact.reviewer.principal_kind == "agent"


def test_action_hash_pattern_enforced() -> None:
    bad = _load_vector("valid")
    bad["artifact"]["action_hash"] = "not-a-sha256-hex"
    with pytest.raises(ValidationError):
        ApprovalArtifactV1.model_validate(bad["artifact"])


def test_extra_field_is_rejected() -> None:
    """``extra="forbid"`` so a typo'd / renamed field surfaces as a
    pydantic error at SDK boundaries instead of silently propagating
    onto the wire."""
    bad = _load_vector("valid")["artifact"].copy()
    bad["unknown_field"] = "oops"
    with pytest.raises(ValidationError):
        ApprovalArtifactV1.model_validate(bad)


# ── 2. EvaluateRequest wire shape ─────────────────────────────────────


def test_evaluate_request_carries_approval_artifact_on_the_wire() -> None:
    valid = _load_vector("valid")
    req = EvaluateRequest(
        action_type="deployment.production.deploy",
        actor_id="agent_test_1",
        resource_id="release:abc123",
        approval=ApprovalReference(
            artifact=ApprovalArtifactV1.model_validate(valid["artifact"]),
        ),
        require_approval=True,
    )
    wire = req.model_dump(by_alias=True, exclude_none=True)
    assert wire["approval"]["artifact"]["version"] == "approval_artifact.v1"
    assert wire["approval"]["artifact"]["nonce"] == valid["artifact"]["nonce"]
    assert wire["require_approval"] is True
    # api_key is excluded from the wire even when omitted.
    assert "api_key" not in wire


def test_evaluate_request_accepts_dict_for_approval() -> None:
    """Ergonomics: callers can pass a plain dict matching
    ``ApprovalReference``; the model validates it. Mirrors what the
    client does internally so users get type checking for free."""
    valid = _load_vector("valid")
    req = EvaluateRequest(
        action_type="deployment.production.deploy",
        actor_id="agent_test_1",
        approval={"approval_id": "apr_xyz", "artifact": valid["artifact"]},
    )
    assert req.approval is not None
    assert req.approval.approval_id == "apr_xyz"
    assert req.approval.artifact is not None
    assert req.approval.artifact.version == "approval_artifact.v1"


def test_evaluate_request_approval_id_only_reference() -> None:
    req = EvaluateRequest(
        action_type="deployment.production.deploy",
        actor_id="agent_test_1",
        approval=ApprovalReference(approval_id="apr_xyz"),
    )
    wire = req.model_dump(by_alias=True, exclude_none=True)
    assert wire["approval"] == {"approval_id": "apr_xyz"}


def test_evaluate_request_omits_approval_when_unset() -> None:
    req = EvaluateRequest(action_type="x", actor_id="y")
    wire = req.model_dump(by_alias=True, exclude_none=True)
    assert "approval" not in wire
    assert "require_approval" not in wire


# ── 3. VerifyRequest wire shape ───────────────────────────────────────


def test_verify_request_carries_require_approval_on_the_wire() -> None:
    req = VerifyRequest(permit_token="pt_x", require_approval=True)
    wire = req.model_dump(by_alias=True, exclude_none=True)
    assert wire["require_approval"] is True
    # context is excluded from the wire even when present.
    assert "context" not in wire


def test_verify_request_omits_require_approval_when_unset() -> None:
    req = VerifyRequest(permit_token="pt_x")
    wire = req.model_dump(by_alias=True, exclude_none=True)
    assert "require_approval" not in wire


# ── 4. EvaluateResult — permit_approval from both wire shapes ─────────


_BINDING = {
    "approval_id": "apr_xyz",
    "artifact_hash": "f" * 64,
    "reviewer_id": "okta|u1",
    "issuer_id": "issuer.qa",
    "kid": "kid-1",
}


def test_evaluate_result_picks_up_console_nested_permit_approval() -> None:
    """atlasent-console returns ``permit.approval`` per PermitV2."""
    result = EvaluateResult.model_validate(
        {
            "decision": "allow",
            "permit_token": "pt_x",
            "permit": {"token": "pt_x", "approval": _BINDING},
        }
    )
    assert isinstance(result.permit_approval, PermitApprovalBinding)
    assert result.permit_approval.approval_id == "apr_xyz"


def test_evaluate_result_picks_up_api_top_level_permit_approval() -> None:
    """atlasent-api exposes top-level ``permit_approval``."""
    result = EvaluateResult.model_validate(
        {
            "decision": "allow",
            "permit_token": "pt_x",
            "permit_approval": _BINDING,
        }
    )
    assert isinstance(result.permit_approval, PermitApprovalBinding)
    assert result.permit_approval.artifact_hash == _BINDING["artifact_hash"]


def test_evaluate_result_permit_approval_absent_when_no_binding() -> None:
    result = EvaluateResult.model_validate(
        {
            "decision": "allow",
            "permit_token": "pt_x",
        }
    )
    assert result.permit_approval is None


# ── 5. VerifyResult — approval + consumed + APPROVAL_LINKAGE_MISSING ──


def test_verify_result_surfaces_binding_on_success() -> None:
    result = VerifyResult.model_validate(
        {
            "valid": True,
            "outcome": "allow",
            "consumed": True,
            "approval": _BINDING,
        }
    )
    assert result.valid is True
    assert result.consumed is True
    assert result.approval is not None
    assert result.approval.kid == "kid-1"


def test_verify_result_approval_linkage_missing_downgrade() -> None:
    """``APPROVAL_LINKAGE_MISSING`` returns ``valid=False`` AND
    ``consumed=True`` — the permit is burned, do not retry."""
    result = VerifyResult.model_validate(
        {
            "valid": False,
            "outcome": "deny",
            "verify_error_code": "APPROVAL_LINKAGE_MISSING",
            "reason": "permit lacks approval binding for an approval-required action",
            "consumed": True,
            "approval": None,
        }
    )
    assert result.valid is False
    assert result.consumed is True
    assert result.verify_error_code == "APPROVAL_LINKAGE_MISSING"
    assert result.approval is None


# ── 6. ApprovalTrustedIssuersConfig — lockstep with TS schema ────────


def test_trusted_issuers_config_round_trips_via_env_dict() -> None:
    """The config the server reads from ``APPROVAL_TRUSTED_ISSUERS``
    has the shape published in
    ``contract/schemas/trusted-issuers-config.schema.json``.

    The Python model parses and re-emits that dict losslessly so
    operators can lint config in CI.
    """
    raw = {
        "issuer.qa": {
            "kid-1": {
                "alg": "HS256",
                "key": (
                    "55555555555555555555555555555555"
                    "55555555555555555555555555555555"
                ),
                "allowed_action_types": ["deployment.production.*"],
                "allowed_environments": ["production"],
                "required_role": "qa_reviewer",
            },
        },
    }
    cfg = ApprovalTrustedIssuersConfig.from_env_dict(raw)
    assert cfg.to_env_dict() == raw

    entry = cfg.root["issuer.qa"]["kid-1"]
    assert isinstance(entry, TrustedIssuerKey)
    assert entry.alg == "HS256"
    assert entry.allowed_action_types == ["deployment.production.*"]


def test_trusted_issuers_config_unscoped_entry_has_none_defaults() -> None:
    """Empty/missing scope fields mean 'any' for that dimension."""
    cfg = ApprovalTrustedIssuersConfig.from_env_dict(
        {
            "issuer.qa": {"kid-1": {"alg": "HS256", "key": "00" * 32}},
        }
    )
    entry = cfg.root["issuer.qa"]["kid-1"]
    assert entry.allowed_action_types is None
    assert entry.allowed_environments is None
    assert entry.required_role is None


def test_trusted_issuers_config_rejects_unknown_alg() -> None:
    with pytest.raises(ValidationError):
        ApprovalTrustedIssuersConfig.from_env_dict(
            {
                "issuer.qa": {"kid-1": {"alg": "RS256", "key": "deadbeef"}},
            }
        )


# ── 7. Sub-shape parity helpers ───────────────────────────────────────


def test_approval_reviewer_kinds() -> None:
    for kind in ("human", "agent", "service_account"):
        ApprovalReviewer(principal_id="x", principal_kind=kind)
    with pytest.raises(ValidationError):
        ApprovalReviewer(principal_id="x", principal_kind="bot")  # type: ignore[arg-type]


def test_approval_issuer_types() -> None:
    for t in ("oidc", "approval_service"):
        ApprovalIssuer(type=t, issuer_id="i", kid="k")
    with pytest.raises(ValidationError):
        ApprovalIssuer(type="other", issuer_id="i", kid="k")  # type: ignore[arg-type]


# ── 8. Identity attestation ───────────────────────────────────────────


from atlasent import (  # noqa: E402
    IdentityAssertionBinding,
    IdentityAssertionV1,
    IdentityIssuer,
    IdentityIssuerKey,
    IdentitySubject,
    IdentityTrustedIssuersConfig,
)

# Identity-assertion fixtures generated alongside the artifact ones.
ID_VECTOR_NAMES = [
    "id-valid",
    "id-missing",
    "id-expired",
    "id-wrong-reviewer",
    "id-wrong-role",
    "id-wrong-environment",
    "id-wrong-action-hash",
    "id-untrusted-issuer",
]


@pytest.mark.parametrize("name", ID_VECTOR_NAMES)
def test_identity_vector_artifact_parses(name: str) -> None:
    """Every identity-attested fixture parses into ApprovalArtifactV1.

    For ``id-missing`` the artifact has no identity_assertion (that's
    the failure mode the fixture is exercising); every other id-*
    fixture must have one.
    """
    vector = _load_vector(name)
    artifact = ApprovalArtifactV1.model_validate(vector["artifact"])
    if name == "id-missing":
        assert artifact.identity_assertion is None
    else:
        assert artifact.identity_assertion is not None
        assert artifact.identity_assertion.version == "identity_assertion.v1"


def test_identity_assertion_round_trip() -> None:
    """Constructing + serializing an IdentityAssertionV1 preserves
    every field with extra='forbid'."""
    a = IdentityAssertionV1(
        subject=IdentitySubject(principal_id="okta|u1", principal_kind="human"),
        role="qa_reviewer",
        binding=IdentityAssertionBinding(
            approval_id="apr_1",
            action_hash="f" * 64,
            tenant_id="tnt_1",
            environment="production",
        ),
        issuer=IdentityIssuer(type="oidc", issuer_id="idp.test", kid="kid-1"),
        issued_at="2026-04-16T12:00:00Z",
        expires_at="2026-04-16T13:00:00Z",
        signature="deadbeef",
    )
    out = a.model_dump(exclude_none=True)
    assert out["version"] == "identity_assertion.v1"
    assert out["subject"]["principal_kind"] == "human"
    assert out["binding"]["action_hash"] == "f" * 64

    # Round-trip
    a2 = IdentityAssertionV1.model_validate(out)
    assert a2 == a


def test_identity_assertion_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        IdentityAssertionV1.model_validate(
            {
                "version": "identity_assertion.v1",
                "subject": {"principal_id": "u", "principal_kind": "human"},
                "role": "r",
                "binding": {
                    "approval_id": "a",
                    "action_hash": "f" * 64,
                    "tenant_id": "t",
                    "environment": "e",
                },
                "issuer": {"type": "oidc", "issuer_id": "i", "kid": "k"},
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
                "signature": "x",
                "extra_field": "oops",
            }
        )


def test_identity_assertion_only_oidc_issuer_type() -> None:
    with pytest.raises(ValidationError):
        IdentityAssertionV1.model_validate(
            {
                "version": "identity_assertion.v1",
                "subject": {"principal_id": "u", "principal_kind": "human"},
                "role": "r",
                "binding": {
                    "approval_id": "a",
                    "action_hash": "f" * 64,
                    "tenant_id": "t",
                    "environment": "e",
                },
                "issuer": {
                    "type": "approval_service",
                    "issuer_id": "i",
                    "kid": "k",
                },  # wrong
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-02T00:00:00Z",
                "signature": "x",
            }
        )


def test_identity_trusted_issuers_config_round_trips() -> None:
    raw = {
        "idp.test": {
            "kid-id-1": {
                "alg": "HS256",
                "key": "9" * 64,
                "allowed_roles": ["qa_reviewer", "security_lead"],
                "allowed_environments": ["production"],
            },
        },
    }
    cfg = IdentityTrustedIssuersConfig.from_env_dict(raw)
    assert cfg.to_env_dict() == raw

    entry = cfg.root["idp.test"]["kid-id-1"]
    assert isinstance(entry, IdentityIssuerKey)
    assert entry.alg == "HS256"
    assert "qa_reviewer" in (entry.allowed_roles or [])


def test_artifact_with_identity_assertion_round_trip() -> None:
    """The artifact carries the assertion and round-trips through
    canonical wire dump + reparse, both directions, with extra=forbid."""
    valid = _load_vector("id-valid")
    artifact = ApprovalArtifactV1.model_validate(valid["artifact"])
    assert artifact.identity_assertion is not None
    dumped = artifact.model_dump(exclude_none=True)
    assert "identity_assertion" in dumped
    assert dumped["identity_assertion"]["subject"]["principal_kind"] == "human"
    # Re-parse — same object, no drift.
    reparsed = ApprovalArtifactV1.model_validate(dumped)
    assert reparsed == artifact


# ── 9. Quorum (additive layer above identity-attested approvals) ──────


from atlasent import (  # noqa: E402
    ApprovalQuorumV1,
    QuorumIndependence,
    QuorumPolicy,
    QuorumProof,
    QuorumRoleRequirement,
)

QUORUM_VECTORS_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "contract"
    / "vectors"
    / "approval-quorum"
)


def _load_quorum_vector(name: str) -> dict:
    with (QUORUM_VECTORS_DIR / f"{name}.json").open("r", encoding="utf-8") as f:
        return json.load(f)


QUORUM_VECTOR_NAMES = [
    "q-valid-2of2",
    "q-required-count-not-met",
    "q-duplicate-reviewer",
    "q-tenant-mismatch",
    "q-action-mismatch",
    "q-environment-mismatch",
    "q-role-mix-unsatisfied",
    "q-role-mix-satisfied",
    "q-distinct-approval-issuers-violated",
    "q-entry-bad-identity",
    "q-package-stale",
]


@pytest.mark.skipif(
    not QUORUM_VECTORS_DIR.exists(),
    reason="contract/vectors/approval-quorum not available",
)
@pytest.mark.parametrize("name", QUORUM_VECTOR_NAMES)
def test_quorum_vector_package_parses(name: str) -> None:
    """Every quorum fixture parses cleanly into ApprovalQuorumV1 with
    extra='forbid'. Drift in field names / types fails immediately."""
    vector = _load_quorum_vector(name)
    pkg = ApprovalQuorumV1.model_validate(vector["package"])
    assert pkg.version == "approval_quorum.v1"
    assert len(pkg.approvals) >= 1
    # Round-trip preserves wire shape.
    assert pkg.model_dump(exclude_none=True) == vector["package"]


def test_quorum_policy_round_trip() -> None:
    p = QuorumPolicy(
        required_count=2,
        required_role_mix=[
            QuorumRoleRequirement(role="qa_reviewer", min=1),
            QuorumRoleRequirement(role="security_lead", min=1),
        ],
        independence=QuorumIndependence(
            distinct_approval_issuers=True,
            distinct_identity_issuers=True,
        ),
        max_age_seconds=3600,
    )
    out = p.model_dump(exclude_none=True)
    assert out["required_count"] == 2
    assert out["independence"]["distinct_approval_issuers"] is True
    p2 = QuorumPolicy.model_validate(out)
    assert p2 == p


def test_quorum_policy_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        QuorumPolicy.model_validate(
            {
                "required_count": 1,
                "unknown": "oops",
            }
        )


def test_quorum_policy_required_count_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        QuorumPolicy.model_validate({"required_count": 0})


def test_quorum_proof_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        QuorumProof.model_validate({"quorum_hash": "not-hex", "approval_ids": []})


def test_quorum_with_invalid_artifact_inside_rejected() -> None:
    """Quorum.approvals items use the same ApprovalArtifactV1 model
    with extra='forbid'. An artifact with an unknown field fails the
    container's parse, surfacing the drift at SDK boundaries."""
    valid = _load_quorum_vector("q-valid-2of2")
    pkg = dict(valid["package"])
    pkg["approvals"] = [dict(a) for a in pkg["approvals"]]
    pkg["approvals"][0]["unknown_field"] = "oops"
    with pytest.raises(ValidationError):
        ApprovalQuorumV1.model_validate(pkg)


# ── approver_grant_assertion.v1 (atlasent-api#3876) ──────────────────

from atlasent import ApproverGrantAssertionV1  # noqa: E402

_CONTRACT_SCHEMAS = (
    Path(__file__).resolve().parent.parent.parent / "contract" / "schemas"
)

_GRANT = {
    "version": "approver_grant_assertion.v1",
    "basis": "atlasent_approver_grant",
    "subject": {
        "principal_id": "11111111-1111-4111-8111-111111111111",
        "principal_kind": "human",
    },
    "grant_id": "22222222-2222-4222-8222-222222222222",
    "binding": {
        "approval_id": "apr_123",
        "action_hash": "f" * 64,
        "action_type": "production.deploy",
        "tenant_id": "tnt_1",
        "environment": "production",
    },
    "issuer": {"issuer_id": "atlasent-console", "kid": "kid-1"},
    "auth_context": {
        "acr": "aal2",
        "amr": ["pwd", "totp"],
        "step_up": "aal2",
        "step_up_at": "2026-10-03T00:00:00Z",
    },
    "issued_at": "2026-10-03T00:00:00Z",
    "expires_at": "2026-10-03T00:05:00Z",
    "nonce": "0123456789abcdef",
    "signature": "deadbeef",
}

_ARTIFACT = {
    "version": "approval_artifact.v1",
    "approval_id": "apr_123",
    "tenant_id": "tnt_1",
    "action_type": "production.deploy",
    "resource_id": "release:abc123",
    "action_hash": "f" * 64,
    "reviewer": {
        "principal_id": "11111111-1111-4111-8111-111111111111",
        "principal_kind": "human",
    },
    "issuer": {
        "type": "approval_service",
        "issuer_id": "atlasent-console",
        "kid": "kid-1",
    },
    "issued_at": "2026-10-03T00:00:00Z",
    "expires_at": "2026-10-03T00:05:00Z",
    "nonce": "n_abcdef01",
    "signature": "deadbeef",
}


def test_approver_grant_assertion_model_matches_schema() -> None:
    schema = json.loads(
        (_CONTRACT_SCHEMAS / "approver-grant-assertion.schema.json").read_text()
    )
    assert set(ApproverGrantAssertionV1.model_fields) == set(schema["properties"])
    assert set(schema["required"]) == set(schema["properties"])
    art = json.loads((_CONTRACT_SCHEMAS / "approval-artifact.schema.json").read_text())
    assert set(ApprovalArtifactV1.model_fields) == set(art["properties"])
    assert "approver_grant_assertion" not in art["required"]


def test_artifact_with_approver_grant_round_trips() -> None:
    a = ApprovalArtifactV1.model_validate(
        {**_ARTIFACT, "approver_grant_assertion": _GRANT}
    )
    assert a.approver_grant_assertion is not None
    assert a.approver_grant_assertion.grant_id == _GRANT["grant_id"]
    assert a.model_dump(exclude_none=True)["approver_grant_assertion"] == _GRANT


def test_artifact_without_approver_grant_unchanged() -> None:
    a = ApprovalArtifactV1.model_validate(_ARTIFACT)
    assert a.approver_grant_assertion is None
    assert "approver_grant_assertion" not in a.model_dump(exclude_none=True)


def test_artifact_with_both_assertions_rejected() -> None:
    identity = {
        "version": "identity_assertion.v1",
        "subject": {"principal_id": "u1", "principal_kind": "human"},
        "role": "approver",
        "binding": {
            "approval_id": "apr_123",
            "action_hash": "f" * 64,
            "tenant_id": "tnt_1",
            "environment": "",
        },
        "issuer": {"type": "oidc", "issuer_id": "idp", "kid": "k1"},
        "issued_at": "2026-10-03T00:00:00Z",
        "expires_at": "2026-10-03T00:05:00Z",
        "signature": "sig",
    }
    with pytest.raises(ValidationError):
        ApprovalArtifactV1.model_validate(
            {
                **_ARTIFACT,
                "identity_assertion": identity,
                "approver_grant_assertion": _GRANT,
            }
        )


@pytest.mark.parametrize(
    "path,value",
    [
        (("basis",), "atlasent_org_role"),
        (("grant_id",), "nope"),
        (("subject", "principal_kind"), "agent"),
        (("subject", "principal_id"), "Not-A-Uuid"),
        (("auth_context", "acr"), "aal3"),
        (("auth_context", "amr"), []),
        (("auth_context", "step_up"), "sms"),
        (("nonce",), "short"),
    ],
)
def test_malformed_approver_grant_rejected(
    path: tuple[str, ...], value: object
) -> None:
    g = json.loads(json.dumps(_GRANT))
    target = g
    for k in path[:-1]:
        target = target[k]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        ApproverGrantAssertionV1.model_validate(g)


# ── meaning / entra_provenance / approval_kind / subject_agent_identity_id ─
#
# The runtime (atlasent-api _shared/approval_artifact.ts) emits and signs
# these four optional fields; before 2026-10-03 the schema and these models
# forbade them, so a real runtime artifact failed SDK validation.

import copy  # noqa: E402

from atlasent import EntraProvenanceV1  # noqa: E402

_ACTION_HASH = "3f" * 32
_AGENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

# Shaped after what the runtime's v1-idp-broker returns from an Entra ID
# approval mint (_shared/evidence-minter.ts mintApprovalArtifact).
_RUNTIME_ENTRA_ARTIFACT = {
    "version": "approval_artifact.v1",
    "approval_id": "apr-0b6c3f0e-5a1d-4c55-9c2e-7a9d2f41e8b3",
    "tenant_id": "923a3b8d-cdaa-4fc7-885f-8d8b11232ca4",
    "action_type": "production.deploy",
    "resource_id": "api-service",
    "action_hash": _ACTION_HASH,
    "reviewer": {
        "principal_id": "entra:5d1e2f3a-0b4c-4d6e-8f7a-9b0c1d2e3f40",
        "principal_kind": "human",
        "roles": ["release-approver"],
    },
    "issuer": {
        "type": "approval_service",
        "issuer_id": "atlasent-idp-broker",
        "kid": "broker-2026-09",
    },
    "issued_at": "2026-10-03T00:00:00.000Z",
    "expires_at": "2026-10-03T00:10:00.000Z",
    "nonce": "6f1d2c3b-4a59-4e8d-9c7b-1a2b3c4d5e6f",
    "meaning": "approved",
    "identity_assertion": {
        "version": "identity_assertion.v1",
        "subject": {
            "principal_id": "entra:5d1e2f3a-0b4c-4d6e-8f7a-9b0c1d2e3f40",
            "principal_kind": "human",
        },
        "role": "release-approver",
        "binding": {
            "approval_id": "apr-0b6c3f0e-5a1d-4c55-9c2e-7a9d2f41e8b3",
            "action_hash": _ACTION_HASH,
            "tenant_id": "923a3b8d-cdaa-4fc7-885f-8d8b11232ca4",
            "environment": "production",
        },
        "issuer": {
            "type": "oidc",
            "issuer_id": "atlasent-idp-broker",
            "kid": "broker-2026-09",
        },
        "issued_at": "2026-10-03T00:00:00.000Z",
        "expires_at": "2026-10-03T00:10:00.000Z",
        "signature": "MEUCIQDexampleIdentitySignature",
    },
    "entra_provenance": {
        "tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
        "org_binding_id": "0e9f8a7b-6c5d-4e3f-a2b1-c0d9e8f7a6b5",
        "mapping_id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
        "mapping_version": 3,
        "relation": "approve",
    },
    "signature": "MEUCIQDexampleArtifactSignature",
}

# Shaped after the ADR CROSS-056 artifact the runtime verifier accepts.
_RUNTIME_KIND_ARTIFACT = {
    "version": "approval_artifact.v1",
    "approval_id": "apr-kind-1",
    "tenant_id": "org-1",
    "action_type": "agent.tool.invoke",
    "resource_id": "tool:deploy",
    "action_hash": _ACTION_HASH,
    "reviewer": {
        "principal_id": "owner-1",
        "principal_kind": "human",
        "roles": ["agent_owner"],
    },
    "issuer": {
        "type": "approval_service",
        "issuer_id": "atlasent-console",
        "kid": "kid-o",
    },
    "issued_at": "2026-10-03T00:00:00Z",
    "expires_at": "2026-10-03T00:05:00Z",
    "nonce": "nonce-kind-123456",
    "approval_kind": "single_human_over_machine",
    "subject_agent_identity_id": _AGENT_ID,
    "signature": "sig",
}


def _drop(key: str):
    return lambda a: a.pop(key)


_MALFORMED_RUNTIME_FIELDS = [
    (_RUNTIME_ENTRA_ARTIFACT, lambda a: a.update(meaning="signed")),
    (_RUNTIME_KIND_ARTIFACT, lambda a: a.update(approval_kind="committee")),
    (_RUNTIME_KIND_ARTIFACT, _drop("subject_agent_identity_id")),
    (_RUNTIME_KIND_ARTIFACT, lambda a: a.update(subject_agent_identity_id="x")),
    (_RUNTIME_KIND_ARTIFACT, _drop("approval_kind")),
    (
        _RUNTIME_ENTRA_ARTIFACT,
        lambda a: a["entra_provenance"].update(relation="request"),
    ),
    (_RUNTIME_ENTRA_ARTIFACT, lambda a: a["entra_provenance"].pop("mapping_id")),
    (_RUNTIME_ENTRA_ARTIFACT, lambda a: a["entra_provenance"].update(tenant_id="")),
    (
        _RUNTIME_ENTRA_ARTIFACT,
        lambda a: a["entra_provenance"].update(mapping_version="3"),
    ),
    (_RUNTIME_ENTRA_ARTIFACT, lambda a: a["entra_provenance"].update(extra="x")),
    (_RUNTIME_ENTRA_ARTIFACT, lambda a: a.update(meaning_v2="approved")),
]


@pytest.mark.parametrize("artifact", [_RUNTIME_ENTRA_ARTIFACT, _RUNTIME_KIND_ARTIFACT])
def test_runtime_shaped_artifact_round_trips(artifact: dict) -> None:
    a = ApprovalArtifactV1.model_validate(artifact)
    assert a.model_dump(exclude_none=True) == artifact


def test_runtime_entra_fields_parsed() -> None:
    a = ApprovalArtifactV1.model_validate(_RUNTIME_ENTRA_ARTIFACT)
    assert a.meaning == "approved"
    assert isinstance(a.entra_provenance, EntraProvenanceV1)
    assert a.entra_provenance.relation == "approve"
    assert a.entra_provenance.mapping_version == 3
    assert a.approval_kind is None and a.subject_agent_identity_id is None


@pytest.mark.parametrize("meaning", ["approved", "reviewed", "authored"])
def test_each_meaning_accepted(meaning: str) -> None:
    a = ApprovalArtifactV1.model_validate({**_ARTIFACT, "meaning": meaning})
    assert a.meaning == meaning


def test_legacy_artifact_has_no_new_fields() -> None:
    dumped = ApprovalArtifactV1.model_validate(_ARTIFACT).model_dump(exclude_none=True)
    for k in ("meaning", "entra_provenance", "approval_kind"):
        assert k not in dumped
    assert "subject_agent_identity_id" not in dumped


@pytest.mark.parametrize("base,mutate", _MALFORMED_RUNTIME_FIELDS)
def test_malformed_runtime_fields_rejected_by_model(base: dict, mutate) -> None:
    a = copy.deepcopy(base)
    mutate(a)
    with pytest.raises(ValidationError):
        ApprovalArtifactV1.model_validate(a)


def _schema_errors(payload: dict) -> list[str]:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    registry = referencing.Registry()
    for p in _CONTRACT_SCHEMAS.glob("*.schema.json"):
        schema = json.loads(p.read_text())
        res = referencing.Resource.from_contents(schema)
        registry = registry.with_resource(uri=schema.get("$id", p.name), resource=res)
    art = json.loads((_CONTRACT_SCHEMAS / "approval-artifact.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(art, registry=registry)
    return [e.message for e in validator.iter_errors(payload)]


@pytest.mark.parametrize(
    "artifact", [_ARTIFACT, _RUNTIME_ENTRA_ARTIFACT, _RUNTIME_KIND_ARTIFACT]
)
def test_runtime_shaped_artifact_validates_against_schema(artifact: dict) -> None:
    assert _schema_errors(artifact) == []


@pytest.mark.parametrize("base,mutate", _MALFORMED_RUNTIME_FIELDS)
def test_malformed_runtime_fields_rejected_by_schema(base: dict, mutate) -> None:
    a = copy.deepcopy(base)
    mutate(a)
    assert _schema_errors(a) != []


def test_entra_provenance_model_matches_schema() -> None:
    schema = json.loads(
        (_CONTRACT_SCHEMAS / "entra-provenance.schema.json").read_text()
    )
    assert set(EntraProvenanceV1.model_fields) == set(schema["properties"])
    assert set(schema["required"]) == set(schema["properties"])
    art = json.loads((_CONTRACT_SCHEMAS / "approval-artifact.schema.json").read_text())
    for k in ("meaning", "entra_provenance", "approval_kind"):
        assert k in art["properties"] and k not in art["required"]
    assert art["properties"]["meaning"]["enum"] == ["approved", "reviewed", "authored"]
    assert art["properties"]["approval_kind"]["enum"] == ["single_human_over_machine"]
    assert art["dependentRequired"] == {
        "approval_kind": ["subject_agent_identity_id"],
        "subject_agent_identity_id": ["approval_kind"],
    }
