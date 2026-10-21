"""Pytest entry points for the contract tooling.

These are thin wrappers so `pytest contract/tests/` is the one command
CI (and humans) run to validate the shared contract.
"""

from __future__ import annotations

from pathlib import Path

from contract.tools import drift, policy_lint, validate_openapi, validate_vectors


def test_ghost_trajectory_contract_cannot_reappear() -> None:
    """Keep the unshipped trajectory route and its public types out of the SDK."""
    root = Path(__file__).resolve().parents[2]
    public_files = [
        *sorted((root / "typescript" / "src").rglob("*.ts")),
        root / "contract" / "openapi.yaml",
        root / "contract" / "openapi-v2.yaml",
        *sorted((root / "contract" / "schemas").glob("*.json")),
    ]
    public_contract = "\n".join(
        path.read_text(encoding="utf-8") for path in public_files
    )
    retired_claims = (
        "/v1/trajectory-verify",
        "proposed_trajectory",
        "authorized_trajectory",
        "TrajectoryStep",
        "ProposedTrajectory",
        "AuthorizedTrajectory",
        "TrajectoryVerifyRequest",
        "TrajectoryVerifyResponse",
        "TrajectoryDeviationType",
        "TrajectoryDeviationEvent",
        "ComplianceComparisonArtifact",
    )
    present = [claim for claim in retired_claims if claim in public_contract]
    assert not present, f"retired trajectory contract claims reappeared: {present}"


def test_vectors_match_schemas() -> None:
    assert validate_vectors.main() == 0


def test_openapi_spec_valid_and_in_sync_with_schemas() -> None:
    assert validate_openapi.main() == 0


def test_no_sdk_drift() -> None:
    report = drift.run()
    assert report.ok, "\n".join(report.errors)


def test_permit_approval_binding_is_drift_checked() -> None:
    """The nested `permit.approval` sub-shape must be a drift-checked endpoint.

    The evaluate-response `permit` body is additionalProperties:true, so a drift
    inside its STRICT `permit.approval` sub-object would slip past the top-level
    `/v1-evaluate` response check. This guards the dedicated nested comparison
    (tracker M2) so it can't be silently dropped, and proves it enforces.
    """
    ep = "/v1-evaluate#permit.approval"
    wire = drift._python_sdk_wire_fields()
    assert ep in wire, "permit.approval binding must be a drift-checked endpoint"
    model_keys = wire[ep]["response_keys"]

    approval = drift._load_schema("evaluate-response.schema.json")["properties"][
        "permit"
    ]["properties"]["approval"]
    required, allowed, extras_allowed = drift._schema_field_sets(approval)
    # The binding is strict — that is exactly why the nested check is needed.
    assert not extras_allowed, "permit.approval must forbid additionalProperties"
    assert (
        model_keys == required == allowed
    ), "PermitApprovalBinding must exactly match the strict permit.approval schema"

    # Enforcement: an extra field (schema forbids extras) and a missing required
    # field must BOTH be reported as drift.
    rogue = drift.DriftReport()
    drift._compare("python", ep, "response", model_keys | {"rogue"}, approval, rogue)
    assert not rogue.ok, "an extra field in permit.approval must be caught"

    missing = drift.DriftReport()
    drift._compare(
        "python", ep, "response", model_keys - {next(iter(required))}, approval, missing
    )
    assert not missing.ok, "a missing required field in permit.approval must be caught"


def test_permit_approval_guard_fails_closed_when_schema_absent(monkeypatch) -> None:
    """If `permit.approval` is deleted/renamed in the schema, drift MUST fail.

    Otherwise the empty-`{}` fallback degrades to "no required, extras allowed" and
    the whole run passes despite the binding it protects having vanished — the
    guard would silently stop guarding.
    """
    real_load = drift._load_schema

    def _load_without_approval(name: str):
        schema = real_load(name)
        if name == "evaluate-response.schema.json":
            schema["properties"]["permit"]["properties"].pop("approval", None)
        return schema

    monkeypatch.setattr(drift, "_load_schema", _load_without_approval)
    report = drift.run()
    assert not report.ok, "drift.run() must FAIL when permit.approval is gone"
    assert any("permit.approval" in e for e in report.errors)


def test_policy_lint_passes_valid_and_rejects_invalid() -> None:
    policies_dir = Path(__file__).resolve().parents[1] / "vectors" / "policies"
    valid = sorted(
        p for p in policies_dir.glob("*.json") if not p.name.startswith("INVALID_")
    )
    invalid = sorted(policies_dir.glob("INVALID_*.json"))
    assert valid, "no positive policy fixtures"
    assert invalid, "no negative policy fixtures"
    assert policy_lint.main([str(p) for p in valid]) == 0
    assert (
        policy_lint.main([str(p) for p in invalid]) == 0
    )  # negatives expected to fail validation


def test_verify_error_code_enum_agrees_across_contract_artifacts() -> None:
    """The verify_error_code enum must be identical in the JSON Schema, the
    OpenAPI description, and the pinned catalog vector (which the TS and
    Python SDK lists are tested against), so no published description of
    /v1-verify-permit disagrees with another."""
    import json as _json
    from pathlib import Path as _Path

    import yaml as _yaml

    root = _Path(__file__).resolve().parents[1]
    schema = _json.loads((root / "schemas" / "verify-permit-response.schema.json").read_text())
    openapi = _yaml.safe_load((root / "openapi.yaml").read_text())
    pinned = _json.loads((root / "vectors" / "verify-error-codes.json").read_text())

    from_schema = schema["properties"]["verify_error_code"]["enum"]
    from_openapi = openapi["components"]["schemas"]["VerifyPermitResponse"]["properties"][
        "verify_error_code"
    ]["enum"]
    from_vector = pinned["emitted"] + pinned["legacy_documented_only"]

    assert len(set(from_schema)) == len(from_schema)
    assert sorted(from_schema) == sorted(from_openapi)
    assert sorted(from_schema) == sorted(from_vector)
