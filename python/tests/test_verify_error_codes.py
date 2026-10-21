"""Typed verify_error_code values and execution_payload_hash_accepted."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import atlasent
from atlasent.models import EvaluateResult, VerifyResult
from atlasent.verify_error_codes import (
    LEGACY_VERIFY_ERROR_CODES,
    TRANSIENT_VERIFY_ERROR_CODES,
    VERIFY_ERROR_CODES,
    is_verify_error_code,
)

_PINNED = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "contract"
        / "vectors"
        / "verify-error-codes.json"
    ).read_text()
)


def test_sets_match_the_pinned_contract_vector() -> None:
    assert VERIFY_ERROR_CODES == frozenset(_PINNED["emitted"])
    assert LEGACY_VERIFY_ERROR_CODES == frozenset(_PINNED["legacy_documented_only"])
    assert TRANSIENT_VERIFY_ERROR_CODES == frozenset(_PINNED["transient"])


def test_is_verify_error_code() -> None:
    assert is_verify_error_code("PAYLOAD_MISMATCH")
    assert is_verify_error_code("UNAUTHORIZED")  # legacy, still known
    assert not is_verify_error_code("FUTURE_CODE")
    assert not is_verify_error_code(None)


def test_exported_from_package() -> None:
    assert atlasent.is_verify_error_code("PERMIT_ALREADY_USED")


def test_verify_result_keeps_unknown_code_open() -> None:
    res = VerifyResult.model_validate(
        {"valid": False, "outcome": "deny", "verify_error_code": "FUTURE_CODE"}
    )
    assert res.verify_error_code == "FUTURE_CODE"
    assert not is_verify_error_code(res.verify_error_code)


@pytest.mark.parametrize("value", [True, False])
def test_execution_payload_hash_accepted_round_trips(value: bool) -> None:
    res = EvaluateResult.model_validate(
        {
            "decision": "allow",
            "permit_token": "pt.v4.x",
            "execution_payload_hash_accepted": value,
        }
    )
    assert res.execution_payload_hash_accepted is value


def test_execution_payload_hash_accepted_absent_is_none() -> None:
    res = EvaluateResult.model_validate(
        {"decision": "allow", "permit_token": "pt.v4.x"}
    )
    assert res.execution_payload_hash_accepted is None
