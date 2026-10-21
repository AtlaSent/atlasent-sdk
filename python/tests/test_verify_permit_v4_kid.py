"""Kid-aware pt.v4 verification (reading side only).

Same vectors as typescript/test/verify-permit-v4-kid.test.ts:
contract/vectors/permit-v4/kid-vectors.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atlasent.verify_permit_v4 import PermitV4VerifyError, verify_permit_v4

_F = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "contract"
        / "vectors"
        / "permit-v4"
        / "kid-vectors.json"
    ).read_text()
)


def _key(name: str):
    return {
        "pinned": _F["pinned_key_b64"],
        "key_set": _F["key_set"],
        "single_set": _F["single_set"],
    }[name]


@pytest.mark.parametrize("case", _F["cases"], ids=lambda c: c["name"])
def test_kid_vectors(case: dict) -> None:
    if case["expect"] == "ok":
        res = verify_permit_v4(case["token"], _key(case["key"]))
        assert res.claims.present_claims() == _F["expected_claims"]
        assert res.kid == case.get("kid")
        if case["key"] == "pinned":
            assert res.verified_with_kid is None
        else:
            assert res.verified_with_kid == case.get("kid", "permit-2026-a")
    else:
        with pytest.raises(PermitV4VerifyError) as exc:
            verify_permit_v4(case["token"], _key(case["key"]))
        assert exc.value.reason == case["expect"]


def test_default_kid_resolves_kidless_token() -> None:
    case = next(c for c in _F["cases"] if c["name"] == "no_kid_ambiguous_key_set")
    res = verify_permit_v4(case["token"], _F["key_set"], default_kid="permit-2026-a")
    assert res.verified_with_kid == "permit-2026-a"


def test_default_kid_never_overrides_header_kid() -> None:
    case = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_b")
    res = verify_permit_v4(case["token"], _F["key_set"], default_kid="permit-2026-a")
    assert res.verified_with_kid == "permit-2026-b"
