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
        "rotation_set": _F["rotation_set"],
        "expired_set": _F["expired_set"],
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


def test_flat_revoked_kids_list_revokes() -> None:
    case = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_a")
    key_set = {**_F["key_set"], "revoked_kids": ["permit-2026-a"]}
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(case["token"], key_set)
    assert exc.value.reason == "key_revoked"


def test_accepts_the_sdk_trust_root_snapshot_dataclasses() -> None:
    from atlasent.trust_root import (
        TrustRootKey,
        TrustRootRevocationEntry,
        TrustRootSnapshot,
    )

    keys = [
        TrustRootKey(**{k: v for k, v in d.items() if k != "tenant"})
        for d in _F["key_set"]["keys"]
    ]
    snap = TrustRootSnapshot(
        valid_until="2099-01-01T00:00:00Z",
        issued_at="2026-01-01T00:00:00Z",
        keys=keys,
        revoked_keys=[
            TrustRootRevocationEntry(
                kid="permit-2026-b", revoked_at="2026-10-01T00:00:00Z"
            )
        ],
    )
    ok = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_a")
    assert verify_permit_v4(ok["token"], snap).verified_with_kid == "permit-2026-a"
    ledger = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_b")
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(ledger["token"], snap)
    assert exc.value.reason == "key_revoked"
