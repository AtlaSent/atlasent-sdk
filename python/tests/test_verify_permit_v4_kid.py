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
        "alias_set": _F["alias_set"],
        "roleless_alias_set": _F["roleless_alias_set"],
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


def test_snapshot_older_than_age_limit_is_refused() -> None:
    import time

    from atlasent.verify_permit_v4 import TRUST_SNAPSHOT_MAX_AGE_MS

    case = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_a")
    now_ms = time.time() * 1000
    snap = {
        **_F["key_set"],
        "fetched_at": now_ms - TRUST_SNAPSHOT_MAX_AGE_MS - 60_000,
        "expires_at": now_ms + 3_600_000,
    }
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(case["token"], snap)
    assert exc.value.reason == "key_set_expired"
    fresh = verify_permit_v4(case["token"], {**snap, "fetched_at": now_ms - 60_000})
    assert fresh.verified_with_kid == "permit-2026-a"
    with pytest.raises(PermitV4VerifyError):
        verify_permit_v4(case["token"], {**snap, "fetched_at": "yesterday"})


@pytest.mark.parametrize("field", ["role", "kty", "crv", "alg"])
def test_entry_without_explicit_metadata_is_never_a_permit_key(field: str) -> None:
    # Codex repro: the audit key with its role dropped must not sign permits.
    def strip(k: dict) -> dict:
        if k["kid"] == "permit-2026-a" or (k["kid"] == "audit-a" and field == "role"):
            return {n: v for n, v in k.items() if n != field}
        return k

    key_set = {**_F["key_set"], "keys": [strip(k) for k in _F["key_set"]["keys"]]}
    for name in ("kid_of_non_permit_role", "kid_selects_key_a"):
        case = next(c for c in _F["cases"] if c["name"] == name)
        with pytest.raises(PermitV4VerifyError) as exc:
            verify_permit_v4(case["token"], key_set)
        assert exc.value.reason == "unknown_kid"


def test_non_eddsa_alg_is_never_a_permit_key() -> None:
    keys = [
        {**k, "alg": "RS256"} if k["kid"] == "permit-2026-a" else k
        for k in _F["key_set"]["keys"]
    ]
    case = next(c for c in _F["cases"] if c["name"] == "kid_selects_key_a")
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(case["token"], {**_F["key_set"], "keys": keys})
    assert exc.value.reason == "unknown_kid"


def _case(name: str) -> dict:
    return next(c for c in _F["cases"] if c["name"] == name)


def _key_entry(kid: str) -> dict:
    return next(k for k in _F["key_set"]["keys"] if k["kid"] == kid)


def test_audit_alias_refuses_that_permit_key_only() -> None:
    alias = {**_key_entry("permit-2026-b"), "kid": "audit-b", "role": "R3_audit"}
    key_set = {**_F["key_set"], "keys": [*_F["key_set"]["keys"], alias]}
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(_case("kid_selects_key_b")["token"], key_set)
    assert exc.value.reason == "key_role_conflict"
    ok = verify_permit_v4(_case("kid_selects_key_a")["token"], key_set)
    assert ok.verified_with_kid == "permit-2026-a"


@pytest.mark.parametrize("role", ["r2_permit", ["R2_permit"], None, ""])
def test_any_non_permit_role_alias_is_refused(role: object) -> None:
    alias = {**_key_entry("permit-2026-a"), "kid": "alias", "role": role}
    key_set = {**_F["key_set"], "keys": [*_F["key_set"]["keys"], alias]}
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(_case("kid_selects_key_a")["token"], key_set)
    assert exc.value.reason == "key_role_conflict"


def test_alias_matched_on_decoded_bytes_in_standard_base64() -> None:
    import base64

    x = _key_entry("permit-2026-a")["x"]
    std = base64.b64encode(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))).decode()
    alias = {
        **_key_entry("permit-2026-a"),
        "kid": "audit-std",
        "role": "R3_audit",
        "x": std,
    }
    key_set = {**_F["key_set"], "keys": [*_F["key_set"]["keys"], alias]}
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(_case("kid_selects_key_a")["token"], key_set)
    assert exc.value.reason == "key_role_conflict"


def test_default_kid_cannot_route_around_alias() -> None:
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(
            _case("no_kid_with_cross_role_alias")["token"],
            _F["alias_set"],
            default_kid="permit-2026-a",
        )
    assert exc.value.reason == "key_role_conflict"


def test_alias_in_object_shaped_key_set_is_refused() -> None:
    from types import SimpleNamespace

    snap = SimpleNamespace(
        keys=_F["alias_set"]["keys"], revoked_keys=[], revoked_kids=[]
    )
    with pytest.raises(PermitV4VerifyError) as exc:
        verify_permit_v4(_case("kid_with_cross_role_alias")["token"], snap)
    assert exc.value.reason == "key_role_conflict"


def test_vector_audit_key_shares_no_material_with_permit_keys() -> None:
    keys = _F["key_set"]["keys"]
    audit = {k["x"].rstrip("=") for k in keys if k["role"] != "R2_permit"}
    assert not [
        k["kid"]
        for k in keys
        if k["role"] == "R2_permit" and k["x"].rstrip("=") in audit
    ]
