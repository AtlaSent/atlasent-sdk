"""Hostile key sets (atlasent-api#4640 parity).

Same rules as typescript/test/verify-permit-v4-keyset-trust.test.ts: a key set
whose revocation state cannot be read is refused as a whole, for kid-bearing
and kid-less tokens, and a kid-less token is bounded by every R2_permit entry
sharing the selected key's material. Shared cases: contract/vectors/permit-v4/
kid-vectors.json; these add SDK snapshot shapes and per-field edge values.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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


def _tok(name: str) -> str:
    return next(c for c in _F["cases"] if c["name"] == name)["token"]


KID_A = _tok("kid_selects_key_a")
NO_KID = _tok("no_kid_single_key_set")
A = _F["single_set"]["keys"][0]
B = next(k for k in _F["key_set"]["keys"] if k["kid"] == "permit-2026-b")


def _reason(token: str, key_set: Any, default_kid: str | None = None) -> str:
    try:
        verify_permit_v4(token, key_set, default_kid=default_kid)
    except PermitV4VerifyError as exc:
        return exc.reason
    return "ok"


def _refused_both(key_set: Any) -> None:
    assert _reason(KID_A, key_set) == "key_set_untrustworthy"
    assert _reason(NO_KID, key_set) == "key_set_untrustworthy"
    assert _reason(NO_KID, key_set, "permit-2026-a") == "key_set_untrustworthy"


_NON_BOOL = [0, 1, None, "false", "true", {"value": False}]


@pytest.mark.parametrize("value", _NON_BOOL, ids=repr)
def test_other_entry_non_boolean_revoked(value: object) -> None:
    _refused_both({"keys": [A, {**B, "revoked": value}]})


@pytest.mark.parametrize("value", _NON_BOOL, ids=repr)
def test_own_entry_non_boolean_revoked(value: object) -> None:
    _refused_both({"keys": [{**A, "revoked": value}]})


def test_entry_missing_revoked() -> None:
    _refused_both({"keys": [A, {k: v for k, v in B.items() if k != "revoked"}]})


@pytest.mark.parametrize("entry", [None, "permit-2026-b", [B]], ids=repr)
def test_entry_not_an_object(entry: object) -> None:
    _refused_both({"keys": [A, entry]})


def test_sound_set_control() -> None:
    assert _reason(KID_A, {"keys": [A, B]}) == "ok"


def test_unresolved_ledger_kid_in_trust_root_snapshot() -> None:
    from atlasent.trust_root import (
        TrustRootKey,
        TrustRootRevocationEntry,
        TrustRootSnapshot,
    )

    snap = TrustRootSnapshot(
        valid_until="2099-01-01T00:00:00Z",
        issued_at="2026-01-01T00:00:00Z",
        keys=[TrustRootKey(**A)],
        revoked_keys=[
            TrustRootRevocationEntry(
                kid="permit-gone", revoked_at="2026-10-01T00:00:00Z"
            )
        ],
    )
    _refused_both(snap)


def test_unresolved_flat_ledger_in_object_shaped_set() -> None:
    now = time.time() * 1000
    _refused_both(
        SimpleNamespace(
            keys=[A],
            revoked_kids=["permit-gone"],
            fetched_at=now,
            expires_at=now + 60_000,
        )
    )


_BAD_X = [
    # Four characters, so a lenient decoder that skips them (Python's default
    # b64decode does) still reads B's key: only a strict alphabet refuses them.
    f"{B['x'][:10]}    {B['x'][10:]}",
    f"{B['x'][:40]}!!!!{B['x'][40:]}",
    f"{B['x']}A"[:41],
    42,
]


@pytest.mark.parametrize("x", _BAD_X, ids=["whitespace", "bang", "length", "number"])
def test_revoked_entry_with_unreadable_material(x: object) -> None:
    _refused_both({"keys": [A, {**B, "revoked": True, "x": x}]})


@pytest.mark.parametrize("x", _BAD_X, ids=["whitespace", "bang", "length", "number"])
def test_ledger_revoked_entry_with_unreadable_material(x: object) -> None:
    _refused_both({"keys": [A, {**B, "x": x}], "revoked_keys": [{"kid": B["kid"]}]})


def test_resolved_ledger_control() -> None:
    assert _reason(KID_A, {"keys": [A, B], "revoked_keys": [{"kid": B["kid"]}]}) == "ok"


def test_anonymous_revocation() -> None:
    anon = {k: v for k, v in B.items() if k not in ("kid", "x")}
    _refused_both({"keys": [A, {**anon, "revoked": True}]})


@pytest.mark.parametrize(
    "extra",
    [
        {"revoked_keys": None},
        {"revoked_keys": {"kid": "x"}},
        {"revoked_keys": [{"kid": ""}]},
        {"revoked_keys": [{"kid": 7}]},
        {"revoked_keys": [None]},
        {"revoked_kids": None},
        {"revoked_kids": "permit-2026-b"},
        {"revoked_kids": [""]},
    ],
    ids=repr,
)
def test_malformed_ledger(extra: dict) -> None:
    _refused_both({"keys": [A], **extra})


def test_null_ledger_on_object_shaped_set() -> None:
    _refused_both(SimpleNamespace(keys=[A], revoked_keys=None))


def test_keys_missing() -> None:
    _refused_both({"revoked_keys": []})


def test_duplicate_kid_even_on_non_permit_entry() -> None:
    _refused_both({"keys": [A, {**B, "kid": "permit-2026-a", "role": "R3_audit"}]})


def _alias(**extra: object) -> dict:
    return {**A, "kid": "permit-a-alias", **extra}


@pytest.mark.parametrize(
    "extra",
    [
        {"valid_until": "2026-02-01T00:00:00Z"},
        {"valid_from": "2099-01-01T00:00:00Z"},
        {"valid_from": 0},
        {"valid_until": "soon"},
    ],
    ids=repr,
)
def test_alias_window_bounds_kidless_fallback(extra: dict) -> None:
    key_set = {"keys": [A, _alias(**extra)]}
    assert _reason(NO_KID, key_set) == "key_not_valid_for_permit"
    assert _reason(NO_KID, key_set, "permit-2026-a") == "key_not_valid_for_permit"
    # A kid names one entry: only that entry's window applies.
    assert _reason(KID_A, key_set) == "ok"


def test_alias_in_standard_base64_still_bounds() -> None:
    raw = base64.urlsafe_b64decode(A["x"] + "=" * (-len(A["x"]) % 4))
    std = base64.b64encode(raw).decode()
    key_set = {"keys": [A, _alias(x=std, valid_until="2026-02-01T00:00:00Z")]}
    assert _reason(NO_KID, key_set) == "key_not_valid_for_permit"


def test_in_window_alias_control() -> None:
    key_set = {"keys": [A, _alias(valid_from=None, valid_until=None)]}
    assert _reason(NO_KID, key_set, "permit-2026-a") == "ok"


def test_revoked_material_alias_is_refused_as_revoked() -> None:
    assert _reason(NO_KID, {"keys": [A, _alias(revoked=True)]}) == "kid_required"


def test_published_trust_root_reaches_the_signature_check() -> None:
    # The vendored snapshot is atlasent-keys' .well-known verifier keys plus
    # its revocation ledger: under the new rules it must still be trusted.
    from atlasent.vendored_trust_root import VENDORED_TRUST_ROOT_SNAPSHOT_DATA as V

    doc = {"keys": V["keys"], "revoked_keys": V["revoked_keys"]}
    assert _reason(NO_KID, doc) == "signature_invalid"
    assert all(isinstance(k.get("revoked"), bool) for k in V["keys"])
