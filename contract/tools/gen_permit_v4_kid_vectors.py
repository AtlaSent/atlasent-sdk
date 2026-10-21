"""Generate kid-aware pt.v4 verification vectors (reading side only).

atlasent-api does not yet put a ``kid`` in the COSE protected header
(``{1: -8}`` is fixed). Verifiers must accept a header with ``kid`` *before*
the runtime starts minting one, so these vectors re-wrap the runtime-minted
claim payload of ``vectors.json``'s ``full`` token under different protected
headers and re-sign with the same public test seed. The claims bytes are the
runtime's own; only the header and signature differ.

    python3 contract/tools/gen_permit_v4_kid_vectors.py \
        > contract/vectors/permit-v4/kid-vectors.json

The key set mirrors atlasent-keys' ``.well-known/atlasent-verifier-keys.json``
entry shape (kid, role, kty, crv, alg, x, revoked, valid_from, valid_until).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
BASE = json.loads((ROOT / "contract/vectors/permit-v4/vectors.json").read_text())

# RFC 8032 test-1 seed (same key as vectors.json) and RFC 8032 test-2 seed.
SEED_A = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
SEED_B = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
# RFC 8032 test-3 seed, and a fourth fixed test seed: key material for the
# REVOKED entries, so revocation never touches SEED_A / SEED_B's live keys.
SEED_C = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
SEED_D = bytes.fromhex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
# RFC 8032 test-1024 seed: the AUDIT (R3) key's own material. An audit key
# must never share material with a permit key (cross-role alias, refused), so
# audit-a no longer reuses SEED_A.
SEED_E = bytes.fromhex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def head(major: int, n: int) -> bytes:
    if n <= 23:
        return bytes([(major << 5) | n])
    if n <= 0xFF:
        return bytes([(major << 5) | 24, n])
    if n <= 0xFFFF:
        return bytes([(major << 5) | 25, n >> 8, n & 0xFF])
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def bstr(b: bytes) -> bytes:
    return head(2, len(b)) + b


def tstr(s: str) -> bytes:
    e = s.encode()
    return head(3, len(e)) + e


def payload_of(token: str) -> bytes:
    """Extract the runtime's permit_claims bytes from a pt.v4 token."""
    raw = b64u_dec(token[len("pt.v4.") :])
    i = 0
    if raw[0] >> 5 == 6:  # tag 18
        i += 1
    assert raw[i] == 0x84
    i += 1
    # protected bstr
    n = raw[i] & 0x1F
    i += 1 + n
    assert raw[i] == 0xA0  # empty unprotected map
    i += 1
    h = raw[i]
    add = h & 0x1F
    i += 1
    if add <= 23:
        n = add
    elif add == 24:
        n = raw[i]
        i += 1
    elif add == 25:
        n = int.from_bytes(raw[i : i + 2], "big")
        i += 2
    else:
        n = int.from_bytes(raw[i : i + 4], "big")
        i += 4
    return raw[i : i + n]


def sign(protected: bytes, payload: bytes, seed: bytes) -> str:
    sig_structure = head(4, 4) + tstr("Signature1") + bstr(protected) + bstr(b"") + bstr(payload)
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    cose = bytes([0xD2]) + head(4, 4) + bstr(protected) + bytes([0xA0]) + bstr(payload) + bstr(sig)
    return "pt.v4." + b64u(cose)


def pub_x(seed: bytes) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return b64u(raw)


def jwk(kid: str, seed: bytes, **extra: object) -> dict:
    return {
        "kid": kid,
        "role": "R2_permit",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": pub_x(seed),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2028-01-01T00:00:00Z",
        "revoked": False,
        **extra,
    }


full = next(v for v in BASE["vectors"] if v["name"] == "full")
payload = payload_of(full["token"])

ALG = bytes([0x01, 0x27])  # 1: -8


def hdr_kid(kid: bytes) -> bytes:
    return bytes([0xA2]) + ALG + bytes([0x04]) + bstr(kid)


KEY_SET = {
    "keys": [
        jwk("permit-2026-a", SEED_A),
        jwk("permit-2026-b", SEED_B),
        # Revoked, and its x deliberately PADDED ("="): the live alias below
        # uses the unpadded form, so only a byte-level comparison links them.
        {**jwk("permit-2025-old", SEED_C, revoked=True), "x": pub_x(SEED_C) + "="},
        # A live entry re-publishing the revoked permit-2025-old material.
        jwk("permit-alias-of-old", SEED_C),
        jwk("audit-a", SEED_E, role="R3_audit"),
        jwk("permit-future", SEED_A, valid_from="2099-01-01T00:00:00Z"),
        jwk("permit-open-ended", SEED_A, valid_from=None, valid_until=None),
        # Revoked through the trust-root revocation ledger only (its own
        # entry still says revoked: false), as atlasent-revocations.json does.
        jwk("permit-ledger-revoked", SEED_D),
    ],
    "revoked_keys": [
        {"kid": "permit-ledger-revoked", "revoked_at": "2026-10-01T00:00:00Z", "role": "R2_permit"}
    ],
}
SINGLE_SET = {"keys": [jwk("permit-2026-a", SEED_A)]}
# Mid-rotation: the current key plus a staged next key not yet valid. A
# kid-less token issued now must still resolve to the one key valid for it.
ROTATION_SET = {
    "keys": [
        jwk("permit-2026-a", SEED_A),
        jwk("permit-next", SEED_B, valid_from="2099-01-01T00:00:00Z", valid_until=None),
    ]
}
# Cross-role alias: the permit key's material re-published under an AUDIT
# role (x padded, so only a byte-level comparison links them). Whoever holds
# the audit private key could sign permits, so the permit key is refused.
ALIAS_SET = {
    "keys": [
        jwk("permit-2026-a", SEED_A),
        {**jwk("audit-alias-of-a", SEED_A, role="R3_audit"), "x": pub_x(SEED_A) + "="},
    ]
}
# The same alias through an entry with no role at all: not a permit key, so
# its material is not permit-only either.
ROLELESS_ALIAS_SET = {
    "keys": [
        jwk("permit-2026-a", SEED_A),
        {k: v for k, v in jwk("unroled-alias-of-a", SEED_A).items() if k != "role"},
    ]
}
# A key set that states its own expiry, already passed.
EXPIRED_SET = {**SINGLE_SET, "valid_until": "2020-01-01T00:00:00Z"}

# ── Untrustworthy key sets (atlasent-api#4640) ──────────────────────────────
# Each holds the live permit-2026-a key, so the ONLY reason to refuse is that
# the set's revocation state cannot be read. Kid-bearing and kid-less tokens
# are both refused (key_set_untrustworthy), so an unreadable revocation can
# never leave the key it might name live.
_A = jwk("permit-2026-a", SEED_A)
_B = jwk("permit-2026-b", SEED_B)
UNTRUSTWORTHY_SETS = {
    # The same kid published twice: the whole document is ambiguous.
    "duplicate_kid_set": {"keys": [_A, jwk("permit-dup", SEED_A), jwk("permit-dup", SEED_B)]},
    # A ledger kid that no entry in `keys` carries: its material is unknown.
    "unresolved_ledger_set": {
        "keys": [_A],
        "revoked_keys": [{"kid": "permit-gone", "revoked_at": "2026-10-01T00:00:00Z"}],
    },
    # The same, through the flat TrustSnapshot `revoked_kids` list.
    "unresolved_flat_ledger_set": {"keys": [_A], "revoked_kids": ["permit-gone"]},
    # A ledger kid whose entry is present but carries no key material.
    "ledger_kid_without_material_set": {
        "keys": [_A, {k: v for k, v in jwk("permit-gone", SEED_D).items() if k != "x"}],
        "revoked_keys": [{"kid": "permit-gone", "revoked_at": "2026-10-01T00:00:00Z"}],
    },
    # An inline revocation whose own material is unreadable.
    "revoked_unreadable_material_set": {
        "keys": [_A, {**jwk("permit-gone", SEED_D, revoked=True), "x": "not base64!"}]
    },
    # An inline revocation with neither a kid nor material.
    "anonymous_revocation_set": {
        "keys": [_A, {k: v for k, v in jwk("_", SEED_D, revoked=True).items() if k not in ("kid", "x")}]
    },
    # An entry with no `revoked` at all.
    "missing_revoked_set": {"keys": [_A, {k: v for k, v in _B.items() if k != "revoked"}]},
    # An entry whose `revoked` is not a boolean.
    "string_revoked_set": {"keys": [_A, {**_B, "revoked": "false"}]},
    # The selected key's OWN entry with no boolean `revoked`.
    "own_revoked_null_set": {"keys": [{**_A, "revoked": None}]},
    # A ledger that is not a list.
    "malformed_ledger_set": {"keys": [_A], "revoked_keys": {"kid": "permit-gone"}},
    # A ledger row that names no kid.
    "kidless_ledger_row_set": {"keys": [_A], "revoked_keys": [{"revoked_at": "2026-10-01T00:00:00Z"}]},
    # A flat ledger that is not a list of kids.
    "malformed_flat_ledger_set": {"keys": [_A], "revoked_kids": "permit-gone"},
    # `keys` that is not a list.
    "keys_not_a_list_set": {"keys": {"permit-2026-a": _A}},
}

# Kid-less fallback validity window (atlasent-api#4640): the selected key is
# bounded by every R2_permit entry carrying its material. A retired entry for
# permit-2026-a's material (under another kid) ends kid-less use of the key;
# a kid naming permit-2026-a still selects only its own entry's window.
RETIRED_ALIAS_SET = {
    "keys": [_A, jwk("permit-2026-a-retired", SEED_A, valid_until="2026-02-01T00:00:00Z")]
}
# The same alias with an unreadable bound (a number, not an ISO-8601 string).
INVALID_BOUND_ALIAS_SET = {
    "keys": [_A, jwk("permit-2026-a-bad-bound", SEED_A, valid_from=1767225600)]
}

cases = [
    # Accept
    {"name": "no_kid_single_key", "token": full["token"], "key": "pinned", "expect": "ok"},
    {"name": "no_kid_single_key_set", "token": full["token"], "key": "single_set", "expect": "ok"},
    {
        "name": "kid_selects_key_a",
        "token": sign(hdr_kid(b"permit-2026-a"), payload, SEED_A),
        "key": "key_set",
        "expect": "ok",
        "kid": "permit-2026-a",
    },
    {
        "name": "kid_selects_key_b",
        "token": sign(hdr_kid(b"permit-2026-b"), payload, SEED_B),
        "key": "key_set",
        "expect": "ok",
        "kid": "permit-2026-b",
    },
    {
        "name": "kid_header_with_pinned_single_key",
        "token": sign(hdr_kid(b"permit-2026-a"), payload, SEED_A),
        "key": "pinned",
        "expect": "ok",
        "kid": "permit-2026-a",
    },
    {
        "name": "kid_before_alg_canonical_order_irrelevant",
        "token": sign(bytes([0xA2, 0x04]) + bstr(b"permit-2026-a") + ALG, payload, SEED_A),
        "key": "key_set",
        "expect": "ok",
        "kid": "permit-2026-a",
    },
    # Reject
    {
        "name": "kid_names_wrong_key",
        "token": sign(hdr_kid(b"permit-2026-b"), payload, SEED_A),
        "key": "key_set",
        "expect": "signature_invalid",
    },
    {
        "name": "unknown_kid",
        "token": sign(hdr_kid(b"permit-2099-x"), payload, SEED_A),
        "key": "key_set",
        "expect": "unknown_kid",
    },
    {
        "name": "revoked_kid",
        "token": sign(hdr_kid(b"permit-2025-old"), payload, SEED_C),
        "key": "key_set",
        "expect": "key_revoked",
    },
    {
        "name": "live_alias_of_revoked_key_material",
        "token": sign(hdr_kid(b"permit-alias-of-old"), payload, SEED_C),
        "key": "key_set",
        "expect": "key_revoked",
    },
    {
        "name": "alg_uint32_alias_of_minus_8",
        "token": sign(bytes([0xA1, 0x01, 0x1A, 0xFF, 0xFF, 0xFF, 0xF8]), payload, SEED_A),
        "key": "pinned",
        "expect": "wrong_protected_header",
    },
    {
        "name": "kid_of_non_permit_role",
        "token": sign(hdr_kid(b"audit-a"), payload, SEED_E),
        "key": "key_set",
        "expect": "unknown_kid",
    },
    {
        "name": "kid_outside_key_validity",
        "token": sign(hdr_kid(b"permit-future"), payload, SEED_A),
        "key": "key_set",
        "expect": "key_not_valid_for_permit",
    },
    {
        "name": "null_validity_bounds_are_unbounded",
        "token": sign(hdr_kid(b"permit-open-ended"), payload, SEED_A),
        "key": "key_set",
        "expect": "ok",
        "kid": "permit-open-ended",
    },
    {
        "name": "kid_revoked_in_ledger_only",
        "token": sign(hdr_kid(b"permit-ledger-revoked"), payload, SEED_D),
        "key": "key_set",
        "expect": "key_revoked",
    },
    {"name": "no_kid_mid_rotation_uses_the_key_valid_for_iat", "token": full["token"], "key": "rotation_set", "expect": "ok"},
    {"name": "expired_key_set", "token": full["token"], "key": "expired_set", "expect": "key_set_expired"},
    {
        "name": "kid_with_cross_role_alias",
        "token": sign(hdr_kid(b"permit-2026-a"), payload, SEED_A),
        "key": "alias_set",
        "expect": "key_role_conflict",
    },
    {"name": "no_kid_with_cross_role_alias", "token": full["token"], "key": "alias_set", "expect": "key_role_conflict"},
    {
        "name": "kid_with_roleless_alias",
        "token": sign(hdr_kid(b"permit-2026-a"), payload, SEED_A),
        "key": "roleless_alias_set",
        "expect": "key_role_conflict",
    },
    {"name": "no_kid_ambiguous_key_set", "token": full["token"], "key": "key_set", "expect": "kid_required"},
    {
        "name": "extra_header_label",
        "token": sign(bytes([0xA3]) + ALG + bytes([0x04]) + bstr(b"permit-2026-a") + bytes([0x03, 0x00]), payload, SEED_A),
        "key": "key_set",
        "expect": "wrong_protected_header",
    },
    {
        "name": "wrong_alg",
        "token": sign(bytes([0xA1, 0x01, 0x26]), payload, SEED_A),
        "key": "pinned",
        "expect": "wrong_protected_header",
    },
    {
        "name": "kid_as_text_string",
        "token": sign(bytes([0xA2]) + ALG + bytes([0x04]) + tstr("permit-2026-a"), payload, SEED_A),
        "key": "key_set",
        "expect": "wrong_protected_header",
    },
    {
        "name": "duplicate_alg_label",
        "token": sign(bytes([0xA2]) + ALG + ALG, payload, SEED_A),
        "key": "pinned",
        "expect": "wrong_protected_header",
    },
    {
        "name": "no_alg",
        "token": sign(bytes([0xA1, 0x04]) + bstr(b"permit-2026-a"), payload, SEED_A),
        "key": "key_set",
        "expect": "wrong_protected_header",
    },
]

_KID_A = sign(hdr_kid(b"permit-2026-a"), payload, SEED_A)
for _set in UNTRUSTWORTHY_SETS:
    _stem = _set[: -len("_set")]
    cases.append({"name": f"kid_with_{_stem}", "token": _KID_A, "key": _set, "expect": "key_set_untrustworthy"})
    cases.append({"name": f"no_kid_with_{_stem}", "token": full["token"], "key": _set, "expect": "key_set_untrustworthy"})
cases += [
    {
        "name": "duplicate_kid_named_by_token",
        "token": sign(hdr_kid(b"permit-dup"), payload, SEED_B),
        "key": "duplicate_kid_set",
        "expect": "key_set_untrustworthy",
    },
    {
        "name": "no_kid_bounded_by_retired_alias_window",
        "token": full["token"],
        "key": "retired_alias_set",
        "expect": "key_not_valid_for_permit",
    },
    {
        "name": "kid_selects_own_window_despite_retired_alias",
        "token": _KID_A,
        "key": "retired_alias_set",
        "expect": "ok",
        "kid": "permit-2026-a",
    },
    {
        "name": "no_kid_bounded_by_alias_with_invalid_bound",
        "token": full["token"],
        "key": "invalid_bound_alias_set",
        "expect": "key_not_valid_for_permit",
    },
]

json.dump(
    {
        "schema": "atlasent.permit_v4_kid_vectors.v1",
        "generator": "contract/tools/gen_permit_v4_kid_vectors.py",
        "note": "Claims bytes are the runtime-minted 'full' token's from vectors.json; headers and signatures are re-made here. Test keys only.",
        "pinned_key_b64": BASE["public_key_b64"],
        "key_set": KEY_SET,
        "single_set": SINGLE_SET,
        "rotation_set": ROTATION_SET,
        "expired_set": EXPIRED_SET,
        "alias_set": ALIAS_SET,
        "roleless_alias_set": ROLELESS_ALIAS_SET,
        "retired_alias_set": RETIRED_ALIAS_SET,
        "invalid_bound_alias_set": INVALID_BOUND_ALIAS_SET,
        **UNTRUSTWORTHY_SETS,
        "expected_claims": full["expected_claims"],
        "cases": cases,
    },
    sys.stdout,
    indent=2,
)
sys.stdout.write("\n")
