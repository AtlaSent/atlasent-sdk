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
        jwk("permit-2025-old", SEED_A, revoked=True),
        jwk("audit-a", SEED_A, role="R3_audit"),
        jwk("permit-future", SEED_A, valid_from="2099-01-01T00:00:00Z"),
        jwk("permit-open-ended", SEED_A, valid_from=None, valid_until=None),
        # Revoked through the trust-root revocation ledger only (its own
        # entry still says revoked: false), as atlasent-revocations.json does.
        jwk("permit-ledger-revoked", SEED_A),
    ],
    "revoked_keys": [
        {"kid": "permit-ledger-revoked", "revoked_at": "2026-10-01T00:00:00Z", "role": "R2_permit"}
    ],
}
SINGLE_SET = {"keys": [jwk("permit-2026-a", SEED_A)]}

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
        "token": sign(hdr_kid(b"permit-2025-old"), payload, SEED_A),
        "key": "key_set",
        "expect": "key_revoked",
    },
    {
        "name": "kid_of_non_permit_role",
        "token": sign(hdr_kid(b"audit-a"), payload, SEED_A),
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
        "token": sign(hdr_kid(b"permit-ledger-revoked"), payload, SEED_A),
        "key": "key_set",
        "expect": "key_revoked",
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

json.dump(
    {
        "schema": "atlasent.permit_v4_kid_vectors.v1",
        "generator": "contract/tools/gen_permit_v4_kid_vectors.py",
        "note": "Claims bytes are the runtime-minted 'full' token's from vectors.json; headers and signatures are re-made here. Test keys only.",
        "pinned_key_b64": BASE["public_key_b64"],
        "key_set": KEY_SET,
        "single_set": SINGLE_SET,
        "expected_claims": full["expected_claims"],
        "cases": cases,
    },
    sys.stdout,
    indent=2,
)
sys.stdout.write("\n")
