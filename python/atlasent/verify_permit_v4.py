"""Offline verifier for pt.v4.* COSE Sign1 permit tokens (ADR-050).

``pt.v4.{base64url(COSE_Sign1_bytes)}`` where COSE_Sign1_bytes is a
CBOR-encoded COSE_Sign1 structure (RFC 9052, CBOR tag 18)::

    #6.18([bstr(protected_header), {}, bstr(permit_claims_cbor), bstr(sig)])

The bytes signed by Ed25519 are the COSE Sig_Structure (RFC 9052 §4.4)::

    ["Signature1", bstr(protected_header), bstr(""), bstr(permit_claims_cbor)]

Protected header: ``{ 1: -8 }`` (EdDSA, RFC 8037), optionally with
``{ 4: bstr(kid) }``; see ``_parse_protected_header``.
Permit claims: CBOR integer-keyed map with keys 4, 6, 7, -1 .. -35 (every key
atlasent-api's ``_shared/cose.ts`` encodes). Cross-language parity vectors:
``contract/vectors/permit-v4/vectors.json``, generated from the runtime's own
``signPermitV4`` (``contract/tools/gen_permit_v4_vectors.ts``).

Offline by design: with a pinned Ed25519 public key (raw 32 bytes,
standard base64) this function needs no network.  It is the Python mirror of
the TypeScript ``verifyPermitV4`` in ``typescript/src/verify-permit-v4.ts``.

Requires the ``cryptography`` library (already a dependency of the SDK).
"""

from __future__ import annotations

import base64
import dataclasses
import json
import uuid as _uuid_module
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ─── Error types ──────────────────────────────────────────────────────────────

REASON_BAD_FORMAT = "bad_format"
REASON_BAD_PREFIX = "bad_prefix"
REASON_COSE_DECODE_FAILED = "cose_decode_failed"
REASON_WRONG_PROTECTED_HEADER = "wrong_protected_header"
REASON_CLAIMS_DECODE_FAILED = "claims_decode_failed"
REASON_SIGNATURE_INVALID = "signature_invalid"
REASON_EXPIRED = "expired"
REASON_UNKNOWN_KID = "unknown_kid"
REASON_KEY_REVOKED = "key_revoked"
REASON_KEY_NOT_VALID_FOR_PERMIT = "key_not_valid_for_permit"
REASON_KID_REQUIRED = "kid_required"
REASON_KEY_SET_EXPIRED = "key_set_expired"

#: Maximum TrustSnapshot age (ms), the TypeScript SDK's DEFAULT_TRUST_TTL_MS.
TRUST_SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60 * 1000


class PermitV4VerifyError(Exception):
    """Raised when a pt.v4.* permit fails verification. ``reason`` is stable."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason


# ─── Permit claims dataclass ──────────────────────────────────────────────────


@dataclass
class PermitClaimsV4:
    permit_id: str  # UUID string (from key 7 / CWT cti — 16-byte bstr)
    exp: int  # Unix epoch seconds (key 4)
    iat: int  # Unix epoch seconds (key 6)
    decision_id: str  # tstr (key -1)
    org_id: str  # UUID string (key -2 — 16-byte bstr)
    action_type: str  # tstr (key -3)
    actor_id: str  # tstr (key -4)
    environment: str  # "live" | "test" (key -5)
    cdo_hash: str | None = None  # 64-char hex sha256 (key -6, optional)
    policy_hash: str | None = None  # 64-char hex sha256 (key -7, optional)
    # P4 delegation lineage (keys -8 .. -11)
    parent_permit_hash: str | None = None  # 64-char hex (key -8)
    parent_permit_id: str | None = None  # UUID (key -9)
    delegation_depth: int | None = None  # uint (key -10)
    delegating_actor_id: str | None = None  # tstr (key -11)
    # Execution binding (keys -12, -13)
    execution_hash_expected: str | None = None  # 64-char hex (key -12)
    envelope_hash: str | None = None  # 64-char hex (key -13)
    # ADR-063 exceptional authority (keys -14, -15)
    exception_id: str | None = None  # UUID (key -14)
    exception_type: str | None = None  # tstr (key -15)
    # AWS locus (keys -16, -17)
    aws_account_id: str | None = None  # tstr (key -16)
    aws_region: str | None = None  # tstr (key -17)
    operation_intent_id: str | None = None  # tstr (key -18)
    # Change brief (keys -19, -20)
    change_brief_id: str | None = None  # tstr (key -19)
    change_brief_digest: str | None = None  # tstr "sha256:..." (key -20)
    # H8 canonical authorization identity (keys -21 .. -23)
    authorization_identity_id: str | None = None  # UUID (key -21)
    authorization_issuance_id: str | None = None  # UUID (key -22)
    authorization_generation: int | None = None  # uint (key -23)
    # agent_runtime_identity.v1 evidence, canonical-JSON tstr (key -24)
    agent_runtime_identity: dict[str, Any] | None = None
    # Entra acceptance slice (keys -25 .. -32, -35)
    entra_tenant_id: str | None = None  # tstr (key -25)
    entra_org_binding_id: str | None = None  # UUID (key -26)
    entra_request_mapping_id: str | None = None  # UUID (key -27)
    entra_request_mapping_version: int | None = None  # uint (key -28)
    entra_approve_mapping_id: str | None = None  # UUID (key -29)
    entra_approve_mapping_version: int | None = None  # uint (key -30)
    pep_audience_executor_id: str | None = None  # tstr (key -31)
    entra_approve_principal_oid: str | None = None  # tstr (key -32)
    # Azure locus (keys -33, -34)
    azure_subscription_id: str | None = None  # tstr (key -33)
    azure_resource_group: str | None = None  # tstr (key -34)
    entra_request_principal_oid: str | None = None  # tstr (key -35)

    def present_claims(self) -> dict[str, Any]:
        """Only the claims the token actually carries (absent = not bound)."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class PermitV4VerifyResult:
    ok: bool
    claims: PermitClaimsV4
    #: kid from the COSE protected header; ``None`` when the header has none.
    kid: str | None = None
    #: kid of the key-set entry that verified the token; ``None`` for a pinned key.
    verified_with_kid: str | None = None


# ─── Minimal CBOR reader ──────────────────────────────────────────────────────


class _CborReader:
    def __init__(self, data: bytes) -> None:
        self._b = data
        self._pos = 0

    def _read_byte(self) -> int:
        if self._pos >= len(self._b):
            raise ValueError("cbor: unexpected end")
        b = self._b[self._pos]
        self._pos += 1
        return b

    def _read_uint_val(self, add: int) -> int:
        if add <= 23:
            return add
        if add == 24:
            return self._read_byte()
        if add == 25:
            hi = self._read_byte()
            lo = self._read_byte()
            return (hi << 8) | lo
        if add == 26:
            a, b, c, d = (self._read_byte() for _ in range(4))
            return (a << 24) | (b << 16) | (c << 8) | d
        raise ValueError(f"cbor: unsupported additional value {add}")

    def _read_head(self) -> tuple[int, int]:
        b = self._read_byte()
        major = (b >> 5) & 7
        n = self._read_uint_val(b & 0x1F)
        return major, n

    def read_bstr(self) -> bytes:
        major, n = self._read_head()
        if major != 2:
            raise ValueError(f"cbor: expected bstr, got major {major}")
        out = self._b[self._pos : self._pos + n]
        self._pos += n
        return out

    def read_array_len(self) -> int:
        major, n = self._read_head()
        if major != 4:
            raise ValueError(f"cbor: expected array, got major {major}")
        return n

    def read_map_len(self) -> int:
        major, n = self._read_head()
        if major != 5:
            raise ValueError(f"cbor: expected map, got major {major}")
        return n

    def read_int(self) -> int:
        major, n = self._read_head()
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        raise ValueError(f"cbor: expected int, got major {major}")

    def read_tstr(self) -> str:
        major, n = self._read_head()
        if major != 3:
            raise ValueError(f"cbor: expected tstr, got major {major}")
        out = self._b[self._pos : self._pos + n]
        self._pos += n
        return out.decode("utf-8")

    def skip(self) -> None:
        major, n = self._read_head()
        if major <= 1:
            return
        if major in (2, 3):
            self._pos += n
            return
        if major == 4:
            for _ in range(n):
                self.skip()
            return
        if major == 5:
            for _ in range(n * 2):
                self.skip()
            return
        if major == 6:
            self.skip()
            return
        raise ValueError(f"cbor: unsupported major {major}")

    def at_end(self) -> bool:
        return self._pos == len(self._b)

    def peek_major(self) -> int:
        return (self._b[self._pos] >> 5) & 7

    def read_tag_num(self) -> int:
        major, n = self._read_head()
        if major != 6:
            raise ValueError(f"cbor: expected tag, got major {major}")
        return n


# ─── CBOR encoding helpers (for Sig_Structure) ───────────────────────────────


def _cbor_uint(n: int) -> bytes:
    if n <= 23:
        return bytes([n])
    if n <= 0xFF:
        return bytes([24, n])
    if n <= 0xFFFF:
        return bytes([25, n >> 8, n & 0xFF])
    return bytes([26, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _cbor_bstr(b: bytes) -> bytes:
    head = bytearray(_cbor_uint(len(b)))
    head[0] |= 0x40
    return bytes(head) + b


def _cbor_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    head = bytearray(_cbor_uint(len(b)))
    head[0] |= 0x60
    return bytes(head) + b


def _cbor_array(items: list[bytes]) -> bytes:
    head = bytearray(_cbor_uint(len(items)))
    head[0] |= 0x80
    return bytes(head) + b"".join(items)


# ─── Protected header ─────────────────────────────────────────────────────────

# Accepted: { 1: -8 } (EdDSA) alone, or with { 4: bstr(kid) }, in either order.
# Anything else (another label, a duplicate, a non-EdDSA alg, a tstr kid) is
# rejected: the runtime mints { 1: -8 } today, and accepting a kid now lets it
# start stamping one without breaking verifiers already in the field.


def _parse_protected_header(data: bytes) -> str | None:
    r = _CborReader(data)
    n = r.read_map_len()
    alg: int | None = None
    kid: str | None = None
    seen: set[int] = set()
    for _ in range(n):
        label = r.read_int()
        if label in seen:
            raise ValueError(f"duplicate protected header label {label}")
        seen.add(label)
        if label == 1:
            alg = r.read_int()
        elif label == 4:
            raw = r.read_bstr()
            if not raw:
                raise ValueError("empty kid")
            kid = raw.decode("utf-8")
        else:
            raise ValueError(f"unexpected protected header label {label}")
    if not r.at_end():
        raise ValueError("trailing bytes after protected header")
    if alg != -8:
        raise ValueError("expected EdDSA protected header { 1: -8 }")
    return kid


def _as_dict(v: Any) -> dict[str, Any] | None:
    """A key or revocation entry as a dict (accepts trust-root dataclasses)."""
    if isinstance(v, dict):
        return v
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return dataclasses.asdict(v)
    return None


def _is_permit_key(k: dict[str, Any]) -> bool:
    return (
        isinstance(k.get("kid"), str)
        and isinstance(k.get("x"), str)
        # Explicit trust metadata only: an entry with no role (or no
        # kty/crv) is never a permit key, so an audit key whose role was
        # dropped cannot sign permits.
        and k.get("role") == "R2_permit"
        and k.get("kty") == "OKP"
        and k.get("crv") == "Ed25519"
    )


def _parse_iso(value: Any) -> float:
    from datetime import datetime

    if not isinstance(value, str):
        raise ValueError("not a timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _key_set_parts(key_set: Any) -> tuple[list[Any], set[str]]:
    """(keys, revoked kids) from a mapping or a TrustRootSnapshot-like object.

    Revocation is read from every place the trust root records it: an entry's
    own ``revoked``, the ledger's ``revoked_keys`` (atlasent-revocations.json
    / ``TrustRootSnapshot.revoked_keys``) and a flat ``revoked_kids`` list.
    """
    if isinstance(key_set, Mapping):
        raw_keys = key_set.get("keys")
        ledger = key_set.get("revoked_keys")
        flat = key_set.get("revoked_kids")
    else:
        raw_keys = getattr(key_set, "keys", None)
        ledger = getattr(key_set, "revoked_keys", None)
        flat = getattr(key_set, "revoked_kids", None)
    revoked: set[str] = set()
    for r in ledger if isinstance(ledger, list) else []:
        d = _as_dict(r)
        if d is not None and isinstance(d.get("kid"), str):
            revoked.add(d["kid"])
    for kid in flat if isinstance(flat, list) else []:
        if isinstance(kid, str):
            revoked.add(kid)
    return (raw_keys if isinstance(raw_keys, list) else []), revoked


def _material(x: Any) -> str | None:
    """Canonical key material: decoded bytes as hex (padding/alphabet-proof)."""
    if not isinstance(x, str):
        return None
    v = x.rstrip("=").replace("+", "-").replace("/", "_")
    try:
        return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).hex()
    except Exception:
        return None


def _in_window(k: dict[str, Any], iat: int) -> bool:
    """True when the permit's iat lies in the key's window (a null bound is open)."""
    try:
        if k.get("valid_from") is not None and iat < _parse_iso(k["valid_from"]):
            return False
        if k.get("valid_until") is not None and iat > _parse_iso(k["valid_until"]):
            return False
    except ValueError:
        return False
    return True


def _assert_key_set_fresh(key_set: Any) -> None:
    """Refuse a key set whose own ``valid_until`` (or ``expires_at``) has passed.

    A ``TrustRootSnapshot`` (or a trust-root document) carries its expiry;
    stale keys and stale revocation state must not keep authorizing permits.
    """
    import time as _time

    if isinstance(key_set, Mapping):
        until = key_set.get("valid_until")
        exp_ms = key_set.get("expires_at")
        fetched_ms = key_set.get("fetched_at")
    else:
        until = getattr(key_set, "valid_until", None)
        exp_ms = getattr(key_set, "expires_at", None)
        fetched_ms = getattr(key_set, "fetched_at", None)
    now = _time.time()
    # A TrustSnapshot-shaped set (``fetched_at`` in epoch ms) is also refused
    # once older than the snapshot age limit, even if ``expires_at`` is later
    # (same rule as the TypeScript SDK's isTrustSnapshotExpired()).
    if fetched_ms is not None and not (
        isinstance(fetched_ms, (int, float))
        and not isinstance(fetched_ms, bool)
        and now * 1000 <= fetched_ms + TRUST_SNAPSHOT_MAX_AGE_MS
    ):
        raise PermitV4VerifyError(
            REASON_KEY_SET_EXPIRED,
            "the key set is older than the trust snapshot age limit (fetched_at)",
        )
    if exp_ms is not None and not (
        isinstance(exp_ms, (int, float)) and exp_ms / 1000 > now
    ):
        raise PermitV4VerifyError(REASON_KEY_SET_EXPIRED, "the key set has expired")
    if until is not None:
        try:
            ok = _parse_iso(until) > now
        except ValueError:
            ok = False
        if not ok:
            raise PermitV4VerifyError(
                REASON_KEY_SET_EXPIRED, "the key set has expired (valid_until)"
            )


def _select_key(
    key_set: Any, kid: str | None, iat: int, default_kid: str | None
) -> dict[str, Any]:
    _assert_key_set_fresh(key_set)
    raw_keys, ledger_revoked = _key_set_parts(key_set)
    keys = [
        d
        for d in (_as_dict(k) for k in raw_keys)
        if d is not None and _is_permit_key(d)
    ]

    def revoked_kid(k: dict[str, Any]) -> bool:
        return k.get("revoked") is True or k.get("kid") in ledger_revoked

    # Revoked key material, compared as decoded bytes: any entry sharing a
    # revoked entry's key is revoked too, so a revoked private key cannot sign
    # under a live alias (however its x is padded or encoded).
    all_entries = [d for d in (_as_dict(k) for k in raw_keys) if d is not None]
    revoked_material = {
        m for d in all_entries if revoked_kid(d) and (m := _material(d.get("x")))
    }

    def revoked(k: dict[str, Any]) -> bool:
        m = _material(k.get("x"))
        return revoked_kid(k) or m is None or m in revoked_material

    wanted = kid if kid is not None else default_kid
    if wanted is not None:
        matches = [k for k in keys if k["kid"] == wanted]
        entry = matches[0] if len(matches) == 1 else None
        if entry is None:
            raise PermitV4VerifyError(
                REASON_UNKNOWN_KID, f"no permit key with kid {wanted!r}"
            )
    else:
        # Exactly one key that is unrevoked AND valid for this permit's iat,
        # so a staged next key or a retired one does not block the fallback.
        usable = [k for k in keys if not revoked(k) and _in_window(k, iat)]
        if len(usable) != 1:
            raise PermitV4VerifyError(
                REASON_KID_REQUIRED,
                "token carries no kid and the key set has "
                f"{len(usable)} permit keys valid for it",
            )
        entry = usable[0]
    if revoked(entry):
        raise PermitV4VerifyError(
            REASON_KEY_REVOKED, f"permit key {entry['kid']} is revoked"
        )
    if not _in_window(entry, iat):
        raise PermitV4VerifyError(
            REASON_KEY_NOT_VALID_FOR_PERMIT,
            f"permit issued outside the validity window of key {entry['kid']}",
        )
    return entry


# ─── COSE Sign1 decode ────────────────────────────────────────────────────────


def _decode_cose_sign1(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (protected_bytes, payload_bytes, sig_bytes)."""
    r = _CborReader(data)
    if r.peek_major() == 6:
        r.read_tag_num()  # optional tag 18
    length = r.read_array_len()
    if length != 4:
        raise ValueError(f"cose: expected 4-element array, got {length}")
    protected_bytes = r.read_bstr()
    r.skip()  # unprotected map {}
    payload_bytes = r.read_bstr()
    sig = r.read_bstr()
    return protected_bytes, payload_bytes, sig


def _build_sig_structure(protected_bytes: bytes, payload_bytes: bytes) -> bytes:
    """Build the COSE Sig_Structure for signing/verification (RFC 9052 §4.4)."""
    return _cbor_array(
        [
            _cbor_tstr("Signature1"),
            _cbor_bstr(protected_bytes),
            _cbor_bstr(b""),
            _cbor_bstr(payload_bytes),
        ]
    )


# ─── Permit claims decode ─────────────────────────────────────────────────────


def _bytes_to_uuid(b: bytes) -> str:
    return str(_uuid_module.UUID(bytes=b))


# Optional claim keys -8 .. -35, by CBOR value type (atlasent-api _shared/cose.ts).
_HEX_KEYS = {
    -8: "parent_permit_hash",
    -12: "execution_hash_expected",
    -13: "envelope_hash",
}
_UUID_KEYS = {
    -9: "parent_permit_id",
    -14: "exception_id",
    -21: "authorization_identity_id",
    -22: "authorization_issuance_id",
    -26: "entra_org_binding_id",
    -27: "entra_request_mapping_id",
    -29: "entra_approve_mapping_id",
}
_UINT_KEYS = {
    -10: "delegation_depth",
    -23: "authorization_generation",
    -28: "entra_request_mapping_version",
    -30: "entra_approve_mapping_version",
}
_TSTR_KEYS = {
    -11: "delegating_actor_id",
    -15: "exception_type",
    -16: "aws_account_id",
    -17: "aws_region",
    -18: "operation_intent_id",
    -19: "change_brief_id",
    -20: "change_brief_digest",
    -25: "entra_tenant_id",
    -31: "pep_audience_executor_id",
    -32: "entra_approve_principal_oid",
    -33: "azure_subscription_id",
    -34: "azure_resource_group",
    -35: "entra_request_principal_oid",
}


def _decode_permit_claims(data: bytes) -> PermitClaimsV4:
    r = _CborReader(data)
    length = r.read_map_len()
    result: dict = {}
    for _ in range(length):
        key = r.read_int()
        if key == 4:
            result["exp"] = r.read_int()
        elif key == 6:
            result["iat"] = r.read_int()
        elif key == 7:
            result["permit_id"] = _bytes_to_uuid(r.read_bstr())
        elif key == -1:
            result["decision_id"] = r.read_tstr()
        elif key == -2:
            result["org_id"] = _bytes_to_uuid(r.read_bstr())
        elif key == -3:
            result["action_type"] = r.read_tstr()
        elif key == -4:
            result["actor_id"] = r.read_tstr()
        elif key == -5:
            result["environment"] = r.read_tstr()
        elif key == -6:
            result["cdo_hash"] = r.read_bstr().hex()
        elif key == -7:
            result["policy_hash"] = r.read_bstr().hex()
        elif key in _HEX_KEYS:
            result[_HEX_KEYS[key]] = r.read_bstr().hex()
        elif key in _UUID_KEYS:
            result[_UUID_KEYS[key]] = _bytes_to_uuid(r.read_bstr())
        elif key in _UINT_KEYS:
            result[_UINT_KEYS[key]] = r.read_int()
        elif key in _TSTR_KEYS:
            result[_TSTR_KEYS[key]] = r.read_tstr()
        elif key == -24:
            parsed = json.loads(r.read_tstr())
            if not isinstance(parsed, dict):
                raise ValueError("agent_runtime_identity claim is not a JSON object")
            result["agent_runtime_identity"] = parsed
        else:
            r.skip()

    required = (
        "exp",
        "iat",
        "permit_id",
        "decision_id",
        "org_id",
        "action_type",
        "actor_id",
        "environment",
    )
    for f in required:
        if f not in result:
            raise ValueError(f"missing required claim: {f}")

    return PermitClaimsV4(**result)


# ─── Main API ─────────────────────────────────────────────────────────────────


def verify_permit_v4(
    token: str,
    public_key_b64: str | Mapping[str, Any] | Any,
    *,
    check_expiry: bool = False,
    default_kid: str | None = None,
) -> PermitV4VerifyResult:
    """Verify a pt.v4.* COSE Sign1 permit token offline.

    Decodes the base64url payload, verifies the EdDSA signature against the
    supplied Ed25519 public key (raw 32 bytes, standard base64), and returns
    the decoded permit claims.

    Does NOT verify ``exp`` unless ``check_expiry=True``.  The permit may
    still be revoked server-side even when this returns ``ok=True``.

    Args:
        token:          Full ``pt.v4.*`` token string.
        public_key_b64: Either one pinned key (raw 32-byte Ed25519, standard
                        base64), used whatever the header says, or a key set
                        (the trust root's atlasent-verifier-keys.json document
                        merged with its revocations, any ``{"keys": [...]}``, or
                        a :class:`~atlasent.trust_root.TrustRootSnapshot`)
                        indexed by the header kid.
        default_kid:    With a key set, the kid to use when the token's header
                        carries none and the set has several permit keys.
        check_expiry:   If True, raises if ``claims.exp ≤ now`` (default False).

    Returns:
        :class:`PermitV4VerifyResult` with ``ok=True`` and the decoded claims.

    Raises:
        :class:`PermitV4VerifyError` on any verification failure.
    """
    import time as _time

    if not isinstance(token, str):
        raise PermitV4VerifyError(REASON_BAD_FORMAT, "token must be a string")
    if not token.startswith("pt.v4."):
        raise PermitV4VerifyError(
            REASON_BAD_PREFIX, f"expected pt.v4.* prefix, got: {token[:12]!r}"
        )

    b64_payload = token[len("pt.v4.") :]
    # base64url → standard base64
    padded = b64_payload.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        cose_bytes = base64.b64decode(padded)
    except Exception as exc:
        raise PermitV4VerifyError(
            REASON_BAD_FORMAT, f"base64url decode failed: {exc}"
        ) from exc

    try:
        protected_bytes, payload_bytes, sig = _decode_cose_sign1(cose_bytes)
    except Exception as exc:
        raise PermitV4VerifyError(REASON_COSE_DECODE_FAILED, str(exc)) from exc

    try:
        header_kid = _parse_protected_header(protected_bytes)
    except Exception as exc:
        raise PermitV4VerifyError(REASON_WRONG_PROTECTED_HEADER, str(exc)) from exc

    try:
        claims = _decode_permit_claims(payload_bytes)
    except Exception as exc:
        raise PermitV4VerifyError(REASON_CLAIMS_DECODE_FAILED, str(exc)) from exc

    verified_with_kid: str | None = None
    if isinstance(public_key_b64, str):
        key_b64 = public_key_b64
        decode_key = base64.b64decode
    else:
        entry = _select_key(public_key_b64, header_kid, claims.iat, default_kid)
        verified_with_kid = entry["kid"]
        key_b64 = entry["x"]

        def decode_key(v: str) -> bytes:
            return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))

    to_verify = _build_sig_structure(protected_bytes, payload_bytes)
    try:
        raw_key = decode_key(key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_key)
        pub_key.verify(sig, to_verify)
    except InvalidSignature:
        raise PermitV4VerifyError(
            REASON_SIGNATURE_INVALID, "Ed25519 signature did not verify"
        )
    except Exception as exc:
        raise PermitV4VerifyError(
            REASON_SIGNATURE_INVALID, f"key or signature error: {exc}"
        ) from exc

    if check_expiry:
        now_sec = int(_time.time())
        if claims.exp <= now_sec:
            from datetime import datetime, timezone

            exp_str = datetime.fromtimestamp(claims.exp, tz=timezone.utc).isoformat()
            raise PermitV4VerifyError(REASON_EXPIRED, f"permit expired at {exp_str}")

    return PermitV4VerifyResult(
        ok=True, claims=claims, kid=header_kid, verified_with_kid=verified_with_kid
    )
