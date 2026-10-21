"""Hybrid trust-root bootstrap and snapshot management.

Seeds synchronously from an embedded baseline snapshot (see
``vendored_trust_root.py``) -- a plain dict literal compiled directly into
that module, not read from disk at import time. Optionally refreshes from
``https://keys.atlasent.io/.well-known/`` on a configurable interval
(default 4h, floor 5 min per ADR-005 D2).  Refresh failure is silent.

Snapshot expiry is fail-closed (ADR-005 D3): ``check_expiry()`` returns
``"expired"`` when ``valid_until`` passes, emits a one-time
``logging.warning`` per process, and causes callers to raise
``BundleVerificationError(reason="trust_snapshot_expired")`` by default.
A half-life warning is also emitted once per process when the snapshot
passes its midpoint.

CORRECTED: this module previously read ``vendor/trust-root/*.json`` via
``Path(__file__).parent.parent.parent / "vendor" / "trust-root"`` at first
use -- the same design (and the same two independent defects) as the
TypeScript SDK's ``trustRoot.ts`` before its fix; see that file's header
for the full incident writeup. In short: (1) ``pyproject.toml``'s
``[tool.setuptools.package-data]`` never listed anything under ``vendor/``,
and ``vendor/`` sits outside the ``atlasent`` package directory entirely,
so it was never part of any real ``pip install``; (2) even had it been
included, ``Path(__file__).parent.parent.parent`` from the *installed*
package's ``site-packages/atlasent/trust_root.py`` lands in
``site-packages`` itself, three levels short of anywhere `vendor/` could
plausibly live -- the path only ever resolved by coincidence in this
monorepo's dev checkout. Every real install's ``_load_vendor_snapshot()``
therefore always hit the ``except Exception`` fallback: a snapshot with
zero keys and zero revocations, valid until 2099. Fixed the same way as
the TypeScript SDK: embed the snapshot as a plain dict literal instead of
reading it from disk.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from atlasent.vendored_trust_root import VENDORED_TRUST_ROOT_SNAPSHOT_DATA

logger = logging.getLogger(__name__)

# Half-life warning: emitted once per process
_half_life_warning_emitted = False
_expired_warning_emitted = False

REFRESH_INTERVAL_SECONDS_DEFAULT = 4 * 60 * 60  # 4 hours
REFRESH_INTERVAL_SECONDS_FLOOR = 5 * 60  # 5 minutes
KEYS_BASE_URL = "https://keys.atlasent.io/.well-known"

TrustKeyRole = Literal["R1_release", "R2_permit", "R3_audit", "R4_pack"]

_TRUST_ROOT_KEY_FIELDS = {
    "kid",
    "role",
    "kty",
    "alg",
    "x",
    "crv",
    "valid_from",
    "valid_until",
    "replaced_by",
    "revoked",
    "tenant",
}
_REVOCATION_ENTRY_FIELDS = {"kid", "revoked_at", "role", "reason"}


@dataclass
class TrustRootKey:
    kid: str
    role: str
    kty: str
    alg: str
    x: str | None = None
    crv: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    replaced_by: str | None = None
    # ``None`` only when a loaded document's entry did not state ``revoked``
    # as a boolean: kept visible so verify_permit_v4 refuses the set
    # (key_set_untrustworthy, atlasent-api#4640) instead of reading False.
    revoked: bool | None = False
    tenant: str | None = None


@dataclass
class TrustRootRevocationEntry:
    kid: str
    revoked_at: str
    role: str | None = None
    reason: str | None = None


@dataclass
class TrustRootSnapshot:
    valid_until: str
    issued_at: str
    keys: list[TrustRootKey] = field(default_factory=list)
    revoked_keys: list[TrustRootRevocationEntry] = field(default_factory=list)
    revoked_identities: list[dict[str, Any]] = field(default_factory=list)


def _make_trust_root_key(d: dict[str, Any]) -> TrustRootKey:
    fields = {k: v for k, v in d.items() if k in _TRUST_ROOT_KEY_FIELDS}
    # A missing or non-boolean ``revoked`` must not become the dataclass
    # default False: that would read an unknown revocation as "not revoked".
    if not isinstance(d.get("revoked"), bool):
        fields["revoked"] = None
    return TrustRootKey(**fields)


def _make_revocation_entry(d: dict[str, Any]) -> TrustRootRevocationEntry:
    return TrustRootRevocationEntry(
        **{k: v for k, v in d.items() if k in _REVOCATION_ENTRY_FIELDS}
    )


class TrustRootManager:
    def __init__(
        self,
        initial_snapshot: TrustRootSnapshot,
        *,
        refresh_base_url: str = KEYS_BASE_URL,
        refresh_interval_seconds: int = REFRESH_INTERVAL_SECONDS_DEFAULT,
        disable_refresh: bool = False,
    ) -> None:
        self._snapshot = initial_snapshot
        self._lock = threading.RLock()
        self._refresh_base_url = refresh_base_url
        self._refresh_interval = max(
            refresh_interval_seconds, REFRESH_INTERVAL_SECONDS_FLOOR
        )
        self._timer: threading.Timer | None = None
        if not disable_refresh:
            self._schedule_refresh()

    def get_snapshot(self) -> TrustRootSnapshot:
        with self._lock:
            return self._snapshot

    def check_expiry(self) -> Literal["ok", "half_life", "expired"]:
        """Check whether the snapshot is expired; emit one-time warnings.

        Returns ``"ok"``, ``"half_life"``, or ``"expired"``.
        Emits a :mod:`logging` WARNING (via the ``atlasent`` logger) once
        per process for each of the half-life and expired conditions.
        """
        global _half_life_warning_emitted, _expired_warning_emitted

        snap = self.get_snapshot()
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        valid_until = datetime.fromisoformat(snap.valid_until.replace("Z", "+00:00"))
        issued_at = datetime.fromisoformat(snap.issued_at.replace("Z", "+00:00"))

        if now > valid_until:
            if not _expired_warning_emitted:
                _expired_warning_emitted = True
                days_ago = (now - valid_until).days
                logger.warning(
                    "[atlasent] Trust snapshot expired %d day(s) ago "
                    "(valid_until: %s). Update to a newer SDK build or "
                    "enable allow_expired_snapshot.",
                    days_ago,
                    snap.valid_until,
                )
            return "expired"
        window = (valid_until - issued_at).total_seconds()
        half_life = issued_at.timestamp() + window / 2
        if now.timestamp() > half_life:
            if not _half_life_warning_emitted:
                _half_life_warning_emitted = True
                days_left = (valid_until - now).days
                logger.warning(
                    "[atlasent] Trust snapshot at half-life: expires in %d day(s) "
                    "(valid_until: %s). Plan an SDK update.",
                    days_left,
                    snap.valid_until,
                )
            return "half_life"
        return "ok"

    def lookup_key(self, kid: str) -> TrustRootKey | None:
        snap = self.get_snapshot()
        for k in snap.keys:
            if k.kid == kid:
                return k
        return None

    def is_revoked(self, kid: str) -> bool:
        snap = self.get_snapshot()
        return any(r.kid == kid for r in snap.revoked_keys)

    def replace_snapshot(self, next_snapshot: TrustRootSnapshot) -> None:
        with self._lock:
            self._snapshot = next_snapshot

    def stop_refresh(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _schedule_refresh(self) -> None:
        self._timer = threading.Timer(
            self._refresh_interval, self._do_refresh_and_reschedule
        )
        self._timer.daemon = True
        self._timer.start()

    def _do_refresh_and_reschedule(self) -> None:
        self._do_refresh()
        self._schedule_refresh()

    def _do_refresh(self) -> None:
        """Attempt a background refresh. All errors are caught and logged silently."""
        try:
            self._do_refresh_inner()
        except Exception as exc:
            logger.debug("trust-root refresh failed (silent): %s", exc)

    def _do_refresh_inner(self) -> None:
        import urllib.request

        base = self._refresh_base_url.rstrip("/")
        urls = {
            "index": f"{base}/atlasent-trust-root.json",
            "keys": f"{base}/atlasent-verifier-keys.json",
            "revocations": f"{base}/atlasent-revocations.json",
        }
        data: dict[str, Any] = {}
        for name, url in urls.items():
            with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
                data[name] = json.loads(resp.read())

        if not data.get("index", {}).get("valid_until"):
            return
        keys_data = data.get("keys", {}).get("keys", [])
        revoc_data = data.get("revocations", {})

        new_snap = TrustRootSnapshot(
            valid_until=data["index"]["valid_until"],
            issued_at=data["index"].get("issued_at", self._snapshot.issued_at),
            keys=[_make_trust_root_key(kd) for kd in keys_data],
            revoked_keys=[
                _make_revocation_entry(rd) for rd in revoc_data.get("revoked_keys", [])
            ],
            revoked_identities=revoc_data.get("revoked_identities", []),
        )
        self.replace_snapshot(new_snap)


# ─── Load the embedded (vendored) snapshot ────────────────────────────────────────


def _load_vendor_snapshot() -> TrustRootSnapshot:
    # The embedded data is committed source (see vendored_trust_root.py),
    # always present at import time -- there is no I/O and nothing to fall
    # back from.
    data = VENDORED_TRUST_ROOT_SNAPSHOT_DATA
    return TrustRootSnapshot(
        valid_until=data["valid_until"],
        issued_at=data["issued_at"],
        keys=[_make_trust_root_key(kd) for kd in data.get("keys", [])],
        revoked_keys=[
            _make_revocation_entry(rd) for rd in data.get("revoked_keys", [])
        ],
        revoked_identities=data.get("revoked_identities", []),
    )


_global_manager: TrustRootManager | None = None
_global_manager_lock = threading.Lock()


def get_global_trust_root_manager(
    *,
    disable_refresh: bool = False,
) -> TrustRootManager:
    global _global_manager
    with _global_manager_lock:
        if _global_manager is None:
            _global_manager = TrustRootManager(
                _load_vendor_snapshot(),
                disable_refresh=disable_refresh,
            )
    return _global_manager


def _set_global_trust_root_manager_for_tests(mgr: TrustRootManager | None) -> None:
    global _global_manager, _half_life_warning_emitted, _expired_warning_emitted
    _global_manager = mgr
    _half_life_warning_emitted = False
    _expired_warning_emitted = False
