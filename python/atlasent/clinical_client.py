"""Clinical trial blinding/unblinding client for the AtlaSent Python SDK.

Thin wrapper over the ``v1-clinical-unblind`` edge function (public wire path
``/v1/clinical-unblind``). Consumes the typed wire shapes in
:mod:`atlasent.clinical`.

Usage::

    from atlasent import AtlaSentClient
    from atlasent.clinical_client import ClinicalTrialsClient

    client = AtlaSentClient(api_key="ask_live_...")
    clinical = ClinicalTrialsClient(client)

    for trial in clinical.list().trials:
        print(trial.trial_id, trial.status)

    result = clinical.request_unblind({
        "trial_id": "NCT12345678",
        "actor_id": "dr.smith",
        "reason": "DSMB interim analysis recommends unblinding",
        "approval_meaning": "I authorize the unblinding of trial NCT12345678.",
    })

Write methods require the ``clinical:manage`` scope; reads require
``clinical:read``.
"""

from __future__ import annotations

import json
import urllib.request as urllib_request
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from ._function_region import function_region_headers
from .clinical import (
    ClinicalBlindRequest,
    ClinicalBlindResponse,
    ClinicalEmergencyRequest,
    ClinicalHistoryResponse,
    ClinicalMutationResponse,
    ClinicalTrialGetResponse,
    ClinicalTrialListResponse,
    ClinicalUnblindRequest,
)
from .exceptions import AtlaSentError

if TYPE_CHECKING:
    from .client import AtlaSentClient


def _request(
    client: AtlaSentClient,
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    qs = ("?" + urlencode(params)) if params else ""
    url = f"{client.base_url.rstrip('/')}{path}{qs}"
    headers = {
        "Authorization": f"Bearer {client.api_key}",
        **function_region_headers(url),
        "Accept": "application/json",
    }
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib_request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except Exception as exc:  # noqa: BLE001
        raise AtlaSentError(f"Clinical unblinding request failed: {exc}") from exc


def _as_body(obj: Any) -> dict[str, Any]:
    """Accept either a pydantic request model or a plain dict."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True)
    return dict(obj)


class ClinicalTrialsClient:
    """Sub-client for the clinical trial unblinding gate.

    Obtain via ``ClinicalTrialsClient(atlasent_client)``.
    """

    _BASE = "/v1/clinical-unblind"

    def __init__(self, client: AtlaSentClient) -> None:
        self._client = client

    # ── Reads (clinical:read) ────────────────────────────────────────────

    def list(
        self,
        *,
        status: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> ClinicalTrialListResponse:
        """List clinical trial blinding records for the caller org."""
        params: dict[str, str] = {}
        if status is not None:
            params["status"] = status
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        data = _request(self._client, "GET", self._BASE, params=params or None)
        return ClinicalTrialListResponse.model_validate(data)

    def get(self, trial_id: str) -> ClinicalTrialGetResponse:
        """Fetch a single trial's blinding record by ``trial_id``."""
        data = _request(self._client, "GET", self._BASE, params={"trial_id": trial_id})
        return ClinicalTrialGetResponse.model_validate(data)

    def history(self, trial_id: str) -> ClinicalHistoryResponse:
        """Fetch the append-only unblinding event ledger for a trial."""
        data = _request(
            self._client, "GET", f"{self._BASE}/history", params={"trial_id": trial_id}
        )
        return ClinicalHistoryResponse.model_validate(data)

    # ── Writes (clinical:manage) ─────────────────────────────────────────

    def blind(
        self, request: ClinicalBlindRequest | dict[str, Any]
    ) -> ClinicalBlindResponse:
        """Establish a new blinding record for a clinical trial."""
        data = _request(
            self._client, "POST", f"{self._BASE}/blind", body=_as_body(request)
        )
        return ClinicalBlindResponse.model_validate(data)

    def request_unblind(
        self, request: ClinicalUnblindRequest | dict[str, Any]
    ) -> ClinicalMutationResponse:
        """Record an authorized standard (protocol-defined) unblinding."""
        data = _request(
            self._client, "POST", f"{self._BASE}/unblind", body=_as_body(request)
        )
        return ClinicalMutationResponse.model_validate(data)

    def emergency_unblind(
        self, request: ClinicalEmergencyRequest | dict[str, Any]
    ) -> ClinicalMutationResponse:
        """Record an emergency individual-patient unblinding (ICH E6(R2) §4.8)."""
        data = _request(
            self._client, "POST", f"{self._BASE}/emergency", body=_as_body(request)
        )
        return ClinicalMutationResponse.model_validate(data)

    def verify_permit(
        self,
        *,
        trial_id: str,
        permit_token: str,
        action_type: str,
        actor_id: str,
    ) -> dict[str, Any]:
        """Verify a clinical permit token inline (proxies to permit verify).

        Returns the raw verifier result (``valid`` / ``outcome`` /
        ``verify_error_code`` / ``reason``).
        """
        body = {
            "trial_id": trial_id,
            "permit_token": permit_token,
            "action_type": action_type,
            "actor_id": actor_id,
        }
        return _request(self._client, "POST", f"{self._BASE}/verify-permit", body=body)
