"""BCCAE V1 — Python client.

BCCAEClient wraps the four BCCAE Phase 3 endpoints:

- evaluate    → POST /v1/bccae/evaluations   (bccae:evaluate scope)
- execute     → POST /v1/bccae/execute        (bccae:execute scope)
- revoke      → POST /v1/bccae/revocations    (bccae:revoke scope)
- get_evidence → GET /v1/bccae/evidence/:id   (bccae:audit scope)

Spec: atlasent-internal/architecture/BCCAE-architecture.md
Phase 3 — Execution Assurance. Not a Deploy Gate V1 customer API.
"""

from __future__ import annotations

import secrets
from typing import Any, Literal
from urllib.parse import quote, urlparse, urlunparse

import httpx

from ._function_region import function_region_headers
from .exceptions import AtlaSentError

DEFAULT_BASE_URL = "https://api.atlasent.io"
DEFAULT_TIMEOUT = 10.0

# ── Types ─────────────────────────────────────────────────────────────────────────────

BccaeActorType = Literal["HUMAN", "AGENT", "SERVICE", "EXTERNAL"]
BccaeTrustLevel = Literal["L0", "L1", "L2", "L3"]
BccaeResourceClassification = Literal[
    "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"
]
BccaeDeploymentEnv = Literal["PROD", "STAGING", "DEV", "TEST"]
BccaeSecurityPosture = Literal["STANDARD", "ELEVATED", "LOCKED"]
BccaeRequestSource = Literal["AGENT", "API", "INTERNAL", "SCHEDULED", "TRIGGERED"]
BccaeRevocationTargetType = Literal["PERMIT", "EVALUATION", "ACTOR", "RESOURCE"]


def generate_bccae_nonce() -> str:
    """Return a cryptographically random 64-character hex nonce (32 bytes)."""
    return secrets.token_hex(32)


def _enforce_tls(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http":
        is_local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if not is_local:
            raise ValueError(
                f"BCCAEClient base_url must use https:// (got scheme={parsed.scheme!r})"
            )
    else:
        raise ValueError(
            f"BCCAEClient base_url must use https:// (got scheme={parsed.scheme!r})"
        )
    # Reconstruct from parsed components (scheme + netloc only) to break the
    # taint chain from the raw caller-supplied string to the outbound request.
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


class BCCAEClient:
    """Synchronous HTTP client for the BCCAE V1 Phase 3 endpoints.

    Each method maps 1:1 to an edge function:
    - :meth:`evaluate`     → v1-bccae-evaluate
    - :meth:`execute`      → v1-bccae-execute
    - :meth:`revoke`       → v1-bccae-revoke
    - :meth:`get_evidence` → v1-bccae-evidence

    Authorization denials are returned (not raised). Network errors,
    invalid API keys, and 5xx responses raise :exc:`~atlasent.AtlaSentError`.

    Use :func:`generate_bccae_nonce` to produce a valid ``caller_nonce``.

    Args:
        api_key: AtlaSent API key with appropriate ``bccae:*`` scopes.
        base_url: Override the API base URL.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key or not isinstance(api_key, str):
            raise ValueError("BCCAEClient: api_key is required")
        self._api_key = api_key
        self._base_url = _enforce_tls(base_url).rstrip("/")
        self._client = httpx.Client(
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "atlasent-bccae-python/1.0",
                **function_region_headers(self._base_url),
            },
            timeout=timeout,
        )

    def __enter__(self) -> BCCAEClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ── Public API ────────────────────────────────────────────────────────────────────

    def evaluate(
        self,
        *,
        actor_id: str,
        actor_type: BccaeActorType,
        actor_trust_level: BccaeTrustLevel,
        action_id: str,
        execution_intent: str,
        caller_nonce: str,
        resource_ref: str,
        resource_type: str,
        resource_classification: BccaeResourceClassification,
        deployment_env: BccaeDeploymentEnv,
        deployment_region: str,
        security_posture: BccaeSecurityPosture,
        actor_claims: dict[str, Any] | None = None,
        organization_version: int | None = None,
        external_signals: list[Any] | None = None,
        dependencies: list[Any] | None = None,
        policy_version_set: list[Any] | None = None,
        request_source: BccaeRequestSource | None = None,
        request_chain_id: str | None = None,
        parent_eval_id: str | None = None,
    ) -> dict[str, Any]:
        """Submit a protected action for BCCAE context construction and evaluation.

        Returns a dict with ``evaluation_id``, ``envelope_hash``,
        ``permit_token``, ``permit_id``, ``expires_at``, and ``outcome``.

        Requires API key with ``bccae:evaluate`` scope.
        """
        body: dict[str, Any] = {
            "actor_id": actor_id,
            "actor_type": actor_type,
            "actor_trust_level": actor_trust_level,
            "action_id": action_id,
            "execution_intent": execution_intent,
            "caller_nonce": caller_nonce,
            "resource_ref": resource_ref,
            "resource_type": resource_type,
            "resource_classification": resource_classification,
            "deployment_env": deployment_env,
            "deployment_region": deployment_region,
            "security_posture": security_posture,
        }
        if actor_claims is not None:
            body["actor_claims"] = actor_claims
        if organization_version is not None:
            body["organization_version"] = organization_version
        if external_signals is not None:
            body["external_signals"] = external_signals
        if dependencies is not None:
            body["dependencies"] = dependencies
        if policy_version_set is not None:
            body["policy_version_set"] = policy_version_set
        if request_source is not None:
            body["request_source"] = request_source
        if request_chain_id is not None:
            body["request_chain_id"] = request_chain_id
        if parent_eval_id is not None:
            body["parent_eval_id"] = parent_eval_id

        return self._post("/v1/bccae/evaluations", body)

    def execute(
        self,
        *,
        permit_token: str,
        action_id: str,
        resource_ref: str,
    ) -> dict[str, Any]:
        """Present a permit token to the Execution Gate (10-check verification).

        Returns a dict with ``authorized`` (bool) and ``outcome``. On denial
        the dict also contains ``check`` and ``reason`` identifying the
        specific gate check that failed.

        Never raises on denial — only raises on network errors or 5xx.
        Requires API key with ``bccae:execute`` scope.
        """
        return self._post(
            "/v1/bccae/execute",
            {
                "permit_token": permit_token,
                "action_id": action_id,
                "resource_ref": resource_ref,
            },
        )

    def revoke(
        self,
        *,
        target_type: BccaeRevocationTargetType,
        target_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Add an entry to the BCCAE revocation ledger.

        Idempotent — raises :exc:`~atlasent.AtlaSentError` with code
        ``conflict`` if the target is already revoked.

        Requires API key with ``bccae:revoke`` scope.
        """
        return self._post(
            "/v1/bccae/revocations",
            {
                "target_type": target_type,
                "target_id": target_id,
                "reason": reason,
            },
        )

    def get_evidence(self, evidence_id: str) -> dict[str, Any]:
        """Fetch a single evidence record and verify its hash chain integrity.

        ``result["chain_integrity"]["hash_intact"]`` is ``True`` when the
        record's ``record_hash`` matches the server-recomputed value.

        Requires API key with ``bccae:audit`` scope.
        """
        if not evidence_id or not isinstance(evidence_id, str):
            raise ValueError("BCCAEClient: evidence_id is required")
        return self._get(f"/v1/bccae/evidence/{quote(evidence_id, safe='')}")

    # ── HTTP primitives ────────────────────────────────────────────────────

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = self._client.post(f"{self._base_url}{path}", json=body)
        except httpx.TransportError as exc:
            raise AtlaSentError(
                f"BCCAEClient: network error on POST {path}: {exc}",
                code="network",
            ) from exc
        return self._handle_response(resp, path)

    def _get(self, path: str) -> dict[str, Any]:
        try:
            resp = self._client.get(f"{self._base_url}{path}")
        except httpx.TransportError as exc:
            raise AtlaSentError(
                f"BCCAEClient: network error on GET {path}: {exc}",
                code="network",
            ) from exc
        return self._handle_response(resp, path)

    def _handle_response(self, resp: httpx.Response, path: str) -> dict[str, Any]:
        try:
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            raise AtlaSentError(
                (
                    "BCCAEClient: non-JSON response "
                    f"(status {resp.status_code}) from {path}"
                ),
                code="network",
            ) from exc

        if not resp.is_success:
            message = (
                data.get("message")  # type: ignore[union-attr]
                if isinstance(data, dict)
                else None
            ) or f"BCCAE request failed with status {resp.status_code}"
            code = {
                401: "unauthorized",
                403: "permission_denied",
                404: "not_found",
                409: "conflict",
                429: "rate_limited",
            }.get(resp.status_code, "network")
            raise AtlaSentError(str(message), code=code)  # type: ignore[arg-type]

        return data
