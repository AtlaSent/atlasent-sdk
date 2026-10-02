"""SSO administration sub-client for the AtlaSent Python SDK.

Mirrors the TypeScript ``client.sso`` surface: connections, JIT
provisioning rules, enforcement state machine, and readiness status.

Usage::

    from atlasent import AtlaSentClient
    from atlasent.sso_client import SsoClient

    client = AtlaSentClient(api_key="...")
    sso = SsoClient(client)

    connections = sso.list_connections()
    sso.enforce("enable")
    status = sso.get_status()

    rules = sso.list_jit_rules(connection_id="conn-abc")
    rule = sso.create_jit_rule(
        connection_id="conn-abc",
        claim_attribute="groups",
        claim_value="admins",
        granted_role="admin",
    )
    sso.delete_jit_rule(rule["id"])
"""

from __future__ import annotations

import json
import urllib.request as urllib_request
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlencode

from ._function_region import function_region_headers
from .exceptions import AtlaSentError

if TYPE_CHECKING:
    from .client import AtlaSentClient


def _enc(value: str) -> str:
    return quote(value, safe="")


def _request(
    client: AtlaSentClient,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> Any:
    qs = ("?" + urlencode(params)) if params else ""
    url = f"{client.base_url.rstrip('/')}{path}{qs}"
    headers = {
        "Authorization": f"Bearer {client.api_key}",
        **function_region_headers(url),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = json.dumps(body).encode() if body is not None else None
    req = urllib_request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except Exception as exc:  # noqa: BLE001
        raise AtlaSentError(f"SSO client request failed: {exc}") from exc


class SsoClient:
    """SSO administration sub-client.

    Obtain via ``SsoClient(atlasent_client)`` or attach it directly::

        client = AtlaSentClient(api_key="...")
        sso = SsoClient(client)
    """

    def __init__(self, client: AtlaSentClient) -> None:
        self._client = client

    # ── Connections ──────────────────────────────────────────────────────────

    def list_connections(self) -> list[dict[str, Any]]:
        """Return all SSO connections for the authenticated org."""
        resp = _request(self._client, "GET", "/v1/sso/connections")
        return resp.get("connections", [])

    def get_connection(self, connection_id: str) -> dict[str, Any]:
        """Return a single SSO connection by ID."""
        return _request(
            self._client, "GET", f"/v1/sso/connections/{_enc(connection_id)}"
        )

    def create_connection(
        self,
        *,
        name: str,
        protocol: str,
        idp_entity_id: str,
        metadata_url: str | None = None,
        metadata_xml: str | None = None,
        email_domain: str | None = None,
        enforce_for_domain: bool | None = None,
    ) -> dict[str, Any]:
        """Create a new SSO connection."""
        body: dict[str, Any] = {
            "name": name,
            "protocol": protocol,
            "idp_entity_id": idp_entity_id,
        }
        if metadata_url is not None:
            body["metadata_url"] = metadata_url
        if metadata_xml is not None:
            body["metadata_xml"] = metadata_xml
        if email_domain is not None:
            body["email_domain"] = email_domain
        if enforce_for_domain is not None:
            body["enforce_for_domain"] = enforce_for_domain
        return _request(self._client, "POST", "/v1/sso/connections", body=body)

    def update_connection(
        self,
        connection_id: str,
        **fields: Any,
    ) -> dict[str, Any]:
        """Patch an existing SSO connection.

        Pass keyword args matching wire field names.
        """
        return _request(
            self._client,
            "PATCH",
            f"/v1/sso/connections/{_enc(connection_id)}",
            body=fields,
        )

    def delete_connection(self, connection_id: str) -> None:
        """Delete an SSO connection."""
        _request(self._client, "DELETE", f"/v1/sso/connections/{_enc(connection_id)}")

    def activate_connection(self, connection_id: str) -> dict[str, Any]:
        """Register the connection with the IdP (sets supabase_provider_id)."""
        return _request(
            self._client,
            "POST",
            f"/v1/sso/connections/{_enc(connection_id)}/activate",
            body={},
        )

    # ── JIT provisioning rules ────────────────────────────────────────────────

    def list_jit_rules(self, connection_id: str | None = None) -> list[dict[str, Any]]:
        """List JIT provisioning rules, optionally filtered to one connection."""
        params = {"connection_id": connection_id} if connection_id else None
        resp = _request(self._client, "GET", "/v1/sso/jit-rules", params=params)
        return resp.get("rules", [])

    def create_jit_rule(
        self,
        *,
        connection_id: str,
        claim_attribute: str,
        claim_value: str,
        granted_role: str,
        precedence: int = 100,
    ) -> dict[str, Any]:
        """Create a new JIT provisioning rule."""
        return _request(
            self._client,
            "POST",
            "/v1/sso/jit-rules",
            body={
                "connection_id": connection_id,
                "claim_attribute": claim_attribute,
                "claim_value": claim_value,
                "granted_role": granted_role,
                "precedence": precedence,
            },
        )

    def patch_jit_rule(self, rule_id: str, **fields: Any) -> dict[str, Any]:
        """Update fields on an existing JIT rule. Pass wire field names as kwargs."""
        return _request(
            self._client,
            "PATCH",
            f"/v1/sso/jit-rules/{_enc(rule_id)}",
            body=fields,
        )

    def delete_jit_rule(self, rule_id: str) -> None:
        """Delete a JIT provisioning rule."""
        _request(self._client, "DELETE", f"/v1/sso/jit-rules/{_enc(rule_id)}")

    # ── Enforcement state machine ─────────────────────────────────────────────

    def enforce(self, action: str) -> dict[str, Any]:
        """Advance the SSO enforcement state machine.

        ``action="enable"``  → sso_enabled=True, enforce_sso=False
        ``action="enforce"`` → sso_enabled=True, enforce_sso=True
        """
        return _request(
            self._client, "POST", "/v1/sso/enforce", body={"action": action}
        )

    def get_status(self) -> dict[str, Any]:
        """Return the four-boolean enforcement readiness checklist."""
        resp = _request(self._client, "GET", "/v1/sso/status")
        return resp.get("readiness", resp)
