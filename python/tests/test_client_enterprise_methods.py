"""Tests for the sync AtlaSentClient enterprise convenience methods.

These methods give the synchronous client method-level parity with the async
client's enterprise surface (SCIM, SIEM, evidence-exports). They delegate to the
verified flat functions in atlasent.{scim,siem,evidence_exports}; these tests
assert the delegation hits the right HTTP method + canonical /v1 path so the
methods can't silently drift from the wire contract.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest

from atlasent import AtlaSentClient

API_KEY = "ask_test_enterprise"
BASE_URL = "https://api.atlasent.io/functions/v1"
ORG = "org_ent_test"


def _client() -> AtlaSentClient:
    return AtlaSentClient(api_key=API_KEY, base_url=BASE_URL)


def _resp(body: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = {"X-Request-ID": "req-ent-1"}
    resp.json = MagicMock(return_value=body)
    return resp


def _capture(client: AtlaSentClient, body: object = None, status: int = 200):
    """Patch the underlying transport, returning the mock for assertions."""
    m = MagicMock(return_value=_resp({} if body is None else body, status))
    client._client.request = m  # type: ignore[method-assign]
    return m


def test_sync_client_exposes_full_async_enterprise_surface() -> None:
    """Every async_* enterprise method has a non-prefixed sync counterpart."""
    from atlasent import AsyncAtlaSentClient

    async_methods = {
        n[len("async_") :]
        for n in dir(AsyncAtlaSentClient)
        if n.startswith("async_")
        and ("scim" in n or "siem" in n or "evidence_export" in n)
    }
    missing = {m for m in async_methods if not hasattr(AtlaSentClient, m)}
    assert not missing, f"sync client missing enterprise parity methods: {missing}"


@pytest.mark.parametrize(
    ("call", "method", "path"),
    [
        (lambda c: c.scim_list_users(ORG), "GET", f"/v1/scim/v2/{ORG}/Users"),
        (lambda c: c.scim_get_user(ORG, "u1"), "GET", f"/v1/scim/v2/{ORG}/Users/u1"),
        (
            lambda c: c.scim_delete_user(ORG, "u1"),
            "DELETE",
            f"/v1/scim/v2/{ORG}/Users/u1",
        ),
        (lambda c: c.scim_list_groups(ORG), "GET", f"/v1/scim/v2/{ORG}/Groups"),
        (lambda c: c.scim_get_group(ORG, "g1"), "GET", f"/v1/scim/v2/{ORG}/Groups/g1"),
        (lambda c: c.get_siem_config(ORG), "GET", f"/v1/orgs/{ORG}/siem-config"),
        (
            lambda c: c.siem_test_delivery(ORG),
            "POST",
            f"/v1/orgs/{ORG}/siem-exports/test",
        ),
        (
            lambda c: c.list_evidence_exports(ORG),
            "GET",
            f"/v1/orgs/{ORG}/evidence-exports",
        ),
        (
            lambda c: c.get_evidence_export(ORG, "e1"),
            "GET",
            f"/v1/orgs/{ORG}/evidence-exports/e1",
        ),
    ],
)
def test_method_hits_canonical_v1_path(call, method, path) -> None:
    c = _client()
    m = _capture(c, body={"ok": True})
    call(c)
    sent_method, sent_url = m.call_args[0][0], m.call_args[0][1]
    assert sent_method == method
    assert sent_url == f"{BASE_URL}{path}"
    c.close()


def test_scim_create_user_injects_schema_and_posts() -> None:
    c = _client()
    m = _capture(c, body={"id": "u1"})
    c.scim_create_user(ORG, {"userName": "a@b.com"})
    assert m.call_args[0][0] == "POST"
    assert m.call_args[0][1] == f"{BASE_URL}/v1/scim/v2/{ORG}/Users"
    sent = json.loads(m.call_args.kwargs["content"])
    assert sent["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert sent["userName"] == "a@b.com"
    c.close()


def test_upsert_siem_config_validates_https() -> None:
    c = _client()
    with pytest.raises(ValueError, match="HTTPS"):
        c.upsert_siem_config(ORG, destination_url="http://insecure.example.com")
    c.close()


def test_create_evidence_export_validates_regime() -> None:
    c = _client()
    with pytest.raises(ValueError, match="regime"):
        c.create_evidence_export(ORG, regime="not-a-regime")
    c.close()


def test_create_evidence_export_posts_regime_body() -> None:
    c = _client()
    m = _capture(c, body={"export_id": "e1"})
    c.create_evidence_export(ORG, regime="soc2_type_ii")
    assert m.call_args[0][0] == "POST"
    sent = json.loads(m.call_args.kwargs["content"])
    assert sent["regime"] == "soc2_type_ii"
    c.close()
