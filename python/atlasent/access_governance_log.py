"""Access governance log client for the AtlaSent Python SDK.

Paginated identity lifecycle event log — SSO logins, session events,
config changes, break-glass activations, JIT provisioning, and API key
refusals.

Usage::

    from atlasent import AtlaSentClient
    from atlasent.access_governance_log import AccessGovernanceLogClient

    client = AtlaSentClient(api_key="...")
    log = AccessGovernanceLogClient(client)

    page = log.list(limit=50, event_type="sso.login")
    for event in page["events"]:
        print(event["event_type"], event["actor_email"])

    if page["next_cursor"]:
        page2 = log.list(cursor=page["next_cursor"])
"""

from __future__ import annotations

import json
import urllib.request as urllib_request
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from ._function_region import function_region_headers
from .exceptions import AtlaSentError

if TYPE_CHECKING:
    from .client import AtlaSentClient


def _request(
    client: AtlaSentClient,
    path: str,
    params: dict[str, str] | None = None,
) -> Any:
    qs = ("?" + urlencode(params)) if params else ""
    url = f"{client.base_url.rstrip('/')}{path}{qs}"
    headers = {
        "Authorization": f"Bearer {client.api_key}",
        **function_region_headers(url),
        "Accept": "application/json",
    }
    req = urllib_request.Request(url, headers=headers, method="GET")
    try:
        with urllib_request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except Exception as exc:  # noqa: BLE001
        raise AtlaSentError(f"Access governance log request failed: {exc}") from exc


class AccessGovernanceLogClient:
    """Sub-client for the access governance log.

    Obtain via ``AccessGovernanceLogClient(atlasent_client)``::

        client = AtlaSentClient(api_key="...")
        log = AccessGovernanceLogClient(client)
        page = log.list(limit=100)
    """

    def __init__(self, client: AtlaSentClient) -> None:
        self._client = client

    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        event_type: str | None = None,
        actor_id: str | None = None,
        from_: str | None = None,
        to: str | None = None,
    ) -> dict[str, Any]:
        """Fetch a page of identity lifecycle events.

        Returns a dict with keys ``events``, ``next_cursor``, ``total_count``.
        Pass ``next_cursor`` as ``cursor`` to fetch the following page.

        :param limit: Max events to return (default 50, max 200).
        :param cursor: Cursor from a previous page's ``next_cursor``.
        :param event_type: Filter by event type (e.g. ``"sso.login"``).
        :param actor_id: Filter by actor email or UUID.
        :param from_: Lower bound on event timestamp (ISO 8601).
        :param to: Upper bound on event timestamp (ISO 8601).
        """
        params: dict[str, str] = {}
        if limit is not None:
            params["limit"] = str(limit)
        if cursor is not None:
            params["cursor"] = cursor
        if event_type is not None:
            params["event_type"] = event_type
        if actor_id is not None:
            params["actor_id"] = actor_id
        if from_ is not None:
            params["from"] = from_
        if to is not None:
            params["to"] = to

        return _request(self._client, "/v1/access-governance-log", params or None)
