"""Usage metering client for the AtlaSent Python SDK.

List and summarize billable evaluation records for the authenticated
organization.

Wire surface: /v1-usage-metering endpoints in atlasent-api.
Requires scope: ``usage:read``.

Usage::

    from atlasent import AtlaSentClient
    from atlasent.usage_metering import UsageMeteringClient

    client = AtlaSentClient(api_key="...")
    metering = UsageMeteringClient(client)

    page = metering.list(limit=50, decision="allow")
    for record in page["data"]:
        print(record["action_type"], record["billable"])

    if page.get("next_cursor"):
        next_page = metering.list(before=page["next_cursor"])

    summary = metering.summary(period="month")
    print(summary["total_evaluations"])
"""

from __future__ import annotations

import json
import urllib.request as urllib_request
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlencode

from ._function_region import function_region_headers
from .exceptions import AtlaSentError

if TYPE_CHECKING:
    from .client import AtlaSentClient

# Reporting period granularity for summary().
UsageMeteringPeriod = Literal["day", "week", "month"]


def _get(
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
        raise AtlaSentError(f"Usage metering client request failed: {exc}") from exc


class UsageMeteringClient:
    """Usage metering sub-client.

    Obtain via ``UsageMeteringClient(atlasent_client)``::

        client = AtlaSentClient(api_key="...")
        metering = UsageMeteringClient(client)
        page = metering.list(limit=100)
        summary = metering.summary(period="month")
    """

    def __init__(self, client: AtlaSentClient) -> None:
        self._client = client

    def list(
        self,
        *,
        limit: int | None = None,
        before: str | None = None,
        decision: str | None = None,
    ) -> dict[str, Any]:
        """List metered evaluation records, most-recent first.

        Returns a dict with keys ``data`` (list of records) and optionally
        ``next_cursor`` (str). Pass ``next_cursor`` as ``before`` to fetch
        the following page.

        Requires scope ``usage:read``.

        :param limit: Max records to return.
        :param before: Cursor from a previous page's ``next_cursor``.
        :param decision: Filter by decision (``"allow"``, ``"deny"``,
            ``"hold"``, ``"escalate"``).
        :returns: Dict with ``data`` (list) and optional ``next_cursor``.
        :raises AtlaSentError: On network or auth failure.
        """
        params: dict[str, str] = {}
        if limit is not None:
            params["limit"] = str(limit)
        if before is not None:
            params["before"] = before
        if decision is not None:
            params["decision"] = decision

        return _get(self._client, "/v1-usage-metering", params or None)

    def summary(
        self,
        *,
        period: UsageMeteringPeriod | None = None,
    ) -> dict[str, Any]:
        """Fetch an aggregated usage summary for a billing period.

        Returns totals for the current calendar period (``"day"``,
        ``"week"``, or ``"month"``). Defaults to ``"month"`` on the server
        when ``period`` is omitted.

        Requires scope ``usage:read``.

        :param period: Reporting period granularity.
        :returns: Dict with ``org_id``, ``period_start``, ``period_end``,
            ``total_evaluations``, ``billable_allows``, ``billable_denies``.
        :raises AtlaSentError: On network or auth failure.
        """
        params: dict[str, str] = {}
        if period is not None:
            params["period"] = period

        return _get(self._client, "/v1-usage-metering/summary", params or None)
