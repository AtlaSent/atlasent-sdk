"""Edge-function region pinning for calls to the AtlaSent runtime.

Supabase runs an edge function in the region nearest the CALLER, not the
database. The hosted runtime's database is in us-west-1, so a call from
elsewhere executes far from its data, and each of the handler's sequential
database round trips pays that distance. Measured on 2026-10-02, v1-evaluate
p50 was 1.8-2.1 s executing in us-west-1 against 5.2-7.3 s in us-east-*.
Supabase supports pinning only per request, through the ``x-region`` header.

This module is the only place that decides whether a request carries that
header and with what value. Clients resolve it once at construction and
include the result in every runtime request.

Resolution, first match wins:

1. ``function_region`` passed to the client
2. the ``ATLASENT_FUNCTION_REGION`` environment variable
3. us-west-1, but only for AtlaSent's hosted runtime
4. nothing (Supabase picks the region, the pre-existing behavior)

Step 3 is scoped to the hosted runtime because a self-hosted runtime in
another region would be made slower, not faster. ``"auto"`` or ``None``
means "send no header". Any other value must be a region id; a malformed
value raises, because a silently ignored typo would put every call back on
the slow path.

Keep in step with the TypeScript SDK's ``functionRegion.ts`` and
atlasent-action's ``@atlasent/enforce`` ``functionRegion``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlparse

FUNCTION_REGION_HEADER = "x-region"
FUNCTION_REGION_ENV = "ATLASENT_FUNCTION_REGION"
#: Region of the hosted runtime's database. Change only if the database moves.
DEFAULT_FUNCTION_REGION = "us-west-1"

#: Hosts that serve AtlaSent's hosted runtime (production and staging).
HOSTED_RUNTIME_HOSTS = frozenset(
    {
        "api.atlasent.io",
        "kttccumlnmdtupgbyfue.supabase.co",
        "lwnqpmnxpeyhpxvastku.supabase.co",
    }
)

#: Regions Supabase accepts for ``x-region``, from
#: https://supabase.com/docs/guides/functions/regional-invocation (2026-10-02).
#: An allowlist, not a pattern: a well-formed typo such as "us-wset-1" must be
#: rejected here, because the platform may not reject it for us.
SUPPORTED_FUNCTION_REGIONS = frozenset(
    {
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-south-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "ca-central-1",
        "us-east-1",
        "us-west-1",
        "us-west-2",
        "eu-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "sa-east-1",
    }
)


class _Unset:
    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "UNSET"


#: Default for ``function_region`` arguments: defer to the environment and default.
UNSET = _Unset()


class FunctionRegionConfigError(ValueError):
    """A configured function region is not a region id or ``"auto"``."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f'Invalid function region "{value}": expected a supported region such as '
            f'"{DEFAULT_FUNCTION_REGION}", or "auto" to let Supabase choose.'
        )


def parse_function_region(value: str) -> str | None:
    """Parse a configured value: a region id, or ``None`` for ``"auto"``."""
    v = value.strip()
    if v == "auto":
        return None
    if v in SUPPORTED_FUNCTION_REGIONS:
        return v
    raise FunctionRegionConfigError(value)


def _is_hosted_runtime(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    return host is not None and host.lower() in HOSTED_RUNTIME_HOSTS


def resolve_function_region(
    base_url: str,
    explicit: str | None | _Unset = UNSET,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """The region requests to ``base_url`` should run in, or ``None``."""
    if explicit is None:
        return None
    if isinstance(explicit, str) and explicit.strip():
        return parse_function_region(explicit)
    environ = os.environ if env is None else env
    from_env = environ.get(FUNCTION_REGION_ENV, "")
    if from_env.strip():
        return parse_function_region(from_env)
    return DEFAULT_FUNCTION_REGION if _is_hosted_runtime(base_url) else None


def function_region_headers(
    base_url: str,
    explicit: str | None | _Unset = UNSET,
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Headers to include in a runtime request. Empty when unpinned."""
    region = resolve_function_region(base_url, explicit, env)
    return {FUNCTION_REGION_HEADER: region} if region else {}
