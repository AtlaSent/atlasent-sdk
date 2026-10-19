"""Global configuration for the AtlaSent SDK."""

from __future__ import annotations

import logging
import os

from ._api_key_hint import MISSING_API_KEY_HINT
from ._base_url import DEFAULT_BASE_URL
from .exceptions import ConfigurationError

logger = logging.getLogger("atlasent")


_global_config: dict[str, str | None] = {
    "api_key": None,
    "anon_key": None,
    "base_url": None,
}


def configure(
    api_key: str | None = None,
    *,
    anon_key: str | None = None,
    base_url: str | None = None,
) -> None:
    """Configure the AtlaSent SDK globally.

    Args:
        api_key: Your AtlaSent API key.  Falls back to the
            ``ATLASENT_API_KEY`` environment variable if not provided.
        anon_key: Anonymous / public key.  Falls back to
            ``ATLASENT_ANON_KEY``.
        base_url: Override the base API URL.  Falls back to the
            ``ATLASENT_BASE_URL`` or ``ATLASENT_API_URL`` environment
            variable, then ``https://api.atlasent.io/functions/v1``.
            Pass ``None`` (the default) to use the environment variable
            or the built-in default.
    """
    _global_config["api_key"] = api_key
    _global_config["anon_key"] = anon_key
    _global_config["base_url"] = base_url
    logger.debug("Configured: base_url=%s", base_url)


def get_api_key() -> str:
    """Return the configured API key, falling back to the env var.

    Raises:
        ConfigurationError: If no API key is available.
    """
    key = _global_config["api_key"] or os.environ.get("ATLASENT_API_KEY")
    if not key:
        raise ConfigurationError(
            "No API key provided. Either call atlasent.configure(api_key=...) "
            "or set the ATLASENT_API_KEY environment variable. " + MISSING_API_KEY_HINT
        )
    return key


def get_anon_key() -> str:
    """Return the configured anonymous key, or empty string."""
    return _global_config["anon_key"] or os.environ.get("ATLASENT_ANON_KEY") or ""


def get_base_url() -> str:
    """Return the configured base API URL.

    Resolution order:
    1. Value passed to :func:`configure` (``base_url`` argument).
    2. ``ATLASENT_BASE_URL`` environment variable.
    3. ``ATLASENT_API_URL`` environment variable.
    4. Built-in default (``https://api.atlasent.io/functions/v1``).

    Supabase-hosted instances must set one of the env vars to
    ``https://<project-ref>.supabase.co/functions/v1``. The client appends
    ``/functions/v1`` to a bare hosted-runtime host (see ``._base_url``).
    """
    return (
        _global_config["base_url"]
        or os.environ.get("ATLASENT_BASE_URL")
        or os.environ.get("ATLASENT_API_URL")
        or DEFAULT_BASE_URL
    )


def reset() -> None:
    """Reset global configuration to defaults.  Useful for testing."""
    _global_config["api_key"] = None
    _global_config["anon_key"] = None
    _global_config["base_url"] = None
