"""Every missing-key error tells the developer where to get a key, with a
link attributed to this SDK's Python error path."""

import pytest

from atlasent import config
from atlasent._api_key_hint import API_KEY_SIGNUP_URL
from atlasent.async_client import AsyncAtlaSentClient
from atlasent.bccae import BCCAEClient
from atlasent.client import AtlaSentClient
from atlasent.exceptions import ConfigurationError


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("ATLASENT_API_KEY", raising=False)
    config.reset()
    yield
    config.reset()


def test_link_is_the_console_sign_up_tagged_as_the_python_error_path():
    assert API_KEY_SIGNUP_URL == (
        "https://console.atlasent.io/auth/sign-up?utm_source=sdk&utm_medium=py-error"
    )


def test_client_without_a_key():
    with pytest.raises(ValueError, match="api_key is required") as exc:
        AtlaSentClient(api_key="")
    assert API_KEY_SIGNUP_URL in str(exc.value)


def test_async_client_without_a_key_or_env():
    with pytest.raises(ConfigurationError) as exc:
        AsyncAtlaSentClient()
    assert API_KEY_SIGNUP_URL in str(exc.value)
    assert "ATLASENT_API_KEY" in str(exc.value)


def test_global_config_without_a_key():
    with pytest.raises(ConfigurationError) as exc:
        config.get_api_key()
    assert API_KEY_SIGNUP_URL in str(exc.value)


def test_bccae_client_without_a_key():
    with pytest.raises(ValueError) as exc:
        BCCAEClient(api_key="")
    assert API_KEY_SIGNUP_URL in str(exc.value)


def test_a_malformed_key_is_not_told_to_sign_up():
    with pytest.raises(ValueError) as exc:
        AtlaSentClient(api_key="not-a-key")
    assert API_KEY_SIGNUP_URL not in str(exc.value)
