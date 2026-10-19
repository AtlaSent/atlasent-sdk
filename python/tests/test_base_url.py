"""Base-URL resolution (atlasent._base_url).

The hosted runtime's gateway answers every path outside ``/functions/v1``
with 404 "requested path is invalid", so a base URL of bare
``https://api.atlasent.io`` made every call from a default-constructed client
fail. These tests pin the default and the bare-host normalization, and that
nothing else is rewritten.
"""

from __future__ import annotations

import pytest

import atlasent
import atlasent.config as config
from atlasent._base_url import (
    DEFAULT_BASE_URL,
    HOSTED_FUNCTIONS_PATH,
    resolve_base_url,
)

KEY = "ask_live_test"


@pytest.fixture(autouse=True)
def _clean_config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ATLASENT_BASE_URL", raising=False)
    monkeypatch.delenv("ATLASENT_API_URL", raising=False)
    config.reset()
    yield
    config.reset()


def test_default_is_the_hosted_functions_root() -> None:
    assert HOSTED_FUNCTIONS_PATH == "/functions/v1"
    assert DEFAULT_BASE_URL == "https://api.atlasent.io/functions/v1"
    assert config.get_base_url() == "https://api.atlasent.io/functions/v1"


def test_public_default_names_agree() -> None:
    from atlasent import async_client, client

    assert client.DEFAULT_BASE_URL == DEFAULT_BASE_URL
    assert async_client.DEFAULT_BASE_URL == DEFAULT_BASE_URL
    assert config.DEFAULT_BASE_URL == DEFAULT_BASE_URL


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("https://api.atlasent.io", "https://api.atlasent.io/functions/v1"),
        ("https://api.atlasent.io/", "https://api.atlasent.io/functions/v1"),
        ("https://api.atlasent.io///", "https://api.atlasent.io/functions/v1"),
        ("https://API.AtlaSent.io", "https://API.AtlaSent.io/functions/v1"),
        (
            "https://kttccumlnmdtupgbyfue.supabase.co",
            "https://kttccumlnmdtupgbyfue.supabase.co/functions/v1",
        ),
        (
            "https://lwnqpmnxpeyhpxvastku.supabase.co/",
            "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1",
        ),
    ],
)
def test_bare_hosted_host_gets_functions_path(given: str, expected: str) -> None:
    assert resolve_base_url(given) == expected


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (
            "https://api.atlasent.io/functions/v1",
            "https://api.atlasent.io/functions/v1",
        ),
        (
            "https://api.atlasent.io/functions/v1/",
            "https://api.atlasent.io/functions/v1",
        ),
        ("https://api.atlasent.io/custom", "https://api.atlasent.io/custom"),
        ("https://atlasent.example.com", "https://atlasent.example.com"),
        ("https://other-project.supabase.co", "https://other-project.supabase.co"),
        (
            "https://api.atlasent.io.evil.example",
            "https://api.atlasent.io.evil.example",
        ),
        ("http://localhost:54321", "http://localhost:54321"),
        ("https://api.atlasent.io/?x=1", "https://api.atlasent.io/?x=1"),
        ("not a url/", "not a url"),
        ("https://[::1/", "https://[::1"),
    ],
)
def test_everything_else_is_left_alone(given: str, expected: str) -> None:
    assert resolve_base_url(given) == expected


def test_idempotent() -> None:
    once = resolve_base_url("https://api.atlasent.io")
    assert resolve_base_url(once) == once


class TestClients:
    def test_sync_default(self) -> None:
        c = atlasent.AtlaSentClient(api_key=KEY)
        assert c._base_url == "https://api.atlasent.io/functions/v1"

    def test_sync_normalizes_bare_host(self) -> None:
        c = atlasent.AtlaSentClient(api_key=KEY, base_url="https://api.atlasent.io")
        assert c._base_url == "https://api.atlasent.io/functions/v1"

    def test_sync_leaves_self_hosted(self) -> None:
        c = atlasent.AtlaSentClient(api_key=KEY, base_url="https://rt.example.com/fn/")
        assert c._base_url == "https://rt.example.com/fn"

    def test_async_default(self) -> None:
        c = atlasent.AsyncAtlaSentClient(api_key=KEY)
        assert c._base_url == "https://api.atlasent.io/functions/v1"

    def test_async_normalizes_bare_host_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ATLASENT_BASE_URL", "https://api.atlasent.io")
        c = atlasent.AsyncAtlaSentClient(api_key=KEY)
        assert c._base_url == "https://api.atlasent.io/functions/v1"

    def test_still_refuses_non_https(self) -> None:
        with pytest.raises(ValueError, match="https"):
            atlasent.AtlaSentClient(api_key=KEY, base_url="http://api.atlasent.io")

    def test_sync_evaluate_posts_to_functions_root(self, mocker) -> None:
        c = atlasent.AtlaSentClient(api_key=KEY, function_region="auto")
        resp = mocker.Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.json.return_value = {
            "decision": "allow",
            "permit_token": "pt.v4.test",
            "request_id": "req_1",
        }
        post = mocker.patch.object(c._client, "post", return_value=resp)
        c.evaluate("a.b", "u", {})
        assert post.call_args[0][0] == (
            "https://api.atlasent.io/functions/v1/v1-evaluate"
        )
