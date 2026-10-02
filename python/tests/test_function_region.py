"""Edge-function region pinning (atlasent._function_region)."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

import atlasent
from atlasent import AsyncAtlaSentClient, AtlaSentClient
from atlasent import usage_metering as um
from atlasent._function_region import (
    DEFAULT_FUNCTION_REGION,
    FUNCTION_REGION_ENV,
    FunctionRegionConfigError,
    function_region_headers,
    resolve_function_region,
)

HOSTED = "https://api.atlasent.io"
HOSTED_PROD_REF = "https://kttccumlnmdtupgbyfue.supabase.co/functions/v1"
SELF_HOSTED = "https://runtime.customer.example/functions/v1"
KEY = "ask_live_test"


@pytest.fixture(autouse=True)
def _no_region_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FUNCTION_REGION_ENV, raising=False)


class TestResolve:
    def test_hosted_runtime_defaults_to_us_west_1(self) -> None:
        assert DEFAULT_FUNCTION_REGION == "us-west-1"
        assert resolve_function_region(HOSTED, env={}) == "us-west-1"
        assert resolve_function_region(HOSTED_PROD_REF, env={}) == "us-west-1"

    def test_self_hosted_and_lookalikes_are_not_pinned_by_default(self) -> None:
        assert resolve_function_region(SELF_HOSTED, env={}) is None
        assert (
            resolve_function_region("https://api.atlasent.io.evil.example", env={})
            is None
        )
        assert resolve_function_region("not a url", env={}) is None

    def test_precedence_explicit_env_default(self) -> None:
        env = {FUNCTION_REGION_ENV: "us-east-1"}
        assert resolve_function_region(SELF_HOSTED, env=env) == "us-east-1"
        assert resolve_function_region(HOSTED, "eu-west-1", env=env) == "eu-west-1"
        assert resolve_function_region(HOSTED, "", env=env) == "us-east-1"

    def test_auto_and_none_disable(self) -> None:
        env = {FUNCTION_REGION_ENV: "us-east-1"}
        assert resolve_function_region(HOSTED, "auto", env=env) is None
        assert resolve_function_region(HOSTED, None, env=env) is None
        assert (
            resolve_function_region(HOSTED, env={FUNCTION_REGION_ENV: "auto"}) is None
        )

    @pytest.mark.parametrize("bad", ["US-WEST-1", "west", "us-west-1\r\nx-evil: 1"])
    def test_malformed_raises(self, bad: str) -> None:
        with pytest.raises(FunctionRegionConfigError):
            resolve_function_region(HOSTED, bad, env={})

    def test_headers(self) -> None:
        assert function_region_headers(HOSTED, env={}) == {"x-region": "us-west-1"}
        assert function_region_headers(SELF_HOSTED, env={}) == {}


class TestClients:
    def test_sync_client_pins_hosted_runtime(self) -> None:
        with AtlaSentClient(api_key=KEY) as c:
            assert c._client.headers["x-region"] == "us-west-1"
            assert c._client.headers["Authorization"] == f"Bearer {KEY}"

    def test_async_client_pins_hosted_runtime(self) -> None:
        c = AsyncAtlaSentClient(api_key=KEY)
        assert c._client.headers["x-region"] == "us-west-1"

    def test_self_hosted_client_headers_unchanged(self) -> None:
        with AtlaSentClient(api_key=KEY, base_url=SELF_HOSTED) as a:
            assert "x-region" not in a._client.headers
        with AtlaSentClient(api_key=KEY, function_region="auto") as b:
            assert "x-region" not in b._client.headers
        assert dict(a._client.headers) == dict(b._client.headers)

    def test_option_overrides_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(FUNCTION_REGION_ENV, "us-east-1")
        with AtlaSentClient(api_key=KEY, function_region="eu-west-1") as c:
            assert c._client.headers["x-region"] == "eu-west-1"
        with AtlaSentClient(api_key=KEY, base_url=SELF_HOSTED) as c:
            assert c._client.headers["x-region"] == "us-east-1"

    def test_malformed_option_raises_at_construction(self) -> None:
        with pytest.raises(FunctionRegionConfigError):
            AtlaSentClient(api_key=KEY, function_region="US-WEST-1")

    def test_header_reaches_the_wire(self) -> None:
        import httpx

        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"decision": "deny", "decision_id": "d1"})

        with AtlaSentClient(api_key=KEY) as c:
            c._client = httpx.Client(
                headers=c._client.headers, transport=httpx.MockTransport(handler)
            )
            try:
                c.evaluate(
                    "production.deploy", "agent-1", {"environment": "production"}
                )
            except Exception:
                pass
        assert seen, "no request was sent"
        assert seen[0].headers["x-region"] == "us-west-1"

    def test_urllib_helper_modules_carry_the_header(self) -> None:
        captured: dict[str, str] = {}

        class _Resp(io.BytesIO):
            def __enter__(self):  # noqa: ANN204
                return self

            def __exit__(self, *a: object) -> None:
                return None

        def fake_urlopen(req, timeout=None):  # noqa: ANN001
            captured.update({k.lower(): v for k, v in req.header_items()})
            return _Resp(json.dumps({"records": [], "total": 0}).encode())

        with (
            AtlaSentClient(api_key=KEY) as c,
            patch.object(um.urllib_request, "urlopen", fake_urlopen),
        ):
            um.UsageMeteringClient(c).list()
        assert captured, "no request was sent"
        assert captured.get("x-region") == "us-west-1"
        assert captured.get("authorization") == f"Bearer {KEY}"

    def test_public_exports(self) -> None:
        assert atlasent.DEFAULT_FUNCTION_REGION == "us-west-1"
        assert issubclass(atlasent.FunctionRegionConfigError, ValueError)


class TestCentralized:
    PKG = Path(atlasent.__file__).parent
    # Modules that send requests but never to a runtime edge function.
    NOT_RUNTIME = {
        "trust_root.py",
        "verticals/deploy_gate.py",
        "vendored_trust_root.py",
    }

    def _modules(self) -> list[Path]:
        return [p for p in self.PKG.rglob("*.py") if "__pycache__" not in p.parts]

    def test_only_the_region_module_writes_the_header(self) -> None:
        offenders = [
            str(p.relative_to(self.PKG))
            for p in self._modules()
            if p.name != "_function_region.py"
            and re.search(r"[\"']x-region[\"']", p.read_text())
        ]
        assert offenders == []

    def test_every_request_sender_uses_the_region_helper(self) -> None:
        missing = []
        for p in self._modules():
            rel = str(p.relative_to(self.PKG))
            if p.name == "_function_region.py" or rel in self.NOT_RUNTIME:
                continue
            src = p.read_text()
            sends = re.search(
                r"httpx\.(Async)?Client\(|urllib_request\.Request\(|urllib\.request\.Request\(",
                src,
            )
            if sends and "function_region_headers(" not in src:
                missing.append(rel)
        assert missing == []
