"""OllamaClient のテスト (respx で HTTP モック)。"""

from __future__ import annotations

import httpx
import pytest
import respx

from suzaku.reader.ollama import (
    DEFAULT_BASE_URL,
    OllamaClient,
    OllamaError,
    OllamaModelError,
    OllamaUnavailableError,
)
from suzaku.witness.guard import ProductionAccessError


class TestGuardEnforced:
    def test_public_host_blocked(self) -> None:
        with pytest.raises(ProductionAccessError):
            OllamaClient(base_url="http://api.openai.com")

    def test_localhost_allowed(self) -> None:
        c = OllamaClient(base_url=DEFAULT_BASE_URL)
        c.close()

    def test_rfc1918_allowed(self) -> None:
        c = OllamaClient(base_url="http://192.168.1.10:11434")
        c.close()


class TestGenerate:
    @respx.mock
    def test_generate_returns_response_field(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200, json={"response": "hello world", "done": True}
        )
        with OllamaClient() as client:
            text = client.generate("prompt")
        assert text == "hello world"

    @respx.mock
    def test_generate_passes_format_and_options(self) -> None:
        route = respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200, json={"response": "{}", "done": True}
        )
        with OllamaClient() as client:
            client.generate(
                "prompt",
                system="you are a test",
                format={"type": "object"},
                options={"temperature": 0.0},
            )
        # 直近リクエストの body にすべて入っていること
        assert route.call_count == 1
        sent = route.calls.last.request.content
        assert b'"system"' in sent
        assert b'"format"' in sent
        assert b'"temperature"' in sent
        assert b'"stream":false' in sent or b'"stream": false' in sent

    @respx.mock
    def test_404_raises_model_error(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            404, json={"error": "model not found"}
        )
        with OllamaClient() as client, pytest.raises(OllamaModelError):
            client.generate("prompt")

    @respx.mock
    def test_connect_error_raises_unavailable(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with OllamaClient() as client, pytest.raises(OllamaUnavailableError):
            client.generate("prompt")

    @respx.mock
    def test_other_4xx_raises_ollama_error(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            500, text="boom"
        )
        with OllamaClient() as client, pytest.raises(OllamaError):
            client.generate("prompt")


class TestHealth:
    @respx.mock
    def test_health_true_when_model_present(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200,
            json={"models": [{"name": "qwen2.5-coder:14b"}, {"name": "llama3:8b"}]},
        )
        with OllamaClient() as client:
            assert client.health() is True

    @respx.mock
    def test_health_true_when_base_name_matches(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "qwen2.5-coder:7b"}]}
        )
        with OllamaClient(model="qwen2.5-coder:14b") as client:
            assert client.health() is True  # base name 一致で OK

    @respx.mock
    def test_health_false_when_model_missing(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "llama3:8b"}]}
        )
        with OllamaClient(model="qwen2.5-coder:14b") as client:
            assert client.health() is False

    @respx.mock
    def test_health_false_when_unavailable(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").mock(
            side_effect=httpx.ConnectError("nope")
        )
        with OllamaClient() as client:
            assert client.health() is False

    @respx.mock
    def test_list_models_returns_names(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "a:1"}, {"name": "b:2"}]}
        )
        with OllamaClient() as client:
            assert client.list_models() == ["a:1", "b:2"]
