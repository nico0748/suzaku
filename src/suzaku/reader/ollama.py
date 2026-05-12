"""Ollama HTTP ラッパー。

設計方針:
- `localhost` (またはユーザが明示した RFC1918/`*.test`) 以外への接続を
  Witness Guard で完全ブロック。``api.openai.com`` 等は ``ProductionAccessError``
- 推論は同期 ``POST /api/generate`` (``stream=False``)
- 不在時は ``OllamaUnavailableError`` で接続ヒントを出力
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from suzaku.witness.guard import enforce_allowed

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:14b"
DEFAULT_TIMEOUT = 300.0


class OllamaError(RuntimeError):
    """Ollama 関連の例外の基底。"""


class OllamaUnavailableError(OllamaError):
    """Ollama が ``base_url`` で起動していない / 応答しない場合に発生。"""


class OllamaModelError(OllamaError):
    """指定モデルが Ollama 側に存在しない場合に発生。"""


@dataclass
class OllamaClient:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT
    _client: httpx.Client = field(init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        host = parsed.hostname or ""
        # Witness Guard を必ず通す (本番ホスト遮断)
        enforce_allowed(host)
        self._client = httpx.Client(timeout=self.timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OllamaClient:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = self._client.post(url, json=payload)
        except httpx.ConnectError as exc:
            raise OllamaUnavailableError(
                f"Failed to reach Ollama at {self.base_url}. "
                "Install via https://ollama.com/, then `ollama serve` and "
                f"`ollama pull {self.model}`."
            ) from exc
        except httpx.TransportError as exc:
            raise OllamaUnavailableError(
                f"Transport error talking to Ollama at {self.base_url}: {exc}"
            ) from exc

        if response.status_code == 404:
            raise OllamaModelError(
                f"Ollama returned 404 for {path}. "
                f"Pull the model with `ollama pull {self.model}`."
            )
        if response.status_code >= 400:
            raise OllamaError(
                f"Ollama HTTP {response.status_code} on {path}: {response.text[:200]}"
            )
        data: Any = response.json()
        if not isinstance(data, dict):
            raise OllamaError(f"Unexpected non-object response from {path}")
        return data

    def _get(self, path: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = self._client.get(url)
        except httpx.TransportError as exc:
            raise OllamaUnavailableError(str(exc)) from exc
        if response.status_code >= 400:
            raise OllamaError(f"Ollama HTTP {response.status_code} on {path}")
        data: Any = response.json()
        if not isinstance(data, dict):
            raise OllamaError(f"Unexpected non-object response from {path}")
        return data

    # ────────────────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        format: dict[str, Any] | str | None = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Ollama ``/api/generate`` を non-streaming で叩き、応答テキストを返す。"""
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system is not None:
            payload["system"] = system
        if format is not None:
            payload["format"] = format
        if options:
            payload["options"] = options
        data = self._post("/api/generate", payload)
        response_text = data.get("response", "")
        if not isinstance(response_text, str):
            raise OllamaError(f"Unexpected 'response' type in generate result: {type(response_text)}")
        return response_text

    def list_models(self) -> list[str]:
        """GET /api/tags でローカルモデル一覧を返す。"""
        data = self._get("/api/tags")
        models = data.get("models", [])
        if not isinstance(models, list):
            return []
        names: list[str] = []
        for m in models:
            if isinstance(m, dict):
                name = m.get("name")
                if isinstance(name, str):
                    names.append(name)
        return names

    def health(self) -> bool:
        """Ollama が起動しているか + 指定モデルが存在するか確認。"""
        try:
            names = self.list_models()
        except OllamaUnavailableError:
            return False
        # tag 完全一致 or model:tag のうち model 部分一致
        model_base = self.model.split(":", 1)[0]
        return any(n == self.model or n.split(":", 1)[0] == model_base for n in names)


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "OllamaClient",
    "OllamaError",
    "OllamaModelError",
    "OllamaUnavailableError",
]
