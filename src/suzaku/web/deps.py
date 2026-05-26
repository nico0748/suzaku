"""FastAPI 依存性注入と設定。"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Literal

WebMode = Literal["ro", "rw"]


@dataclass
class WebSettings:
    """``suzaku web serve`` の起動時設定。

    Web プロセス起動時に 1 度だけ生成し、以降は ``Depends(get_settings)`` で参照する。
    """

    mode: WebMode = "ro"
    host: str = "127.0.0.1"
    port: int = 8765
    allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1",
        "http://localhost",
    )
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))


_settings: WebSettings | None = None


def configure(settings: WebSettings) -> None:
    """プロセス全体の設定を差し替える (``suzaku web serve`` から呼ぶ)。"""
    global _settings
    _settings = settings


def get_settings() -> WebSettings:
    """現在のプロセス設定を取得する。未設定ならデフォルト。"""
    global _settings
    if _settings is None:
        _settings = WebSettings()
    return _settings


__all__ = ["WebMode", "WebSettings", "configure", "get_settings"]
