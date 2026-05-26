"""Web テスト共通フィクスチャ。"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from suzaku.web.app import create_app
from suzaku.web.deps import WebSettings


@pytest.fixture
def web_settings() -> WebSettings:
    """テスト用の固定 WebSettings (CSRF トークンが安定する)。"""
    return WebSettings(
        mode="ro",
        host="127.0.0.1",
        port=8765,
        csrf_token="test-csrf-token-fixed",
    )


@pytest.fixture
def app(web_settings: WebSettings) -> FastAPI:
    return create_app(web_settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
