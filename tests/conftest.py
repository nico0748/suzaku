"""Pytest 共通フィクスチャ。"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def tmp_log_path(tmp_path: Path) -> Iterator[Path]:
    """テスト用の一時ログパス。"""
    path = tmp_path / "suzaku.log.jsonl"
    yield path
