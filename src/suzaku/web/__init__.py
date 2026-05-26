"""Suzaku Web UI — Phase 3-A.

CLI / MCP に並ぶ第3の UI 層 (FastAPI + React)。読み取り系 4 モジュール
(Sentinel / Compass / Lineage / Chronicle) を GUI で操作するためのバックエンド。

設計詳細: ``docs/SPEC-phase3-web-ui.md``。
"""

from suzaku.web.app import create_app

__all__ = ["create_app"]
