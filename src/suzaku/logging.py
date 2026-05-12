"""structlog ベースの構造化ロギング + ハッシュチェイン。

各実行ログに SHA-256 を付与し、append-only でファイル保存する。
証跡の改ざん検知を可能にする。
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from pathlib import Path
from threading import Lock
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger


class HashChain:
    """ログイベントを SHA-256 のチェインで連結する。

    各イベントは前のエントリのハッシュを含めてハッシュ化することで、
    後からの差し込み・削除を検知できる。
    """

    def __init__(self, log_path: Path | None = None) -> None:
        self._lock = Lock()
        self._prev_hash = "0" * 64
        self._log_path = log_path
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # 既存ファイルがあれば最後のハッシュを引き継ぐ
            if log_path.exists():
                self._prev_hash = self._load_last_hash(log_path)

    @staticmethod
    def _load_last_hash(path: Path) -> str:
        last = "0" * 64
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    last = entry.get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            payload = dict(event)
            payload["prev_hash"] = self._prev_hash
            canonical = json.dumps(payload, sort_keys=True, default=str)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            payload["hash"] = digest
            self._prev_hash = digest
            if self._log_path is not None:
                with self._log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, default=str) + "\n")
            return payload


_chain: HashChain | None = None


def _hash_chain_processor(
    _logger: WrappedLogger, _method_name: str, event_dict: EventDict
) -> EventDict:
    global _chain
    if _chain is None:
        return event_dict
    sealed = _chain.append(dict(event_dict))
    event_dict["hash"] = sealed["hash"]
    event_dict["prev_hash"] = sealed["prev_hash"]
    return event_dict


def configure_logging(
    level: str = "INFO",
    log_path: Path | None = None,
) -> None:
    """structlog を設定する。

    Args:
        level: ログレベル (DEBUG/INFO/WARNING/ERROR)
        log_path: 指定すると append-only な JSON Lines として保存される
    """
    global _chain
    _chain = HashChain(log_path=log_path)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _hash_chain_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """構造化ロガーを取得する。"""
    return structlog.get_logger(name)  # type: ignore[no-any-return]


def verify_chain(log_path: Path) -> bool:
    """ハッシュチェインの整合性を検証する。

    Returns:
        True: 改ざんなし / False: 不整合あり
    """
    prev = "0" * 64
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            stored_hash = entry.pop("hash", None)
            if stored_hash is None:
                return False
            if entry.get("prev_hash") != prev:
                return False
            canonical = json.dumps(entry, sort_keys=True, default=str)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if digest != stored_hash:
                return False
            prev = stored_hash
    return True
