"""Witness 証跡保管 + 改ざん検知。

PoC 再現で生成された全ファイルの SHA-256 を ``evidence.lock`` に
append-only な JSON Lines で記録する。各エントリは前エントリの
ハッシュを含めることで改ざん検知を可能にする。

仕様 (SPEC.md §Witness):
- Dockerfile / docker-compose.yml / steps.md / stdout.log / stderr.log /
  HTTP トレースを保存
- 実行日時、対象 commit SHA、Docker image SHA も記録
- ``evidence.lock`` で改ざん検知 (``suzaku witness verify`` で検証)
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CHUNK_SIZE = 64 * 1024
HASH_HEX_LEN = 64
GENESIS_HASH = "0" * HASH_HEX_LEN


def compute_file_hash(path: Path) -> str:
    """ファイルの SHA-256 を 16 進文字列で返す。"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def _aggregate_hash(entries: list[dict[str, Any]], prev: str) -> str:
    """エントリ群のハッシュを順にチェインして 1 つの aggregate を返す。"""
    payload = json.dumps({"prev_hash": prev, "files": entries}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class EvidenceStore:
    """各 finding の証跡ディレクトリを管理する。

    レイアウト::

        base_dir/
            F-001/
                Dockerfile
                docker-compose.yml
                steps.md
                stdout.log
                stderr.log
                evidence.lock        # append-only JSON Lines
    """

    LOCK_FILENAME = "evidence.lock"

    def __init__(self, base_dir: Path) -> None:
        self._base = base_dir
        self._base.mkdir(parents=True, exist_ok=True)

    def evidence_dir(self, finding_id: str) -> Path:
        d = self._base / finding_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _lock_path(self, finding_id: str) -> Path:
        return self.evidence_dir(finding_id) / self.LOCK_FILENAME

    def _read_last_aggregate(self, finding_id: str) -> str:
        lock = self._lock_path(finding_id)
        if not lock.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        for line in lock.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                last = entry.get("aggregate", last)
            except json.JSONDecodeError:
                continue
        return last

    def record(self, finding_id: str, files: list[Path]) -> str:
        """``files`` の SHA-256 を計算して ``evidence.lock`` に追記する。

        Args:
            finding_id: 対象 finding の ID
            files: 証跡として記録するファイル群

        Returns:
            この record 呼び出し全体の aggregate hash (16 進)
        """
        prev = self._read_last_aggregate(finding_id)
        evidence_root = self.evidence_dir(finding_id)
        file_entries: list[dict[str, Any]] = []
        for f in files:
            try:
                rel = str(f.resolve().relative_to(evidence_root.resolve()))
            except ValueError:
                rel = str(f.resolve())
            file_entries.append({"path": rel, "sha256": compute_file_hash(f)})

        aggregate = _aggregate_hash(file_entries, prev)
        record_entry = {
            "recorded_at": datetime.now(UTC).isoformat(),
            "prev_hash": prev,
            "files": file_entries,
            "aggregate": aggregate,
        }
        with self._lock_path(finding_id).open("a", encoding="utf-8") as lf:
            lf.write(json.dumps(record_entry, sort_keys=True) + "\n")
        return aggregate

    def verify(self, finding_id: str) -> bool:
        """ハッシュチェインとファイル内容の整合性を検証する。"""
        evidence_root = self.evidence_dir(finding_id)
        lock = self._lock_path(finding_id)
        if not lock.exists():
            return False

        prev = GENESIS_HASH
        had_entry = False
        for line in lock.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
            file_entries = entry.get("files")
            stored_aggregate = entry.get("aggregate")
            if file_entries is None or stored_aggregate is None:
                return False
            if entry.get("prev_hash") != prev:
                return False
            # 各ファイルの現在のハッシュを再計算
            for fe in file_entries:
                rel = fe.get("path")
                expected = fe.get("sha256")
                if rel is None or expected is None:
                    return False
                p = (evidence_root / rel) if not Path(rel).is_absolute() else Path(rel)
                if not p.exists():
                    return False
                if compute_file_hash(p) != expected:
                    return False
            recomputed = _aggregate_hash(file_entries, prev)
            if recomputed != stored_aggregate:
                return False
            prev = stored_aggregate
            had_entry = True

        return had_entry
