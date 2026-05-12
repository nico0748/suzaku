"""Witness Evidence (証跡保管 + ハッシュ検証) のテスト。"""

from __future__ import annotations

from pathlib import Path

from suzaku.witness.evidence import EvidenceStore, compute_file_hash


class TestComputeFileHash:
    def test_hash_is_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_bytes(b"hello suzaku")
        assert compute_file_hash(f) == compute_file_hash(f)

    def test_hash_changes_on_content_change(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt"
        f.write_bytes(b"a")
        h1 = compute_file_hash(f)
        f.write_bytes(b"b")
        assert h1 != compute_file_hash(f)


class TestEvidenceStore:
    def test_evidence_dir_created(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        d = store.evidence_dir("F-001")
        assert d.exists()
        assert d == tmp_path / "F-001"

    def test_record_creates_lock_file(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        f1 = tmp_path / "F-001" / "Dockerfile"
        f1.parent.mkdir(parents=True)
        f1.write_text("FROM scratch")
        f2 = tmp_path / "F-001" / "steps.md"
        f2.write_text("# steps")

        aggregate = store.record("F-001", files=[f1, f2])

        lock = tmp_path / "F-001" / "evidence.lock"
        assert lock.exists()
        assert len(aggregate) == 64  # SHA-256 hex

    def test_record_appends_not_overwrites(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        d = store.evidence_dir("F-001")
        f1 = d / "Dockerfile"
        f1.write_text("FROM scratch")
        store.record("F-001", files=[f1])

        f2 = d / "steps.md"
        f2.write_text("# v1")
        store.record("F-001", files=[f2])

        lock = d / "evidence.lock"
        lines = lock.read_text().strip().splitlines()
        # 2回 record すれば 2 行以上 (各 record が複数 file エントリを書くこともある)
        assert len(lines) >= 2

    def test_verify_passes_for_untampered(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        d = store.evidence_dir("F-001")
        f = d / "Dockerfile"
        f.write_text("FROM alpine:3.20")
        store.record("F-001", files=[f])

        assert store.verify("F-001") is True

    def test_verify_detects_file_tampering(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        d = store.evidence_dir("F-001")
        f = d / "Dockerfile"
        f.write_text("FROM alpine:3.20")
        store.record("F-001", files=[f])

        # ファイル内容を改ざん
        f.write_text("FROM evil:latest")
        assert store.verify("F-001") is False

    def test_verify_detects_lock_tampering(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        d = store.evidence_dir("F-001")
        f = d / "Dockerfile"
        f.write_text("FROM alpine:3.20")
        store.record("F-001", files=[f])

        lock = d / "evidence.lock"
        # aggregate / sha256 のどちらを変えても verify は失敗するはず
        content = lock.read_text()
        tampered = content.replace('"sha256": "', '"sha256": "0')
        # 1 文字余分に挿入されハッシュ長が変わる -> verify 失敗
        lock.write_text(tampered)
        assert store.verify("F-001") is False

    def test_verify_missing_evidence_dir(self, tmp_path: Path) -> None:
        store = EvidenceStore(base_dir=tmp_path)
        # record していない finding は False
        assert store.verify("F-999") is False
