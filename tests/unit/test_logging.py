"""ハッシュチェイン付きロギングのテスト。"""

from __future__ import annotations

import json
from pathlib import Path

from suzaku.logging import HashChain, configure_logging, get_logger, verify_chain


class TestHashChain:
    def test_append_writes_jsonl(self, tmp_log_path: Path) -> None:
        chain = HashChain(log_path=tmp_log_path)
        chain.append({"event": "first"})
        chain.append({"event": "second"})

        lines = tmp_log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        entry1 = json.loads(lines[0])
        entry2 = json.loads(lines[1])
        assert entry1["event"] == "first"
        assert entry2["event"] == "second"
        assert entry2["prev_hash"] == entry1["hash"]

    def test_chain_first_prev_is_zero(self, tmp_log_path: Path) -> None:
        chain = HashChain(log_path=tmp_log_path)
        chain.append({"event": "first"})
        entry = json.loads(tmp_log_path.read_text().strip().splitlines()[0])
        assert entry["prev_hash"] == "0" * 64

    def test_verify_chain_passes_on_untampered_log(self, tmp_log_path: Path) -> None:
        chain = HashChain(log_path=tmp_log_path)
        chain.append({"event": "a"})
        chain.append({"event": "b"})
        chain.append({"event": "c"})
        assert verify_chain(tmp_log_path) is True

    def test_verify_chain_detects_tampering(self, tmp_log_path: Path) -> None:
        chain = HashChain(log_path=tmp_log_path)
        chain.append({"event": "a"})
        chain.append({"event": "b"})

        # 1行目の event を改ざん
        lines = tmp_log_path.read_text().strip().splitlines()
        first = json.loads(lines[0])
        first["event"] = "tampered"
        lines[0] = json.dumps(first)
        tmp_log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert verify_chain(tmp_log_path) is False

    def test_continues_from_existing_file(self, tmp_log_path: Path) -> None:
        chain1 = HashChain(log_path=tmp_log_path)
        chain1.append({"event": "a"})
        last_hash = json.loads(tmp_log_path.read_text().strip().splitlines()[-1])["hash"]

        chain2 = HashChain(log_path=tmp_log_path)
        chain2.append({"event": "b"})
        entries = [json.loads(line) for line in tmp_log_path.read_text().strip().splitlines()]
        assert entries[1]["prev_hash"] == last_hash


class TestConfigureLogging:
    def test_configures_without_error(self, tmp_log_path: Path) -> None:
        configure_logging(level="INFO", log_path=tmp_log_path)
        logger = get_logger("test")
        logger.info("hello", action="probe")
        # ログファイルが作られ少なくとも1行書かれていること
        assert tmp_log_path.exists()
        assert tmp_log_path.read_text().strip() != ""
