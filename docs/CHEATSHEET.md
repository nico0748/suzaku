# Suzaku コマンドチート表

> CLI コマンドの早見表。詳細な解説は [`GETTING_STARTED.md`](./GETTING_STARTED.md) を参照。

## 起動

```bash
suzaku --help               # 全モジュール一覧
suzaku version              # バージョン表示
python3 -m suzaku ...       # モジュール経由でも同じ
```

## ① Sentinel (斥候)

```bash
suzaku sentinel scan --language python --min-stars 500 --top 20
suzaku sentinel scan --language php --topic wordpress-plugin --pushed-after 2026-01-01 --json > targets.json
suzaku sentinel list-signals
suzaku sentinel show targets.json
```

設定: `src/suzaku/sentinel/signals.yaml` (weights / keywords / thresholds)

## ② Reader (読眼, Phase 2-A1)

```bash
ollama serve
ollama pull qwen2.5-coder:14b

suzaku reader check
suzaku reader list-models
suzaku reader read /path/to/repo --stage overview
suzaku reader read /path/to/repo                       # 4 段階一気通貫
suzaku reader read /path/to/repo --model qwen2.5-coder:7b
```

### Fine-tuning (Phase 2-A2)

```bash
suzaku reader finetune build-dataset findings.jsonl --out data/reader-sft.jsonl
suzaku reader finetune train data/reader-sft.jsonl --output run-001 --dry-run
suzaku reader finetune export run-001 --tag suzaku-reader-coder:14b --register
suzaku reader finetune eval data/reader-eval.jsonl --model suzaku-reader-coder:14b
```

環境変数: `SUZAKU_OLLAMA_BASE_URL` (default `http://localhost:11434`), `SUZAKU_OLLAMA_MODEL`

## ③ Compass (羅針)

```bash
suzaku compass list-rules
suzaku compass show-rule ssrf
suzaku compass scan /path/to/repo --rule danger_funcs_php
suzaku compass scan /path/to/repo --rule patterns/zip_slip
suzaku compass scan /path/to/repo --all --json > findings.json
```

ルールは `src/suzaku/compass/rules/{danger_funcs,patterns}/*.yaml`

## ④ Lineage (継, Phase 2-C)

```bash
suzaku lineage ingest /path/to/nvd.json --out cve_record.json
suzaku lineage ingest --cve CVE-2024-12345 --out cve_record.json
suzaku lineage extract cve_record.json --out variant_rules.json
suzaku lineage extract cve_record.json --offline       # GitHub fetch スキップ
suzaku lineage scan /path/to/repo --rules variant_rules.json --out variants.json
suzaku lineage demo /path/to/repo                      # オフライン smoke test
```

許可ホスト: `src/suzaku/lineage/data/allowed_hosts.yaml`

## ⑥ Witness (証立) — Docker + 安全機構

```bash
suzaku witness init F-001 --category ZipSlip --affected-version '>=1.0.0,<1.2.3' --commit deadbeef
suzaku witness reproduce F-001 --target-host localhost   # docker compose up
suzaku witness stop F-001                                # docker compose down -v
suzaku witness record F-001 pocs/F-001/Dockerfile pocs/F-001/steps.md
suzaku witness verify F-001
suzaku witness check-host 127.0.0.1                      # ガード単体確認
suzaku witness check-host github.com                     # → BLOCKED
```

ガード違反は **exit 4** で停止。

## ⑦ Herald (奏上)

```bash
suzaku herald cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
suzaku herald checklist advisory.json
suzaku herald list-routes
suzaku herald submit ghsa advisory.json > advisory.md
suzaku herald submit huntr advisory.json --context huntr_ctx.json
suzaku herald submit mitre advisory.json --context mitre_ctx.json
suzaku herald submit jpcert advisory.json
suzaku herald submit wordfence advisory.json --context wp_ctx.json
suzaku herald submit hackerone advisory.json --context program_ctx.json
suzaku herald submit bugcrowd advisory.json --context program_ctx.json
suzaku herald email advisory.json > report.eml
```

### ルート別 RouteContext 例

```jsonc
// MITRE — vendor_contact_attempts 必須
{"vendor_contact_attempts": [
  {"attempted_at": "2026-01-01T00:00:00+00:00", "channel": "email", "response": "no_response"}
]}

// huntr
{"huntr_package_name": "lodash", "huntr_package_ecosystem": "npm", "huntr_repo_url": "https://github.com/lodash/lodash"}

// Wordfence / Patchstack
{"wp_plugin_slug": "example-plugin", "wp_active_installs": 12000}

// HackerOne / Bugcrowd
{"program_handle": "github", "asset_identifier": "api.github.com"}
```

## ⑧ Chronicle (歴記)

```bash
suzaku chronicle init S-001
suzaku chronicle status S-001
suzaku chronicle set-vendor S-001 acknowledged   # no_response/acknowledged/fixing/fixed/rejected
suzaku chronicle list
suzaku chronicle publish S-001                   # ACCS ガード経由
suzaku chronicle publish S-001 --fixed-at 2026-03-01T00:00:00+00:00
```

state ファイル: `./.suzaku/chronicle/<sid>.json` (`--state-dir` で変更可)

## MCP サーバ (Phase 2-B)

```bash
suzaku mcp list-tools --mode ro                  # 19 ツール
suzaku mcp list-tools --mode rw                  # 23 ツール (+rw 4)
suzaku mcp serve --mode ro                       # stdio で起動
suzaku mcp serve --mode rw
```

Claude Desktop 連携 (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "suzaku": {
      "command": "suzaku",
      "args": ["mcp", "serve", "--mode", "ro"],
      "env": {"SUZAKU_GITHUB_TOKEN": "ghp_..."}
    }
  }
}
```

## 開発・運用

```bash
make install        # pip install -e ".[dev]"
make check          # ruff + mypy + pytest
make test
make lint
make format         # ruff format
make typecheck
make clean
```

## 環境変数

| 変数 | 用途 |
|---|---|
| `SUZAKU_GITHUB_TOKEN` | Sentinel / Lineage の GitHub API |
| `SUZAKU_NOTION_TOKEN` | Notion 同期 (Phase 2 future) |
| `SUZAKU_OLLAMA_BASE_URL` | Reader (default `http://localhost:11434`) |
| `SUZAKU_OLLAMA_MODEL` | Reader (default `qwen2.5-coder:14b`) |
| `SUZAKU_DATA_DIR` | 内部状態 (default `./.suzaku`) |
| `SUZAKU_EVIDENCE_DIR` | 証跡 (default `./evidence`) |
| `SUZAKU_POCS_DIR` | PoC (default `./pocs`) |
| `SUZAKU_LOG_LEVEL` | DEBUG / INFO / WARNING / ERROR |

## Exit code 一覧

| Code | 意味 |
|---|---|
| 0 | success |
| 1 | 一般失敗 |
| 2 | 引数誤り |
| 3 | 外部依存欠落 (rg 等) |
| 4 | **ProductionAccessError** (Witness Guard) |
| 5 | **ACCSViolationError** (Chronicle Guard) |
| 6 | OllamaUnavailableError |
| 7 | Reader model not found |
| 8 | ReaderParseError |
| 9 | TrainError (Fine-tune) |
| 10 | ExportError (Fine-tune) |
| 11 | NVDFilterError (Lineage) |
| 12 | LineageEgressError |
