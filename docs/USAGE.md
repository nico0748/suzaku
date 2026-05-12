# Suzaku 使い方ガイド

> 朱雀 (`#B43E3E`) — OSS 脆弱性調査支援システム / Phase 1 MVP

すべてのコマンドは `suzaku` または `python -m suzaku` から呼び出します。

## インストール

```bash
git clone https://github.com/nico0748/suzaku
cd suzaku
pip install -e ".[dev]"
cp .env.example .env       # GITHUB_TOKEN 等を埋める
make check                 # lint + typecheck + test
suzaku version
```

外部依存:

- **ripgrep** (`rg`) — `apt-get install ripgrep` / `brew install ripgrep`
- **Docker** + **docker compose v2** — Witness 再現用
- (任意) **Semgrep** — `pip install semgrep`。無くても grep-only モードで動作

## End-to-End シナリオ (E2E-1: WordPressプラグインで CVE を取りに行く)

### 1. Sentinel で候補を抽出

```bash
suzaku sentinel scan \
    --language php \
    --min-stars 100 \
    --pushed-after 2026-01-01 \
    --topic wordpress-plugin \
    --top 20 \
    --json > targets.json
```

8 シグナルで scoring し、上位 20 件を JSON で出力します。重みを変えるなら
`src/suzaku/sentinel/signals.yaml` を編集して再実行。

```bash
suzaku sentinel list-signals     # 現在の重み一覧
suzaku sentinel show targets.json
```

### 2. 対象をローカルクローン

```bash
git clone https://github.com/example/vulnerable-plugin /tmp/target
```

### 3. Compass で初手スキャン

```bash
suzaku compass list-rules
suzaku compass scan /tmp/target --rule danger_funcs_php
suzaku compass scan /tmp/target --all --json > findings.json
```

ripgrep が見つからないと `RipgrepNotFoundError` で停止します (exit 3)。

### 4. Witness で PoC 再現

```bash
suzaku witness init F-001 \
    --category ZipSlip \
    --affected-version '>=1.0.0,<1.2.3' \
    --commit deadbeefcafe123 \
    --target-url http://localhost:8080
suzaku witness reproduce F-001 --target-host localhost
# -> docker compose up --build -d
# ガード違反 (例: --target-host github.com) は exit 4 で停止
suzaku witness record F-001 ./pocs/F-001/Dockerfile ./pocs/F-001/steps.md
suzaku witness verify F-001
suzaku witness stop F-001
```

### 5. Herald で GHSA / メール生成

事前に `submission.json` (5 点セット入り) を用意:

```json
{
    "submission": {
        "product_name": "vulnerable-plugin",
        "vendor": "Example Inc.",
        "affected_versions": ">=1.0.0,<1.2.3",
        "cwe": "CWE-22",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "reproduction_steps_path": "./pocs/F-001/steps.md",
        "reference_urls": ["https://github.com/example/x/commit/abc"]
    },
    "summary": "Zip Slip during plugin import",
    "impact_description": "An attacker who can upload ...",
    "mitigation": "Validate each entry with os.path.realpath",
    "steps": ["Send crafted zip", "Trigger import", "Observe path traversal"],
    "tested_version": "1.2.2",
    "commit_sha": "deadbeefcafe1234",
    "fixed_version": "1.2.3",
    "reporter_contact": "reporter@example.test",
    "reporter_name": "Suzaku Reporter"
}
```

実行:

```bash
suzaku herald cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
suzaku herald checklist submission.json
suzaku herald ghsa submission.json > advisory.md
suzaku herald email submission.json > report.eml
```

`render_email` には **脅迫的表現の禁止語ガード** が組み込まれており、
"pay first" 等が混入すると `ExtortionLanguageError` で生成を阻止します。

### 6. Chronicle で 90 日タイムライン

```bash
suzaku chronicle init S-001
suzaku chronicle status S-001
suzaku chronicle set-vendor S-001 acknowledged
suzaku chronicle list

# Day 90 経過前の公開は ACCS ガードで拒否される (exit 5)
suzaku chronicle publish S-001
```

`--state-dir` でステート保存先を変更可。デフォルトは `./.suzaku/chronicle/`。

## Claude Code / Claude Desktop から呼ぶ (Phase 2-B MCP)

Suzaku は MCP (Model Context Protocol) サーバとしても動作します。Claude Code / Claude Desktop に登録すると自然言語で各モジュールを呼べます。

```bash
# stdio トランスポートで起動 (Claude Code/Desktop が prepare して呼び出す)
suzaku mcp serve --mode ro       # 読み取り専用ツールのみ (推奨)
suzaku mcp serve --mode rw       # rw ツールも公開 (witness_init / chronicle_init 等)

# 公開されるツール一覧を確認
suzaku mcp list-tools --mode ro
suzaku mcp list-tools --mode rw
```

Claude Desktop の `claude_desktop_config.json` 設定例:

```json
{
  "mcpServers": {
    "suzaku": {
      "command": "suzaku",
      "args": ["mcp", "serve", "--mode", "ro"],
      "env": {
        "SUZAKU_GITHUB_TOKEN": "ghp_..."
      }
    }
  }
}
```

公開されるツール (mode=ro/rw 別):

| Tool | Mode | 説明 |
|---|---|---|
| `suzaku_version` | ro | バージョン |
| `sentinel_list_signals` / `sentinel_score` | ro | 8 シグナル評価 |
| `compass_list_rules` / `compass_show_rule` / `compass_scan` | ro | ルール一覧 / 単発スキャン |
| `witness_check_host` / `witness_verify` | ro | ガード判定 / 証跡検証 |
| `herald_cvss` / `herald_checklist` / `herald_list_routes` / `herald_render` | ro | CVSS 計算 / 8 ルート対応 |
| `chronicle_status` / `chronicle_list` | ro | 90 日タイムライン |
| `witness_init` / `witness_record` | rw | PoC 展開 / 証跡記録 |
| `chronicle_init` / `chronicle_set_vendor` | rw | disclosure 開始 / ベンダ状態更新 |

公開**しない** (Phase 2-B 範囲外、SPEC 参照): `witness_reproduce`, `chronicle_publish`, `sentinel_scan` (実 GitHub API call), `compass_scan --all` 等。

詳細仕様: [`SPEC-phase2-mcp.md`](./SPEC-phase2-mcp.md)。

## Reader — ローカル LLM コード読解 (Phase 2-A1)

Reader は Ollama 経由でローカル LLM を呼び、4 段階のコード読解を行います。**未公開脆弱性候補コードを外部に送らない方針** のため、クラウド LLM は利用しません。

事前準備:
```bash
# Ollama を https://ollama.com/ からインストールしてから:
ollama serve
ollama pull qwen2.5-coder:14b   # 既定モデル (約 9GB)
```

CLI:
```bash
suzaku reader check                     # 疎通 + 既定モデルの存在チェック
suzaku reader list-models               # Ollama 登録モデル一覧
suzaku reader read /path/to/repo                 # 4 段階一気通貫
suzaku reader read /path/to/repo --stage overview  # 概観のみ
suzaku reader read /path/to/repo --model qwen2.5-coder:7b  # モデル指定
```

環境変数: `SUZAKU_OLLAMA_BASE_URL` (既定 `http://localhost:11434`), `SUZAKU_OLLAMA_MODEL` (既定 `qwen2.5-coder:14b`)。

4 段階:
1. **概観** — リポジトリの tech stack / 主要ディレクトリ / 推定 LOC
2. **入口の特定** — http_route / cli / ipc / rpc / websocket / queue
3. **信頼境界の追跡** — 入口 → sink までのデータフロー要約
4. **仮説生成** — sink ごとに CWE トップ 3 (`herald/data/cwe.json` の許可リストに限定)

ガード:
- `OllamaClient` は **Witness Guard を必ず経由** — `--ollama-url http://api.openai.com` を渡すと `ProductionAccessError` (exit 4) で停止
- LLM 出力は Pydantic + JSON Schema で強制検証 — 未知 CWE は除外、JSON 不正は `ReaderParseError` (exit 8)
- 報告メールに脅迫的表現を生成しないよう Hypothesis のプロンプトで明示

詳細仕様: [`SPEC-phase2-reader-core.md`](./SPEC-phase2-reader-core.md)

### Reader Fine-tuning Pipeline (Phase 2-A2)

ローカル GPU 環境向けの LoRA SFT パイプライン。実学習は外部スクリプト
(Unsloth 想定) を呼び、本ツールはデータセット構築・コマンド組み立て・
GGUF 変換・Modelfile 生成・評価のラッパを提供する。

```bash
# 1. データセット構築 (公開 Finding のみ、PII は redact)
suzaku reader finetune build-dataset findings.jsonl --out ./data/reader-sft.jsonl

# 2. 学習 (まず --dry-run でコマンドを確認 → GPU 環境で本実行)
suzaku reader finetune train ./data/reader-sft.jsonl \
    --output ./reader/finetuned/run-001 --epochs 3 --dry-run

# 3. GGUF 変換 + Ollama 登録 (要 llama.cpp / ollama)
suzaku reader finetune export ./reader/finetuned/run-001 \
    --tag suzaku-reader-coder:14b --register

# 4. 評価
suzaku reader finetune eval ./data/reader-eval.jsonl \
    --model suzaku-reader-coder:14b --per-sample --out ./eval-001.json
```

安全要件 (機械的にガード):
- `Finding.state != "published"` は **学習データから機械除外**
- 禁止フレーズ (`FORBIDDEN_PHRASES`) 12 種を含むサンプルも除外
- メールアドレス / 電話番号 / JWT 風文字列を `<REDACTED_*>` に置換
- データセットの SHA-256 を `BuildStats.dataset_sha256` に記録 (証跡用)
- 評価では CWE Top-1/Top-3 / JSON 準拠率 / ハルシネーション率 / **禁止語混入率 (0 必須)** を測定

詳細仕様: [`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md)

## Lineage — Variant Analysis (Phase 2-C)

公開済み CVE の修正パッチから類似パターンを抽出し、Sentinel 候補リポ
ジトリへ横展開検索する。**未公開 CVE は対象外** (`vulnStatus` 厳格判定)。

```bash
# 1. NVD JSON 取り込み (オフライン or オンライン)
suzaku lineage ingest /path/to/cve.json --out cve_record.json
suzaku lineage ingest --cve CVE-2024-1234 --out cve_record.json  # NVD API

# 2. commit diff から VariantRule を抽出
suzaku lineage extract cve_record.json --out variant_rules.json
suzaku lineage extract cve_record.json --offline  # GitHub fetch しない

# 3. 自前リポジトリで横展開検索
suzaku lineage scan /path/to/repo --rules variant_rules.json --out findings.json

# 4. オフライン demo (内蔵 CVE で 4 stage を試走)
suzaku lineage demo /path/to/repo
```

### Lineage Egress Guard

Lineage は読み取り専用の外部 API (NVD / GitHub) を呼ぶ必要があるため、
**Witness Guard とは独立した allow-list** を `src/suzaku/lineage/data/allowed_hosts.yaml` で管理:

```yaml
read_only_egress:
  - api.github.com
  - services.nvd.nist.gov
  - nvd.nist.gov
```

許可外ホスト (`api.openai.com` 等) は `LineageEgressError` (exit 12) で拒否。
Witness Reproducer のガード (本番アクセス遮断) は変更されません。

### 安全要件

- `vulnStatus` ホワイトリスト (`Public` / `Modified` / `Analyzed`) — `Awaiting Analysis` は除外
- CWE allow-list 外の CVE は VariantRule を生成しない
- 生成 regex は `Severity = MEDIUM` 既定 (Compass で再検証してから Herald へ)
- 削除行 (脆弱コード) は **完全コピーで保存せず regex 化のみ**、追加行 (mitigation) は `must_not_contain` に転写

詳細仕様: [`SPEC-phase2-lineage.md`](./SPEC-phase2-lineage.md)

## モジュール別リファレンス

### Sentinel

| Command | 説明 |
|---|---|
| `sentinel scan` | 8 シグナル評価で OSS をランキング |
| `sentinel list-signals` | `signals.yaml` の重み一覧 |
| `sentinel show <json>` | 過去スキャン JSON の詳細 |

### Compass

| Command | 説明 |
|---|---|
| `compass scan <repo> --rule <id>` | 特定ルールでスキャン |
| `compass scan <repo> --all` | 同梱ルール全て |
| `compass list-rules` | 同梱 10 ルール一覧 |
| `compass show-rule <id>` | ルール定義を JSON で表示 |

### Witness (本番アクセス絶対禁止)

| Command | 説明 | Exit |
|---|---|---|
| `witness init <id>` | PoC テンプレ展開 | |
| `witness reproduce <id>` | docker compose up | 4 (ガード違反) |
| `witness stop <id>` | docker compose down -v | |
| `witness record <id> <files...>` | 証跡 SHA-256 記録 | |
| `witness verify <id>` | チェイン検証 | 1 (改ざん検知) |
| `witness check-host <host>` | ガード単体確認 | 1 (block) |

### Herald (Phase 2-D で 8 ルート対応)

| Command | 説明 | Exit |
|---|---|---|
| `herald cvss <vector>` | CVSS v3.1 スコア | 2 (形式誤り) |
| `herald checklist <json>` | 5 点セット欠落検査 | 1 (欠落) |
| `herald ghsa <json>` | GHSA Markdown 生成 (legacy alias) | 1 (検証失敗) |
| `herald email <json>` | 報告メール生成 | 1 (禁止語) |
| `herald list-routes` | 同梱 8 ルート一覧 + 申請 URL | |
| `herald submit <route> <json> [--context ctx.json]` | 各ルート向けテンプレート生成 | 1 (検証失敗) / 2 (未知ルート) |

利用可能なルート (`<route>` 値):
- `ghsa` — GitHub Security Advisory (デフォルト)
- `mitre` — MITRE CNA-LR (ベンダ無応答時の CVE 採番)
- `huntr` — huntr.dev (OSS bug bounty)
- `jpcert` — JPCERT/CC (国内・日本語)
- `wordfence` / `patchstack` — WordPress 専用
- `hackerone` / `bugcrowd` — VDP プラットフォーム

ルート別 `ctx.json` 例:

```jsonc
// MITRE 用 (vendor_contact_attempts >= 1 が必須)
{
  "vendor_contact_attempts": [
    {"attempted_at": "2026-01-01T00:00:00+00:00", "channel": "email security@", "response": "no_response"},
    {"attempted_at": "2026-01-14T00:00:00+00:00", "channel": "github_issue #42", "response": "no_response"}
  ]
}

// huntr 用
{"huntr_package_name": "example", "huntr_package_ecosystem": "npm", "huntr_repo_url": "https://github.com/example/x"}

// Wordfence / Patchstack 用
{"wp_plugin_slug": "example-plugin", "wp_active_installs": 12000}

// HackerOne / Bugcrowd 用
{"program_handle": "github", "asset_identifier": "api.github.com"}
```

詳細仕様は [`SPEC-phase2-herald-routes.md`](./SPEC-phase2-herald-routes.md) を参照。

### Chronicle (ACCS ガード組込)

| Command | 説明 | Exit |
|---|---|---|
| `chronicle init <id>` | Day 0 開始 | |
| `chronicle status <id>` | 現マイルストーン + 推奨アクション | |
| `chronicle set-vendor <id> <state>` | ベンダ状態更新 | |
| `chronicle publish <id>` | ACCS ガード経由で公開 | 5 (ACCS 違反) |
| `chronicle list` | 全 disclosure 一覧 | |

## Exit Code 規約

| Code | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 一般失敗 (検証失敗・欠落) |
| 2 | 引数誤り |
| 3 | 外部依存欠落 (ripgrep) |
| **4** | **本番アクセスガード違反** (`ProductionAccessError`) |
| **5** | **ACCS事件 3 手順違反** (`ACCSViolationError`) |

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `RipgrepNotFoundError` | `apt-get install ripgrep` または `brew install ripgrep` |
| `ProductionAccessError` | `--target-host` を `localhost` / RFC1918 / `*.test` に |
| `ACCSViolationError` | Day 90 経過待ち、または修正リリース後 +30 日待つ |
| 認証関連 (Sentinel) | `.env` の `SUZAKU_GITHUB_TOKEN` を設定 |

## さらに

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — モジュール設計と Phase 2/3 構想
- [`ROADMAP.md`](./ROADMAP.md) — 今後の予定
- [`../LEGAL.md`](../LEGAL.md) — ACCS事件 3 手順 / 不正アクセス禁止法
- [`SPEC.md`](./SPEC.md) — 元仕様 (Phase 1 MVP 受け入れ基準を含む)
