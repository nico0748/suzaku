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

### Herald (Phase 1 は GHSA のみ)

| Command | 説明 | Exit |
|---|---|---|
| `herald cvss <vector>` | CVSS v3.1 スコア | 2 (形式誤り) |
| `herald checklist <json>` | 5 点セット欠落検査 | 1 (欠落) |
| `herald ghsa <json>` | GHSA Markdown 生成 | 1 (検証失敗) |
| `herald email <json>` | 報告メール生成 | 1 (禁止語) |

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
