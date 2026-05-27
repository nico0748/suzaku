# Suzaku 使い方ガイド (Getting Started)

> 朱雀 — OSS 脆弱性調査支援システム
> 個人セキュリティリサーチャー向け Hands-on チュートリアル

このガイドでは、Suzaku を **ゼロから使い始めて、最初の脆弱性候補を見つけ、報告までこぎつける** まで、すべてのモジュールを順に体験できます。約 60 分で一周できる構成です。

実コマンドの一覧だけ欲しい方は [`CHEATSHEET.md`](./CHEATSHEET.md) を、 E2E シナリオ全体を一気に追いたい方は [`E2E.md`](./E2E.md) を参照してください。

---

## 0. 朱雀の世界観 (3 分)

朱雀は四神の一柱で、「広い空から異変を見つけて告げる存在」。Suzaku もこれに倣い、OSS の海から脆弱性候補を見つけ出し、適切な手順で社会と共有することを目的とします。

**5 つのハードルール** (絶対遵守):

1. **本番アクセス禁止** — 検証は Docker 内のローカル再現のみ
2. **ACCS事件の 3 手順** — 通知 → 修正期間 → 公表 を逸脱しない
3. **武器化エクスプロイト自動公開禁止** — PoC は検証可能な範囲に留める
4. **シークレットの直書き禁止** — 環境変数 / 1Password CLI 経由
5. **証跡の改ざん検知** — 全ログに SHA-256 を付与し append-only

これらは Suzaku の各モジュール (Witness Guard / ACCS Guard / Extortion Guard / 証跡チェイン) で **機械的に強制** されます。

---

## 1. インストール (5 分)

### 必須

```bash
git clone https://github.com/nico0748/suzaku
cd suzaku
python3 -m pip install -e ".[dev]"
cp .env.example .env       # GitHub token 等を埋める
make check                 # lint + typecheck + test
suzaku version
```

### 外部依存

| ツール | 用途 | インストール |
|---|---|---|
| **ripgrep** (`rg`) | Compass / Lineage の高速スキャン | `apt-get install ripgrep` / `brew install ripgrep` |
| **Docker** + compose v2 | Witness PoC 再現 | https://docs.docker.com/get-docker/ |
| **Ollama** | Reader (ローカル LLM) | https://ollama.com/ |
| `qwen2.5-coder:14b` (~9GB) | Reader 既定モデル | `ollama pull qwen2.5-coder:14b` |
| **Semgrep** (任意) | Compass の SAST 補強 | `pip install semgrep` |

Reader / Lineage を使わないなら ripgrep + Docker だけで十分です。

### 動作確認

```bash
suzaku --help
# → 7 モジュール (sentinel/compass/witness/herald/chronicle/reader/lineage)
#   + mcp サブコマンドが表示されれば OK
```

---

## 2. モジュール早見表 (3 分)

| # | モジュール | 役割 | 主要コマンド |
|---|---|---|---|
| ① | **Sentinel** (斥候) | 8 シグナルで OSS をスコア | `sentinel scan` |
| ② | **Reader** (読眼) | ローカル LLM でコード読解 | `reader read` |
| ③ | **Compass** (羅針) | grep + Semgrep ルール | `compass scan` |
| ④ | **Lineage** (継) | CVE 修正パッチから横展開 | `lineage extract / scan` |
| ⑥ | **Witness** (証立) | Docker 内 PoC + ガード | `witness init / reproduce` |
| ⑦ | **Herald** (奏上) | GHSA / 8 ルートのメール | `herald submit` |
| ⑧ | **Chronicle** (歴記) | 90 日タイムライン | `chronicle init / status` |

加えて **MCP サーバ** (`suzaku mcp serve`) で Claude Code / Desktop から呼べます。

---

## 3. ハンズオン (45 分)

### Step A: 安全機構を体感する (5 分)

まず Witness Guard が本番アクセスを完全に遮断することを確認しましょう。

```bash
suzaku witness check-host localhost
# → ALLOWED (exit 0)

suzaku witness check-host github.com
# → BLOCKED (exit 1)

suzaku witness check-host 0177.0.0.1
# → ALLOWED (8 進表記の 127.0.0.1)

suzaku witness check-host 2130706433
# → ALLOWED (decimal 表記の 127.0.0.1)
```

IPv4 表記バイパス・DNS rebinding まで全て塞いであります。**この層を突き抜けることはありません**。

### Step B: Sentinel — OSS の候補を抽出 (5 分)

GitHub から PHP 製の WordPress プラグインをスター数 100+ で 20 件、Sentinel の 8 シグナルでスコアリングします。

```bash
export SUZAKU_GITHUB_TOKEN=ghp_...   # .env から自動ロードも可
suzaku sentinel scan \
    --language php \
    --min-stars 100 \
    --pushed-after 2026-01-01 \
    --topic wordpress-plugin \
    --top 20 \
    --json > targets.json
```

8 シグナルの重みは `src/suzaku/sentinel/signals.yaml` で変更可能:

```bash
suzaku sentinel list-signals
# → maintenance_inactivity / thin_auth_layer / monetary / ... の現在の重み一覧
```

重みを書き換えると順位が変わります (テストで保証されています)。

### Step C: Compass — 静的スキャン (5 分)

候補リポを 1 件選んで clone し、Compass で danger function + パターンスキャン。

```bash
git clone https://github.com/example/vulnerable-plugin /tmp/target

suzaku compass list-rules
# → 同梱 10 ルール (6 言語 + 4 パターン) が見える

suzaku compass scan /tmp/target --rule danger_funcs_php
suzaku compass scan /tmp/target --rule patterns/ssrf
suzaku compass scan /tmp/target --all --json > findings.json
```

ヒットは `Finding` 型で出力されます。

### Step D: Reader — LLM で仮説生成 (10 分)

Compass は「事実」を出します。Reader は **ローカル LLM** で「攻撃面の仮説」を出します。クラウド LLM ではなくローカル動作なので、未公開脆弱性候補コードを外部に送りません。

```bash
ollama serve &                          # 既に動いていればスキップ
ollama pull qwen2.5-coder:14b           # 約 9GB

suzaku reader check                     # 疎通確認
suzaku reader read /tmp/target --stage overview   # 概観のみ (1 LLM call)
suzaku reader read /tmp/target          # 4 段階一気通貫 (数分)
```

4 段階の出力:

1. **概観** — tech stack / 主要ディレクトリ / 推定 LOC
2. **入口** — HTTP route / CLI / WS 等の externally reachable な箇所
3. **信頼境界** — 入口 → sink までのデータフロー要約
4. **仮説** — 各 sink で発火しうる CWE トップ 3 (allow-list で検証)

> Reader はクラウド LLM を一切使いません。`OllamaClient(base_url="http://api.openai.com")` を渡しても Witness Guard が `ProductionAccessError` (exit 4) で初期化を拒否します。

### Step E: Lineage — 既知 CVE からの横展開 (5 分)

公開済み CVE の修正パッチから「他リポにも残ってそうな同種の脆弱性パターン」を自動抽出します。

```bash
# 1. NVD JSON 取り込み (オンライン or ローカルファイル)
suzaku lineage ingest --cve CVE-2024-12345 --out cve_record.json

# 2. commit diff -> VariantRule
suzaku lineage extract cve_record.json --out variant_rules.json

# 3. 自前リポへ横展開検索
suzaku lineage scan /tmp/target --rules variant_rules.json --out variants.json
```

Lineage は **Witness Guard とは独立した allow-list** (NVD / GitHub のみ) で外部 API を呼びます (`LineageEgressGuard`)。Witness Reproducer の遮断ロジックは一切変えません。

### Step F: Witness — Docker で安全に PoC (8 分)

候補が固まったら Docker 内で再現します。**本番ホストには絶対に到達しません**。

```bash
suzaku witness init F-001 \
    --category ZipSlip \
    --affected-version '>=1.0.0,<1.2.3' \
    --commit deadbeefcafe123

# pocs/F-001/ に Dockerfile / docker-compose.yml / steps.md が展開される

suzaku witness reproduce F-001 --target-host localhost
# → docker compose up --build -d

suzaku witness record F-001 \
    pocs/F-001/Dockerfile \
    pocs/F-001/steps.md
# → evidence.lock に SHA-256 を append

suzaku witness verify F-001
# → OK (改ざんなし) / TAMPERED (検知)

suzaku witness stop F-001
```

ガードが効いていることも単独で確認できます:

```bash
suzaku witness reproduce F-001 --target-host github.com
# → exit 4 ProductionAccessError
```

### Step G: Herald — 5 点セット + 8 ルートの申請 (7 分)

報告に必要な情報 (5 点セット) を 1 つの JSON にまとめて、ルートを選んでテンプレートを生成します。

```bash
cat > advisory.json <<'JSON'
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
  "impact_description": "An attacker who can upload a crafted archive ...",
  "mitigation": "Validate each entry with os.path.realpath before write.",
  "steps": ["Send crafted zip", "Trigger import", "Observe path traversal"],
  "tested_version": "1.2.2",
  "commit_sha": "deadbeefcafe1234",
  "fixed_version": "1.2.3",
  "reporter_contact": "researcher@example.test",
  "reporter_name": "Suzaku Reporter"
}
JSON

suzaku herald cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# → 9.8 / Critical

suzaku herald checklist advisory.json
# → 5 点セット OK

suzaku herald list-routes
# → ghsa / mitre / huntr / jpcert / wordfence / patchstack / hackerone / bugcrowd

suzaku herald submit ghsa advisory.json > advisory.md
suzaku herald submit huntr advisory.json --context huntr_ctx.json
suzaku herald submit mitre advisory.json --context mitre_ctx.json
```

Herald の **禁止語ガード** がメール / 出力本文に脅迫的表現が混入していないかを毎回検査します (12 種、case-insensitive)。混入すると `ExtortionLanguageError` で出力を阻止します。

### Step H: Chronicle — 90 日タイムライン管理 (5 分)

通知から 90 日のタイムラインを開始し、進捗を Chronicle に記録します。

```bash
suzaku chronicle init S-001
# → .suzaku/chronicle/S-001.json (Day 0 = 今日)

suzaku chronicle status S-001
# → 現マイルストーン + 推奨アクション

# ベンダから返事が来たら
suzaku chronicle set-vendor S-001 acknowledged

# Day 90 経過前の公開試行は ACCS Guard が拒否
suzaku chronicle publish S-001
# → exit 5 ACCSViolationError "Day N — cannot publish before Day 90"
```

ACCS Guard は通知前公開 / Day 90 未満 / 修正後 30 日未満を **機械的に** 拒否します。

---

## 4. Claude Code / Desktop から呼ぶ (5 分)

Suzaku は MCP (Model Context Protocol) サーバとしても動作するので、Claude Code / Claude Desktop から自然言語で呼び出せます。

```bash
suzaku mcp list-tools --mode ro
# → 19 ツール (suzaku_version / sentinel_* / compass_* / witness_*
#   / herald_* / chronicle_* / reader_* / lineage_*)

suzaku mcp serve --mode ro   # stdio で起動
```

Claude Desktop の `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "suzaku": {
      "command": "suzaku",
      "args": ["mcp", "serve", "--mode", "ro"],
      "env": { "SUZAKU_GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

これで Claude に「この CVSS ベクタを計算して」「Day 30 の Chronicle ステータスを教えて」と依頼するだけで Suzaku が呼ばれます。`--mode rw` で `witness_init` / `chronicle_init` も解禁できます。

---

## 5. Exit Code 規約

| Code | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 一般失敗 (検証失敗・欠落) |
| 2 | 引数誤り (CVSS ベクタ等) |
| 3 | 外部依存欠落 (ripgrep) |
| **4** | **`ProductionAccessError`** (Witness Guard) |
| **5** | **`ACCSViolationError`** (Chronicle Guard) |
| 6 | Ollama unavailable |
| 7 | Reader model not found |
| 8 | LLM JSON parse failed |
| 9 | Fine-tune (TrainError) |
| 10 | Fine-tune export (ExportError) |
| 11 | NVDFilterError (Lineage) |
| 12 | LineageEgressError |

---

## 6. よくある詰まりどころ

| 症状 | 対処 |
|---|---|
| `RipgrepNotFoundError` | `apt-get install ripgrep` / `brew install ripgrep` |
| `ProductionAccessError` | `--target-host` を `localhost` / RFC1918 / `*.test` に |
| `ACCSViolationError` | Day 90 経過待ち or 修正リリース後 +30 日待つ |
| `OllamaUnavailableError` | `ollama serve` + `ollama pull qwen2.5-coder:14b` |
| `LineageEgressError` | NVD/GitHub 以外の host を踏もうとした。設計通りの拒否 |
| `ExtortionLanguageError` | summary / impact 等から脅迫的表現を取り除く |
| Sentinel が API 制限 | `SUZAKU_GITHUB_TOKEN` を `.env` に設定 |

---

## 4.5. Web UI を起動する (Phase 3-A、進行中)

ブラウザでも操作したい場合は FastAPI + React の Web UI を立ち上げる:

```bash
# Terminal 1 — FastAPI バックエンド (127.0.0.1:8765)
suzaku web serve

# Terminal 2 — Vite dev server (127.0.0.1:5173, /api/* を 8765 へ proxy)
cd web
npm install     # 初回のみ
npm run dev
```

ブラウザで `http://127.0.0.1:5173/` を開く。現状 (Phase 3-A PR #4 時点) は Dashboard のみ機能し、Sentinel / Compass / Lineage / Chronicle 各ページは "Coming soon" のスタブ。後続 PR で順次実装する。

API スキーマは `http://127.0.0.1:8765/docs` (Swagger UI) で確認できる。

---

## 7. 次のステップ

- **詳細仕様**: `docs/SPEC*.md` (Phase 1 + Phase 2-A/B/C/D)
- **アーキテクチャ**: [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- **ロードマップ**: [`ROADMAP.md`](./ROADMAP.md)
- **チート表**: [`CHEATSHEET.md`](./CHEATSHEET.md)
- **E2E シナリオ**: [`E2E.md`](./E2E.md)
- **法的免責**: [`../LEGAL.md`](../LEGAL.md) (ACCS事件 3 手順 / 不正アクセス禁止法)

ハッキングは「合理的に予想される以上の時間をかける」ことから生まれる、と Tavis Ormandy は言いました。Suzaku はその翼です。安全に、誠実に、空から異変を探してください。
