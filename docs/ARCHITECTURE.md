# Suzaku Architecture

> Phase 1 MVP では 5 モジュール (Sentinel / Compass / Witness / Herald / Chronicle) を実装。Phase 2 以降で Reader / Lineage / Probe を追加。

## 思想

朱雀 (Suzaku) は四神の一柱。「広い空から異変を見つけ出し、災厄を告げる存在」というメタファに沿い、本システムは **OSS に潜在する脆弱性を調査・分析し、CVE / JVNDB への報告につなげる** ことを使命とする。

ハードルール (絶対遵守):

1. **本番アクセス禁止** — Docker でのローカル再現のみ
2. **ACCS事件の3手順** — 通知 → 修正期間 → 公表
3. **武器化エクスプロイト自動公開禁止**
4. **シークレットの直書き禁止** — 環境変数 / 1Password CLI 経由
5. **証跡の改ざん検知** — 全実行ログに SHA-256 を付与し append-only

## 8 サブシステム構想 (Phase 1 は 5 つ実装)

```
┌─────────────────────────────────────────────────────────────────┐
│                          Suzaku CLI (Typer)                     │
└────┬──────────┬──────────┬──────────┬──────────┬───────────────┘
     │          │          │          │          │
   ┌─┴─┐      ┌─┴─┐      ┌─┴─┐      ┌─┴─┐      ┌─┴─┐
   │ ① │      │ ③ │      │ ⑥ │      │ ⑦ │      │ ⑧ │
   │斥候│      │羅針│      │証立│      │奏上│      │歴記│
   └────┘     └────┘     └────┘     └────┘     └────┘
   Sentinel   Compass    Witness    Herald     Chronicle
     │          │          │          │          │
     ▼          ▼          ▼          ▼          ▼
   GitHub     ripgrep/   Docker     CVSS/GHSA  Day0..Day90
   Search     Semgrep    Guard      CWE map    ACCS guard
```

| # | 名称 | 役割 | Phase 1 |
|---|---|---|---|
| ① | Sentinel (斥候) | 8 シグナル評価で OSS ターゲット選定 | ✅ |
| ② | Reader (読眼) | コード読解 4 段階 | ⏸ Phase 2 |
| ③ | Compass (羅針) | 危険関数 grep + Semgrep | ✅ |
| ④ | Lineage (継) | variant analysis | ⏸ Phase 2 |
| ⑤ | Probe (試火) | ファジング | ⏸ Phase 3 |
| ⑥ | Witness (証立) | Docker 内 PoC 再現 (ガード組込) | ✅ |
| ⑦ | Herald (奏上) | GHSA / メール生成 (Phase 1 は GHSA 限定) | ✅ |
| ⑧ | Chronicle (歴記) | 90 日タイムライン + ACCS ガード | ✅ |

## データフロー

```
Sentinel ──Target──> Compass ──Finding──> Witness ──PoCArtifact──> Herald ──Submission──> Chronicle ──Disclosure──> (公開 or 修正待機)
                                              │                                                                          │
                                              │                                                                          │
                                              ▼                                                                          ▼
                                          guard.py                                                              ACCSViolationError
                                  (本番アクセス完全ブロック)                                                  (通知前公開を機械的に拒否)
```

- 全モジュールは `models.py` の Pydantic v2 データクラスでデータを受け渡す
- 各 CLI コマンドは独立して JSON 出力対応 (`--json`)、パイプ可能

## モジュール構造

```
src/suzaku/
├── cli.py                # メイン Typer エントリポイント
├── config.py             # pydantic-settings
├── models.py             # Target / Finding / PoCArtifact / Submission / Disclosure
├── logging.py            # structlog + SHA-256 ハッシュチェイン
├── sentinel/             # ① 斥候
│   ├── cli.py
│   ├── scoring.py        # RepoSignals + 8 評価関数
│   ├── search.py         # GitHub Search ラッパー (rate-limit 対応)
│   └── signals.yaml      # weights + keywords + thresholds
├── compass/              # ③ 羅針
│   ├── cli.py
│   ├── rules.py          # YAML ルールローダ
│   ├── grep_runner.py    # ripgrep --pcre2 ラッパー
│   ├── semgrep_runner.py # graceful fallback
│   └── rules/
│       ├── danger_funcs/{php,python,nodejs,java,go,cpp}.yaml
│       └── patterns/{jwt,zip_slip,proto_pollution,ssrf}.yaml
├── witness/              # ⑥ 証立
│   ├── cli.py
│   ├── guard.py          # ⚠️ 本番アクセス検知ガード (最重要)
│   ├── reproducer.py     # docker compose ラッパー
│   ├── evidence.py       # SHA-256 チェイン
│   └── templates/poc/    # Jinja: Dockerfile / docker-compose / steps.md
├── herald/               # ⑦ 奏上
│   ├── cli.py
│   ├── cvss.py           # CVSS v3.1 Base Score
│   ├── checklist.py      # 5 点セット欠落検査
│   ├── ghsa.py           # Advisory -> GHSA Markdown (legacy alias)
│   ├── email_tmpl.py     # 報告メール + 禁止語ガード
│   ├── routes.py         # Phase 2-D: 8 ルートディスパッチャ
│   └── data/
│       ├── cwe.json
│       ├── routes.yaml   # Phase 2-D: ルートメタ
│       └── templates/    # ghsa / email / mitre_cna_lr / huntr /
│                         # jpcert / wordfence / patchstack /
│                         # hackerone / bugcrowd
└── chronicle/            # ⑧ 歴記
    ├── cli.py
    ├── timeline.py       # Day 0..90 マイルストーン
    └── escalation.py     # アラート判定 + ACCSViolationError
```

## 安全機構の二重防御

### Witness Guard (`witness/guard.py`)

- **許可ホスト**: literal (`localhost` / `127.0.0.1` / `0.0.0.0` / `::1`)、サフィックス (`.test` / `.local` / `.localhost` / `.invalid`)、IPv4 RFC1918、IPv6 ULA / LL / IPv4-mapped
- **IP 表記バイパス対策**: 8 進 / 16 進 / decimal / short-form を全て正規化
  - `0177.0.0.1`, `2130706433`, `0x7f000001`, `127.1` を全て 127.0.0.1 に
- **DNS rebinding 対策**: ホスト名がホワイトリスト・サフィックスに該当しない限り名前解決結果に関わらず拒否
- 違反時は `ProductionAccessError` (exit 4)

### ACCS Guard (`chronicle/escalation.py`)

- **通知前公開**: Day 0 経過前の `chronicle publish` を `ACCSViolationError` で拒否
- **Day 90 未満公開**: 修正リリース無し + ベンダ未拒否なら `ACCSViolationError`
- **修正後 30 日待機**: `fixed_released_at` 指定時は +30 日経過 (`fix_grace_days`) を必須化
- 違反時は exit 5

### Herald 文面ガード (`herald/email_tmpl.py`)

- 報告メール生成結果に脅迫的表現 (`pay first`, `ransom`, `last warning` 等 12 種) が混入していれば `ExtortionLanguageError` で出力阻止
- 朱雀ナレッジに記載の倫理ガイドラインを機械的に強制

## 証跡チェイン

- `logging.py`: 全実行ログを SHA-256 でチェインし append-only JSONL に保存。`verify_chain()` で改ざん検知。
- `witness/evidence.py`: PoC ファイル群を `evidence.lock` に SHA-256 で記録。`prev_hash` チェイン + record ごとの `aggregate` で二重チェック。

## テスト戦略

- **TDD**: テスト → 実装 → リファクタ
- カバレッジ 80% 以上 (現状 86%)
- pytest + pytest-mock + respx (HTTP モック)
- 危険関数ルールは `tests/fixtures/vulnerable_repo/` で意図的ヒットを検証
- Docker 連携は integration マーカで分離
- mypy strict + ruff (E/F/W/I/B/UP/N/SIM/RUF)

## CLI Exit Code 規約

| Code | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 一般失敗 (検証失敗・欠落) |
| 2 | 引数誤り (CVSS ベクタ等) |
| 3 | 外部依存欠落 (ripgrep) |
| **4** | **`ProductionAccessError`** (Witness Guard 違反) |
| **5** | **`ACCSViolationError`** (Chronicle 違反) |

## 拡張ポイント

- **新ルール追加**: `compass/rules/` 配下に YAML を置くだけ
- **シグナル重み変更**: `sentinel/signals.yaml` を編集
- **CWE 追加**: `herald/data/cwe.json` に追記
- **テンプレ調整**: `herald/data/templates/*.j2` / `witness/templates/poc/*.j2`
- **新エクスポート先**: Phase 2 で Reader / Lineage / Probe / 追加 Herald ルート

## 依存関係 (実行時)

| 必須 | 任意 |
|---|---|
| Python 3.11+ | Semgrep (無くても grep-only) |
| ripgrep 14+ | Notion API (Phase 2) |
| Docker + compose v2 | 1Password CLI (`op`) |
