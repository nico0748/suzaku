# Suzaku Phase 2-C — Lineage (Variant Analysis) 詳細仕様

> 対象: Lineage モジュール ④ — 既知 CVE の修正パッチから類似パターンを抽出し、Sentinel 候補リポジトリ集合へ横展開検索する
> 前提: Phase 1 MVP + Phase 2-D + 2-B + 2-A1 + 2-A2 完了
> 参照: [`SPEC.md`](./SPEC.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md)

## 1. 目的

公開済み CVE 1 件には、しばしば「同じ脆弱性パターンが他の OSS にも残っている」可能性がある。Lineage はこれを機械化する:

1. NVD JSON (CVE feed) を取り込み、参照 URL から修正コミット URL を抽出
2. 修正コミット diff を取得し、**削除行 (脆弱コード) のパターン** を抽出
3. パターンを **Compass ルール (YAML)** に変換し、対象リポジトリ集合に対し横展開検索

実 API 呼び出しを避けたい場合のためにモック注入できる構成にする (Witness Guard と整合)。

## 2. 絶対遵守の原則 (Phase 1 から継承)

1. **本番アクセス禁止** — NVD / GitHub の **公開エンドポイント** は許可、ただし `httpx` レイヤで読み取り専用に限定。Witness Guard の **読み取り例外リスト** (`api.github.com`, `services.nvd.nist.gov`) は本 Phase で導入するが、ユーザ書込・状態変更を伴うエンドポイントは引き続き禁止
2. **ACCS事件の3手順** — Lineage は公開済 CVE のみを扱う (未公開脆弱性は対象外)
3. **武器化エクスプロイト自動公開禁止** — diff の追加行 (修正後) は記録するが、削除行 (脆弱コード) を **完全な PoC として保存しない**
4. **シークレットの直書き禁止** — GitHub token は環境変数経由
5. **証跡の改ざん検知** — 取込 CVE / 変換ルール / スキャン結果を SHA-256 でハッシュ管理
6. **過剰実装の禁止** — ML ベースの diff 学習・大規模 distributed crawling は範囲外

加えて Lineage 固有の禁則:

7. **公開済み CVE のみを取り込む** — `vulnStatus == "Modified" / "Analyzed" / "Public"` のみ。`"Awaiting Analysis"` 等は除外
8. **生成ルールに即座に Suzaku から自動申請しない** — Lineage の出力は「候補」であり、Compass で再検証してから Herald に渡す必要がある
9. **diff パース失敗を warning にとどめ、プロセス全体を止めない**

## 3. システム設計

### 3.1 モジュール構造

```
src/suzaku/lineage/
├── __init__.py
├── cli.py                # suzaku lineage CLI
├── nvd.py                # NVD JSON ロード + 参照 URL 抽出
├── github_patches.py     # GitHub commit diff フェッチ + 削除/追加行抽出
├── extract.py            # 削除行 -> Suzaku Compass ルール変換
├── scan.py               # 生成ルールでリポジトリスキャン (Compass GrepRunner 再利用)
├── models.py             # Pydantic: CVERecord / PatchHunk / VariantRule / VariantFinding
└── data/
    └── allowed_hosts.yaml   # NVD/GitHub 等の許可ホワイトリスト
```

### 3.2 データモデル (Pydantic v2)

```python
class CVERecord(BaseModel):
    cve_id: str                     # "CVE-2024-XXXXX"
    description: str
    cwe: list[str]                  # 1+ CWE-NNN
    cvss_score: float | None
    severity_label: str | None
    references: list[HttpUrl]
    commit_urls: list[HttpUrl]      # references から抽出
    published_at: datetime
    last_modified_at: datetime
    vuln_status: str

class PatchHunk(BaseModel):
    commit_url: HttpUrl
    file_path: str
    language: str                   # "python" / "javascript" / ... or "unknown"
    deleted_lines: list[str]
    added_lines: list[str]
    context_before: str
    context_after: str

class VariantRule(BaseModel):
    rule_id: str                    # "lineage_CVE-2024-XXXXX_001"
    derived_from_cve: str
    cwe: str
    severity: Severity
    language: str
    grep: str                       # 削除行から抽出した regex
    must_not_contain: str | None    # 追加行 (修正パターン) から抽出
    source_commit: HttpUrl
    rationale: str

class VariantFinding(BaseModel):
    rule_id: str
    derived_from_cve: str
    target_repo: str                # local path or url
    file_path: str
    line_number: int
    snippet: str
    similarity: float               # 0.0-1.0 (regex match の信頼度)
```

### 3.3 NVD JSON 取込

```python
# nvd.py

def load_nvd_feed(path: Path) -> list[CVERecord]:
    """ローカルにダウンロード済みの NVD JSON Feed をパース。"""

def load_nvd_single(path: Path) -> CVERecord:
    """単一 CVE JSON (cveform.mitre.org export 等) をパース。"""

def fetch_nvd(cve_id: str, client: httpx.Client | None = None) -> CVERecord:
    """services.nvd.nist.gov から 1 件取得。Witness Guard 経由。"""
```

参照 URL 中の `https://github.com/<owner>/<repo>/commit/<sha>` を `commit_urls` に抽出する。`vuln_status` の許可リスト外は `NVDFilterError` で除外。

### 3.4 GitHub Commit Diff

```python
# github_patches.py

def fetch_commit_diff(
    commit_url: str,
    token: str | None = None,
    client: httpx.Client | None = None,
) -> list[PatchHunk]:
    """commit URL から GitHub REST API `commits/<sha>` を取得し、files[].patch を解析する。"""
```

- `api.github.com/repos/<o>/<r>/commits/<sha>` を Witness Guard の **許可済みホスト** (本 Phase で追加) として呼ぶ
- レートリミット対応は既存 `sentinel.search.GitHubSearch` のパターンを再利用
- patch parse は標準 unified diff の最小実装 (`unidiff` 等の外部 lib に依存しない)

### 3.5 パターン抽出

```python
# extract.py

def hunks_to_rules(
    cve: CVERecord,
    hunks: list[PatchHunk],
    *,
    max_rules: int = 5,
) -> list[VariantRule]:
    """削除行から候補 regex を抽出して VariantRule を組み立てる。

    実装:
    1. 各 hunk の deleted_lines を最も短い意味単位 (関数呼び出し / 危険 API) で分割
    2. ホワイトスペース正規化 + 識別子のうち英数字 ID をワイルドカードに置換
    3. 追加行 (修正パターン) を must_not_contain に転写
    4. CVE の CWE が Suzaku の allow-list にあるもののみ採用
    """
```

ルール ID は `lineage_<CVE_ID>_<index>` 形式で、同 CVE 由来でも複数ファイル向けに複数ルールを生成しうる。

### 3.6 横展開スキャン

```python
# scan.py

def scan_with_variant_rules(
    repo_path: Path,
    rules: list[VariantRule],
) -> list[VariantFinding]:
    """既存の Compass GrepRunner を流用してスキャン。"""
```

Compass の `Rule` 型に詰め直して `GrepRunner.scan` を呼ぶ。出力は `VariantFinding` に変換。

### 3.7 Witness Guard の許可ホスト拡張

Phase 1 の Witness Guard は `localhost` / RFC1918 / `*.test` のみを許可していた。Lineage は読み取り専用の外部 API を呼ぶ必要があるため、**Witness Guard とは別系統の `read_only_egress_allowed_hosts`** を `lineage/data/allowed_hosts.yaml` で管理する:

```yaml
read_only_egress:
  - api.github.com
  - services.nvd.nist.gov
  - nvd.nist.gov
```

`lineage/nvd.py` / `lineage/github_patches.py` は **専用の `LineageEgressGuard.assert_allowed(host)` を経由** して接続する。これにより:

- Witness Reproducer (Docker 内 PoC 実行) のガードは **変更なし** (本番ホスト遮断のまま)
- Lineage の外向き API 呼出のみ、明示ホワイトリストで限定的に解禁

`LineageEgressGuard` も Witness Guard と同じく IP バイパス対策・DNS rebinding 対策を有効化する。

### 3.8 CLI

```bash
suzaku lineage ingest <nvd.json>            # NVD ファイル -> CVERecord JSON 出力
suzaku lineage ingest --cve CVE-2024-XXXXX  # 単一 CVE をオンライン取得
suzaku lineage extract <cve-record.json>    # CVE + commit diff -> VariantRule
suzaku lineage scan <repo> --rules <rules.json>  # 横展開検索
suzaku lineage demo                         # サンプル CVE で 4 stage を試運転 (オフライン)
```

### 3.9 MCP 露出 (ro モード)

| Tool | 説明 |
|---|---|
| `lineage_extract_from_nvd` | NVD JSON 1 件 → VariantRule[] (オフライン、外部接続なし) |
| `lineage_scan` | リポジトリパス + VariantRule[] → VariantFinding[] |

`lineage_ingest_online` (NVD/GitHub 接続) は **本 Phase の MCP 公開対象外**。CLI からのみ呼べる。

## 4. 受け入れ基準 (DoD)

### 4.1 機能受け入れ

- ✅ `load_nvd_single()` で NVD JSON 1 件をパースし `CVERecord` を返す
- ✅ `vuln_status` がホワイトリスト外なら `NVDFilterError`
- ✅ `references` から GitHub commit URL を抽出
- ✅ `fetch_commit_diff()` (モック化可) が `PatchHunk[]` を返す
- ✅ `hunks_to_rules()` が削除行から regex を生成し、追加行を `must_not_contain` に転写
- ✅ CWE allow-list (`cwe.json`) 外の CVE は `VariantRule` 生成をスキップ
- ✅ `scan_with_variant_rules()` が Compass の `GrepRunner` を流用して動作
- ✅ `LineageEgressGuard.assert_allowed("api.github.com")` は OK、`google.com` は拒否
- ✅ `suzaku lineage demo` で外部接続なしに変換 + スキャン flow が試せる
- ✅ MCP `lineage_extract_from_nvd` / `lineage_scan` が ro モードで列挙

### 4.2 品質ゲート

- ✅ pytest 全件パス (新規 30+ tests)
- ✅ ruff check clean
- ✅ mypy --strict clean
- ✅ カバレッジ 80% 以上を維持

### 4.3 ガードの維持

- ✅ Witness Guard (Phase 1) の挙動は変わらない (本番ホスト遮断のまま)
- ✅ `LineageEgressGuard` は独立した allow-list で、Witness 系と混ざらない
- ✅ Phase 1〜2-A2 のテスト全パス

## 5. 実装順序 (TDD)

### Step C-1: SPEC + 骨格 (30 分)
- 本 SPEC を確定
- `src/suzaku/lineage/` ディレクトリ + 空モジュール
- `lineage/data/allowed_hosts.yaml`

### Step C-2: models + egress guard (1 時間)
- Pydantic モデル定義
- `LineageEgressGuard` (allow-list は YAML)
- 単体テスト (許可/拒否 + IP バイパス + DNS rebind)

### Step C-3: nvd.py + github_patches.py (1.5 時間)
- NVD JSON パース (フィード / 単発)
- GitHub commit API → PatchHunk 抽出
- httpx + respx でモック

### Step C-4: extract.py + scan.py (1 時間)
- 削除行 → regex 変換
- 追加行 → must_not_contain 転写
- Compass GrepRunner ラップ
- CWE allow-list フィルタ

### Step C-5: CLI + MCP 統合 (45 分)
- `suzaku lineage` サブコマンド
- `lineage_extract_from_nvd` / `lineage_scan` を MCP ro tool に追加
- 統合テスト

### Step C-6: ドキュメント (15 分)
- USAGE.md に Lineage 章
- ARCHITECTURE.md に lineage/ サブモジュール
- ROADMAP.md の Lineage 項目を完了マーク

## 6. リスクと対応

| リスク | 対応 |
|---|---|
| 大量 diff パースのコスト | per-PR 最大 50 patch / per-file 最大 1000 行で打ち切り |
| 外部 API のレートリミット | 既存 Sentinel パターン (5 残量で sleep) を再利用 |
| 生成 regex の偽陽性爆発 | `must_not_contain` で抑制 + `Severity = MEDIUM` 既定 + Compass 再検証 |
| 武器化 PoC 化 | added_lines (修正) を主に記録し、deleted_lines は regex 化のみ。完全コード保存しない |
| 公開済み判定の誤り | `vuln_status` ホワイトリストで明示制御 |

## 7. Phase 2-C の範囲外

- 自動 GitHub Issue / GHSA 申請 (Compass + Herald に通すこと)
- 機械学習 (transformer) ベースのパターン抽出
- 大規模 distributed crawling
- 多言語 CVE feed (CNNVD/JVNDB) — Phase 3
- patch のセマンティクス解析 (AST diff)

## 8. 参考

- NVD JSON Feed: https://nvd.nist.gov/vuln/data-feeds
- NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
- GitHub Get Commit: https://docs.github.com/en/rest/commits/commits#get-a-commit
- Unified diff format: https://en.wikipedia.org/wiki/Diff#Unified_format
