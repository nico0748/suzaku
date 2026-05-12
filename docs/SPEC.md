# Suzaku — Claude Code 向け実装プロンプト (Phase 1 MVP)

> このファイルをそのまま Claude Code (`claude` コマンド) に貼り付けてください。
> 空ディレクトリで起動するか、`suzaku/` を作って `cd suzaku && claude` から開始するのが推奨です。

---

## あなたの役割

あなたは **Suzaku** という個人セキュリティリサーチ支援システムの初期実装を担当する Claude Code エージェントです。Phase 1 MVP のスコープで、Python 製の CLI 群を TDD でゼロから構築してください。

Suzaku は四神の一柱「朱雀」に由来します。朱雀は「広い空から異変を見つけ出し、災厄を告げる存在」であり、本システムは OSS に潜在する脆弱性を調査・分析し、CVE / JVNDB への報告につなげることを使命とします。**「まだ知られていない脆弱性を発見し、社会へ共有する」** — この役割を朱雀の姿に重ねて命名されています。

ブランドカラー: 朱 (`#B43E3E` / 濃赤 `#8C1F1F`)。CLI 出力もこれに合わせてください。

---

## 絶対遵守の原則 (Hard Constraints)

以下は実装の前提であり、妥協してはいけません。各原則は対応するテストで検証します。

1. **本番アクセス禁止**: 全ての検証は Docker でローカル再現する。本番ドメイン宛のリクエスト送信は CLI レベルでブロックし、警告ログを残す。ホワイトリスト方式 (`localhost`, `127.0.0.1`, `0.0.0.0`, `*.test`, `*.local`, RFC1918 IP のみ許可)。
2. **ACCS事件の3手順遵守**: 「通知 → 修正期間設定 → 公表」を逸脱する操作は禁止。通知前公開・24時間最後通牒・武器化PoCの publicな配布を UI/CLI でブロック。
3. **武器化エクスプロイト自動公開禁止**: PoC は「検証可能なレベル」までに留める。完全エクスプロイトを Herald から外部送信する経路を作らない。
4. **シークレットの直書き禁止**: PGP鍵・APIトークン・パスワードはコードに埋め込まず、環境変数または `1password-cli` (`op read ...`) 経由で取得。
5. **再現可能性**: 全ての PoC は Dockerfile / docker-compose.yml で完結する。「動かしたPC環境に依存する手順」を残さない。
6. **証跡の改ざん検知**: 全実行ログに SHA-256 ハッシュを付与し、append-only で保存。
7. **過剰実装の禁止**: Phase 1 MVP に明記されていない機能は実装しない (YAGNI)。

---

## システム全体像 (参考: 8 サブシステム)

Phase 2 以降を含めると 8 サブシステムですが、**Phase 1 では下表の 5 つのみ実装** します。

| # | 名称 | 役割 | Phase 1 |
|---|---|---|---|
| ① | Sentinel (斥候) | OSS ターゲット選定 (8シグナル評価) | ✅ 実装 |
| ② | Reader (読眼) | コード読解 (4段階) | ⏸ Phase 2 |
| ③ | Compass (羅針) | 脆弱性検出 (危険関数grep + Semgrep) | ✅ 実装 |
| ④ | Lineage (継) | variant analysis | ⏸ Phase 2 |
| ⑤ | Probe (試火) | ファジング | ⏸ Phase 3 |
| ⑥ | Witness (証立) | PoC 再現 (Docker) | ✅ 実装 |
| ⑦ | Herald (奏上) | CVE 申請テンプレ (Phase 1 は GHSA のみ) | ✅ 実装 (GHSA限定) |
| ⑧ | Chronicle (歴記) | Disclosure 90日管理 | ✅ 実装 |

---

## 技術スタック

| 領域 | 採用技術 | 理由 |
|---|---|---|
| 言語 | **Python 3.11+** | OSSセキュリティツール群との親和性 |
| CLI | **Typer** | 型ヒントベース・補完が効く |
| データモデル | **Pydantic v2** | バリデーション + JSON 5.1 互換 |
| 静的解析 | **Semgrep** (CLI 経由) | 軽量・YAML ルール |
| 高速 grep | **ripgrep** (`rg`) | 速い |
| Notion 連携 | **notion-client** (公式) | 既存ナレッジDB の SSOT |
| GitHub 連携 | **PyGithub** + REST API (Code Search) | Sentinel/Herald |
| HTTP クライアント | **httpx** | 非同期対応 |
| テスト | **pytest** + **pytest-mock** + **respx** | HTTP モック |
| Lint/Format | **ruff** | 速い |
| 型チェック | **mypy** (strict) | 個人運用でも品質確保 |
| ロギング | **structlog** | 構造化ログ・改ざん検知に必要 |
| 設定管理 | **pydantic-settings** + `.env` | 環境変数前提 |
| Docker | **docker-compose** v2 | PoC 再現の標準 |

**禁止**: Django/FastAPI/Flask 等のWebフレームワーク (Phase 1 は不要)、ORM、Celery、Redis、データベース (SQLite 以外)。

---

## プロジェクト構造

以下の構造で作成してください。`tree` 出力例:

```
suzaku/
├── README.md
├── CLAUDE.md                    # Claude Code 用永続コンテキスト
├── LEGAL.md                     # 法的免責・遵守事項
├── pyproject.toml               # uv または poetry 想定
├── .env.example
├── .gitignore                   # secrets, .venv, __pycache__, *.db
├── docker-compose.yml           # PoC 再現用のサンプル
├── Makefile                     # よく使うコマンドショートカット
├── src/
│   └── suzaku/
│       ├── __init__.py          # __version__ = "0.1.0"
│       ├── __main__.py          # `python -m suzaku`
│       ├── cli.py               # Typer エントリポイント
│       ├── config.py            # pydantic-settings
│       ├── models.py            # Target / Finding / PoC / Submission / Disclosure
│       ├── logging.py           # structlog 設定 + ハッシュチェイン
│       ├── notion_client.py     # ラッパー
│       ├── github_client.py     # ラッパー
│       ├── sentinel/
│       │   ├── __init__.py
│       │   ├── cli.py           # `suzaku sentinel` サブコマンド
│       │   ├── scoring.py       # 8 シグナル評価ロジック
│       │   ├── search.py        # GitHub Code Search クエリビルダー
│       │   └── signals.yaml     # シグナル定義 (重み付け編集可能)
│       ├── compass/
│       │   ├── __init__.py
│       │   ├── cli.py
│       │   ├── grep_runner.py   # ripgrep ラッパー
│       │   ├── semgrep_runner.py
│       │   └── rules/
│       │       ├── danger_funcs/
│       │       │   ├── php.yaml
│       │       │   ├── python.yaml
│       │       │   ├── nodejs.yaml
│       │       │   ├── java.yaml
│       │       │   ├── go.yaml
│       │       │   └── cpp.yaml
│       │       └── patterns/
│       │           ├── jwt.yaml
│       │           ├── zip_slip.yaml
│       │           ├── proto_pollution.yaml
│       │           └── ssrf.yaml
│       ├── witness/
│       │   ├── __init__.py
│       │   ├── cli.py
│       │   ├── reproducer.py    # Docker 起動 / 停止
│       │   ├── guard.py         # ⚠️ 本番アクセス検知ガード (最重要)
│       │   ├── evidence.py      # 証跡保管 (Dockerfile, steps.md, ログ, ハッシュ)
│       │   └── templates/
│       │       └── poc/
│       │           ├── Dockerfile.j2
│       │           ├── docker-compose.yml.j2
│       │           └── steps.md.j2
│       ├── herald/
│       │   ├── __init__.py
│       │   ├── cli.py
│       │   ├── cvss.py          # CVSS v3.1 計算機
│       │   ├── checklist.py     # 5 点セット
│       │   ├── ghsa.py          # GHSA Markdown 生成
│       │   ├── email_tmpl.py    # 報告メール文面
│       │   └── data/
│       │       ├── cwe.json     # CWE 一覧 (CWE-79, CWE-89, ...)
│       │       └── templates/
│       │           ├── ghsa.md.j2
│       │           └── email.txt.j2
│       └── chronicle/
│           ├── __init__.py
│           ├── cli.py
│           ├── timeline.py      # Day0 から Day90 の生成
│           ├── escalation.py    # アラート判定
│           ├── calendar.py      # Google Calendar 連携 (任意)
│           └── notion_sync.py   # Disclosure DB 同期
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_witness_guard.py    # 🔴 最優先
│   │   ├── test_herald_cvss.py
│   │   ├── test_herald_checklist.py
│   │   ├── test_sentinel_scoring.py
│   │   ├── test_compass_grep.py
│   │   ├── test_chronicle_timeline.py
│   │   ├── test_chronicle_escalation.py
│   │   └── test_models.py
│   ├── integration/
│   │   ├── test_witness_reproduce.py
│   │   └── test_herald_ghsa.py
│   └── fixtures/
│       ├── vulnerable_repo/         # 意図的に脆弱なミニリポ
│       └── sample_finding.json
└── docs/
    ├── ARCHITECTURE.md
    ├── USAGE.md
    └── ROADMAP.md               # Phase 2/3 予定
```

---

## 共通データモデル (Pydantic v2)

`src/suzaku/models.py` に以下を定義してください。

```python
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingState(str, Enum):
    NEW = "new"
    VALIDATING = "validating"
    POC_BUILDING = "poc_building"
    READY_TO_SUBMIT = "ready_to_submit"
    SUBMITTED = "submitted"
    RESERVED = "reserved"
    PUBLISHED = "published"
    REJECTED = "rejected"
    DISPUTED = "disputed"

class Route(str, Enum):
    GHSA = "ghsa"
    MITRE = "mitre"
    HUNTR = "huntr"
    JPCERT = "jpcert"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    WORDFENCE = "wordfence"
    PATCHSTACK = "patchstack"

class Target(BaseModel):
    """Sentinel が評価する対象 OSS"""
    name: str
    url: HttpUrl
    language: str
    star_count: int
    last_commit_at: datetime
    score: float  # 0.0 - 10.0 (8シグナル合計)
    signals: dict[str, float]  # シグナル別スコア
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)

class Finding(BaseModel):
    """Compass / Reader が検出した脆弱性候補"""
    id: str
    target_url: HttpUrl
    category: str  # JWT / SSRF / ZipSlip / ProtoPollution / ...
    severity: Severity
    cwe: Optional[str] = None
    file_path: str
    line_number: int
    snippet: str
    state: FindingState = FindingState.NEW
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

class PoCArtifact(BaseModel):
    """Witness が記録する PoC エビデンス"""
    finding_id: str
    dockerfile_path: str
    compose_path: str
    steps_md_path: str
    affected_version: str  # semver range
    fixed_version: Optional[str] = None
    commit_sha: str  # 検証時の対象 SHA
    evidence_hash: str  # 全証跡の SHA-256

class Submission(BaseModel):
    """Herald が生成する申請データ"""
    finding_id: str
    route: Route
    cvss_vector: str  # "CVSS:3.1/AV:N/..."
    cvss_score: float
    cwe: str
    affected_versions: str
    fixed_version: Optional[str] = None
    reference_urls: list[HttpUrl]
    poc_artifact_id: str
    submitted_at: Optional[datetime] = None
    cve_id: Optional[str] = None  # 採番後

class Disclosure(BaseModel):
    """Chronicle が管理する開示タイムライン"""
    submission_id: str
    day_0: datetime  # 初回連絡日
    day_3_done: bool = False
    day_14_done: bool = False
    day_30_done: bool = False
    day_60_done: bool = False
    day_90_done: bool = False
    publication_planned_at: Optional[datetime] = None
    vendor_state: str = "no_response"  # no_response / acknowledged / fixing / fixed / rejected
```

---

## 各モジュール詳細仕様

### ① Sentinel (斥候) — OSS ターゲット選定

**目的**: 8 シグナル評価で有望な OSS を抽出する。

**CLI**:
```bash
suzaku sentinel scan --language python --min-stars 500 --pushed-after 2025-01-01 --top 20
suzaku sentinel show <target-url>
suzaku sentinel sync-notion  # Notion DB へ書き戻し
```

**8シグナル評価 (各 0.0-1.0 を加重平均)**:
1. **メンテ非活発度** (`maintenance_inactivity`): 直近 Issue 応答日数 > 30日 → 高スコア
2. **認証層の薄さ** (`thin_auth_layer`): `routes` 数に対する認証 middleware 数の比率
3. **複雑機能の急追加** (`recent_complex_features`): 直近30日に importer/uploader/SSO 系コミット
4. **新リリース直後** (`fresh_release`): 直近7日内のリリース
5. **複数フロント/バックエンド構成** (`multi_tier`): docker-compose のサービス数
6. **依存ライブラリ多** (`many_deps`): 50超で 1.0
7. **独自実装の暗号/パーサ** (`roll_your_own`): `crypto`, `parse`, `tokenizer` 等のディレクトリの自前実装比率
8. **金銭処理** (`monetary`): `payment`, `subscription`, `coupon`, `billing` 等のキーワード

各シグナルの重みは `signals.yaml` で変更可能にしてください:

```yaml
# src/suzaku/sentinel/signals.yaml
weights:
  maintenance_inactivity: 1.5
  thin_auth_layer: 1.5
  recent_complex_features: 1.2
  fresh_release: 1.0
  multi_tier: 1.0
  many_deps: 0.8
  roll_your_own: 1.5
  monetary: 1.2

# 検出のヒント
keywords:
  monetary: ["payment", "subscription", "coupon", "billing", "stripe", "paypal"]
  complex_features: ["upload", "import", "export", "sso", "oauth", "saml", "i18n"]
  roll_your_own: ["crypto", "jwt", "parser", "tokenizer", "encoder"]
```

**受け入れ基準**:
- 100 件のリポジトリを 5 分以内に評価できる
- `signals.yaml` の重みを変えると順位が変わることをテストで確認
- GitHub レートリミット (5000/h) を尊重 (実装側で待機)
- 結果を JSON / Notion に書き出せる

---

### ③ Compass (羅針) — 脆弱性検出

**目的**: 危険関数 grep と Semgrep ルールで初手の検出を行う。

**CLI**:
```bash
suzaku compass scan <repo-path> --rule danger_funcs/php
suzaku compass scan <repo-path> --rule patterns/jwt
suzaku compass scan <repo-path> --all  # 全ルール
suzaku compass list-rules
```

**Phase 1 で必須のルール**:

`rules/danger_funcs/*.yaml`:
- **PHP**: `eval`, `assert (string)`, `unserialize`, `include $_GET`, `extract($_POST)`, `system`, `exec`, `shell_exec`, `passthru`, `preg_replace /e`
- **Python**: `pickle.loads`, `cPickle.loads`, `yaml.load` (no SafeLoader), `subprocess.*(shell=True)`, `os.system`, `eval`, `exec`, `compile`, `marshal.loads`, `xml.etree` (no XXE対策)
- **Node.js**: `eval`, `new Function`, `vm.runIn*Context`, `_.merge`, `_.mergeWith`, `Object.assign(target, untrusted)`, `child_process.exec` (文字列連結), `require(userInput)`
- **Java**: `ObjectInputStream.readObject`, `Context.lookup` (JNDI), `Runtime.exec`, `DocumentBuilder` (no XXE対策)
- **Go**: `exec.Command("sh", "-c", userInput)`, `filepath.Join` の `../` 未検査, `template.HTML(userInput)`, `encoding/gob.Decode`
- **C/C++**: `strcpy`, `strcat`, `sprintf`, `memcpy` (attacker-controlled len), `gets`, `printf(userInput)`

`rules/patterns/*.yaml`:
- **jwt.yaml**: `alg:none` 受理 / `RS256→HS256` confusion / 弱秘密 / `jwk`, `jku`, `kid`, `x5u` ヘッダ
- **zip_slip.yaml**: アーカイブ展開で `../` 未検証 (zip/tar/jar/war/cpio/apk/rar/7z)
- **proto_pollution.yaml**: deep merge / lodash `defaultsDeep` / `__proto__` キー受理
- **ssrf.yaml**: `169.254.169.254`, `metadata.google.internal`, `gopher://`, `0177.0.0.1` 等のIP表記バイパス

**ルール YAML フォーマット** (例: `zip_slip.yaml`):

```yaml
id: zip_slip
name: Zip Slip (Archive Extraction Path Traversal)
description: |
  アーカイブ内のファイル名に ../ を含めて展開した場合、
  展開先ディレクトリ外にファイルが書き出される脆弱性。
cwe: CWE-22
severity: high
patterns:
  - language: python
    grep: 'zipfile\.extract\(|tarfile\.extract'
    must_not_contain: 'realpath|abspath'  # 同ファイル内で正規化が無ければ疑陽性
  - language: javascript
    grep: '\.extract\(|extractAllTo|adm-zip'
    must_not_contain: 'path\.normalize|path\.resolve'
references:
  - https://snyk.io/blog/zip-slip-vulnerability/
```

**受け入れ基準**:
- ripgrep が見つからなければエラーメッセージで案内
- Semgrep が見つからなければ grep-only モードで動作
- 30 秒以内に初手の grep 結果を返す
- 検出結果は `Finding` 型で JSON 出力
- `tests/fixtures/vulnerable_repo/` の各ルールで意図的なヒットが取れることをテスト

---

### ⑥ Witness (証立) — PoC 再現 (最重要)

**目的**: 本番アクセスを完全に防ぎ、Docker 内でのみ再現する。

**CLI**:
```bash
suzaku witness init <finding-id>            # PoC テンプレを ./pocs/<id>/ に展開
suzaku witness reproduce <finding-id>       # docker-compose up + steps 実行
suzaku witness record <finding-id> --evidence-dir ./evidence/
suzaku witness verify <finding-id>          # ハッシュ検証
```

**guard.py の仕様 (本番アクセス検知ガード)**:

```python
# 概要: 全 HTTP リクエスト / DNS 解決を傍受し、許可ホストのみ通す
ALLOWED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}
ALLOWED_SUFFIXES = (".test", ".local", ".localhost", ".invalid")
ALLOWED_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

def is_allowed(host: str) -> bool:
    """許可ホストかどうかを判定する。
    True: 通す / False: SecurityError を投げる
    """
    ...

class ProductionAccessError(Exception):
    """本番アクセスの試みを検知。CLI は即終了し、警告ログを残す。"""
    pass
```

**受け入れ基準** (`tests/unit/test_witness_guard.py` で全てカバー):
- `localhost`, `127.0.0.1`, `*.test`, `192.168.x.x` は通る
- `github.com`, `8.8.8.8`, `example.com` はブロックされる
- IP 表記バイパス (`0177.0.0.1` = 127.0.0.1) は許可。`2130706433` (decimal) も許可
- IPv6 `[::ffff:7f00:0001]` は許可
- DNS rebinding 対策: ホスト名解決後の IP が ALLOWED_CIDRS 外なら拒否

**証跡 (evidence.py)**:
- 各実行で以下を保存:
  - `Dockerfile`, `docker-compose.yml`, `steps.md` (PoC手順)
  - 実行ログ (`stdout.log`, `stderr.log`)
  - HTTP トレース (httpx の hook)
  - 実行日時、対象 commit SHA、Docker image SHA
- 全ファイルの SHA-256 を `evidence.lock` に append-only で記録
- `suzaku witness verify` で改ざん検知

---

### ⑦ Herald (奏上) — CVE 申請 (Phase 1 は GHSA のみ)

**目的**: GHSA Markdown と CVSS ベクタを生成し、5 点セットを欠落なく管理する。

**CLI**:
```bash
suzaku herald checklist <finding-id>        # 5点セットの欠落チェック
suzaku herald cvss --interactive            # CVSS v3.1 ベクタを対話式で生成
suzaku herald ghsa <finding-id> > advisory.md  # GHSA Markdown 出力
suzaku herald email <finding-id> > report.eml  # 報告メール文面
```

**5 点セット** (`checklist.py`):
1. 製品名・ベンダ・**バージョン範囲** (semver `>=1.0.0, <2.3.5`)
2. **CWE** (CWE-79=XSS, CWE-89=SQLi, CWE-22=PathTraversal, CWE-78=OSCmd, CWE-352=CSRF, CWE-918=SSRF, CWE-502=Deserialization, CWE-1321=ProtoPollution)
3. **CVSS v3.1** ベクタ + スコア
4. **PoC・再現手順** (Witness の `steps.md` を参照)
5. **参考 URL** (修正コミット、Issue、ブログ等)

**CVSS v3.1 計算** (`cvss.py`):
```
ベクタ例: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- AV: Attack Vector       (N/A/L/P)
- AC: Attack Complexity   (L/H)
- PR: Privileges Required (N/L/H)
- UI: User Interaction    (N/R)
- S:  Scope               (U/C)
- C/I/A: Conf/Integ/Avail (N/L/H)
```

`first.org/cvss/calculator/3.1` の計算式に厳密準拠してください (Base score のみで OK)。

**GHSA Markdown テンプレ** (`herald/data/templates/ghsa.md.j2`):
```jinja
## Summary
{{ summary }}

## Affected Versions
- Affected: {{ affected_versions }}
- Fixed: {{ fixed_version | default("(pending)") }}
- Tested on: {{ tested_version }} (commit `{{ commit_sha[:7] }}`)

## Impact
- CVSS 3.1: **{{ cvss_score }} / {{ severity_label }}**
- Vector: `{{ cvss_vector }}`
- CWE: [{{ cwe }}](https://cwe.mitre.org/data/definitions/{{ cwe_number }}.html)

{{ impact_description }}

## Reproduction Steps
{% for step in steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Suggested Mitigation
{{ mitigation }}

## References
{% for url in references %}
- {{ url }}
{% endfor %}
```

**報告メール文面** (`herald/data/templates/email.txt.j2`):
朱雀ナレッジに記載の標準構成 (Subject / Summary / Affected / Impact / Reproduction / Mitigation / Disclosure Plan / Contact) で生成。**「危険な脆弱性、詳細は報酬支払後」のような脅迫的文面は絶対に生成しない**。

**受け入れ基準**:
- 5 点セットの 1 つでも欠けていたら `herald ghsa` がエラーで止まる
- CVSS ベクタの計算結果が公式 calculator と一致する (テストで主要パターンを検証)
- ベクタ → スコア・ラベル (Critical/High/Medium/Low) のマッピングが正確

---

### ⑧ Chronicle (歴記) — Disclosure 90日管理

**目的**: 90日ルールに沿ったタイムラインを生成・追跡する。

**CLI**:
```bash
suzaku chronicle init <submission-id>        # Day 0 を今日に設定
suzaku chronicle status <submission-id>      # 現在の状態
suzaku chronicle list                        # 全 disclosure
suzaku chronicle check                       # アラート判定 (cron 用)
```

**マイルストーン** (`timeline.py`):
```
Day 0      初回送信 (security@, SECURITY.md 記載チャネル, GHSA PVR)
Day 3-5    リマインド1回目
Day 14     別チャネルで連絡 (GitHub Issue 等)
Day 30     third reminder + 「90日後に公開予定」を明記
Day 60     CNA-LR エスカレーション検討
Day 90     修正なくても公開 (disclosure)
```

**エスカレーション判定** (`escalation.py`):
- Day 3 経過 + ベンダ無応答 → アラート (リマインド送信用テンプレ生成)
- Day 14 経過 + 無応答 → 別チャネル提案 (GitHub Issue, Twitter DM, distros@vs.openwall.org)
- Day 30 経過 + 無応答 → 公開予定明記の文面生成
- Day 60 経過 + 無応答 → CNA-LR ルート (MITRE 直接) を推奨
- Day 90 達成 → 公開可能ステータスへ

**ACCS事件ガード**:
- Day 0 経過前 (まだベンダに連絡していない) に「公開」アクションを取ろうとすると拒否
- `chronicle publish` 実行時に必ず「修正リリース後+30日が経過しているか」を確認

**受け入れ基準**:
- `init` で Day 0 から Day 90 の datetime が生成される
- `check` 実行時、現在日が Day 3/14/30/60/90 を超えていれば該当アラートを返す
- Notion DB へマイルストーンを同期できる (任意機能・スキップ可)
- 通知前公開を試みた際 `ACCSViolationError` を投げる

---

## CLAUDE.md の内容 (プロジェクトに置く永続コンテキスト)

最初に `CLAUDE.md` を以下の内容で作成してください:

```markdown
# Suzaku Project — Claude Code Context

## Mission
OSS脆弱性発見〜CVE取得までを支援する個人向けワークフローシステム。
朱雀のメタファに沿い、「広い空から異変を見つけ、社会に共有する」役割を担う。

## Hard Rules (絶対に逸脱しない)
1. 本番アクセス禁止。Docker でのローカル再現のみ。
2. ACCS事件の3手順 (通知 → 修正期間 → 公表) を守る。
3. 武器化エクスプロイトを Herald から外部送信しない。
4. シークレットは環境変数 / 1Password CLI 経由のみ。
5. 全実行ログに SHA-256 を付与し append-only で保存。

## Tech Stack
Python 3.11+, Typer, Pydantic v2, Semgrep, ripgrep, Docker.
禁止: Webフレームワーク, ORM, Celery, Redis.

## Architecture
5 modules in Phase 1: Sentinel, Compass, Witness, Herald, Chronicle.
各モジュールは独立しつつ models.py 経由でデータ受け渡し。

## Coding Conventions
- ruff (formatter + linter)
- mypy strict
- pytest, テストカバレッジ 80%+
- 関数は単一責務、副作用がある関数は名前で明示
- 全コメント・docstring は日本語可
- エラーメッセージは英語 (技術用語の翻訳ブレ防止)
```

---

## 実装順序 (TDD)

**重要**: テストファースト。各ステップで「テスト → 実装 → リファクタ」のサイクルを必ず守る。

### Step 0: プロジェクト骨格 (30 分)
- `pyproject.toml`, `.gitignore`, `.env.example`, `Makefile`, `README.md`, `CLAUDE.md`, `LEGAL.md`
- ディレクトリ構造を作成 (空の `__init__.py` を含む)
- `ruff`, `mypy`, `pytest` を `pyproject.toml` に設定
- `make test`, `make lint`, `make typecheck` が動くこと

### Step 1: 共通モデル + ロギング (30 分)
- `src/suzaku/models.py` (上記の Pydantic モデル)
- `src/suzaku/logging.py` (structlog + ハッシュチェイン)
- `src/suzaku/config.py` (pydantic-settings)
- `tests/unit/test_models.py`

### Step 2: 🔴 Witness Guard (最優先・1〜2時間)
**Suzaku の最も重要な安全機構。ここを先に堅牢にする。**
- `tests/unit/test_witness_guard.py` を先に書く
- 上記の受け入れ基準を全網羅
- `src/suzaku/witness/guard.py` を実装
- IPv4/IPv6 のあらゆるバイパス表記をテストする
- DNS rebinding 対策

### Step 3: Witness Reproducer + Evidence (1〜2時間)
- `tests/integration/test_witness_reproduce.py`
- `tests/unit/test_witness_evidence.py` (ハッシュチェイン)
- `src/suzaku/witness/reproducer.py` (docker-compose ラッパー)
- `src/suzaku/witness/evidence.py`
- `templates/poc/` の Jinja テンプレート

### Step 4: Herald CVSS + Checklist (1〜2時間)
- `tests/unit/test_herald_cvss.py` (公式計算機との一致を主要 10 パターンで検証)
- `tests/unit/test_herald_checklist.py`
- `src/suzaku/herald/cvss.py`
- `src/suzaku/herald/checklist.py`
- `cwe.json` データを `data/` に格納

### Step 5: Herald GHSA + Email (1時間)
- `tests/integration/test_herald_ghsa.py`
- `src/suzaku/herald/ghsa.py`
- `src/suzaku/herald/email_tmpl.py`
- Jinja2 テンプレート

### Step 6: Compass Rules + Runner (2〜3時間)
- `tests/unit/test_compass_grep.py` を `tests/fixtures/vulnerable_repo/` で検証
- 各言語の `danger_funcs/*.yaml` 完成
- 4 つの `patterns/*.yaml` 完成
- `src/suzaku/compass/grep_runner.py` (ripgrep ラッパー)
- `src/suzaku/compass/semgrep_runner.py`

### Step 7: Sentinel Scoring (1〜2時間)
- `tests/unit/test_sentinel_scoring.py`
- `src/suzaku/sentinel/scoring.py`
- `src/suzaku/sentinel/search.py` (GitHub API レートリミット対応)
- `signals.yaml`

### Step 8: Chronicle Timeline + Escalation (1〜2時間)
- `tests/unit/test_chronicle_timeline.py`
- `tests/unit/test_chronicle_escalation.py`
- `src/suzaku/chronicle/timeline.py`
- `src/suzaku/chronicle/escalation.py`
- ACCSViolationError のテスト

### Step 9: CLI 統合 (1時間)
- `src/suzaku/cli.py` で各モジュールの subcommand を統合
- `python -m suzaku --help` で全体ヘルプが見える
- 朱雀ブランドカラーを `rich` で適用

### Step 10: ドキュメント (30 分)
- `README.md` (使い方の最小例)
- `docs/USAGE.md` (各 CLI の詳細)
- `docs/ARCHITECTURE.md` (図 + 8モジュール構想)
- `docs/ROADMAP.md` (Phase 2/3 の計画)

---

## Phase 1 完了の判定基準 (Definition of Done)

以下のシナリオが通れば Phase 1 完了:

### シナリオ E2E-1: WordPressプラグインでCVEを取りに行く
```bash
# 1. Sentinel で候補を出す
suzaku sentinel scan --language php --topic wordpress-plugin --top 20

# 2. ローカルクローン
git clone https://github.com/example/vulnerable-plugin /tmp/target

# 3. Compass で grep
suzaku compass scan /tmp/target --rule patterns/csrf
# ヒット → Finding が生成

# 4. Witness で再現環境
suzaku witness init <finding-id>
suzaku witness reproduce <finding-id>
# ガードが本番アクセスを完全にブロック

# 5. Herald で GHSA Markdown 生成
suzaku herald cvss --interactive
suzaku herald ghsa <finding-id> > advisory.md

# 6. Chronicle で開示タイムライン開始
suzaku chronicle init <submission-id>
suzaku chronicle status <submission-id>
# Day 0 = 今日, Day 90 = 今日+90日
```

### 品質ゲート
- [ ] `make test` がパス (カバレッジ 80%+)
- [ ] `make lint` がパス (ruff)
- [ ] `make typecheck` がパス (mypy strict)
- [ ] `test_witness_guard.py` が **すべて** パス
- [ ] CLI ヘルプが日本語で表示される
- [ ] 朱雀の朱色 (`#B43E3E`) で出力が色付けされる
- [ ] README に「Phase 1 で動くこと/動かないこと」が明記されている
- [ ] LEGAL.md に ACCS事件の3手順が記載されている

---

## 開発時に守ってほしい運用ルール

1. **最初に `CLAUDE.md` と `LEGAL.md` を作る**。これらが基準。
2. **テストファースト**。新機能を書く前にテストを書く。
3. **ガード機構を先に作る**。Witness guard が最優先。これがあれば後で誤って本番に飛ばす事故を防げる。
4. **小さく、確実に**。1 機能 1 コミット相当。各 Step 後に手で挙動を確認。
5. **質問しすぎない**。仕様で不明な点はこのドキュメントを優先、それでも不明なら合理的に推測してコメント `# ASSUMPTION:` で残す。
6. **過剰実装しない**。Phase 1 に書いていないものは作らない。`docs/ROADMAP.md` にメモして次に回す。
7. **CLI 出力は短く**。エラーメッセージは原因と対処を 2 行で。

---

## 最初にやってほしいこと

このプロンプトを受け取ったら、まず以下を実行してください:

1. このプロンプト全文を `docs/SPEC.md` に保存する
2. `CLAUDE.md` を上述の内容で作成する
3. `LEGAL.md` を以下の内容で作成する:
   ```markdown
   # Suzaku 法的免責・遵守事項

   ## ACCS事件 (2003-2005) の教訓
   東京地裁2005年3月25日判決により、通知前公開・本番テストは刑事罰の対象。
   Suzaku ユーザーは以下を必ず守ること:

   1. **通知**: ベンダ・メンテに事前通知する。
   2. **修正期間設定**: 90日を基本値とする。
   3. **公表**: 修正リリース後+30日を基本ウィンドウとする。

   ## 不正アクセス禁止法
   検査目的でも、許諾なき他人 server へのテストは違法となりうる。
   Suzaku の Witness は本番アクセスを完全にブロックする設計だが、
   ユーザー自身も操作前に対象が VDP / Safe Harbor 配下か確認すること。

   ## Safe Harbor が確認できない対象
   Suzaku は使えるが、テストは Docker 内のローカル再現に限定する。
   ```
4. `pyproject.toml` を作成 (uv 想定で OK)
5. Step 1 (共通モデル) から順に着手

完了したら最初の git commit を作って、Step 0/1 が動くことを確認してから Step 2 (Witness Guard) に進んでください。

---

## Suzaku の心得 (最後に)

> Tavis Ormandy:
> "Sometimes, hacking is just someone spending more time on something than anyone else might reasonably expect."

Suzaku は、ユーザーが「合理的に予想される以上の時間」を捧げるための翼です。
空から異変を見つけ、誠実に報告し、社会を一歩安全にする — その手段として、
コードの一行一行を丁寧に、安全に、書いてください。
