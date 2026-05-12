# Suzaku Phase 2-A1 — Reader Core 詳細仕様

> 対象: Reader モジュール ② のコア (Ollama ベース LLM コード読解, 4 段階)
> 前提: Phase 1 MVP + Phase 2-D + Phase 2-B 完了 (`claude/vulnerability-assessment-setup-U45lW`)
> 後続: [`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md) (Phase 2-A2 / 将来)
> 参照: [`SPEC.md`](./SPEC.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md)

## 1. 目的

調査者がリポジトリを開いたとき、人手で「全体構造」「入口」「信頼境界」「攻撃面の仮説」を整理するのには時間がかかる。Reader はこれを **ローカル LLM** (Ollama 経由 `qwen2.5-coder:14b` 既定) で自動化し、Sentinel/Compass の出力を解釈可能な形にする。

Phase 2-A1 では **Reader Core** (4 段階コード読解 + プロンプト + Ollama 連携 + CLI/MCP 露出) のみを実装する。Fine-tuning は [`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md) で別途扱う。

## 2. 絶対遵守の原則 (Phase 1 から継承)

1. **本番アクセス禁止** — LLM 推論先も Witness Guard を通す
   (`localhost` / RFC1918 / `*.test` のみ。Ollama デフォルト `http://localhost:11434` は通る)
2. **クラウド LLM 不使用** — 未公開脆弱性候補コードを外部に送らない (Suzaku の精神に合わせローカル LLM 一本)
3. **武器化エクスプロイト自動公開禁止** — Reader は「仮説」を出すのみで、完全 PoC は生成しない
4. **シークレットの直書き禁止** — Ollama URL は環境変数 (`SUZAKU_OLLAMA_BASE_URL`)
5. **証跡の改ざん検知** — LLM 推論結果も `evidence.lock` に記録可能 (オプション)
6. **過剰実装の禁止** — fine-tuning / 複数プロバイダ / SSE streaming は本 Phase の範囲外

加えて Reader Core 固有の禁則:

7. **LLM 出力を Compass ルール代替にしない** — Reader は仮説、Compass は事実検出。混同しない
8. **個人情報・コミット履歴を LLM に丸投げしない** — リポジトリ内のソース・設定のみを文脈に
9. **ハルシネーション対策** — JSON Schema での出力強制 + 後段バリデーション

## 3. 設計

### 3.1 4 段階コード読解 (SPEC.md §Reader 由来)

| Stage | 入力 | 出力 (Pydantic model) | LLM call 数 |
|---|---|---|---|
| 1. **概観** | リポジトリパス | `RepoOverview` (summary / tech_stack / main_dirs / estimated_loc) | 1 |
| 2. **入口の特定** | リポ + 概観 | `list[Entrypoint]` (kind / file_path / line / description) | 1 (chunked) |
| 3. **信頼境界の追跡** | エントリポイント | `list[TrustBoundary]` (source / sink / flow_summary) | N (per entrypoint, 上限あり) |
| 4. **仮説生成** | 信頼境界 | `list[Hypothesis]` (sink / top-3 CWE / rationale) | N (per boundary, 上限あり) |

各 stage は **JSON Schema を `format` パラメータで強制** し、不正出力を `ReaderParseError` で検知する。

### 3.2 Ollama HTTP API ラッパー

```python
# reader/ollama.py

@dataclass
class OllamaClient:
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:14b"
    timeout: float = 120.0

    def __post_init__(self) -> None:
        # Witness Guard を必ず通す
        host = urlparse(self.base_url).hostname or ""
        enforce_allowed(host)
        ...

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        format: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        """POST /api/generate (non-streaming, ``stream=False``)。"""

    def health(self) -> bool:
        """GET /api/tags で疎通確認 (起動時 + reader check で使う)。"""
```

- HTTP は `httpx.Client` (既存依存)
- Ollama 不在時は `OllamaUnavailableError(host=..., hint=...)` で接続手順を案内
- `format` は Ollama の structured output (JSON Schema を渡せる)

### 3.3 Stage 関数 (純粋関数化)

```python
# reader/stages.py

def stage_overview(repo: RepoSummary, client: OllamaClient) -> RepoOverview: ...

def stage_entrypoints(
    repo: RepoSummary, overview: RepoOverview, client: OllamaClient,
    max_files: int = 30,
) -> list[Entrypoint]: ...

def stage_trust_boundaries(
    repo: RepoSummary, entrypoints: list[Entrypoint], client: OllamaClient,
    max_per_entrypoint: int = 3,
) -> list[TrustBoundary]: ...

def stage_hypotheses(
    boundaries: list[TrustBoundary], client: OllamaClient,
    top_k_cwe: int = 3,
) -> list[Hypothesis]: ...


def read_repo(repo_path: Path, client: OllamaClient | None = None) -> ReaderReport:
    """4 stage を順に実行して ReaderReport を返す。"""
```

`RepoSummary` は Reader 用の軽量ラッパで、`find` で得たファイル一覧 + 抜粋 (各ファイル先頭 100 行など) を抱える。**ファイル丸ごと LLM に送らない** ことでハルシネーションとコンテキスト爆発を抑える。

### 3.4 出力データモデル

```python
# reader/models.py

class RepoOverview(BaseModel):
    summary: str                  # 1-3 文
    tech_stack: list[str]
    main_directories: list[str]
    estimated_loc: int

class EntrypointKind(StrEnum):
    HTTP_ROUTE = "http_route"
    CLI = "cli"
    IPC = "ipc"
    RPC = "rpc"
    WEBSOCKET = "websocket"
    QUEUE = "queue"
    EVENT_HANDLER = "event_handler"

class Entrypoint(BaseModel):
    kind: EntrypointKind
    file_path: str
    line_number: int = Field(ge=0)
    description: str

class TrustBoundary(BaseModel):
    entrypoint_index: int        # 元の Entrypoint への参照
    sink_description: str
    flow_summary: str

class Hypothesis(BaseModel):
    boundary_index: int          # 元の TrustBoundary への参照
    cwe_candidates: list[str]    # ["CWE-79", "CWE-22", "CWE-918"] など
    rationale: str

class ReaderReport(BaseModel):
    overview: RepoOverview
    entrypoints: list[Entrypoint]
    trust_boundaries: list[TrustBoundary]
    hypotheses: list[Hypothesis]
    model: str
    generated_at: datetime
```

`Hypothesis.cwe_candidates` は既存 `herald/data/cwe.json` に含まれる CWE id のみを許容 (検証で弾く)。

### 3.5 プロンプト

`src/suzaku/reader/data/prompts/` に Jinja2 テンプレートを 4 本同梱:

| ファイル | 説明 |
|---|---|
| `overview.j2` | リポジトリ概観の summary 生成 |
| `entrypoints.j2` | エントリポイント抽出 (HTTP route / CLI 等) |
| `trust_boundaries.j2` | 入口 → sink の信頼境界追跡 |
| `hypotheses.j2` | sink 別に CWE トップ 3 を生成 |

各プロンプトは:

- システム指示 (英語、ハルシネーション抑制 + JSON Schema 強制)
- リポジトリの抜粋 (ファイル一覧 + 主要設定ファイルの先頭 N 行)
- 期待する JSON Schema (Pydantic を `.model_json_schema()` で生成)

LLM 入力は **英語固定** (qwen2.5-coder は英語の方が安定。日本語要約は別途生成しない)。

### 3.6 CLI 統合

```bash
suzaku reader read <repo-path>                    # 4 stage 一気通貫実行
suzaku reader read <repo-path> --stage overview   # 単独 stage 実行
suzaku reader check                               # Ollama 疎通確認 + モデル存在チェック
suzaku reader list-models                         # ローカル Ollama の利用可能モデル一覧
```

オプション:

- `--ollama-url` / `SUZAKU_OLLAMA_BASE_URL` (default: `http://localhost:11434`)
- `--model` / `SUZAKU_OLLAMA_MODEL` (default: `qwen2.5-coder:14b`)
- `--json` で `ReaderReport` を JSON 出力
- `--record <evidence_dir>` で生成結果を SHA-256 付きで保存 (任意)

### 3.7 MCP 露出

Phase 2-B の MCP server に **read-only** で 3 ツール追加:

| Tool | Mode | 説明 |
|---|---|---|
| `reader_check` | ro | Ollama 疎通確認 (model loaded か) |
| `reader_overview` | ro | リポジトリ概観のみ生成 (1 LLM call で軽量) |
| `reader_read` | ro | 4 stage 一気通貫 (時間がかかる旨を description に明記) |

`reader_read` は数十秒〜数分かかるが、MCP には timeout がないので OK。

### 3.8 ファイル構造

```
src/suzaku/reader/
├── __init__.py
├── cli.py            # suzaku reader CLI
├── ollama.py         # Ollama HTTP ラッパー (Witness Guard 統合)
├── models.py         # Pydantic v2 出力モデル
├── repo_summary.py   # リポ抜粋ヘルパ (ファイル一覧 + head N 行)
├── stages.py         # 4 stage の純粋関数
└── data/prompts/
    ├── overview.j2
    ├── entrypoints.j2
    ├── trust_boundaries.j2
    └── hypotheses.j2
```

## 4. 受け入れ基準 (DoD)

### 4.1 機能受け入れ

- ✅ `suzaku reader check` で Ollama に疎通できれば `OK`、できなければ `OllamaUnavailableError` で停止
- ✅ `OllamaClient` が許可外ホスト (`api.openai.com` 等) で初期化されると `ProductionAccessError`
- ✅ `stage_overview` / `stage_entrypoints` / `stage_trust_boundaries` / `stage_hypotheses` が Ollama レスポンスから `Pydantic` モデルを生成
- ✅ LLM 応答が JSON Schema に従わない場合 `ReaderParseError` で安全に失敗
- ✅ `Hypothesis.cwe_candidates` に未知 CWE が混入したら検証エラー
- ✅ `suzaku reader read <repo>` で `ReaderReport` を JSON 出力
- ✅ MCP `reader_check` / `reader_overview` / `reader_read` が ro モードで列挙される
- ✅ `--record` オプションで SHA-256 入りの証跡が `evidence.lock` に append される

### 4.2 品質ゲート

- ✅ pytest 全件パス (新規 20+ tests)
- ✅ ruff check clean
- ✅ mypy --strict clean
- ✅ カバレッジ 80% 以上を維持

### 4.3 ガードの維持

- ✅ `OllamaClient(base_url="http://api.openai.com")` で `ProductionAccessError`
- ✅ Phase 1 (244) + Phase 2-D (25) + Phase 2-B (38) のテストが全パス
- ✅ MCP `compass_scan` 等の既存ツールに影響なし

## 5. 実装順序 (TDD)

### Step A1-1: SPEC + 骨格 (30 分)
- 本 SPEC を `docs/SPEC-phase2-reader-core.md` として確定
- `docs/SPEC-phase2-reader-finetune.md` を Phase 2-A2 用に書き下ろし (実装は別 PR)
- `pyproject.toml` に `httpx` (既存) / `jinja2` (既存) のみで足りる確認

### Step A1-2: models.py + ollama.py (1 時間)
- Pydantic モデル定義 + JSON Schema 生成
- `OllamaClient` 実装 (Witness Guard 統合 + httpx)
- 単体テスト (respx で Ollama HTTP モック)

### Step A1-3: 4 stage + prompts (2 時間)
- プロンプトテンプレ 4 本
- `repo_summary.py` でリポ抜粋ヘルパ
- 各 stage 関数 (Ollama 呼び出し + 出力パース + バリデーション)
- 単体テスト

### Step A1-4: CLI + MCP 統合 (1 時間)
- `suzaku reader` サブコマンド (check / read / list-models)
- MCP tools (`reader_check` / `reader_overview` / `reader_read`)
- 統合テスト

### Step A1-5: ドキュメント (30 分)
- USAGE.md に Reader 章
- ARCHITECTURE.md に Reader モジュール追記
- ROADMAP.md の Reader 項目を進捗マーク

## 6. リスクと対応

| リスク | 対応 |
|---|---|
| Ollama 不在環境でのテスト | respx で HTTP モック、Ollama を実起動しない |
| LLM 出力のハルシネーション | Pydantic v2 + JSON Schema 強制 + 未知 CWE の事後検証 |
| 長時間ファイル全送信 | repo_summary で head N 行に限定 |
| クラウド LLM への迂回 | Witness Guard で host 判定、許可外で例外 |
| プロンプトインジェクション (リポ内コードから) | system prompt で明示 + LLM 出力を JSON 形式に強制 |
| モデル切替時の精度劣化 | テストはモック中心、実モデル評価は別途 (fine-tune SPEC で扱う) |

## 7. Phase 2-A1 の範囲外

- **Fine-tuning** — Phase 2-A2 で別実装 ([`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md))
- **Lineage 連携** — Phase 2-C で別実装
- **複数 LLM プロバイダ抽象** — Phase 3 以降
- **SSE / streaming** — 同期 `generate` のみ
- **マルチターン chat** — single-shot generate のみ
- **画像入力 (vision)** — 不要
- **Compass ルール自動生成** — Reader 仮説 → Compass ルール変換は Phase 3 で別検討

## 8. 参考

- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
- qwen2.5-coder: https://ollama.com/library/qwen2.5-coder
- deepseek-coder-v2: https://ollama.com/library/deepseek-coder-v2
- Suzaku Reader (Phase 1 SPEC.md §Reader): 計画段階
