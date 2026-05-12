# Suzaku Phase 2-B — MCP サーバ化 詳細仕様

> 対象: Suzaku モジュールを Model Context Protocol (MCP) サーバとして公開し、Claude Code / Claude Desktop から直接呼び出せるようにする
> 前提: Phase 1 MVP + Phase 2-D 完了 (`claude/vulnerability-assessment-setup-U45lW`)
> 参照: [`SPEC.md`](./SPEC.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`ROADMAP.md`](./ROADMAP.md)
> SDK: Anthropic MCP Python SDK (`mcp` package, v1.x)

## 1. 目的

Suzaku は CLI 単体ツールとして完結しているが、調査者が Claude Code (CLI) や Claude Desktop で対話しながら脆弱性調査をする場合、現状は人間が `suzaku` コマンドを別ターミナルで叩く必要がある。

MCP (Model Context Protocol) サーバとして Suzaku を公開すると、エージェントから:

- 「このリポを Sentinel でスコアして」
- 「この CVSS ベクタを計算して」
- 「Day 30 の Chronicle ステータスを教えて」

と自然言語で依頼するだけで、Suzaku の機能が呼び出せるようになる。

## 2. 絶対遵守の原則 (Phase 1 から継承)

MCP サーバ化でも以下のハードルールは緩めない:

1. **本番アクセス禁止** — MCP 経由でも Witness Guard がアプリ層で遮断する
2. **ACCS事件の3手順** — `publish` 系ツールには Chronicle Guard を通す
3. **武器化エクスプロイト自動公開禁止** — 完全エクスプロイト出力ツールを公開しない
4. **シークレットの直書き禁止** — `SUZAKU_GITHUB_TOKEN` 等は環境変数経由
5. **証跡の改ざん検知** — MCP 経由の操作も `evidence.lock` に SHA-256 記録できる
6. **過剰実装の禁止** — 申請 API への自動送信は引き続き Phase 2-B でも実装しない

加えて Phase 2-B 固有の禁則:

7. **read-write 操作の MCP exposure** はオプトイン (`--mode {ro,rw}`)。デフォルトは read-only。
8. **任意のシェルコマンド実行ツール** (`shell_exec` のようなもの) は MCP に公開しない。

## 3. 設計

### 3.1 公開するツール一覧

| Tool name | モード | 動作 | 元 CLI |
|---|---|---|---|
| `suzaku_version` | ro | バージョン文字列 | `suzaku version` |
| `sentinel_list_signals` | ro | `signals.yaml` の重み一覧 | `suzaku sentinel list-signals` |
| `sentinel_score` | ro | `RepoSignals` JSON を直接 scoring | (純粋関数) |
| `compass_list_rules` | ro | 同梱ルール一覧 | `suzaku compass list-rules` |
| `compass_show_rule` | ro | ルール定義 JSON | `suzaku compass show-rule` |
| `compass_scan` | ro (filesystem read only) | リポジトリスキャン | `suzaku compass scan` |
| `witness_check_host` | ro | ガード判定 (純粋関数) | `suzaku witness check-host` |
| `witness_verify` | ro | evidence.lock 整合性検証 | `suzaku witness verify` |
| `witness_init` | rw | PoC テンプレ展開 | `suzaku witness init` |
| `witness_record` | rw | 証跡 SHA-256 追記 | `suzaku witness record` |
| `herald_cvss` | ro | CVSS スコア計算 | `suzaku herald cvss` |
| `herald_checklist` | ro | 5 点セット検証 | `suzaku herald checklist` |
| `herald_list_routes` | ro | 8 ルート一覧 | `suzaku herald list-routes` |
| `herald_render` | ro | 任意ルートのテンプレート生成 | `suzaku herald submit` |
| `chronicle_status` | ro | マイルストーン + アラート | `suzaku chronicle status` |
| `chronicle_list` | ro | 全 disclosure 一覧 | `suzaku chronicle list` |
| `chronicle_init` | rw | Day 0 開始 | `suzaku chronicle init` |
| `chronicle_set_vendor` | rw | ベンダ状態更新 | `suzaku chronicle set-vendor` |

意図的に公開しないもの (本 Phase の範囲外):

- `witness_reproduce` (docker compose up) — MCP 経由での起動はリスク高
- `chronicle_publish` — ACCS Guard を通すが、外部から最終公開判断を委ねるべきでない
- `sentinel_scan` (実 GitHub API call) — レートリミット消費と認証管理が複雑
- `compass_scan` の `--all` を伴う長時間スキャン

これらは将来 (Phase 3 以降) で安全機構を追加した上で検討する。

### 3.2 モード切替 (`--mode`)

`suzaku mcp serve` に `--mode {ro,rw}` オプションを追加:

- `ro` (デフォルト): 上記表の **ro** マーク付きツールのみを公開
- `rw`: rw ツールも追加で公開 (`witness_init`, `witness_record`, `chronicle_init`, `chronicle_set_vendor`)

`witness_reproduce` / `chronicle_publish` は **どちらのモードでも公開しない** (Phase 2-B 範囲外)。

### 3.3 トランスポート

MCP は 3 つのトランスポートに対応:

- **stdio** (デフォルト) — Claude Code / Claude Desktop が起動して標準入出力でやり取り
- **SSE** (Server-Sent Events) — リモート HTTP 経由
- **streamable HTTP** — 最新の MCP

Phase 2-B では **stdio のみ** をサポート。SSE / streamable HTTP は Phase 3 で検討。

### 3.4 ツールのスキーマ

各ツールは JSON Schema で入力を厳格定義する。例:

```python
Tool(
    name="herald_cvss",
    description="Compute CVSS v3.1 Base Score and severity label from a vector string.",
    inputSchema={
        "type": "object",
        "properties": {
            "vector": {
                "type": "string",
                "description": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 形式",
            }
        },
        "required": ["vector"],
    },
)
```

すべての入力は Pydantic v2 で再検証する (Suzaku の既存パターンに合わせる)。

### 3.5 エラー応答

MCP ツールは例外を投げず、`isError=True` の `CallToolResult` を返す。Suzaku の既知例外を以下にマップ:

| 例外 | MCP 表現 |
|---|---|
| `ProductionAccessError` | `isError=True`, body に "[guard] ..." |
| `ACCSViolationError` | `isError=True`, body に "[ACCS] ..." |
| `ChecklistError` | `isError=True`, body に "[checklist] ..." |
| `RouteError` | `isError=True`, body に "[route] ..." |
| `ExtortionLanguageError` | `isError=True`, body に "[forbidden] ..." |
| `CVSSError` | `isError=True`, body に "[cvss] ..." |
| その他 `ValueError` | `isError=True`, body にメッセージ |
| 想定外 `Exception` | プロセス全体をクラッシュさせず `isError=True` で包む |

### 3.6 ファイル構造

```
src/suzaku/mcp/
├── __init__.py
├── server.py         # MCP Server 本体 (tool registry + dispatch)
├── tools.py          # 各ツールの Python 実装 (純粋関数)
└── cli.py            # `suzaku mcp serve` Typer 統合
```

`server.py` は `mcp.server.Server` をラップ。`tools.py` には MCP に依存しない純粋関数を置き、両 API (CLI + MCP) から再利用できるようにする。

### 3.7 CLI 統合

```bash
suzaku mcp serve [--mode {ro,rw}]       # stdio で MCP サーバ起動
suzaku mcp list-tools [--mode {ro,rw}]  # 公開予定ツール一覧 (debug 用)
```

Claude Desktop の `claude_desktop_config.json` 設定例 (USAGE.md に追記):

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

## 4. 受け入れ基準 (DoD)

### 4.1 機能受け入れ

- ✅ `suzaku mcp list-tools` で 13 ツール (ro) / 17 ツール (rw) が列挙される
- ✅ `herald_cvss` ツールに `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` を渡すと 9.8 / Critical が返る
- ✅ `witness_check_host` で github.com を渡すと "BLOCKED" 応答
- ✅ `chronicle_status` で過去 Day 0 の submission に対し milestone と alert を返す
- ✅ `--mode ro` では `witness_init` / `chronicle_init` 等が **non-existent tool** として返される
- ✅ `--mode rw` ではそれらも呼べる
- ✅ 各種 Suzaku 例外が `isError=True` の TextContent としてラップされる
- ✅ `witness_reproduce` / `chronicle_publish` / `sentinel_scan` / `compass_scan --all` は **どちらのモードでも公開されない**

### 4.2 品質ゲート

- ✅ `pytest` 全件パス (新規追加 15+ tests)
- ✅ `ruff check` clean
- ✅ `mypy --strict` clean
- ✅ カバレッジ 80% 以上を維持

### 4.3 ガードの維持

- ✅ MCP 経由のツール呼び出しでも Witness Guard / ACCS Guard / Extortion Guard が発火する
- ✅ MCP サーバ自身は本番アクセスを行わない (httpx のテスト用は除外)
- ✅ シークレットは環境変数のみ (`SUZAKU_GITHUB_TOKEN`, etc.)

## 5. 実装順序 (TDD)

### Step B-1: SPEC + 依存追加 (30 分)
- 本 SPEC を `docs/SPEC-phase2-mcp.md` として確定
- `pyproject.toml` に `mcp >= 1.27` を追加
- `src/suzaku/mcp/{__init__,tools,server,cli}.py` のスケルトン

### Step B-2: tools.py 純粋関数化 (1 時間)
- 既存 CLI ロジックから例外マップ可能な薄い関数群を抽出
- 各ツールの input/output dataclass を定義
- 単体テスト (純粋関数のため決定的)

### Step B-3: server.py の MCP 統合 (1 時間)
- `mcp.server.Server` 上に list_tools / call_tool ハンドラを実装
- `--mode` でツール集合を切り替え
- 各 Suzaku 例外を `isError=True` にマップ
- in-process な MCP client で end-to-end 検証

### Step B-4: CLI 統合 (30 分)
- `suzaku mcp serve` (stdio で長時間ブロック)
- `suzaku mcp list-tools` (debug 用)

### Step B-5: ドキュメント (30 分)
- `USAGE.md` に Claude Desktop / Claude Code 連携手順
- `ARCHITECTURE.md` に MCP モジュール追記
- `ROADMAP.md` の MCP 項目を完了マーク

## 6. リスクと対応

| リスク | 対応 |
|---|---|
| ツール呼び出しでの本番アクセス | 既存 Witness Guard をツール内で必ず再呼び出し |
| `--mode rw` での意図しない state 変更 | デフォルトを `ro` に。`rw` は明示指定必須 |
| Claude が自動で `chronicle_publish` を呼んで誤公開 | 本ツール自体を MCP に公開しない |
| 機密 token の漏洩 | tool response に環境変数値を含めない |
| 長時間スキャン (compass --all) | Phase 2-B では公開しない。将来 streaming で対応 |
| MCP SDK のバージョン更新 | `mcp >= 1.27, < 2` で固定 |

## 7. Phase 2-B の範囲外

- SSE / streamable HTTP トランスポート
- `witness_reproduce` の MCP 公開
- `chronicle_publish` の MCP 公開
- `sentinel_scan` の MCP 公開 (実 GitHub API call)
- `compass_scan --all` (長時間)
- LLM サンプリング (`sampling/createMessage`) — Reader モジュール (Phase 2-A) で別途実装
- MCP リソース (resources/list) — Phase 3
- MCP プロンプト (prompts/list) — Phase 3

## 8. 参考リンク

- MCP 仕様: https://modelcontextprotocol.io/
- Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Claude Code MCP ガイド: https://docs.claude.com/en/docs/claude-code/mcp
- Claude Desktop MCP ガイド: https://modelcontextprotocol.io/quickstart/user
