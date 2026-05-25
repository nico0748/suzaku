# Suzaku Roadmap

> Phase 1 MVP は完了。本ファイルは Phase 2/3 の構想を記録する。

## Phase 1 MVP — 完了

| Step | モジュール | 状態 |
|---|---|---|
| 0+1 | プロジェクト骨格・共通モデル・ロギング | ✅ |
| 2 | Witness Guard (本番アクセス検知) | ✅ |
| 3 | Witness Reproducer + Evidence | ✅ |
| 4 | Herald CVSS + 5 点セット Checklist | ✅ |
| 5 | Herald GHSA Markdown + 報告メール | ✅ |
| 6 | Compass 危険関数 grep + Semgrep | ✅ |
| 7 | Sentinel 8 シグナル + GitHub Search | ✅ |
| 8 | Chronicle 90 日タイムライン + ACCS ガード | ✅ |
| 9 | CLI 統合 | ✅ |
| 10 | ドキュメント | ✅ |

品質ゲート:

- ✅ pytest 244 件 / カバレッジ 86%
- ✅ ruff clean / mypy strict clean
- ✅ Witness Guard テスト全 46 件パス
- ✅ CVSS は FIRST.org 計算機と 11 ベクタで一致

## Phase 2 (中期構想)

### ② Reader (読眼) — コード読解 4 段階 ✅ Phase 2-A1 完了

LLM 支援によるリポジトリ要約・脆弱性仮説生成 (Phase 2-A1):

1. ✅ **概観**: ディレクトリ構造 + 主要技術スタックの自動要約
2. ✅ **入口の特定**: HTTP route / CLI / IPC / RPC / WS / queue を列挙
3. ✅ **信頼境界の追跡**: 入力 → sink のデータフローを文章化
4. ✅ **仮説生成**: 各 sink で発火しうる CWE トップ 3 (allow-list 検証付き)

実装: Ollama 経由ローカル LLM (既定: `qwen2.5-coder:14b`)。Witness Guard で
クラウドホストを完全遮断し、未公開脆弱性候補コードを外部に流出させない。

詳細: [`SPEC-phase2-reader-core.md`](./SPEC-phase2-reader-core.md)

### Reader Fine-tuning Pipeline ✅ Phase 2-A2 完了

`qwen2.5-coder:14b` を Suzaku の脆弱性検出用途に LoRA で軽量 fine-tune し、
GGUF 化して Ollama に登録するためのラッパー一式:

- ✅ データセット構築: PUBLISHED Finding のみ + 禁止語除外 + PII redact + SHA-256
- ✅ 学習: Unsloth 呼出のコマンド組み立て + `--dry-run` で安全試運転
- ✅ エクスポート: llama.cpp 経由 GGUF + Modelfile + `ollama create`
- ✅ 評価: CWE Top-1/3 / parse rate / hallucinated path rate / **禁止語率 (0 必須)**

実 GPU 学習は外部スクリプト想定。本ツールはあくまでラッパで、安全要件
(未公開データ流出防止) を機械的に強制する。

詳細: [`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md)

### ④ Lineage (継) — Variant Analysis ✅ Phase 2-C 完了

公開 CVE の修正コミット diff から類似パターンを検索:

- ✅ `suzaku lineage ingest` で NVD JSON を取り込み (オンライン/オフライン両対応)
- ✅ `extract` で commit 修正 diff から regex ベースの VariantRule を生成
- ✅ `scan` で対象リポジトリに対し横展開検索 (Compass GrepRunner を流用)
- ✅ Witness Guard とは独立した read-only egress allow-list
  (`api.github.com`, `services.nvd.nist.gov` のみ)
- ✅ `Awaiting Analysis` 等の未確定 CVE は機械的に除外

詳細: [`SPEC-phase2-lineage.md`](./SPEC-phase2-lineage.md)

### Herald — 追加申請ルート ✅ (Phase 2-D 完了)

- ✅ MITRE CNA-LR 直接ルート (Vendor Contact Timeline 必須)
- ✅ huntr.dev (package + ecosystem 必須)
- ✅ JPCERT/CC 報告フォーム (日本語テンプレ)
- ✅ Wordfence / Patchstack (plugin slug 必須)
- ✅ HackerOne / Bugcrowd (program_handle 必須)
- 詳細仕様: [`SPEC-phase2-herald-routes.md`](./SPEC-phase2-herald-routes.md)

### Chronicle — Notion DB 同期

- Notion API で disclosure timeline を双方向同期
- Google Calendar に Day 3 / 14 / 30 / 60 / 90 のリマインダ自動投入

### Sentinel — 並列 fetch + GraphQL

- httpx async で 100 件 / 5 分の SLO を確実達成
- GitHub GraphQL `search` + repo metadata 結合で API call 数を削減

## Phase 3 (長期構想)

### ⑤ Probe (試火) — ファジング

- `atheris` (libFuzzer) / `boofuzz` (network) でターゲットを叩く
- corpus を `evidence/<finding_id>/corpus/` に保管
- クラッシュ時は自動で Witness Reproducer の minimization にかける

### MCP サーバとしての提供 ✅ (Phase 2-B 完了)

- ✅ Suzaku モジュールを Anthropic MCP サーバとして公開 (`suzaku mcp serve`)
- ✅ Claude Code / Claude Desktop から 14 (ro) / 18 (rw) ツールを呼び出し
- ✅ stdio トランスポート + `--mode {ro,rw}` 切替
- ✅ Suzaku 全例外を `isError=True` の TextContent にラップ
- 詳細仕様: [`SPEC-phase2-mcp.md`](./SPEC-phase2-mcp.md)
- Phase 3 候補: SSE / streamable HTTP, `chronicle_publish`, `sentinel_scan` の安全な公開

### Web UI (Phase 3-A) — 進行中

CLI / MCP に並ぶ第3の UI 層として、FastAPI バックエンド + React フロントを追加する。

- バックエンド: `src/suzaku/web/` (FastAPI、127.0.0.1 バインド、認証なし、Origin/CSRF のみ)
- フロント: `web/` (Vite + React 18 + TypeScript + shadcn/ui + TanStack Query)
- v1 スコープ (読み取り系 4 モジュール): Sentinel scan / Compass scan / Lineage ingest+extract+scan / Chronicle status
- 既存 pure functions を直接呼ぶ — Witness Guard / ACCS Guard / Extortion Guard は自動継承
- 永続化は引き続き JSON ファイル + SHA-256 チェイン (DB は導入しない)
- 仕様: [`SPEC-phase3-web-ui.md`](./SPEC-phase3-web-ui.md)

### TUI ダッシュボード (Phase 3-B 候補)

- Textual TUI で disclosure pipeline の進捗を可視化 (Web UI と択一ではなく並列)

## アーキテクチャ拡張のガードレール

新機能を追加する際は以下を厳守:

1. **ハードルール 5 つは絶対に緩めない**
2. テストカバレッジは 80% を維持
3. 新たな危険関数・武器化エクスプロイトを Herald から自動送信しない
4. シークレットは引き続き環境変数 / 1Password CLI 経由のみ
5. Phase 1 のモジュール境界 (`models.py` 経由のデータ受け渡し) を破らない

## 参考: Phase 1 受け入れ基準

[SPEC.md](./SPEC.md) §「Phase 1 完了の判定基準」 を参照。E2E シナリオは [USAGE.md](./USAGE.md) §「End-to-End シナリオ」 に記載。
