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

### Reader Fine-tuning (Phase 2-A2 / 将来)

`qwen2.5-coder:14b` を Suzaku の脆弱性検出用途に LoRA で軽量 fine-tune し、
GGUF 化して Ollama に登録する。詳細仕様は
[`SPEC-phase2-reader-finetune.md`](./SPEC-phase2-reader-finetune.md) を参照。
データ流出防止のため、未公開 Finding (`state != PUBLISHED`) は学習データから
完全除外する。実装は別 PR。

### ④ Lineage (継) — Variant Analysis

公開 CVE の修正コミット diff から類似パターンを検索:

- `lineage cve-import <id>` で NVD JSON を取り込み
- 修正前 AST 形を Semgrep autofix pattern に変換
- Sentinel 出力済みのリポジトリ集合に対して横展開検索

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

### TUI / Web ダッシュボード

- Phase 1 で禁止した Web フレームワークを Phase 3 で限定的に解禁 (read-only)
- Textual TUI で disclosure pipeline の進捗を可視化

## アーキテクチャ拡張のガードレール

新機能を追加する際は以下を厳守:

1. **ハードルール 5 つは絶対に緩めない**
2. テストカバレッジは 80% を維持
3. 新たな危険関数・武器化エクスプロイトを Herald から自動送信しない
4. シークレットは引き続き環境変数 / 1Password CLI 経由のみ
5. Phase 1 のモジュール境界 (`models.py` 経由のデータ受け渡し) を破らない

## 参考: Phase 1 受け入れ基準

[SPEC.md](./SPEC.md) §「Phase 1 完了の判定基準」 を参照。E2E シナリオは [USAGE.md](./USAGE.md) §「End-to-End シナリオ」 に記載。
