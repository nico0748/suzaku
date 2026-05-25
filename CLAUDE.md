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
- Phase 1〜2 (CLI / MCP): Python 3.11+, Typer, Pydantic v2, Semgrep, ripgrep, Docker
- Phase 3 (Web UI): FastAPI (バックエンド) + React 18 + Vite + TypeScript + shadcn/ui (フロント)
- 禁止: ORM, Celery, Redis, 重量フレームワーク (Django 等)
- Phase 3 で FastAPI を解禁するが、永続化は引き続き JSON ファイル + SHA-256 チェイン (DB は導入しない)

## Architecture
- Phase 1 MVP: Sentinel / Compass / Witness / Herald / Chronicle (5 モジュール)
- Phase 2: Reader / Lineage / MCP server を追加
- Phase 3: Web UI (`src/suzaku/web/` + `web/` フロント) — 既存の pure functions を直接呼び、CLI / MCP と並列の UI 層
- 各モジュールは独立しつつ models.py 経由でデータ受け渡し
- すべての UI 層 (CLI / MCP / Web) で同一の Guard (Witness / ACCS / Extortion) が発火する

## Coding Conventions
- ruff (formatter + linter)
- mypy strict
- pytest, テストカバレッジ 80%+
- 関数は単一責務、副作用がある関数は名前で明示
- 全コメント・docstring は日本語可
- エラーメッセージは英語 (技術用語の翻訳ブレ防止)

## Branch Strategy
- 機能ごとに `feature/<name>` ブランチを切る
- 各機能完了で draft PR を作成し、レビュー後に統合ブランチへマージ
- Witness Guard など安全機構は単独 PR で十分にレビューする

## Test Strategy
- TDD: テスト → 実装 → リファクタ
- Witness Guard のテストは最優先・全パターン網羅
- HTTP は respx でモック、Docker 連携は integration マーカで分離
