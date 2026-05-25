# Suzaku 

> 広い空から異変を見つけ、社会へ伝える — OSS 脆弱性調査支援システム

Suzaku は、個人セキュリティリサーチャー向けに OSS の脆弱性発見から CVE 取得までのワークフローを支援する CLI 群です。Python 3.11+ を前提とします。

ブランドカラー: 朱 `#B43E3E` / 濃赤 `#8C1F1F`

## 動作する機能

### Phase 1 MVP

| モジュール | 機能 |
|---|---|
| ① **Sentinel** (斥候) | 8 シグナル評価による OSS ターゲット選定 |
| ③ **Compass** (羅針) | 危険関数 grep + Semgrep ルールによる初手検出 |
| ⑥ **Witness** (証立) | Docker 内 PoC 再現 + **本番アクセス完全ブロック** |
| ⑦ **Herald** (奏上) | GHSA Markdown 生成 + CVSS v3.1 計算 |
| ⑧ **Chronicle** (歴記) | 90 日開示タイムライン + **ACCS Guard** |

### Phase 2

| モジュール | 機能 |
|---|---|
| ② **Reader** (読眼) | ローカル LLM (Ollama / qwen2.5-coder:14b) で 4 段階コード読解 + LoRA fine-tune パイプライン |
| ④ **Lineage** (継) | 公開 CVE 修正パッチからの variant 検索 |
| Herald 拡張 | MITRE / huntr / JPCERT / Wordfence / Patchstack / HackerOne / Bugcrowd の 7 ルート追加 (計 8 ルート) |
| **MCP サーバ** | Claude Code / Claude Desktop から自然言語で Suzaku を呼出 (ro=19 + rw=4 ツール) |

## クイックスタート

```bash
make install            # 依存をインストール
cp .env.example .env    # 環境変数を埋める
make check              # lint + typecheck + test
suzaku --help
```

## ドキュメント

- 📖 [`docs/GETTING_STARTED.md`](./docs/GETTING_STARTED.md) — Hands-on チュートリアル (60 分で一周)
- ⚡ [`docs/CHEATSHEET.md`](./docs/CHEATSHEET.md) — コマンド早見表
- 🎯 [`docs/E2E.md`](./docs/E2E.md) — 完全な E2E シナリオ (WordPress プラグインで CVE を取りに行く)
- 🏛 [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — アーキテクチャ + 8 サブシステム構想
- 🗺 [`docs/ROADMAP.md`](./docs/ROADMAP.md) — Phase 2/3 計画
- 📐 詳細仕様: `docs/SPEC*.md` (Phase 1 + Phase 2-A/B/C/D)
- ⚖️ [`LEGAL.md`](./LEGAL.md) — ACCS事件 3 手順 / 不正アクセス禁止法 / 免責

## ハードルール (絶対遵守)

1. **本番アクセス禁止** — Docker 内ローカル再現のみ (`ProductionAccessError` / exit 4)
2. **ACCS事件の3手順** — 通知 → 修正期間 → 公表 を逸脱しない (`ACCSViolationError` / exit 5)
3. **武器化エクスプロイト自動公開禁止** — Herald 文面ガード (`ExtortionLanguageError`)
4. **シークレット直書き禁止** — 環境変数 / 1Password CLI 経由
5. **証跡の改ざん検知** — 全ログに SHA-256 を付与し append-only

詳細は [`LEGAL.md`](./LEGAL.md), [`CLAUDE.md`](./CLAUDE.md) を参照。

## Phase 1〜2 で動かないこと

- Probe (ファジング) — Phase 3
- 申請 API への自動 POST (テンプレ生成のみ。手動投稿が前提)
- Web UI — **Phase 3 で解禁** (下記参照)
- ORM / Redis / Celery — 引き続き不採用

## Phase 3: Web UI (進行中)

CLI / MCP に並ぶ第3の UI 層として、FastAPI バックエンド + React フロントで読み取り系 4 モジュール (Sentinel / Compass / Lineage / Chronicle) を GUI 化する。

- デフォルト `127.0.0.1` バインド・認証なし (個人ローカル利用前提)
- 既存の pure functions を直接呼び、Witness Guard / ACCS Guard / Extortion Guard を継承
- 永続化は引き続き JSON ファイル + SHA-256 チェイン (DB は導入しない)
- 仕様: [`docs/SPEC-phase3-web-ui.md`](./docs/SPEC-phase3-web-ui.md)

## License

MIT
