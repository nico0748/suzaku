# Suzaku Phase 3-A — Web UI 詳細仕様

> 対象: CLI / MCP に並ぶ第3の UI 層として、FastAPI バックエンド + React フロントを追加する
> 前提: Phase 1 MVP + Phase 2-A〜D 完了
> 参照: [`SPEC.md`](./SPEC.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`ROADMAP.md`](./ROADMAP.md), [`SPEC-phase2-mcp.md`](./SPEC-phase2-mcp.md)
> 関連ブランチ: `feature/web-ui-docs` → `feature/web-ui-backend` → `feature/web-ui-frontend`

## 1. 目的

CLI / MCP は完成しているが、調査者がブラウザでクリック操作したいユースケースがある:

- 8 シグナルの重みを変えながら Sentinel の順位変化を観察する
- Compass のルールを切り替えながら hit 件数の変化を見る
- Lineage で複数 CVE を ingest → extract → scan のパイプラインを目視で組む
- Chronicle のタイムライン進捗をブラウザで一覧する

このユースケースを満たすため、Phase 3-A で読み取り系 4 モジュールの Web UI を提供する。

## 2. 絶対遵守の原則 (Phase 1 から継承)

UI 層が増えてもハードルールは緩めない:

1. **本番アクセス禁止** — Web UI 経由でも `Witness Guard` がアプリ層で遮断する
2. **ACCS事件の3手順** — `chronicle publish` 系は v1 では Web UI から不可 (`--mode ro` のみ)
3. **武器化エクスプロイト自動公開禁止** — Herald は v1 スコープ外
4. **シークレットの直書き禁止** — トークン類は引き続き環境変数経由
5. **証跡の改ざん検知** — Web 経由の API call も `logging.py` の SHA-256 チェインに記録する

加えて Phase 3-A 固有の禁則:

6. **デフォルトで `127.0.0.1` バインド** — `--host 0.0.0.0` 指定時は警告を出す
7. **永続化 DB は導入しない** — JSON ファイル + SHA-256 チェインのまま
8. **書き込み系操作のデフォルト遮断** — `chronicle init` / `witness init` 等の rw は v1 では Web UI から提供しない

## 3. 設計

### 3.1 v1 で公開する API エンドポイント

| Method | Path | 役割 | 元 CLI |
|---|---|---|---|
| `GET` | `/api/health` | バージョン + 稼働状態 | (新規) |
| `GET` | `/api/sentinel/signals` | `signals.yaml` の重み一覧 | `suzaku sentinel list-signals` |
| `POST` | `/api/sentinel/scan` | GitHub Search + 8 シグナルスコアリング | `suzaku sentinel scan` |
| `GET` | `/api/compass/rules` | 同梱ルール一覧 | `suzaku compass list-rules` |
| `POST` | `/api/compass/scan` | repo_path のスキャン (Finding[]) | `suzaku compass scan` |
| `POST` | `/api/lineage/ingest` | CVE record 取得 (`--cve` または NVD JSON path) | `suzaku lineage ingest` |
| `POST` | `/api/lineage/extract` | CVE record → VariantRule[] | `suzaku lineage extract` |
| `POST` | `/api/lineage/scan` | repo_path + rules → VariantFinding[] | `suzaku lineage scan` |
| `GET` | `/api/chronicle/list` | `.suzaku/chronicle/*.json` の一覧 | (新規) |
| `GET` | `/api/chronicle/{id}/status` | timeline + 推奨アクション | `suzaku chronicle status` |

書き込み系 (`witness init`, `chronicle init/publish`, `herald submit`, `reader read` 等) は v1 では提供しない。Phase 3-B で `--mode rw` として段階解禁する。

### 3.2 バックエンド構造

```
src/suzaku/web/
├── __init__.py
├── cli.py              # `suzaku web serve` Typer サブコマンド
├── app.py              # FastAPI() インスタンス + ルータ登録
├── deps.py             # 依存性注入 (config, logger)
├── middleware.py       # Origin 検査, CSRF, request logging
├── routers/
│   ├── health.py
│   ├── sentinel.py
│   ├── compass.py
│   ├── lineage.py
│   └── chronicle.py
└── schemas.py          # FastAPI 用 Pydantic レスポンス (既存 models.py を再利用)
```

- 各ルータは既存の pure functions (`suzaku.sentinel.scoring`, `suzaku.compass.grep_runner` 等) を直接呼ぶ
- subprocess で CLI を叩かない (ガード継承を担保しやすくするため)
- 長時間タスク (`sentinel scan` は 30 秒〜数分) は SSE (`text/event-stream`) で進捗ストリーミング
- 既存例外 (`ProductionAccessError`, `ACCSViolationError`, `RipgrepNotFoundError` 等) は HTTP 4xx にマップ

### 3.3 例外 → HTTP ステータスのマッピング

| 例外 | HTTP | body |
|---|---|---|
| `ProductionAccessError` | 403 | `{"error": "production_access_blocked", "host": "..."}` |
| `ACCSViolationError` | 409 | `{"error": "accs_violation", "day": N, "required": "Day 90"}` |
| `RipgrepNotFoundError` | 503 | `{"error": "ripgrep_missing"}` |
| `NVDFilterError` | 422 | `{"error": "nvd_filtered", "reason": "..."}` |
| `LineageEgressError` | 403 | `{"error": "egress_blocked", "host": "..."}` |
| `typer.BadParameter` 相当 | 400 | `{"error": "bad_request", "detail": "..."}` |
| その他 | 500 | `{"error": "internal_error"}` |

### 3.4 フロントエンド構造

```
web/                              # リポ直下、Python パッケージとは分離
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── api/
│   │   └── client.ts            # OpenAPI 自動生成 + TanStack Query ラッパ
│   ├── components/
│   │   └── ui/                  # shadcn/ui コンポーネント
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Sentinel.tsx
│   │   ├── Compass.tsx
│   │   ├── Lineage.tsx
│   │   └── Chronicle.tsx
│   └── lib/
│       └── theme.ts             # 朱雀ブランドカラー (#B43E3E / #8C1F1F)
└── public/
    └── suzaku-icon.svg
```

- ビルド成果物 `web/dist/` は FastAPI から `StaticFiles` でマウントして同一オリジンで配信
- 開発時は Vite dev server (`localhost:5173`) → FastAPI (`localhost:8765/api/`) に proxy

### 3.5 CLI

```bash
suzaku web serve                          # 127.0.0.1:8765, mode=ro
suzaku web serve --host 0.0.0.0 --port 8000   # 警告表示してから起動
suzaku web build                          # フロントの npm run build を実行 (任意)
suzaku web open                           # OS デフォルトブラウザで http://127.0.0.1:8765 を開く
```

## 4. 安全機構

### 4.1 ネットワーク層

- **デフォルト `127.0.0.1` バインド**: `--host 0.0.0.0` 指定時は確認プロンプトを通す
- **Origin 検査**: `Origin` ヘッダが `http://127.0.0.1:*` / `http://localhost:*` 以外の POST はすべて 403
- **CSRF トークン**: `GET /api/health` で発行された `X-Suzaku-CSRF` を以降の POST で必須化
- **API レート制限**: per-IP で `60 req/min` (FastAPI middleware で実装)

### 4.2 アプリ層 (既存ガードの継承)

- `Witness Guard`: Compass/Lineage の scan 系は filesystem のみで egress なし → 元々発火しない
- `Lineage Egress Guard`: ingest/extract 時に api.github.com / services.nvd.nist.gov 以外を弾く (HTTP 403)
- `ACCS Guard`: v1 では publish 操作を Web UI から提供しないので発火経路なし

### 4.3 ロギング

- すべての API call を `.suzaku/web/access.jsonl` に append-only で記録
- 各エントリは前レコードの SHA-256 を `prev_hash` に持つチェイン形式 (既存 `logging.py` を流用)
- `suzaku web verify-log` で改ざん検知

## 5. テスト戦略

- バックエンド: `httpx.AsyncClient` + `pytest-asyncio` で FastAPI を直接叩く
- 各エンドポイントに対し:
  - 正常系 1 件
  - 既存 Suzaku 例外が正しく HTTP マップされるか確認 1 件
  - Origin / CSRF が無いリクエストが弾かれるか確認 1 件
- E2E は Playwright で `dashboard → sentinel → compass → lineage` の主導線を 1 本確保
- カバレッジ目標: バックエンド 85%+ (既存 86% を下げない)

## 6. 段階的 PR 計画

| PR | ブランチ | 内容 | 行数目安 |
|---|---|---|---|
| #1 | `feature/web-ui-docs` | CLAUDE.md / README / ROADMAP / 本仕様の追加 | 〜50 |
| #2 | `feature/web-ui-backend-skeleton` | FastAPI 骨格 + `/api/health` + Sentinel エンドポイント + テスト | 〜400 |
| #3 | `feature/web-ui-backend-modules` | Compass / Lineage / Chronicle エンドポイント | 〜400 |
| #4 | `feature/web-ui-frontend-skeleton` | Vite + React + shadcn + ルーティング | 〜600 |
| #5 | `feature/web-ui-pages-readonly` | Sentinel + Compass ページ | 〜500 |
| #6 | `feature/web-ui-pages-lineage` | Lineage + Chronicle + Dashboard | 〜500 |

各 PR は単独でビルド・テスト通過する状態でマージする。

## 7. 受け入れ基準 (Phase 3-A 完了の判定)

- [ ] `suzaku web serve` で 127.0.0.1:8765 が起動し、ブラウザから 4 モジュールが操作できる
- [ ] 全 API エンドポイントが OpenAPI スキーマに反映され、`/openapi.json` で取得できる
- [ ] バックエンドテスト 30+ 件、フロント Playwright E2E 1 本
- [ ] `0.0.0.0` バインド時に確認プロンプトが表示される
- [ ] 既存 244 件の CLI テストが引き続きパスする (デグレなし)
- [ ] README / GETTING_STARTED に Web UI の起動方法が追記されている
