# Suzaku (朱雀)

> 広い空から異変を見つけ、社会へ伝える — OSS 脆弱性調査支援システム

Suzaku は、個人セキュリティリサーチャー向けに OSS の脆弱性発見から CVE 取得までのワークフローを支援する CLI 群です。本リポジトリは **Phase 1 MVP** の実装で、Python 3.11+ を前提とします。

ブランドカラー: 朱 `#B43E3E` / 濃赤 `#8C1F1F`

## Phase 1 で動くこと

| モジュール | 機能 |
|---|---|
| Sentinel (斥候) | 8 シグナル評価による OSS ターゲット選定 |
| Compass (羅針) | 危険関数 grep + Semgrep ルールによる初手検出 |
| Witness (証立) | Docker 内 PoC 再現 + **本番アクセス完全ブロック** |
| Herald (奏上) | GHSA Markdown 生成 + CVSS v3.1 計算 |
| Chronicle (歴記) | 90 日開示タイムライン管理 |

## Phase 1 で動かないこと

- Reader (コード読解 4 段階) — Phase 2
- Lineage (variant analysis) — Phase 2
- Probe (ファジング) — Phase 3
- MITRE / huntr / JPCERT / HackerOne 等への直接申請 — Phase 2 以降
- Web UI、データベース、Web フレームワーク

## クイックスタート

```bash
make install            # 依存をインストール
cp .env.example .env    # 環境変数を埋める
make check              # lint + typecheck + test
suzaku --help
```

## ハードルール (絶対遵守)

1. **本番アクセス禁止** — Docker 内ローカル再現のみ
2. **ACCS事件の3手順** — 通知 → 修正期間 → 公表 を逸脱しない
3. **武器化エクスプロイト自動公開禁止**
4. **シークレット直書き禁止** — 環境変数 / 1Password CLI 経由
5. **証跡の改ざん検知** — 全ログに SHA-256 を付与し append-only

詳細は [`LEGAL.md`](./LEGAL.md), [`CLAUDE.md`](./CLAUDE.md), [`docs/SPEC.md`](./docs/SPEC.md) を参照。

## License

MIT
