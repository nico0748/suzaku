# Suzaku Phase 2-D — Herald 追加申請ルート 詳細仕様

> 対象: Herald モジュール拡張 (Phase 1 の GHSA に加えて 6 ルートを追加)
> 前提: Phase 1 MVP がリリース可能状態 (`claude/vulnerability-assessment-setup-U45lW`)
> 関連: [`docs/SPEC.md`](./SPEC.md), [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md), [`docs/ROADMAP.md`](./ROADMAP.md)

## 1. 目的

Phase 1 の Herald は GHSA Markdown + vendor 向け coordinated-disclosure メールの 2 経路のみだった。Phase 2-D ではこれを拡張し、ベンダ応答状況 / 対象エコシステムに応じて最適な申請ルートを選択できるようにする。

具体的には以下 6 ルートを追加する:

| Route enum | 申請先 | 主な用途 | Phase |
|---|---|---|---|
| `Route.GHSA` | GitHub Security Advisory | 既定 (Phase 1) | ✅ |
| `Route.MITRE` | MITRE CNA-LR (CVE 直接申請) | ベンダ無応答時の CVE 採番 | **2-D** |
| `Route.HUNTR` | huntr.dev | OSS bug bounty | **2-D** |
| `Route.JPCERT` | JPCERT/CC | 国内 OSS / 日本語ベンダ | **2-D** |
| `Route.WORDFENCE` | Wordfence Threat Intel | WordPress plugin/theme | **2-D** |
| `Route.PATCHSTACK` | Patchstack Alliance | WordPress plugin/theme | **2-D** |
| `Route.HACKERONE` | HackerOne プラットフォーム | VDP/プログラムで採用 | **2-D** |
| `Route.BUGCROWD` | Bugcrowd プラットフォーム | VDP/プログラムで採用 | **2-D** |

(MITRE は Chronicle の Day 60+ エスカレーションで推奨されている経路。Phase 1 で `Route` enum には既に値が定義済み。)

## 2. 絶対遵守の原則 (Phase 1 から継承)

1. **本番アクセス禁止** — テンプレート生成のみ。実 API への自動送信は **本 Phase でも実装しない** (送信は人間が最終確認する)。
2. **ACCS事件の3手順** — `chronicle publish` 経由で公開ガードに通すこと。Herald 単独で「公開」アクションは取らない。
3. **武器化エクスプロイト自動公開禁止** — どのルートでも完全エクスプロイトを含めない (PoC は steps.md パス参照のみ)。
4. **シークレットの直書き禁止** — API トークンは環境変数経由のみ。
5. **証跡の改ざん検知** — 生成済みの advisory 出力は `evidence.lock` に SHA-256 で記録できること (既存 `EvidenceStore` を再利用)。
6. **脅迫的文面の禁止** — 既存の `FORBIDDEN_PHRASES` ガードを全テンプレートに適用する。
7. **過剰実装の禁止** — 申請 API への自動送信、ステータス追跡、報酬受領などは **Phase 2-D の範囲外**。

## 3. システム設計

### 3.1 データモデルの拡張

Phase 1 の `Advisory` (in `herald/ghsa.py`) は GHSA + vendor email を想定した汎用構造だった。Phase 2-D ではルート別の追加情報を表す `RouteContext` を導入する:

```python
# herald/routes.py (新規)

@dataclass
class RouteContext:
    """ルート別の補足情報を抱えるオプショナルコンテキスト。

    Advisory にぶら下げる形で `render_for_route(advisory, route, context)` に渡す。
    """

    # MITRE 用
    vendor_contact_attempts: list[ContactAttempt] = field(default_factory=list)
    """無応答エスカレーション時の通知履歴 (Day 0/3/14/30/60 等)。"""

    # huntr 用
    huntr_package_name: str | None = None
    """huntr.dev で扱うパッケージ ID (例: 'lodash')。"""
    huntr_package_ecosystem: str | None = None
    """npm / pip / packagist / maven / go / nuget。"""

    # JPCERT 用
    jpcert_reporter_role: str = "security_researcher"
    """reporter / security_researcher / pentester など。"""

    # Wordfence / Patchstack 用
    wp_plugin_slug: str | None = None
    """WordPress.org の plugin slug (例: 'akismet')。"""
    wp_active_installs: int | None = None
    """有効インストール数 (公開情報)。"""

    # HackerOne / Bugcrowd 用
    program_handle: str | None = None
    """プラットフォームのプログラム識別子 (例: 'github')。"""
    asset_identifier: str | None = None
    """プログラム内の対象アセット (例: 'github.com', 'api.github.com')。"""


@dataclass(frozen=True)
class ContactAttempt:
    """ベンダ通知履歴のエントリ。MITRE 申請時のタイムライン記載に使う。"""

    attempted_at: datetime
    channel: str    # "email" / "github_issue" / "twitter" / "distros@" など
    response: str   # "no_response" / "acknowledged" / "ignored" / "bounced"
    note: str = ""
```

`Advisory` 自体は触らず、`RouteContext` を別パラメータとして受け取る形にする (後方互換)。

### 3.2 ルートディスパッチャ

```python
# herald/routes.py

class RouteError(ValueError):
    """ルート別の必須フィールドが欠けている場合に発生。"""


ROUTE_TEMPLATES: dict[Route, str] = {
    Route.GHSA: "ghsa.md.j2",
    Route.MITRE: "mitre_cna_lr.md.j2",
    Route.HUNTR: "huntr.md.j2",
    Route.JPCERT: "jpcert.txt.j2",
    Route.WORDFENCE: "wordfence.md.j2",
    Route.PATCHSTACK: "patchstack.md.j2",
    Route.HACKERONE: "hackerone.md.j2",
    Route.BUGCROWD: "bugcrowd.md.j2",
}


def render_for_route(
    advisory: Advisory,
    route: Route,
    context: RouteContext | None = None,
) -> str:
    """指定ルートのテンプレートをレンダリングして返す。

    - Advisory の 5 点セットは ChecklistError で先に検証
    - ルート別の必須フィールドは RouteError で検証
    - 生成結果に FORBIDDEN_PHRASES が混入していれば ExtortionLanguageError
    """
```

### 3.3 ルート別の必須フィールド

| Route | RouteContext 必須 | 説明 |
|---|---|---|
| `GHSA` | (なし) | Phase 1 と同じ。`render_ghsa()` を移行ラッパとして残す。 |
| `MITRE` | `vendor_contact_attempts` >= 1 件 | CNA-LR は無応答後の最後通牒経路。少なくとも 1 件の通知履歴が必須。 |
| `HUNTR` | `huntr_package_name`, `huntr_package_ecosystem` | エコシステム未指定だと huntr 側で受理できない。 |
| `JPCERT` | (なし) | reporter 役職のみ任意。 |
| `WORDFENCE` | `wp_plugin_slug` | プラグイン特定子が必須。 |
| `PATCHSTACK` | `wp_plugin_slug` | 同上。 |
| `HACKERONE` | `program_handle` | 報告先プログラム必須。 |
| `BUGCROWD` | `program_handle` | 同上。 |

不足時は `RouteError("Route X requires field Y")` を投げる。

### 3.4 テンプレート

新規 7 テンプレートを `src/suzaku/herald/data/templates/` に追加:

| ファイル | 出力形式 | 必須セクション |
|---|---|---|
| `mitre_cna_lr.md.j2` | Markdown | Title / Reporter / Product / CWE / CVSS / Description / Reproduction / **Vendor Contact Timeline** / References |
| `huntr.md.j2` | Markdown | Repository / Package / Vulnerability Type / CWE / CVSS / Reproduction / Proof of Concept / Suggested Fix |
| `jpcert.txt.j2` | プレーンテキスト | 報告者情報 / 製品情報 / 脆弱性情報 / 影響 / 検出経緯 / 連絡先 |
| `wordfence.md.j2` | Markdown | Plugin Slug / Active Installs / Vulnerability Type / CWE / CVSS / Reproduction / Mitigation |
| `patchstack.md.j2` | Markdown | Plugin Slug / Vulnerability Type / CWE / CVSS / Reproduction / Researcher |
| `hackerone.md.j2` | Markdown | Program / Asset / Summary / Reproduction / Impact / Suggested Severity |
| `bugcrowd.md.j2` | Markdown | Program / Target / Title / Description / Repro Steps / Impact |

すべて Jinja2 で `trim_blocks=True` / `lstrip_blocks=True`。各テンプレートは Phase 1 の GHSA テンプレートと同じく、reproduction_steps_path への参照のみで完全な PoC body を埋め込まない。

### 3.5 CLI 拡張

`suzaku herald` に新サブコマンドを追加:

```
suzaku herald submit <route> <advisory.json> [--context <route_context.json>]
suzaku herald list-routes
```

- `submit <route>`: 指定ルートのテンプレートを stdout に出力
- `list-routes`: 同梱ルート一覧 + 必須フィールド

既存の `herald ghsa` / `herald email` はそのまま (後方互換)。

### 3.6 設定

`src/suzaku/herald/data/routes.yaml` を追加し、ルート別のメタ情報 (申請 URL / 連絡先) を一元管理:

```yaml
routes:
  mitre:
    name: "MITRE CNA-LR (CVE direct)"
    submit_url: "https://cveform.mitre.org/"
    note: "Use when vendor has not responded for 60+ days."
  huntr:
    name: "huntr.dev"
    submit_url: "https://huntr.com/bounties/new"
    requires_repo_url: true
  jpcert:
    name: "JPCERT/CC"
    submit_url: "https://www.jpcert.or.jp/form/"
    language: "ja"
  wordfence:
    name: "Wordfence Threat Intel"
    submit_url: "https://www.wordfence.com/threat-intel/vulnerabilities/submit"
    ecosystem: "wordpress"
  patchstack:
    name: "Patchstack Alliance"
    submit_url: "https://patchstack.com/articles/submit"
    ecosystem: "wordpress"
  hackerone:
    name: "HackerOne"
    submit_url: "https://hackerone.com/reports/new"
  bugcrowd:
    name: "Bugcrowd"
    submit_url: "https://bugcrowd.com/submissions/new"
```

## 4. 受け入れ基準 (Definition of Done)

### 4.1 機能受け入れ

- ✅ 7 ルート全てで `render_for_route(advisory, route, context)` が成功する
- ✅ 各ルートで必須フィールドが欠けると `RouteError` が発生する
- ✅ どのテンプレートを通しても `FORBIDDEN_PHRASES` が混入すれば `ExtortionLanguageError`
- ✅ MITRE 出力に Vendor Contact Timeline (`ContactAttempt` の一覧) がレンダリングされる
- ✅ `suzaku herald list-routes` で 8 ルートが一覧される (GHSA + 新規 7)
- ✅ `suzaku herald submit huntr advisory.json --context ctx.json` で huntr 用 Markdown を生成
- ✅ ルート別の追加フィールドが Advisory 本体に侵入していない (`Advisory` 定義を変更しない)

### 4.2 品質ゲート

- ✅ `pytest` 全件パス (新規追加 25+ tests)
- ✅ `ruff check` clean
- ✅ `mypy --strict` clean
- ✅ カバレッジ 80% 以上を維持

### 4.3 ガードの維持

- ✅ Phase 1 のテスト 244 件は引き続きパス
- ✅ `Advisory` データクラスのフィールドは変更しない (後方互換)
- ✅ `render_ghsa(advisory)` は `render_for_route(advisory, Route.GHSA)` の薄いラッパとして残す
- ✅ Phase 1 で書いた GHSA テンプレートも変更しない

## 5. 実装順序 (TDD)

### Step D-1: SPEC + 骨格 (30 分)
- 本 SPEC を `docs/SPEC-phase2-herald-routes.md` として確定
- `src/suzaku/herald/routes.py` の dataclass / enum / ROUTE_TEMPLATES スケルトン
- `routes.yaml` の追加

### Step D-2: テンプレート 7 本 (1 時間)
- `mitre_cna_lr.md.j2`, `huntr.md.j2`, `jpcert.txt.j2`, `wordfence.md.j2`, `patchstack.md.j2`, `hackerone.md.j2`, `bugcrowd.md.j2`

### Step D-3: ディスパッチャ + 検証 (1 時間)
- `render_for_route()` の実装 + ルート別必須フィールド検証
- `tests/integration/test_herald_routes.py` (各ルート最低 3 テスト: 成功 / 必須欠落 / 禁止語ガード)

### Step D-4: CLI 統合 (30 分)
- `herald submit <route>` / `herald list-routes` を `src/suzaku/herald/cli.py` に追加
- `tests/unit/test_cli.py` に CLI 統合テスト 3 件追加

### Step D-5: ドキュメント (15 分)
- `docs/USAGE.md` に Phase 2-D の使用例セクション追加
- `docs/ARCHITECTURE.md` に Phase 2-D の差分追記

## 6. リスクと対応

| リスク | 対応 |
|---|---|
| 申請 API の仕様変更 | テンプレートのみ提供し、実 API 送信は実装しない (人間が手動投稿) |
| MITRE 経路の濫用 | Chronicle Day 60+ アラートと連携した実装ガイドを `USAGE.md` に明記 |
| 個人情報の漏洩 | reporter 情報は `Advisory.reporter_*` のまま、ルート別 context にも reporter は含めない |
| 申請先プラットフォームのレート制限 | 自動送信を実装しないので影響なし |
| エコシステム判定の誤検出 (Wordfence/Patchstack/huntr) | ユーザが明示的にルートを指定する設計で誤検出を排除 |

## 7. Phase 2-D の範囲外 (Out of scope)

- 申請 API への自動送信 (POST etc)
- 申請ステータスの追跡 (CVE 採番待ち / 修正待ち)
- 報酬受領フローや交渉
- 国際的な PSIRT 連携 (FIRST.org SIG など)
- 既存の GHSA テンプレートの再設計
- 言語切替 (JPCERT は日本語専用、他は英語のみ)

これらは Phase 3 以降で検討する。

## 8. 後方互換性

- `render_ghsa(advisory)` は内部で `render_for_route(advisory, Route.GHSA)` を呼ぶ薄いラッパとして残す
- `render_email(advisory)` は変更なし (vendor 向けメールは別経路)
- 既存 `Advisory` フィールドは追加・変更しない
- Phase 1 のテスト 244 件は変更不要

## 9. 参考リンク

- MITRE CNA-LR: https://www.cve.org/PartnerInformation/ListofPartners/partner/MITRE-CNA-LR
- huntr.dev: https://huntr.com/
- JPCERT/CC: https://www.jpcert.or.jp/vh/
- Wordfence: https://www.wordfence.com/threat-intel/
- Patchstack: https://patchstack.com/
- HackerOne disclosure guidelines: https://docs.hackerone.com/
- Bugcrowd disclosure: https://www.bugcrowd.com/resources/
