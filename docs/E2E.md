# Suzaku End-to-End シナリオ

> Sentinel → Reader → Compass → Lineage → Witness → Herald → Chronicle の **完全な調査フロー** を 1 本のスクリプトに収めた実例。コピペで一通り体験できます。

詳細な解説は [`GETTING_STARTED.md`](./GETTING_STARTED.md)、コマンドのみは [`CHEATSHEET.md`](./CHEATSHEET.md) を参照。

---

## シナリオ: WordPress プラグインで CVE を取りに行く

### 前提

```bash
# 必須ツール
which rg                # ripgrep
docker --version        # docker
ollama --version        # Ollama (Reader を使う場合)

# 環境変数
export SUZAKU_GITHUB_TOKEN=ghp_...
```

### Stage 0: 環境セットアップ

```bash
git clone https://github.com/nico0748/suzaku
cd suzaku
pip install -e ".[dev]"
make check
mkdir -p work && cd work
```

### Stage 1: Sentinel — 候補抽出

```bash
suzaku sentinel scan \
    --language php \
    --topic wordpress-plugin \
    --min-stars 100 \
    --pushed-after 2026-01-01 \
    --top 20 \
    --json > targets.json

# 上位を確認
suzaku sentinel show targets.json
```

候補が出てきたら 1 件選び、ローカルに clone:

```bash
git clone https://github.com/example/vulnerable-plugin /tmp/target
```

### Stage 2: Reader — LLM で攻撃面を把握 (任意)

```bash
ollama serve &
ollama pull qwen2.5-coder:14b

suzaku reader check
suzaku reader read /tmp/target > reader_report.json
```

`reader_report.json` の `hypotheses[]` を眺めて、優先的に深掘りすべき sink を 2-3 個ピックアップ。

### Stage 3: Compass — 静的スキャン

```bash
suzaku compass scan /tmp/target --rule danger_funcs_php --json > danger_php.json
suzaku compass scan /tmp/target --rule patterns/zip_slip --json > zip_slip.json
suzaku compass scan /tmp/target --rule patterns/ssrf --json > ssrf.json

# Reader の仮説と照合: hypotheses で挙がった CWE と Compass ヒットが
# 重なる箇所を最優先で深掘りする
```

### Stage 4: Lineage — 既知 CVE の横展開

調査対象に類似機能を持つ既知 CVE を見つけたら、その修正パッチから変種を探します。

```bash
suzaku lineage ingest --cve CVE-2024-12345 --out cve.json
suzaku lineage extract cve.json --out variant_rules.json
suzaku lineage scan /tmp/target --rules variant_rules.json --out variants.json
```

Compass ヒットと突き合わせて、同一脆弱性パターンが残っていれば候補確定。

### Stage 5: Witness — Docker 内 PoC

候補が固まったら Docker 内で再現します。

```bash
suzaku witness init F-001 \
    --category ZipSlip \
    --affected-version '>=1.0.0,<1.2.3' \
    --commit $(cd /tmp/target && git rev-parse HEAD)

# pocs/F-001/ に Dockerfile / docker-compose.yml / steps.md
$EDITOR pocs/F-001/steps.md   # 再現手順を実装

suzaku witness reproduce F-001 --target-host localhost
# (中で実証)
suzaku witness stop F-001

# 証跡を記録
suzaku witness record F-001 \
    pocs/F-001/Dockerfile \
    pocs/F-001/docker-compose.yml \
    pocs/F-001/steps.md

suzaku witness verify F-001
```

### Stage 6: Herald — 5 点セット + 申請ルート

```bash
cat > advisory.json <<'JSON'
{
  "submission": {
    "product_name": "vulnerable-plugin",
    "vendor": "Example Inc.",
    "affected_versions": ">=1.0.0,<1.2.3",
    "cwe": "CWE-22",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "reproduction_steps_path": "./pocs/F-001/steps.md",
    "reference_urls": ["https://github.com/example/x/commit/abc"]
  },
  "summary": "Zip Slip during plugin import",
  "impact_description": "An attacker who can upload a crafted archive ...",
  "mitigation": "Validate each entry with os.path.realpath before write.",
  "steps": ["Send crafted zip", "Trigger import", "Observe path traversal"],
  "tested_version": "1.2.2",
  "commit_sha": "deadbeefcafe1234",
  "fixed_version": "1.2.3",
  "reporter_contact": "researcher@example.test",
  "reporter_name": "Suzaku Reporter"
}
JSON

# CVSS 確認
suzaku herald cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# → 9.8 / Critical

# 5 点セット検証
suzaku herald checklist advisory.json

# 申請テンプレート (用途別)
suzaku herald submit ghsa advisory.json > ghsa_advisory.md
suzaku herald submit wordfence advisory.json --context wp_ctx.json > wordfence.md
suzaku herald submit patchstack advisory.json --context wp_ctx.json > patchstack.md
suzaku herald email advisory.json > vendor_email.eml
```

```bash
# wp_ctx.json
cat > wp_ctx.json <<'JSON'
{"wp_plugin_slug": "vulnerable-plugin", "wp_active_installs": 5000}
JSON
```

### Stage 7: Chronicle — 90 日タイムライン

ベンダに通知したら、その日を Day 0 として Chronicle に登録します。

```bash
suzaku chronicle init S-001

# 状態確認 (cron で日次実行を推奨)
suzaku chronicle status S-001

# 返事が来たら
suzaku chronicle set-vendor S-001 acknowledged

# 修正リリースされたら
suzaku chronicle set-vendor S-001 fixed

# 修正後 +30 日経過後に公開 (ACCS Guard が機械的に検証)
suzaku chronicle publish S-001 --fixed-at 2026-03-01T00:00:00+00:00
```

Day 90 経過しても無応答なら、CNA-LR ルート (MITRE 直接申請) を Herald で:

```bash
cat > mitre_ctx.json <<'JSON'
{
  "vendor_contact_attempts": [
    {"attempted_at": "2026-01-01T00:00:00+00:00", "channel": "security@example.com", "response": "no_response"},
    {"attempted_at": "2026-01-15T00:00:00+00:00", "channel": "GitHub Issue #42", "response": "no_response"},
    {"attempted_at": "2026-02-01T00:00:00+00:00", "channel": "Twitter DM", "response": "no_response"}
  ]
}
JSON

suzaku herald submit mitre advisory.json --context mitre_ctx.json > mitre_cna_lr.md
```

---

## 安全機構が発火する例

調査の途中で **本番ホストに到達しようとした場合**:

```bash
suzaku witness reproduce F-001 --target-host wordpress.org
# → exit 4 ProductionAccessError
```

**通知前に公開しようとした場合**:

```bash
suzaku chronicle publish S-001     # まだ Day 0 経過直後
# → exit 5 ACCSViolationError
```

**脅迫的メール文面を生成しようとした場合**:

```bash
# advisory.json の summary に "pay first" を含む
suzaku herald submit ghsa advisory.json
# → exit 1 ExtortionLanguageError
```

これらは設計上の **正しい挙動** です。ガードに止められたら、まずアプローチ自体を見直してください。

---

## 完了基準 (DoD)

1. ✅ Sentinel で候補リスト + スコア
2. ✅ Reader で攻撃面の仮説 (任意だが推奨)
3. ✅ Compass + Lineage で実コードヒット確認
4. ✅ Witness で Docker 内 PoC + evidence.lock 記録
5. ✅ Herald で 5 点セット + GHSA (+ 必要に応じ Wordfence/Patchstack/MITRE)
6. ✅ Chronicle Day 0 開始 → Day 90 / 修正後 +30 日 で公開

これで 1 件の CVE 取得サイクルが完了します。
