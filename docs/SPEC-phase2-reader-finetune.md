# Suzaku Phase 2-A2 — Reader Fine-tuning Pipeline 詳細仕様

> 対象: Reader モジュール ② のローカル LLM ファインチューニング基盤
> 前提: Phase 2-A1 (Reader Core) 完了 = 統合ブランチに merge 済み
> ステータス: **実装は Phase 2-A1 完了後に着手** (本ドキュメントは構想を凍結する目的)

## 1. 目的

Phase 2-A1 で `qwen2.5-coder:14b` (汎用コードモデル) を Reader のバックエンドとして採用したが、**Suzaku 用途 (脆弱性発見の仮説生成)** に特化させると精度が大きく上がる余地がある。本 Phase で:

1. Suzaku が過去に出した Findings + 公開 CVE の修正パッチを **ラベル付きデータセット** に整形
2. ベースモデル (`qwen2.5-coder:14b` 等) を **LoRA / QLoRA** で軽量 fine-tune
3. fine-tuned モデルを **GGUF にエクスポート** して Ollama 経由で配信
4. 評価指標で精度を継続測定

クラウド LLM へのデータ流出は避け、すべてローカル GPU で完結させる。

## 2. 絶対遵守の原則 (Phase 1 から継承)

1. **本番アクセス禁止** — fine-tuning でも外部 API を呼ばない (Hugging Face Hub の参照は許容)
2. **クラウド LLM 不使用** — 学習データはローカルのみ
3. **武器化エクスプロイト自動公開禁止** — fine-tuned モデルから完全 PoC を吐かないよう RLHF/DPO は採用しない (SFT のみ)
4. **シークレットの直書き禁止** — HF Hub token は環境変数 (任意)
5. **証跡の改ざん検知** — 学習データセット + 学習済み LoRA adapter の SHA-256 を `evidence.lock` に記録
6. **過剰実装の禁止** — RLHF / GRPO / 大規模 distributed training は範囲外。**LoRA SFT のみ**

新規禁則:

7. **未公開脆弱性情報を学習データに含めない** — Suzaku 内部の Finding のうち `state in {NEW, VALIDATING, POC_BUILDING}` は学習除外。`PUBLISHED` のみ使う
8. **報酬要求・脅迫的応答を学習させない** — `email_tmpl.FORBIDDEN_PHRASES` を含むサンプルは学習データから除外
9. **学習データに個人情報が混入していないか必ず PII スクリーニング**

## 3. 設計

### 3.1 データセット構築

`src/suzaku/reader/finetune/dataset.py`:

データソース (ローカル):

| Source | 用途 | 抽出方法 |
|---|---|---|
| `published Findings` (Phase 1 出力) | 入力: snippet → 出力: CWE + rationale | `models.Finding` + `Submission` を join |
| **Lineage NVD JSON** (Phase 2-C 連携) | 入力: 修正前 patch context → 出力: CWE + flow | `lineage cve-import` の成果物を再利用 |
| Compass ルール hit + 人手ラベル | 真陽性確認のサンプリング | `compass scan --json` をスポット採取 |

データセット形式 (JSON Lines):

```jsonl
{"instruction": "Analyze the following code excerpt for potential vulnerabilities ...",
 "input": "<code snippet, max 4096 chars>",
 "output": "{\"cwe_candidates\": [\"CWE-22\", \"CWE-918\"], \"rationale\": \"...\"}",
 "metadata": {"source": "finding", "id": "F-...", "state": "published"}}
```

サンプル数の目標: **3,000-10,000 件** (LoRA なら十分)。

### 3.2 学習スクリプト

`src/suzaku/reader/finetune/train.py`:

- ベース: **Unsloth** (`unsloth` library) — qwen2.5-coder を 4-bit でロード + LoRA で学習可能 (低 VRAM)
- ハイパラ: LoRA rank=16, alpha=32, dropout=0.05, lr=2e-4, batch_size=auto-detect, epochs=3-5
- 学習方法: SFT (Supervised Fine-Tuning) only (RLHF/DPO は範囲外)
- 出力: `./reader/finetuned/<run_id>/` 配下に LoRA adapter + tokenizer + config

```bash
suzaku reader finetune train \
    --base qwen2.5-coder:14b \
    --dataset ./data/reader-sft.jsonl \
    --epochs 3 \
    --output ./reader/finetuned/run-001
```

### 3.3 GGUF エクスポート + Ollama 配信

`src/suzaku/reader/finetune/export.py`:

1. `llama.cpp` の `convert_hf_to_gguf.py` を呼んで GGUF 化
2. 量子化 (`q4_k_m` 既定) を実行
3. `Modelfile` を生成し `ollama create suzaku-reader-coder:latest -f Modelfile` でローカル登録

```bash
suzaku reader finetune export \
    --run ./reader/finetuned/run-001 \
    --quant q4_k_m \
    --tag suzaku-reader-coder:14b
```

エクスポート完了後は通常の Ollama モデルとして `--model suzaku-reader-coder:14b` で利用できる。

### 3.4 評価指標 (eval.py)

`src/suzaku/reader/finetune/eval.py`:

- **CWE Top-1 / Top-3 accuracy**: ラベル CWE と仮説の一致率
- **JSON Schema 準拠率**: 出力が Pydantic でパースできた割合
- **ハルシネーション率**: 存在しないファイルパス / 行番号を返した割合
- **本番アクセス漏洩テスト**: 出力に `http://` を含む public URL が出ないか

```bash
suzaku reader finetune eval \
    --model suzaku-reader-coder:14b \
    --eval-set ./data/reader-eval.jsonl
```

評価結果は `evaluation.json` に保存し、`evidence.lock` でハッシュ管理。

### 3.5 ファイル構造

```
src/suzaku/reader/finetune/
├── __init__.py
├── dataset.py        # データセット構築 (Finding + Lineage)
├── train.py          # Unsloth + LoRA 学習スクリプト
├── export.py         # HF -> GGUF -> Ollama Modelfile 生成
├── eval.py           # CWE accuracy / schema 準拠 / hallucination
├── cli.py            # suzaku reader finetune <subcommand>
└── data/
    ├── system_prompt.txt
    └── modelfile.j2  # Ollama Modelfile テンプレ
```

## 4. 受け入れ基準 (DoD)

### 4.1 機能受け入れ

- ✅ `suzaku reader finetune build-dataset` で 1,000+ サンプルの JSONL が生成される
- ✅ サンプルから未公開 Finding (`state != PUBLISHED`) が完全除外される
- ✅ `suzaku reader finetune train` が GPU でも CPU でも (低速ながら) 動作 (CPU 動作は `--epochs 1 --max-samples 100` 等で smoke test 可能)
- ✅ `suzaku reader finetune export` で GGUF + Modelfile が生成される
- ✅ `ollama list` に `suzaku-reader-coder` が現れ、`suzaku reader read` でこのモデルが指定できる
- ✅ `eval` で CWE Top-3 accuracy が **ベースモデルより 10pt 以上向上** (smoke test data)
- ✅ 評価結果に "pay first" / "ransom" 等の禁止語が **0 件**

### 4.2 品質ゲート

- ✅ pytest 全件パス (mock 中心、実 GPU は CI から除外)
- ✅ ruff check clean
- ✅ mypy --strict clean
- ✅ カバレッジ 80% 以上を維持

### 4.3 ガードの維持

- ✅ Phase 1/2-D/2-B/2-A1 の全テストパス
- ✅ Witness Guard / ACCS Guard / Extortion Guard が引き続き発火

## 5. 範囲外 (本 SPEC でも扱わない)

- RLHF / DPO / GRPO 等の強化学習
- マルチノード distributed training
- LoRA 以外の方法 (full fine-tune / prefix tuning 等)
- 自動データセット拡張 (synthetic data 生成)
- Compass ルール自動生成への利用 (Phase 3)

## 6. 参考

- Unsloth: https://github.com/unslothai/unsloth
- llama.cpp GGUF: https://github.com/ggerganov/llama.cpp/blob/master/convert_hf_to_gguf.py
- Ollama Modelfile: https://github.com/ollama/ollama/blob/main/docs/modelfile.md
- LoRA: Hu et al. 2021 (https://arxiv.org/abs/2106.09685)
