"""Suzaku Reader Fine-tuning Pipeline (Phase 2-A2)。

詳細仕様: ``docs/SPEC-phase2-reader-finetune.md``

責務:
- 公開済み Finding + (任意) Lineage CVE データから SFT データセット構築
- Unsloth + LoRA で軽量 fine-tune (学習自体は GPU が必要、本パッケージは
  ラッパーのみ提供。GPU 無し環境では subprocess call が失敗する想定で
  テストはモック)
- HF -> GGUF 変換 + Ollama Modelfile 生成
- fine-tuned モデルの評価 (CWE accuracy / hallucination / 禁止語ガード)
"""
