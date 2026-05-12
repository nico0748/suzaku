"""HuggingFace LoRA -> GGUF -> Ollama Modelfile エクスポート (Phase 2-A2)。

実コマンド:
- llama.cpp の ``convert_hf_to_gguf.py`` (HF -> GGUF)
- llama.cpp の ``llama-quantize`` (量子化)
- ``ollama create <tag> -f Modelfile`` で登録

subprocess は :data:`CommandRunner` で差し替え可能 (テストで mock)。
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

DATA_DIR = Path(__file__).parent / "data"
MODELFILE_TEMPLATE = "modelfile.j2"
DEFAULT_SYSTEM_PROMPT_PATH = DATA_DIR / "system_prompt.txt"

DEFAULT_TEMPLATE_BODY = "{{ .System }}\n\n{{ .Prompt }}"
DEFAULT_QUANT = "q4_k_m"
DEFAULT_TAG = "suzaku-reader-coder:14b"

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _default_runner(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=False)


class ExportError(RuntimeError):
    """GGUF 変換 / Modelfile 生成 / Ollama 登録の失敗。"""


@dataclass
class ExportPlan:
    run_dir: Path
    output_dir: Path
    quant: str = DEFAULT_QUANT
    tag: str = DEFAULT_TAG
    convert_script: str = "convert_hf_to_gguf.py"  # llama.cpp 同梱
    quantize_binary: str = "llama-quantize"


def _render_modelfile(
    gguf_filename: str,
    system_prompt: str,
    template_body: str = DEFAULT_TEMPLATE_BODY,
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(DATA_DIR)),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(MODELFILE_TEMPLATE).render(
        gguf_filename=gguf_filename,
        system_prompt=system_prompt,
        template_body=template_body,
    )


def _ensure(binary: str) -> str:
    found = shutil.which(binary)
    if found is None:
        raise ExportError(f"{binary!r} not found in PATH")
    return found


def export_model(
    plan: ExportPlan,
    *,
    system_prompt: str | None = None,
    register_with_ollama: bool = False,
    runner: CommandRunner = _default_runner,
) -> dict[str, object]:
    """LoRA を GGUF にエクスポートし、Modelfile を生成する。"""
    if not plan.run_dir.is_dir():
        raise ExportError(f"run_dir not found: {plan.run_dir}")
    plan.output_dir.mkdir(parents=True, exist_ok=True)

    gguf_path = plan.output_dir / f"{plan.tag.replace(':', '_').replace('/', '_')}.gguf"

    convert = _ensure(plan.convert_script)
    quantize = _ensure(plan.quantize_binary)

    convert_cmd = [
        convert,
        str(plan.run_dir),
        "--outfile",
        str(gguf_path),
        "--outtype",
        "f16",
    ]
    convert_result = runner(convert_cmd)
    if convert_result.returncode != 0:
        raise ExportError(
            f"convert failed (code={convert_result.returncode}): "
            f"{convert_result.stderr.strip()[:200]}"
        )

    if plan.quant:
        quantized = plan.output_dir / gguf_path.with_suffix(f".{plan.quant}.gguf").name
        quant_cmd = [quantize, str(gguf_path), str(quantized), plan.quant]
        quant_result = runner(quant_cmd)
        if quant_result.returncode != 0:
            raise ExportError(
                f"quantize failed (code={quant_result.returncode}): "
                f"{quant_result.stderr.strip()[:200]}"
            )
        gguf_final = quantized
    else:
        gguf_final = gguf_path

    # Modelfile
    if system_prompt is None:
        system_prompt = DEFAULT_SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    modelfile_path = plan.output_dir / "Modelfile"
    modelfile_path.write_text(
        _render_modelfile(gguf_final.name, system_prompt=system_prompt),
        encoding="utf-8",
    )

    ollama_result: dict[str, object] | None = None
    if register_with_ollama:
        ollama = _ensure("ollama")
        register_cmd = [ollama, "create", plan.tag, "-f", str(modelfile_path)]
        rg = runner(register_cmd)
        ollama_result = {
            "command": register_cmd,
            "returncode": rg.returncode,
            "stderr": rg.stderr.strip()[:400],
        }
        if rg.returncode != 0:
            raise ExportError(
                f"`ollama create` failed (code={rg.returncode}): {rg.stderr.strip()[:200]}"
            )

    return {
        "tag": plan.tag,
        "gguf_path": str(gguf_final),
        "modelfile": str(modelfile_path),
        "ollama_registered": register_with_ollama,
        "ollama_result": ollama_result,
    }


__all__ = [
    "DEFAULT_QUANT",
    "DEFAULT_TAG",
    "CommandRunner",
    "ExportError",
    "ExportPlan",
    "export_model",
]
