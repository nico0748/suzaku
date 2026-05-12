"""Witness Reproducer — Docker 内 PoC 再現。

責務:
- Jinja テンプレートから Dockerfile / docker-compose.yml / steps.md を展開
- ``docker compose up`` / ``down`` をラップ
- 起動前にターゲットホストを :mod:`suzaku.witness.guard` でチェック

実 Docker 操作は :class:`Reproducer` の ``runner`` 引数経由で差し替え可能。
テストでは subprocess を直接呼ばないモック runner を注入する。
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from jinja2 import Environment, FileSystemLoader, select_autoescape

from suzaku.witness.guard import enforce_allowed

TEMPLATES_DIR = Path(__file__).parent / "templates" / "poc"

CommandResult = subprocess.CompletedProcess[str]
Runner = Callable[[Sequence[str], Path], CommandResult]


def _default_runner(cmd: Sequence[str], cwd: Path) -> CommandResult:
    """実環境用: subprocess.run でコマンドを実行する。"""
    return subprocess.run(
        list(cmd),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


@dataclass
class PoCContext:
    """テンプレート展開に渡すコンテキスト。"""

    finding_id: str
    category: str | None = None
    target_url: str | None = None
    affected_version: str | None = None
    commit_sha: str | None = None
    base_image: str = "alpine:3.20"
    extra_packages: list[str] = field(default_factory=list)
    entrypoint: str | None = None
    ports: list[int] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    steps: list[str] = field(default_factory=list)
    expected_result: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "target_url": self.target_url,
            "affected_version": self.affected_version,
            "commit_sha": self.commit_sha,
            "base_image": self.base_image,
            "extra_packages": self.extra_packages,
            "entrypoint": self.entrypoint,
            "ports": self.ports,
            "env": self.env,
            "steps": self.steps,
            "expected_result": self.expected_result,
        }


class Reproducer:
    """Docker Compose ベースの PoC 再現ハーネス。"""

    TEMPLATE_FILES: ClassVar[dict[str, str]] = {
        "Dockerfile.j2": "Dockerfile",
        "docker-compose.yml.j2": "docker-compose.yml",
        "steps.md.j2": "steps.md",
    }

    def __init__(
        self,
        pocs_dir: Path,
        templates_dir: Path = TEMPLATES_DIR,
        runner: Runner = _default_runner,
    ) -> None:
        self._pocs_dir = pocs_dir
        self._pocs_dir.mkdir(parents=True, exist_ok=True)
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(disabled_extensions=("j2",)),
            keep_trailing_newline=True,
        )
        self._runner = runner

    def poc_dir(self, finding_id: str) -> Path:
        d = self._pocs_dir / finding_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def init_poc(self, ctx: PoCContext) -> Path:
        """テンプレートを展開して PoC ディレクトリを準備する。"""
        target = self.poc_dir(ctx.finding_id)
        for tpl, out in self.TEMPLATE_FILES.items():
            rendered = self._env.get_template(tpl).render(**ctx.as_dict())
            (target / out).write_text(rendered, encoding="utf-8")
        return target

    def _compose(self, finding_id: str, args: Sequence[str]) -> CommandResult:
        return self._runner(["docker", "compose", *args], self.poc_dir(finding_id))

    def up(self, finding_id: str, target_host: str = "localhost") -> CommandResult:
        """``docker compose up`` を実行する。起動前に host をガードする。"""
        enforce_allowed(target_host)
        return self._compose(finding_id, ["up", "--build", "-d"])

    def down(self, finding_id: str) -> CommandResult:
        return self._compose(finding_id, ["down", "-v"])

    def logs(self, finding_id: str) -> CommandResult:
        return self._compose(finding_id, ["logs", "--no-color"])
