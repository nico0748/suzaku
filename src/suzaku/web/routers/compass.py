"""``/api/compass/*`` — 危険関数 grep + パターンスキャン。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from suzaku.compass.grep_runner import GrepRunner, RipgrepNotFoundError
from suzaku.compass.rules import (
    RuleError,
    load_all_rules,
    load_rule_by_id,
)

router = APIRouter(prefix="/api/compass", tags=["compass"])


class CompassRuleSummary(BaseModel):
    id: str
    name: str
    cwe: str
    severity: str
    languages: list[str]


class CompassScanRequest(BaseModel):
    repo_path: str = Field(description="対象 repo の絶対パス")
    rule_ids: list[str] = Field(
        default_factory=list,
        description="ルール ID の配列。空配列なら同梱ルール全て (`--all` 相当)",
    )


class CompassScanResponse(BaseModel):
    repo_path: str
    rules_run: list[str]
    findings: list[dict[str, Any]]


@router.get("/rules", response_model=list[CompassRuleSummary])
def get_rules() -> list[CompassRuleSummary]:
    """同梱ルール一覧を返す。"""
    rules = load_all_rules()
    return [
        CompassRuleSummary(
            id=r.id,
            name=r.name,
            cwe=r.cwe,
            severity=r.severity.value,
            languages=sorted({p.language for p in r.patterns}),
        )
        for r in rules
    ]


@router.post("/scan", response_model=CompassScanResponse)
def post_scan(req: CompassScanRequest) -> CompassScanResponse:
    """``repo_path`` を ``rule_ids`` でスキャンする。空配列なら全ルール。"""
    repo = Path(req.repo_path)
    if not repo.exists() or not repo.is_dir():
        raise HTTPException(status_code=400, detail=f"repo_path not found: {req.repo_path}")

    try:
        rules = (
            load_all_rules()
            if not req.rule_ids
            else [load_rule_by_id(rid) for rid in req.rule_ids]
        )
    except RuleError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    runner = GrepRunner()
    all_findings = []
    rules_run: list[str] = []
    for r in rules:
        try:
            findings = runner.scan(repo, r)
        except RipgrepNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        rules_run.append(r.id)
        all_findings.extend(findings)

    return CompassScanResponse(
        repo_path=str(repo),
        rules_run=rules_run,
        findings=[f.model_dump(mode="json") for f in all_findings],
    )


__all__ = ["router"]
