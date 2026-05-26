"""``/api/lineage/*`` — CVE variant analysis パイプライン。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from suzaku.lineage.egress import LineageEgressError
from suzaku.lineage.extract import hunks_to_rules
from suzaku.lineage.github_patches import GitHubPatchError, fetch_commit_diff
from suzaku.lineage.models import CVERecord, VariantRule, variant_rule_dump
from suzaku.lineage.nvd import fetch_nvd, load_nvd_single
from suzaku.lineage.scan import scan_with_variant_rules

router = APIRouter(prefix="/api/lineage", tags=["lineage"])


class LineageIngestRequest(BaseModel):
    cve: str | None = Field(
        default=None,
        description="NVD API から取得する CVE id (例: CVE-2026-42281)。--file と排他",
    )
    file: str | None = Field(
        default=None,
        description="ローカルの NVD JSON ファイルパス。--cve と排他",
    )


class LineageExtractRequest(BaseModel):
    cve_record: dict[str, Any] = Field(
        description="CVERecord の JSON dump。`ingest` の出力をそのまま渡す"
    )
    commit_urls: list[str] = Field(
        default_factory=list,
        description="commit URL の追加注入 (NVD references に commit が無いケース)",
    )
    max_rules: int = Field(default=5, ge=1, le=20)
    token: str | None = Field(default=None, description="GitHub PAT")


class LineageScanRequest(BaseModel):
    repo_path: str
    rules: list[dict[str, Any]] = Field(
        description="VariantRule の JSON 配列。`extract` の出力をそのまま渡す"
    )


@router.post("/ingest", response_model=CVERecord)
def post_ingest(req: LineageIngestRequest) -> CVERecord:
    """NVD API またはローカル JSON から CVERecord を取得する。"""
    if (req.cve is None) == (req.file is None):
        raise HTTPException(
            status_code=400, detail="exactly one of 'cve' or 'file' is required"
        )
    if req.cve is not None:
        return fetch_nvd(req.cve)
    assert req.file is not None
    path = Path(req.file)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"file not found: {req.file}")
    return load_nvd_single(path)


@router.post("/extract", response_model=list[dict[str, Any]])
def post_extract(req: LineageExtractRequest) -> list[dict[str, Any]]:
    """CVE record + commit diff から VariantRule を抽出する。"""
    record = CVERecord.model_validate(req.cve_record)
    urls = [str(u) for u in record.commit_urls] + req.commit_urls

    hunks = []
    for url in urls:
        try:
            hunks.extend(fetch_commit_diff(url, token=req.token))
        except GitHubPatchError:
            # 取得できない commit は skip。Lineage CLI と同じ寛容な挙動。
            continue

    rules = hunks_to_rules(record, hunks, max_rules=req.max_rules)
    return [variant_rule_dump(r) for r in rules]


@router.post("/scan", response_model=list[dict[str, Any]])
def post_scan(req: LineageScanRequest) -> list[dict[str, Any]]:
    """VariantRule[] で repo をスキャンする。"""
    repo = Path(req.repo_path)
    if not repo.exists() or not repo.is_dir():
        raise HTTPException(status_code=400, detail=f"repo_path not found: {req.repo_path}")
    try:
        rules = [VariantRule.model_validate(r) for r in req.rules]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid rules: {e}") from e

    findings = scan_with_variant_rules(repo, rules)
    return [f.model_dump(mode="json") for f in findings]


__all__ = ["LineageEgressError", "router"]
