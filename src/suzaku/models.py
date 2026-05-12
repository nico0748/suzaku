"""Suzaku 共通データモデル (Pydantic v2)。

各モジュール (Sentinel / Compass / Witness / Herald / Chronicle) はこの
データモデル経由でデータを受け渡す。
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingState(StrEnum):
    NEW = "new"
    VALIDATING = "validating"
    POC_BUILDING = "poc_building"
    READY_TO_SUBMIT = "ready_to_submit"
    SUBMITTED = "submitted"
    RESERVED = "reserved"
    PUBLISHED = "published"
    REJECTED = "rejected"
    DISPUTED = "disputed"


class Route(StrEnum):
    GHSA = "ghsa"
    MITRE = "mitre"
    HUNTR = "huntr"
    JPCERT = "jpcert"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    WORDFENCE = "wordfence"
    PATCHSTACK = "patchstack"


class VendorState(StrEnum):
    NO_RESPONSE = "no_response"
    ACKNOWLEDGED = "acknowledged"
    FIXING = "fixing"
    FIXED = "fixed"
    REJECTED = "rejected"


class Target(BaseModel):
    """Sentinel が評価する対象 OSS。"""

    name: str
    url: HttpUrl
    language: str
    star_count: int = Field(ge=0)
    last_commit_at: datetime
    score: float = Field(ge=0.0, le=10.0)
    signals: dict[str, float]
    evaluated_at: datetime = Field(default_factory=_utcnow)


class Finding(BaseModel):
    """Compass / Reader が検出した脆弱性候補。"""

    id: str
    target_url: HttpUrl
    category: str
    severity: Severity
    cwe: str | None = None
    file_path: str
    line_number: int = Field(ge=0)
    snippet: str
    state: FindingState = FindingState.NEW
    discovered_at: datetime = Field(default_factory=_utcnow)


class PoCArtifact(BaseModel):
    """Witness が記録する PoC エビデンス。"""

    finding_id: str
    dockerfile_path: str
    compose_path: str
    steps_md_path: str
    affected_version: str
    fixed_version: str | None = None
    commit_sha: str
    evidence_hash: str


class Submission(BaseModel):
    """Herald が生成する申請データ。"""

    finding_id: str
    route: Route
    cvss_vector: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    cwe: str
    affected_versions: str
    fixed_version: str | None = None
    reference_urls: list[HttpUrl] = Field(default_factory=list)
    poc_artifact_id: str
    submitted_at: datetime | None = None
    cve_id: str | None = None


class Disclosure(BaseModel):
    """Chronicle が管理する開示タイムライン。"""

    submission_id: str
    day_0: datetime
    day_3_done: bool = False
    day_14_done: bool = False
    day_30_done: bool = False
    day_60_done: bool = False
    day_90_done: bool = False
    publication_planned_at: datetime | None = None
    vendor_state: VendorState = VendorState.NO_RESPONSE
