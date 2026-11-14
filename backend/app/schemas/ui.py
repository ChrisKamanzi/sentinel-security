"""Response/request schemas for the web UI adapter (app.api.routes.ui).

These mirror the frontend contract in sentinel-security's src/lib/api/types.ts
and serialize with camelCase keys. Fields the backend has no real data for are
``None`` rather than invented values.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

Severity = Literal["critical", "high", "medium", "low", "info"]
# The backend's own scan statuses, passed through unchanged (incl. "partial").
AssessmentStatus = Literal["queued", "running", "completed", "partial", "failed"]
# "failed"/"skipped" extend the frontend's pending|running|done so a failed
# scanner is never displayed as done.
StageStatus = Literal["pending", "running", "done", "failed", "skipped"]


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class SeverityCounts(CamelModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class AssessmentOut(CamelModel):
    id: str
    target: str
    name: str
    status: AssessmentStatus
    progress: int
    started_at: str
    finished_at: str | None = None
    risk_score: int
    findings: SeverityCounts
    profile: str


class ScanStageOut(CamelModel):
    key: str
    label: str
    description: str
    status: StageStatus


class LogEntryOut(CamelModel):
    time: str
    message: str
    level: Literal["info", "warn", "finding"]


class ScanDetailOut(AssessmentOut):
    stages: list[ScanStageOut]
    log: list[LogEntryOut]
    # Not tracked by the backend: always null.
    requests_sent: int | None = None
    # From scanner artifacts (Nmap HTTP services + FFUF discoveries); null if none ran.
    endpoints_discovered: int | None = None


class EvidenceOut(CamelModel):
    # Scanners store one evidence text block, not a request/response pair.
    request: str
    response: str


class FindingOut(CamelModel):
    id: str
    title: str
    severity: Severity
    category: str
    scanner: str
    assessment_id: str
    target: str
    endpoint: str
    cwe: str
    # Only scanners that report CVSS (Nuclei) provide one; otherwise null.
    cvss: float | None = None
    # The backend has no triage workflow, so every finding is "open".
    status: Literal["open", "triaged", "fixed"] = "open"
    discovered_at: str
    description: str
    evidence: EvidenceOut
    business_impact: str
    remediation: list[str]


class FindingsOverTimePoint(CamelModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int


class ScanActivityPoint(CamelModel):
    day: str
    scans: int


class ActivityOut(CamelModel):
    id: str
    time: str
    message: str
    type: Literal["scan", "finding", "report"]


class DashboardSummaryOut(CamelModel):
    risk_score: int
    risk_trend: int
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    critical_findings: int
    breakdown: SeverityCounts
    findings_over_time: list[FindingsOverTimePoint]
    scan_activity: list[ScanActivityPoint]
    recent_activity: list[ActivityOut]


class ReportOut(CamelModel):
    id: str
    assessment_id: str
    title: str
    target: str
    generated_at: str
    # Reports are Markdown (app.services.report); not pdf/html/json.
    format: Literal["md"] = "md"
    size_kb: float
    findings: int


class NewAssessmentIn(CamelModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    name: str = Field(default="", max_length=120)
    authorized: bool
    profile: Literal["quick", "standard", "deep"]
    # UI test-module labels. The backend selects scanners per profile, so these
    # are accepted for compatibility but do not change what runs.
    modules: list[str] = Field(default_factory=list, max_length=20)
    auth_header: str | None = Field(default=None, max_length=4096)
    max_rps: int = Field(default=10, ge=1, le=100)
