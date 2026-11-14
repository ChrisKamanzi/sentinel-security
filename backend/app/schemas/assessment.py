import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.scan import ScanStatus
from app.models.scanner_run import ScannerRunStatus


class StartAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Scanner names; run in pipeline order regardless of the order given.
    scanners: list[str] = Field(default_factory=lambda: ["nmap"], min_length=1, max_length=10)
    # Per-scanner options keyed by scanner name, e.g. {"nmap": {"top_ports": 100}}.
    options: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ScannerRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    scanner: str
    attempt: int
    order: int
    status: ScannerRunStatus
    progress: int
    command: list[str] | None
    exit_code: int | None
    error_message: str | None
    findings_count: int
    artifacts: dict[str, Any] | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None


class AssessmentRead(BaseModel):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID | None
    target_url: str
    status: ScanStatus
    scanners: list[str]
    options: dict[str, Any] | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    runs: list[ScannerRunRead]
    findings_total: int
    findings_by_severity: dict[str, int]
    findings_by_scanner: dict[str, int]


class ToolStatusRead(BaseModel):
    name: str
    display_name: str
    implemented: bool
    available: bool
    path: str | None
    version: str | None
