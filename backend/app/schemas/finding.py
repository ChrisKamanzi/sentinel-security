import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.models.finding import FindingSeverity
from app.schemas.types import Title255, reject_null


class FindingCreate(BaseModel):
    """Manual finding entry. Scanner findings are created by the orchestrator."""

    title: Title255
    severity: FindingSeverity = FindingSeverity.INFO
    description: str | None = None
    recommendation: str | None = None
    location: str | None = Field(default=None, max_length=2048)
    evidence: str | None = None


class FindingUpdate(BaseModel):
    title: Annotated[Title255 | None, AfterValidator(reject_null)] = None
    severity: Annotated[FindingSeverity | None, AfterValidator(reject_null)] = None
    description: str | None = None
    recommendation: str | None = None
    location: str | None = Field(default=None, max_length=2048)
    evidence: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: FindingSeverity
    description: str | None
    recommendation: str | None
    location: str | None  # affected endpoint (host:port, URL, ...)
    evidence: str | None
    created_at: datetime
    # Scanner provenance (null for manually entered findings)
    scanner: str | None = None
    scanner_run_id: uuid.UUID | None = None
    detected_by: list[str] | None = None
    source_id: str | None = None
    original_severity: str | None = None
    confidence: str | None = None
    cwe: str | None = None
    references: list[str] | None = None
