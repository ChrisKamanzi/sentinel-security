import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AIAnalysis(Base):
    """One Claude AI Analyst run over a scan's normalized findings."""

    __tablename__ = "ai_analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus, native_enum=False), nullable=False, default=AnalysisStatus.PENDING, index=True
    )
    model: Mapped[str] = mapped_column(String(80), nullable=False)  # requested model
    served_by_model: Mapped[str | None] = mapped_column(String(80), nullable=True)
    fallback_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redactions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overall_risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    technical_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Full validated analyst output (per-finding analyses, remediation plan, ...)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    usage: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="analyses")
