import enum
import uuid
from datetime import datetime

from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"  # some scanners completed, others failed
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable FK to an approved Target. A scan is only accepted when it points
    # at an authorized Target (enforced in the API layer). Kept nullable so the
    # existing scans table can gain this column via a non-destructive migration.
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Denormalized URL actually scanned, derived from the approved Target.
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scanner: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False),
        nullable=False,
        default=ScanStatus.QUEUED,
        index=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Per-scanner options chosen when the assessment was started.
    options: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped["Project"] = relationship(back_populates="scans")
    target: Mapped["Target | None"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    analyses: Mapped[list["AIAnalysis"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="AIAnalysis.created_at",
    )
    runs: Mapped[list["ScannerRun"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScannerRun.attempt, ScannerRun.order",
    )
