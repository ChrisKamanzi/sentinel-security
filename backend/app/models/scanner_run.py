import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ScannerRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScannerRun(Base):
    """One execution of one scanner (nmap, nuclei, ...) within a Scan."""

    __tablename__ = "scanner_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanner: Mapped[str] = mapped_column(String(40), nullable=False)
    # 1 for the first start of this scan, 2 for the next, ... (timestamps only
    # have one-second resolution in SQLite, so they cannot order attempts).
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Position in the pipeline for this assessment (0 = first).
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[ScannerRunStatus] = mapped_column(
        Enum(ScannerRunStatus, native_enum=False),
        nullable=False,
        default=ScannerRunStatus.PENDING,
        index=True,
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Exact argv executed (list of strings) for transparency/reproducibility.
    command: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Structured, machine-readable results consumed by later pipeline stages
    # (e.g. Nmap's discovered HTTP services feed Nuclei/FFUF/ZAP).
    artifacts: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Raw machine-readable tool output (e.g. Nmap XML), size-capped.
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="runs")
