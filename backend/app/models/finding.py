import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(Base):
    __tablename__ = "findings"
    # One row per (scan, fingerprint): re-detections are merged, not duplicated.
    # NULL fingerprints (manual findings) never collide in SQLite.
    __table_args__ = (
        Index("uq_findings_scan_fingerprint", "scan_id", "fingerprint", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=False,
        default=FindingSeverity.INFO,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    location: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # --- Scanner provenance (all nullable: manual findings have none) -------
    scanner: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    scanner_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scanner_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Every scanner that reported this same issue (deduplicated by fingerprint).
    detected_by: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    # Tool-specific identifier: Nuclei template-id, ZAP plugin id, nmap port key.
    source_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Severity exactly as the tool reported it (null if the tool has none).
    original_severity: Mapped[str | None] = mapped_column(String(40), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True)
    references: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
