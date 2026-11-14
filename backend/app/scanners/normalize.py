"""Persist normalized findings with fingerprint-based deduplication."""

import hashlib
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingSeverity
from app.scanners.base import NormalizedFinding

SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


def fingerprint(nf: NormalizedFinding) -> str:
    """Same issue at the same location => same fingerprint, whichever tool found it."""
    key = f"{nf.dedup_key.strip().lower()}|{(nf.location or '').strip().lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


def _merge_list(current: list[str] | None, extra: list[str]) -> list[str]:
    merged = list(current or [])
    for item in extra:
        if item not in merged:
            merged.append(item)
    return merged


def save_findings(
    db: Session,
    scan_id: uuid.UUID,
    scanner_run_id: uuid.UUID,
    scanner: str,
    findings: list[NormalizedFinding],
) -> tuple[int, int]:
    """Insert new findings, merge re-detections. Returns (created, merged)."""
    created = merged = 0
    for nf in findings:
        fp = fingerprint(nf)
        existing = db.scalar(
            select(Finding).where(Finding.scan_id == scan_id, Finding.fingerprint == fp)
        )
        if existing is not None:
            existing.detected_by = _merge_list(existing.detected_by, [scanner])
            existing.references = _merge_list(existing.references, nf.references)
            if SEVERITY_RANK[nf.severity] > SEVERITY_RANK[existing.severity]:
                existing.severity = nf.severity
            merged += 1
            continue
        db.add(Finding(
            scan_id=scan_id,
            scanner_run_id=scanner_run_id,
            scanner=scanner,
            detected_by=[scanner],
            title=nf.title[:255],
            severity=nf.severity,
            description=nf.description,
            recommendation=nf.recommendation,
            location=(nf.location or None) and nf.location[:2048],
            evidence=nf.evidence,
            original_severity=nf.original_severity,
            confidence=nf.confidence,
            source_id=nf.source_id,
            cwe=nf.cwe,
            references=nf.references or None,
            fingerprint=fp,
        ))
        db.flush()  # keep the (scan_id, fingerprint) lookup above accurate
        created += 1
    return created, merged
