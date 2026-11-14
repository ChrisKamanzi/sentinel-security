"""Assessment orchestration: runs the selected scanners for one Scan, in
pipeline order, one assessment at a time.

Every scanner execution is preceded by a fresh scope/authorization check
(app.core.scope.authorize_scan). A scope failure aborts the remaining scanners;
any other scanner failure is recorded and the pipeline continues, so scanners
stay independent.
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.scope import ScopeError, authorize_scan
from app.models.scan import Scan, ScanStatus
from app.models.scanner_run import ScannerRun, ScannerRunStatus
from app.scanners.base import ScanContext, ScannerError, ScannerUnavailable
from app.scanners.normalize import save_findings
from app.scanners.registry import SCANNERS

logger = logging.getLogger(__name__)

ACTIVE_RUN_STATUSES = (ScannerRunStatus.PENDING, ScannerRunStatus.RUNNING)

_assessment_lock = threading.Lock()


class AssessmentConflict(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def assessment_in_progress(db: Session) -> bool:
    active_runs = db.scalar(
        select(func.count()).select_from(ScannerRun)
        .where(ScannerRun.status.in_(ACTIVE_RUN_STATUSES))
    )
    running_scans = db.scalar(
        select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.RUNNING)
    )
    return bool(active_runs or running_scans)


def prepare_assessment(
    db: Session, scan: Scan, scanners: list[str], options: dict[str, BaseModel]
) -> list[ScannerRun]:
    """Queue one ScannerRun per selected scanner (already in pipeline order)."""
    if assessment_in_progress(db):
        raise AssessmentConflict("Another assessment is already queued or running")
    scan.status = ScanStatus.QUEUED
    scan.scanner = ",".join(scanners)[:40]
    scan.options = {name: opts.model_dump() for name, opts in options.items()}
    scan.error_message = None
    scan.started_at = None
    scan.completed_at = None
    attempt = (db.scalar(
        select(func.max(ScannerRun.attempt)).where(ScannerRun.scan_id == scan.id)
    ) or 0) + 1
    runs = [
        ScannerRun(scan_id=scan.id, scanner=name, order=i, attempt=attempt,
                   status=ScannerRunStatus.PENDING)
        for i, name in enumerate(scanners)
    ]
    db.add_all(runs)
    db.commit()
    return runs


def run_assessment(scan_id: uuid.UUID, bind: Engine) -> None:
    """Background entry point. Uses its own sessions on the given engine."""
    factory = sessionmaker(bind=bind, autoflush=False, autocommit=False)
    if not _assessment_lock.acquire(blocking=False):
        with factory() as db:
            _fail_queued(db, scan_id, "Another assessment is already running")
        return
    try:
        with factory() as db:
            _execute(db, scan_id)
    except Exception:  # never let a background task die silently
        logger.exception("Assessment %s crashed", scan_id)
        with factory() as db:
            _fail_queued(db, scan_id, "Assessment crashed unexpectedly; see server logs")
    finally:
        _assessment_lock.release()


def _fail_queued(db: Session, scan_id: uuid.UUID, reason: str) -> None:
    db.rollback()
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    for run in scan.runs:
        if run.status in ACTIVE_RUN_STATUSES:
            run.status = ScannerRunStatus.FAILED
            run.error_message = reason
            run.completed_at = _now()
    scan.status = ScanStatus.FAILED
    scan.error_message = reason
    scan.completed_at = _now()
    db.commit()


def _execute(db: Session, scan_id: uuid.UUID) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    runs = [r for r in scan.runs if r.status == ScannerRunStatus.PENDING]
    runs.sort(key=lambda r: r.order)
    scan.status = ScanStatus.RUNNING
    scan.started_at = _now()
    db.commit()

    previous: dict[str, dict] = {}
    abort_reason: str | None = None

    for run in runs:
        if abort_reason:
            run.status = ScannerRunStatus.SKIPPED
            run.error_message = abort_reason
            db.commit()
            continue

        run.status = ScannerRunStatus.RUNNING
        run.started_at = _now()
        run.progress = 5
        db.commit()
        started = time.monotonic()

        def report_progress(pct: int, _run=run) -> None:
            _run.progress = max(0, min(99, int(pct)))
            db.commit()

        try:
            # Scope check immediately before EVERY scanner execution.
            scope = authorize_scan(db, scan_id)
            scanner_cls = SCANNERS.get(run.scanner)
            if scanner_cls is None:
                raise ScannerUnavailable(f"scanner '{run.scanner}' is not implemented")
            path = scanner_cls.locate()
            if path is None:
                raise ScannerUnavailable(f"{scanner_cls.display_name} is not installed")
            options = scanner_cls.Options.model_validate((scan.options or {}).get(run.scanner, {}))
            ctx = ScanContext(
                scan_id=scan_id,
                target_id=scope.target_id,
                host=scope.host,
                ips=scope.ips,
                base_url=scope.base_url,
                target_url=scope.target_url,
                options=options,
                previous=dict(previous),
                report_progress=report_progress,
                revalidate=lambda: authorize_scan(db, scan_id),
            )
            run.progress = 10
            db.commit()

            output = scanner_cls(path).run(ctx)

            created, merged = save_findings(db, scan_id, run.id, run.scanner, output.findings)
            run.command = output.command
            run.exit_code = output.exit_code
            run.artifacts = output.artifacts
            run.raw_output = output.raw_output
            run.findings_count = created + merged
            run.status = ScannerRunStatus.COMPLETED
            run.progress = 100
            previous[run.scanner] = output.artifacts
        except ScopeError as exc:
            db.rollback()
            run.status = ScannerRunStatus.FAILED
            run.error_message = f"Scope check failed: {exc}"
            abort_reason = "Skipped because the scope check failed"
        except ScannerError as exc:
            db.rollback()
            run.status = ScannerRunStatus.FAILED
            run.error_message = str(exc)
            if exc.process is not None:
                run.command = exc.process.argv
                run.exit_code = exc.process.exit_code
                run.raw_output = (exc.process.stdout or exc.process.stderr) or None
        except Exception as exc:
            logger.exception("Scanner %s failed in scan %s", run.scanner, scan_id)
            db.rollback()
            run.status = ScannerRunStatus.FAILED
            run.error_message = f"Unexpected error: {type(exc).__name__}: {exc}"
        finally:
            run.completed_at = _now()
            run.duration_seconds = round(time.monotonic() - started, 3)
            db.commit()

    statuses = [r.status for r in runs]
    failed = [r for r in runs if r.status != ScannerRunStatus.COMPLETED]
    if statuses and all(s == ScannerRunStatus.COMPLETED for s in statuses):
        scan.status = ScanStatus.COMPLETED
    elif any(s == ScannerRunStatus.COMPLETED for s in statuses):
        scan.status = ScanStatus.PARTIAL
    else:
        scan.status = ScanStatus.FAILED
    scan.error_message = (
        "; ".join(f"{r.scanner}: {r.error_message}" for r in failed)[:4000] or None
    )
    scan.completed_at = _now()
    db.commit()


def recover_interrupted_assessments(factory: sessionmaker) -> int:
    """On startup: anything left queued/running was interrupted by a restart."""
    reason = "Interrupted: the server stopped before this finished"
    with factory() as db:
        runs = db.scalars(
            select(ScannerRun).where(ScannerRun.status.in_(ACTIVE_RUN_STATUSES))
        ).all()
        scan_ids = {r.scan_id for r in runs}
        scan_ids.update(db.scalars(select(Scan.id).where(Scan.status == ScanStatus.RUNNING)))
        for run in runs:
            run.status = ScannerRunStatus.FAILED
            run.error_message = reason
            run.completed_at = _now()
        for sid in scan_ids:
            scan = db.get(Scan, sid)
            if scan is not None:
                scan.status = ScanStatus.FAILED
                scan.error_message = reason
                scan.completed_at = scan.completed_at or _now()
        db.commit()
        return len(scan_ids)
