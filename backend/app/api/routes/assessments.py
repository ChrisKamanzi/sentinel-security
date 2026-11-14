import uuid
from collections import Counter

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope import ScopeError, authorize_scan
from app.database.database import get_db
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.schemas.assessment import (
    AssessmentRead,
    ScannerRunRead,
    StartAssessmentRequest,
    ToolStatusRead,
)
from app.scanners.registry import KNOWN_TOOLS, SCANNERS, order_scanners, tool_statuses
from app.services.orchestrator import AssessmentConflict, prepare_assessment, run_assessment

router = APIRouter(tags=["Assessments"])


def _get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _latest_runs(scan: Scan) -> list[ScannerRun]:
    """Runs of the most recent start (earlier attempts stay in /runs)."""
    if not scan.runs:
        return []
    latest = max(r.attempt for r in scan.runs)
    return sorted((r for r in scan.runs if r.attempt == latest), key=lambda r: r.order)


def _assessment_read(db: Session, scan: Scan) -> AssessmentRead:
    db.refresh(scan)
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    by_severity = {s.value: 0 for s in FindingSeverity}
    by_severity.update(Counter(f.severity.value for f in findings))
    duration = None
    if scan.started_at and scan.completed_at:
        duration = round((scan.completed_at - scan.started_at).total_seconds(), 3)
    return AssessmentRead(
        scan_id=scan.id,
        project_id=scan.project_id,
        target_id=scan.target_id,
        target_url=scan.target_url,
        status=scan.status,
        scanners=[s for s in scan.scanner.split(",") if s and s != "pending"],
        options=scan.options,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=duration,
        runs=[ScannerRunRead.model_validate(r) for r in _latest_runs(scan)],
        findings_total=len(findings),
        findings_by_severity=by_severity,
        findings_by_scanner=dict(Counter(f.scanner or "manual" for f in findings)),
    )


@router.get("/tools", response_model=list[ToolStatusRead])
def list_tools():
    """Installation status of every scanner in the planned workflow."""
    return [ToolStatusRead(**vars(t)) for t in tool_statuses()]


@router.post(
    "/scans/{scan_id}/start",
    response_model=AssessmentRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses={403: {"description": "Target out of scope"}, 409: {"description": "Conflict"}},
)
def start_assessment(
    scan_id: uuid.UUID,
    payload: StartAssessmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan = _get_scan_or_404(db, scan_id)

    unknown = sorted(set(payload.scanners) - KNOWN_TOOLS.keys())
    if unknown:
        raise HTTPException(422, detail=f"Unknown scanner(s): {', '.join(unknown)}")
    not_ready = sorted(set(payload.scanners) - SCANNERS.keys())
    if not_ready:
        raise HTTPException(422, detail=f"Scanner(s) not implemented yet: {', '.join(not_ready)}")
    scanners = order_scanners(payload.scanners)

    stray = sorted(set(payload.options) - set(scanners))
    if stray:
        raise HTTPException(422, detail=f"Options given for unselected scanner(s): {', '.join(stray)}")
    options: dict[str, BaseModel] = {}
    for name in scanners:
        try:
            options[name] = SCANNERS[name].Options.model_validate(payload.options.get(name, {}))
        except ValidationError as exc:
            raise HTTPException(
                422, detail={"scanner": name, "errors": exc.errors(include_url=False, include_context=False)}
            ) from exc

    # Pre-flight scope check (repeated before every scanner during the run).
    try:
        authorize_scan(db, scan.id)
    except ScopeError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Out of scope: {exc}") from exc

    missing = [SCANNERS[n].display_name for n in scanners if SCANNERS[n].locate() is None]
    if missing:
        raise HTTPException(409, detail=f"Not installed: {', '.join(missing)}")

    try:
        prepare_assessment(db, scan, scanners, options)
    except AssessmentConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    background_tasks.add_task(run_assessment, scan.id, db.get_bind())
    return _assessment_read(db, scan)


@router.get("/scans/{scan_id}/assessment", response_model=AssessmentRead)
def get_assessment(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    """Overall status, per-scanner progress/duration/errors and finding counts."""
    return _assessment_read(db, _get_scan_or_404(db, scan_id))


@router.get("/scans/{scan_id}/runs", response_model=list[ScannerRunRead])
def list_runs(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    """All scanner runs for a scan, including earlier attempts."""
    _get_scan_or_404(db, scan_id)
    stmt = (
        select(ScannerRun).where(ScannerRun.scan_id == scan_id)
        .order_by(ScannerRun.attempt, ScannerRun.order)
    )
    return db.scalars(stmt).all()


def _get_run_or_404(db: Session, run_id: uuid.UUID) -> ScannerRun:
    run = db.get(ScannerRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scanner run not found")
    return run


@router.get("/scanner-runs/{run_id}", response_model=ScannerRunRead)
def get_run(run_id: uuid.UUID, db: Session = Depends(get_db)):
    return _get_run_or_404(db, run_id)


@router.get("/scanner-runs/{run_id}/raw", response_class=PlainTextResponse)
def get_run_raw_output(run_id: uuid.UUID, db: Session = Depends(get_db)):
    """Raw machine-readable tool output (e.g. Nmap XML)."""
    return PlainTextResponse(_get_run_or_404(db, run_id).raw_output or "")
