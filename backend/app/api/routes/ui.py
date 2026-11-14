"""Web UI adapter: the exact API contract of the sentinel-security frontend.

Read endpoints map stored records (app.services.ui_views). Assessment creation
reuses the existing project -> target -> scan -> start workflow and its safety
checks; it never approves a target on its own. The frontend's "I am authorized"
checkbox is required but not sufficient: the URL must match a Target that was
already marked ``is_authorized`` through the targets API.
"""

import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope import ScopeError, authorize_scan, validate_host
from app.database.database import get_db
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.scanners import registry
from app.schemas.ui import (
    AssessmentOut,
    DashboardSummaryOut,
    FindingOut,
    NewAssessmentIn,
    ReportOut,
    ScanDetailOut,
    SeverityCounts,
)
from app.services import orchestrator, ui_views
from app.services.report import build_markdown_report

router = APIRouter(tags=["Web UI"])


def _get_scan_or_404(db: Session, scan_id: uuid.UUID, what: str = "Assessment") -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"{what} not found")
    return scan


# --- dashboard / assessments ------------------------------------------------------

@router.get("/dashboard/summary", response_model=DashboardSummaryOut)
def dashboard_summary(db: Session = Depends(get_db)):
    return ui_views.dashboard_summary(db)


@router.get("/assessments", response_model=list[AssessmentOut])
def list_assessments(db: Session = Depends(get_db)):
    return ui_views.list_assessments(db)


@router.get("/assessments/{assessment_id}", response_model=ScanDetailOut)
def get_assessment_detail(assessment_id: uuid.UUID, db: Session = Depends(get_db)):
    return ui_views.scan_detail(db, _get_scan_or_404(db, assessment_id))


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("target must be an http(s) URL")
    if parts.username or parts.password:
        raise ValueError("target URL must not contain credentials")
    if not parts.hostname:
        raise ValueError("target URL must include a hostname")
    port = parts.port or (443 if scheme == "https" else 80)  # .port raises on invalid ports
    return scheme, validate_host(parts.hostname), port


def _approved_target(db: Session, origin: tuple[str, str, int]) -> Target | None:
    """Most recently created authorized Target whose approved origin equals ``origin``."""
    candidates = db.scalars(
        select(Target)
        .where(Target.is_authorized.is_(True), Target.host == origin[1])
        .order_by(Target.created_at.desc())
    ).all()
    for target in candidates:
        try:
            if _origin(target.base_url or f"https://{target.host}") == origin:
                return target
        except ValueError:
            continue
    return None


def _profile_options(profile: str, max_rps: int) -> dict[str, dict]:
    return {
        "nmap": {"top_ports": 100} if profile == "quick" else {},
        "ffuf": {"rate_limit": min(max_rps, 100)},
        "nuclei": {"rate_limit": min(max_rps, 150)},
        "zap": {},
    }


@router.post(
    "/assessments",
    response_model=AssessmentOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        403: {"description": "Not confirmed, no approved target, or out of scope"},
        409: {"description": "Scanner not installed or another assessment is running"},
    },
)
def create_assessment(
    payload: NewAssessmentIn, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
):
    if not payload.authorized:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Authorization confirmation is required")
    if payload.auth_header and payload.auth_header.strip():
        raise HTTPException(422, detail="Authenticated scans are not supported by the backend yet")
    try:
        origin = _origin(payload.target)
    except ValueError as exc:
        raise HTTPException(422, detail=f"Invalid target URL: {exc}") from exc

    target = _approved_target(db, origin)
    if target is None:
        scheme, host, port = origin
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(f"No approved target matches {scheme}://{host}:{port}. Register it and mark it "
                    "authorized via /api/v1/projects/{project_id}/targets before scanning."),
        )

    scanners = registry.order_scanners(ui_views.PROFILE_SCANNERS[payload.profile])
    missing_impl = [n for n in scanners if n not in registry.SCANNERS]
    if missing_impl:
        raise HTTPException(422, detail=f"Scanner(s) not implemented yet: {', '.join(missing_impl)}")
    wanted = _profile_options(payload.profile, payload.max_rps)
    options: dict[str, BaseModel] = {}
    for name in scanners:
        option_cls = registry.SCANNERS[name].Options
        raw = {k: v for k, v in wanted.get(name, {}).items() if k in option_cls.model_fields}
        try:
            options[name] = option_cls.model_validate(raw)
        except ValidationError as exc:
            raise HTTPException(
                422, detail={"scanner": name, "errors": exc.errors(include_url=False, include_context=False)}
            ) from exc

    # Same as POST /projects/{id}/scans: the URL comes from the approved Target.
    scan = Scan(
        project_id=target.project_id,
        target_id=target.id,
        target_url=target.base_url or f"https://{target.host}",
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.flush()
    try:
        # Same pre-flight as POST /scans/{id}/start (repeated before every scanner).
        try:
            authorize_scan(db, scan.id)
        except ScopeError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Out of scope: {exc}") from exc
        missing = [registry.SCANNERS[n].display_name for n in scanners if registry.SCANNERS[n].locate() is None]
        if missing:
            raise HTTPException(status.HTTP_409_CONFLICT, detail=f"Not installed: {', '.join(missing)}")
        try:
            orchestrator.prepare_assessment(db, scan, scanners, options)  # commits
        except orchestrator.AssessmentConflict as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except HTTPException:
        db.rollback()  # leave no orphan scan behind
        raise

    background_tasks.add_task(orchestrator.run_assessment, scan.id, db.get_bind())
    db.refresh(scan)
    return ui_views.assessment_out(scan, SeverityCounts())


# --- findings ---------------------------------------------------------------------

@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    severity: FindingSeverity | None = None,
    assessment_id: uuid.UUID | None = Query(default=None, alias="assessmentId"),
    limit: int = Query(default=500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    return ui_views.list_findings(db, severity=severity, assessment_id=assessment_id, limit=limit)


# The frontend's GET /findings/{id} is taken by the existing snake_case endpoint
# (kept for API compatibility), so the UI shape lives one level down.
@router.get("/findings/{finding_id}/detail", response_model=FindingOut)
def get_finding_detail(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return ui_views.finding_detail(db, finding)


# --- reports ----------------------------------------------------------------------

@router.get("/reports", response_model=list[ReportOut])
def list_reports(db: Session = Depends(get_db)):
    return ui_views.list_reports(db)


@router.get(
    "/reports/{report_id}/download",
    response_class=PlainTextResponse,
    responses={409: {"description": "Assessment not finished"}},
)
def download_report(report_id: uuid.UUID, db: Session = Depends(get_db)):
    """Markdown report for an assessment (a report id is the assessment id)."""
    scan = _get_scan_or_404(db, report_id, what="Report")
    total = len(scan.findings)
    if not ui_views.report_available(scan, total):
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"No report yet: assessment is {scan.status.value}")
    return PlainTextResponse(
        build_markdown_report(db, scan),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{ui_views.report_filename(scan)}"'},
    )
