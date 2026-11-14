import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.models.ai_analysis import AIAnalysis, AnalysisStatus
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.schemas.analysis import AnalysisRead
from app.services.ai_analyst import run_analysis
from app.services.report import build_markdown_report

router = APIRouter(tags=["AI Analysis"])


def _get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _latest(db: Session, scan_id: uuid.UUID) -> AIAnalysis | None:
    return db.scalars(
        select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at.desc())
    ).first()


@router.post(
    "/scans/{scan_id}/analysis",
    response_model=AnalysisRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses={409: {"description": "Scan still running, no findings, or analysis in progress"}},
)
def start_analysis(scan_id: uuid.UUID, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Queue a Claude AI Analyst run over this scan's normalized findings."""
    scan = _get_scan_or_404(db, scan_id)
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING) and scan.runs:
        raise HTTPException(409, detail="Assessment still in progress; analyze it once it finishes")
    count = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id))
    if not count:
        raise HTTPException(409, detail="Scan has no findings to analyze")
    active = db.scalar(select(func.count()).select_from(AIAnalysis).where(
        AIAnalysis.scan_id == scan_id,
        AIAnalysis.status.in_((AnalysisStatus.PENDING, AnalysisStatus.RUNNING))))
    if active:
        raise HTTPException(409, detail="An analysis for this scan is already in progress")

    analysis = AIAnalysis(scan_id=scan_id, model=settings.anthropic_model, status=AnalysisStatus.PENDING)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    background_tasks.add_task(run_analysis, analysis.id, db.get_bind())
    return analysis


@router.get("/scans/{scan_id}/analysis", response_model=AnalysisRead)
def get_latest_analysis(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    """The most recent analysis (any status) for this scan."""
    _get_scan_or_404(db, scan_id)
    analysis = _latest(db, scan_id)
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No analysis for this scan yet")
    return analysis


@router.get("/scans/{scan_id}/analyses", response_model=list[AnalysisRead])
def list_analyses(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    _get_scan_or_404(db, scan_id)
    return db.scalars(
        select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at)
    ).all()


@router.get("/scans/{scan_id}/report", response_class=PlainTextResponse)
def get_report(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    """Markdown report: findings plus the latest completed AI analysis."""
    scan = _get_scan_or_404(db, scan_id)
    return PlainTextResponse(build_markdown_report(db, scan), media_type="text/markdown; charset=utf-8")
