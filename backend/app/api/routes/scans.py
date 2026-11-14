import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.schemas.scan import ScanCreate, ScanRead, ScanUpdate

router = APIRouter(tags=["Scans"])


def _get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return scan


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    project_id: uuid.UUID, payload: ScanCreate, db: Session = Depends(get_db)
):
    if db.get(Project, project_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )

    target = db.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )
    if target.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to this project",
        )
    # Scope gate: never create a scan against an unauthorized target.
    if not target.is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is not authorized for scanning",
        )

    scan = Scan(
        project_id=project_id,
        target_id=target.id,
        target_url=target.base_url or f"https://{target.host}",
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/projects/{project_id}/scans", response_model=list[ScanRead])
def list_scans(project_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )
    stmt = (
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at)
    )
    return db.scalars(stmt).all()


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    return _get_scan_or_404(db, scan_id)


@router.patch("/scans/{scan_id}", response_model=ScanRead)
def update_scan(
    scan_id: uuid.UUID, payload: ScanUpdate, db: Session = Depends(get_db)
):
    scan = _get_scan_or_404(db, scan_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(scan, field, value)
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = _get_scan_or_404(db, scan_id)
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING) and scan.runs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan has an assessment queued or running",
        )
    db.delete(scan)
    db.commit()
