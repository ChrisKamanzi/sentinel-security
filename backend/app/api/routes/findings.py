import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan
from app.schemas.finding import FindingCreate, FindingRead, FindingUpdate

router = APIRouter(tags=["Findings"])


def _get_finding_or_404(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )
    return finding


@router.post(
    "/scans/{scan_id}/findings",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    scan_id: uuid.UUID, payload: FindingCreate, db: Session = Depends(get_db)
):
    if db.get(Scan, scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    finding = Finding(scan_id=scan_id, **payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/scans/{scan_id}/findings", response_model=list[FindingRead])
def list_findings(
    scan_id: uuid.UUID,
    severity: FindingSeverity | None = None,
    scanner: str | None = None,
    db: Session = Depends(get_db),
):
    if db.get(Scan, scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at)
    )
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if scanner is not None:
        stmt = stmt.where(Finding.scanner == scanner)
    return db.scalars(stmt).all()


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    return _get_finding_or_404(db, finding_id)


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: uuid.UUID, payload: FindingUpdate, db: Session = Depends(get_db)
):
    finding = _get_finding_or_404(db, finding_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_finding(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = _get_finding_or_404(db, finding_id)
    db.delete(finding)
    db.commit()
