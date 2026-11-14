import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope import validate_base_url
from app.database.database import get_db
from app.models.project import Project
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate

router = APIRouter(tags=["Targets"])


def _get_target_or_404(db: Session, target_id: uuid.UUID) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Target not found"
        )
    return target


@router.post(
    "/projects/{project_id}/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    project_id: uuid.UUID, payload: TargetCreate, db: Session = Depends(get_db)
):
    if db.get(Project, project_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )
    target = Target(project_id=project_id, **payload.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/projects/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )
    stmt = (
        select(Target)
        .where(Target.project_id == project_id)
        .order_by(Target.created_at)
    )
    return db.scalars(stmt).all()


@router.get("/targets/{target_id}", response_model=TargetRead)
def get_target(target_id: uuid.UUID, db: Session = Depends(get_db)):
    return _get_target_or_404(db, target_id)


@router.patch("/targets/{target_id}", response_model=TargetRead)
def update_target(
    target_id: uuid.UUID, payload: TargetUpdate, db: Session = Depends(get_db)
):
    target = _get_target_or_404(db, target_id)
    changes = payload.model_dump(exclude_unset=True)
    new_host = changes.get("host", target.host)
    new_base_url = changes.get("base_url", target.base_url)
    if new_base_url is not None:
        try:
            changes["base_url"] = validate_base_url(new_base_url, new_host)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
    for field, value in changes.items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: uuid.UUID, db: Session = Depends(get_db)):
    target = _get_target_or_404(db, target_id)
    db.delete(target)
    db.commit()
