import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict

from app.models.scan import ScanStatus
from app.schemas.types import reject_null


class ScanCreate(BaseModel):
    # A scan must reference an approved Target. The target_url is derived from
    # that Target server-side; arbitrary URLs are never accepted here.
    target_id: uuid.UUID


class ScanUpdate(BaseModel):
    status: Annotated[ScanStatus | None, AfterValidator(reject_null)] = None
    error_message: str | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID | None
    target_url: str
    scanner: str
    status: ScanStatus
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
