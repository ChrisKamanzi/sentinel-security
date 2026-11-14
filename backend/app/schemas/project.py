import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict

from app.schemas.types import Name120, reject_null


class ProjectCreate(BaseModel):
    name: Name120
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: Annotated[Name120 | None, AfterValidator(reject_null)] = None
    description: str | None = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
