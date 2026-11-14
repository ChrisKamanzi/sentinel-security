import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.core.scope import validate_base_url
from app.schemas.types import Host, Name120, reject_null


class TargetCreate(BaseModel):
    name: Name120
    # Bare hostname or IP only; see app.core.scope.validate_host.
    host: Host
    # Optional http(s) URL; its hostname must equal `host`.
    base_url: str | None = Field(default=None, max_length=2048)
    is_authorized: bool = False
    description: str | None = None

    @model_validator(mode="after")
    def _base_url_matches_host(self):
        if self.base_url is not None:
            self.base_url = validate_base_url(self.base_url, self.host)
        return self


class TargetUpdate(BaseModel):
    # The base_url/host consistency check needs the stored Target, so it is
    # enforced in the PATCH route after merging these values.
    name: Annotated[Name120 | None, AfterValidator(reject_null)] = None
    host: Annotated[Host | None, AfterValidator(reject_null)] = None
    base_url: str | None = Field(default=None, max_length=2048)
    is_authorized: Annotated[bool | None, AfterValidator(reject_null)] = None
    description: str | None = None


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    host: str
    base_url: str | None
    is_authorized: bool
    description: str | None
    created_at: datetime
