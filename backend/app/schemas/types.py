"""Reusable constrained field types for request schemas."""

from typing import Annotated, Any

from pydantic import AfterValidator, StringConstraints

from app.core.scope import validate_host


def reject_null(value: Any) -> Any:
    """For PATCH schemas: a field may be omitted, but not explicitly null."""
    if value is None:
        raise ValueError("may not be null; omit the field to leave it unchanged")
    return value


# Strings are stripped first, so whitespace-only values fail min_length=1.
Name120 = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)
]
Title255 = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]
Host = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=255),
    AfterValidator(validate_host),
]
