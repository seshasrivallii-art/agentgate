"""Strict schemas for untrusted tool arguments.

extra="forbid" means fields like role, tenant_id, or approved are rejected,
not silently accepted. Privileges never come from tool arguments.
"""
import unicodedata
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class DocumentSearchArgs(StrictModel):
    query: str = Field(min_length=1, max_length=200)
    limit: int = Field(default=5, ge=1, le=10)


class CustomerLookupArgs(StrictModel):
    customer_id: str = Field(pattern=ID_PATTERN)


class TicketCreateArgs(StrictModel):
    customer_id: str = Field(pattern=ID_PATTERN)
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=1, max_length=2000)
    priority: Literal["low", "normal", "high"] = "normal"

    @field_validator("title", "description", mode="before")
    @classmethod
    def _normalize(cls, value):
        # Canonical form so the approval digest is stable for equivalent text.
        if isinstance(value, str):
            value = unicodedata.normalize("NFC", value).strip()
        return value

    @field_validator("title")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if any(ord(ch) < 32 for ch in value):
            raise ValueError("title must not contain control characters")
        return value


TOOL_SCHEMAS: dict[str, type[StrictModel]] = {
    "documents.search": DocumentSearchArgs,
    "customers.lookup": CustomerLookupArgs,
    "tickets.create": TicketCreateArgs,
}


class ApprovalDecision(StrictModel):
    # The approver confirms the exact action they reviewed.
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    comment: str | None = Field(default=None, max_length=500)
