"""Request/response models. Kept separate from `core.client_report`'s own
`ConsolidatedFinding`/`RunReportData` dataclasses deliberately — those are
internal pipeline shapes; these are the public HTTP contract, allowed to
evolve independently of the engine's internals.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CreateAccountResponse(BaseModel):
    account_id: str
    api_key: str = Field(
        description="Shown exactly once. Store it now — it cannot be retrieved again, only revoked/rotated."
    )
    key_id: str


class CreateApiKeyResponse(BaseModel):
    key_id: str
    api_key: str = Field(description="Shown exactly once, same as account creation.")


class RotateKeyResponse(BaseModel):
    old_key_id: str
    old_key_valid_until: str
    new_key_id: str
    new_api_key: str = Field(description="Shown exactly once.")


class CreateScanRequest(BaseModel):
    domain: str = Field(min_length=1, description="Target domain, e.g. example.com")


class CreateScanResponse(BaseModel):
    scan_id: str
    status: Literal["queued"]


class ScanStatusResponse(BaseModel):
    scan_id: str
    domain: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: str
    updated_at: str
    error_message: str | None = None


class ClientReportRequest(BaseModel):
    format: Literal["markdown", "docx"] = "markdown"
    language: Literal["en", "es"] = "es"


class ErrorResponse(BaseModel):
    error: str
    detail: str
