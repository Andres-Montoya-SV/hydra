"""Productization Phase 11c: tenant export and deletion, self-service.

Organizations (owners only; members 403, outsiders 404):
- `GET /organizations/{id}/export`: everything, as one ZIP
  (api/tenant_export.py).
- `DELETE /organizations/{id}`: schedules the deletion 30 days out (202).
- `POST /organizations/{id}/deletion/cancel`: until it is due.

The calling account:
- `GET /account/export`: what this service holds about the account itself.
- `DELETE /account`: schedules its deletion, including organizations it
  owns alone.
- `POST /account/deletion/cancel`.

Every one of these is recorded in the security audit log. The purge
itself runs in the daily reconciliation loop (api/tenant_lifecycle.py),
or at once from the host.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from dataclasses import asdict
from typing import IO, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from api import security_audit as audit
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.routers.org_access import control_db, require_owner
from api.schemas import AccountExportResponse, DeletionScheduledResponse
from api.settings import APISettings
from api.tenant_export import ExportTooLargeError, write_organization_export
from api.tenant_lifecycle import due_date

router = APIRouter(tags=["tenant-lifecycle"])

_CHUNK = 64 * 1024


def _stream(spool: IO[bytes]) -> Iterator[bytes]:
    try:
        spool.seek(0)
        while chunk := spool.read(_CHUNK):
            yield chunk
    finally:
        spool.close()


@router.get("/organizations/{organization_id}/export")
def export_organization(
    organization_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> StreamingResponse:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    settings: APISettings = request.app.state.api_settings
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    try:
        manifest = write_organization_export(
            db, organization_id, spool, max_bytes=settings.export_max_bytes
        )
    except ExportTooLargeError as exc:
        spool.close()
        raise HTTPException(
            status_code=413,
            detail="This organization's export is larger than the API serves; an operator "
            "can produce it (python -m api.tenants export-organization).",
        ) from exc
    rows = sum(dataset["rows"] for dataset in manifest["datasets"])
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ORGANIZATION_EXPORTED,
            actor_account_id=auth.account_id,
            organization_id=organization_id,
            target=("organization", organization_id),
            details={"rows": rows},
        ),
    )
    filename = f"hydra-organization-{organization_id}.zip"
    return StreamingResponse(
        _stream(spool),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete(
    "/organizations/{organization_id}",
    status_code=202,
    response_model=DeletionScheduledResponse,
)
def request_organization_deletion(
    organization_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> DeletionScheduledResponse:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    due = db.request_organization_deletion(
        organization_id, actor_account_id=auth.account_id, due_at=due_date()
    )
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ORGANIZATION_DELETION_REQUESTED,
            actor_account_id=auth.account_id,
            organization_id=organization_id,
            target=("organization", organization_id),
            details={"deletion_due_at": due},
        ),
    )
    return DeletionScheduledResponse(deletion_due_at=due)


@router.post("/organizations/{organization_id}/deletion/cancel", status_code=204)
def cancel_organization_deletion(
    organization_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> None:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    if not db.cancel_organization_deletion(organization_id):
        raise HTTPException(status_code=404, detail="No deletion is pending")
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ORGANIZATION_DELETION_CANCELLED,
            actor_account_id=auth.account_id,
            organization_id=organization_id,
            target=("organization", organization_id),
        ),
    )


def _account_export(db: ControlDB, account_id: str) -> AccountExportResponse:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    subscription = db.get_subscription(account_id)
    return AccountExportResponse(
        account={
            "account_id": account.account_id,
            "created_at": account.created_at,
            "email": account.email,
            "email_verified_at": account.email_verified_at,
            "deletion_due_at": db.account_deletion_due_at(account_id),
        },
        subscription=None if subscription is None else asdict(subscription),
        api_keys=[asdict(key) for key in db.list_keys_for_account(account_id)],
        memberships=[
            {"organization_id": organization_id, "role": role}
            for organization_id, role in db.list_organizations_for_account(account_id)
        ],
        security_events=[
            {
                **{k: v for k, v in asdict(event).items() if k != "details_json"},
                "details": json.loads(event.details_json),
            }
            for event in db.list_security_events_for_account(account_id, limit=500, offset=0)
        ],
    )


@router.get("/account/export", response_model=AccountExportResponse)
def export_account(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> AccountExportResponse:
    db = control_db(request)
    export = _account_export(db, auth.account_id)
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ACCOUNT_EXPORTED,
            actor_account_id=auth.account_id,
            subject_account_id=auth.account_id,
            target=("account", auth.account_id),
        ),
    )
    return export


@router.delete("/account", status_code=202, response_model=DeletionScheduledResponse)
def request_account_deletion(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> DeletionScheduledResponse:
    db = control_db(request)
    due = db.request_account_deletion(auth.account_id, due_at=due_date())
    details: dict[str, Any] = {
        "deletion_due_at": due,
        "organizations_deleted_with_it": db.sole_owned_organizations(auth.account_id),
    }
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ACCOUNT_DELETION_REQUESTED,
            actor_account_id=auth.account_id,
            subject_account_id=auth.account_id,
            target=("account", auth.account_id),
            details=details,
        ),
    )
    return DeletionScheduledResponse(deletion_due_at=due)


@router.post("/account/deletion/cancel", status_code=204)
def cancel_account_deletion(request: Request, auth: AuthContext = Depends(require_api_key)) -> None:
    db = control_db(request)
    if not db.cancel_account_deletion(auth.account_id):
        raise HTTPException(status_code=404, detail="No deletion is pending")
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ACCOUNT_DELETION_CANCELLED,
            actor_account_id=auth.account_id,
            subject_account_id=auth.account_id,
            target=("account", auth.account_id),
        ),
    )
