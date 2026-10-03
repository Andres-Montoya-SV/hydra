"""`POST /demo/organization` (Productization Phase 13b): the caller's demo
organization, built from safe fixtures. See `api/demo.py`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from api import security_audit as audit
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.demo import create_demo_organization
from api.schemas import OrganizationResponse
from api.settings import APISettings

router = APIRouter(prefix="/demo", tags=["demo"])


@router.post(
    "/organization",
    response_model=OrganizationResponse,
    status_code=201,
    responses={200: {"description": "The account's existing demo organization."}},
)
def create_demo(
    request: Request, response: Response, auth: AuthContext = Depends(require_api_key)
) -> OrganizationResponse:
    """201 with a new demo organization, or 200 with the account's existing
    one. Sample data only: read-only, never scanned, and not counted
    against the organization entitlement."""
    db: ControlDB = request.app.state.control_db
    api_settings: APISettings = request.app.state.api_settings
    organization_id, created = create_demo_organization(db, api_settings, auth.account_id)
    org = db.get_organization(organization_id)
    if org is None:
        raise RuntimeError(f"demo organization {organization_id!r} vanished after creation")
    if created:
        audit.record(
            db,
            request,
            audit.AuditEvent(
                audit.DEMO_ORGANIZATION_CREATED,
                actor_account_id=auth.account_id,
                subject_account_id=auth.account_id,
                organization_id=organization_id,
                target=("organization", organization_id),
            ),
        )
    else:
        response.status_code = 200
    return OrganizationResponse(
        organization_id=org.organization_id,
        name=org.name,
        role="owner",
        created_at=org.created_at,
        updated_at=org.updated_at,
        is_demo=True,
    )
