"""Productization Phase 11b: reading the security audit log.

- `GET /organizations/{id}/security-events`: owners only (members get 403,
  non-members 404), the organization's events.
- `GET /account/security-events`: the caller's own account events (its
  keys and memberships).
- `GET /admin/security-events`: operators only (everyone else 404); every
  event, including failed sign-ins. Reading it is itself recorded.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from fastapi import APIRouter, Depends, Request

from api import security_audit as audit
from api.auth import AuthContext, require_api_key, require_operator
from api.control_db import SecurityEvent
from api.routers.delivery_logs import Page, page
from api.routers.org_access import control_db, require_owner
from api.schemas import SecurityEventResponse

router = APIRouter(tags=["security-events"])


def _responses(events: list[SecurityEvent]) -> list[SecurityEventResponse]:
    responses = []
    for event in events:
        fields = asdict(event)
        details = json.loads(fields.pop("details_json"))
        responses.append(SecurityEventResponse.model_validate({**fields, "details": details}))
    return responses


@router.get(
    "/organizations/{organization_id}/security-events",
    response_model=list[SecurityEventResponse],
)
def organization_security_events(
    organization_id: str,
    request: Request,
    paging: Page = Depends(page),
    auth: AuthContext = Depends(require_api_key),
) -> list[SecurityEventResponse]:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    return _responses(
        db.list_security_events_for_organization(
            organization_id, limit=paging.limit, offset=paging.offset
        )
    )


@router.get("/account/security-events", response_model=list[SecurityEventResponse])
def account_security_events(
    request: Request,
    paging: Page = Depends(page),
    auth: AuthContext = Depends(require_api_key),
) -> list[SecurityEventResponse]:
    db = control_db(request)
    return _responses(
        db.list_security_events_for_account(
            auth.account_id, limit=paging.limit, offset=paging.offset
        )
    )


@router.get("/admin/security-events", response_model=list[SecurityEventResponse])
def all_security_events(
    request: Request,
    paging: Page = Depends(page),
    operator: AuthContext = Depends(require_operator),
) -> list[SecurityEventResponse]:
    db = control_db(request)
    events = db.list_security_events(limit=paging.limit, offset=paging.offset)
    audit.record(
        db,
        request,
        audit.ADMIN_EVENTS_LISTED,
        actor_type="operator",
        actor_account_id=operator.account_id,
        details={"limit": paging.limit, "offset": paging.offset},
    )
    return _responses(events)
