"""The organization access checks every organization-scoped router uses,
defined once so the rules can't drift: not a member -> 404 (a foreign
organization is indistinguishable from a missing one), a member without the
owner role changing something -> 403."""

from __future__ import annotations

from fastapi import HTTPException, Request

from api.control_db import ControlDB, role_can_modify_scope
from api.db import set_request_organization


def control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def require_member(db: ControlDB, account_id: str, organization_id: str) -> str:
    """The caller's role in the organization."""
    role = db.get_role_for_account_organization(account_id, organization_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    # Productization Phase 10c: the rest of this request reads and writes
    # this organization only, also at the database (row-level security).
    set_request_organization(organization_id)
    return role


def require_owner(db: ControlDB, account_id: str, organization_id: str) -> None:
    if not role_can_modify_scope(require_member(db, account_id, organization_id)):
        raise HTTPException(status_code=403, detail="Owner role required")
