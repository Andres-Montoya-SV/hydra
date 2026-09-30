"""Business context an organization declares about an asset (Productization
Phase 06): environment, business criticality, data handled, owner. It feeds
the deterministic risk engine (`core/risk_scoring.py`); nothing here is
inferred. Any member can read; only an owner can change it, and every
change is audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.routers.org_access import control_db, require_member, require_owner
from api.schemas import (
    AssetBusinessContextRequest,
    AssetBusinessContextResponse,
    AssetContextAuditResponse,
)
from core.risk_scoring import BusinessContext

router = APIRouter(prefix="/organizations", tags=["asset-context"])


def _require_asset(db: ControlDB, organization_id: str, asset_id: str) -> None:
    if db.get_asset(organization_id, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")


def _response(asset_id: str, context: BusinessContext | None) -> AssetBusinessContextResponse:
    if context is None:
        return AssetBusinessContextResponse(asset_id=asset_id, declared=False)
    return AssetBusinessContextResponse(
        asset_id=asset_id,
        declared=True,
        environment=context.environment,
        criticality=context.criticality,
        data_handled=sorted(context.data_handled),
        owner=context.owner,
    )


@router.get(
    "/{organization_id}/assets/{asset_id}/context",
    response_model=AssetBusinessContextResponse,
)
def get_asset_context(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> AssetBusinessContextResponse:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    return _response(asset_id, db.get_asset_business_context(organization_id, asset_id))


@router.put(
    "/{organization_id}/assets/{asset_id}/context",
    response_model=AssetBusinessContextResponse,
)
def set_asset_context(
    organization_id: str,
    asset_id: str,
    body: AssetBusinessContextRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> AssetBusinessContextResponse:
    """Owner-only. Replaces the whole declared context; saving the same
    values again changes nothing and adds no audit entry."""
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    context = BusinessContext(
        environment=body.environment,
        criticality=body.criticality,
        data_handled=frozenset(body.data_handled),
        owner=body.owner,
    )
    db.set_asset_business_context(
        organization_id=organization_id,
        asset_id=asset_id,
        actor_account_id=auth.account_id,
        context=context,
    )
    return _response(asset_id, context)


@router.get(
    "/{organization_id}/assets/{asset_id}/context/audit",
    response_model=list[AssetContextAuditResponse],
)
def list_asset_context_audit(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[AssetContextAuditResponse]:
    """Every change to the asset's declared context, newest first."""
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    return [
        AssetContextAuditResponse(
            audit_id=row.audit_id,
            actor_account_id=row.actor_account_id,
            before=row.before,
            after=row.after,
            created_at=row.created_at,
        )
        for row in db.list_asset_business_context_audit(
            organization_id, asset_id, limit=limit, offset=offset
        )
    ]
