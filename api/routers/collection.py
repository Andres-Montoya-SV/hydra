"""Organization collection settings (Productization Roadmap v2, "Capability
& Tool Access"): which optional providers the organization's scans run,
the tier ceiling that bounds them, and the audit trail of every change.

Read by any member; changed only by an owner. Enablement narrows what is
collected within an already-authorized scope — it never grants
authorization to collect against a target.
"""

from __future__ import annotations

from typing import Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.collection_capabilities import (
    CapabilityRequestError,
    builtin_default,
    not_entitled,
    provider_catalog,
    tier_ceiling,
    validate_requested,
)
from api.control_db import ControlDB, role_can_modify_scope
from api.schemas import (
    CapabilityAuditResponse,
    CollectionSettingsResponse,
    ProviderCapabilityInfo,
    UpdateCollectionSettingsRequest,
)

router = APIRouter(prefix="/organizations", tags=["collection"])


def _db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _require_role(db: ControlDB, account_id: str, organization_id: str) -> str:
    role = db.get_role_for_account_organization(account_id, organization_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return role


def account_tier(db: ControlDB, account_id: str) -> str:
    """Tiers are per account. The ceiling applied is the tier of the account
    performing the action (saving the default, or starting the scan)."""
    return subscriptions.effective_limits(
        subscriptions.get_or_create_subscription(db, account_id)
    ).tier


def entitlement_error(tier: str, providers: list[str]) -> HTTPException:
    """A typed error, never a silent downgrade: the request is rejected and
    names exactly which providers the tier doesn't include."""
    return HTTPException(
        status_code=403,
        detail={
            "error": "capability_not_entitled",
            "tier": tier,
            "providers": providers,
            "message": f"Your {tier!r} tier does not include: {', '.join(providers)}.",
        },
    )


def invalid_request_error(exc: CapabilityRequestError) -> HTTPException:
    return HTTPException(
        status_code=422, detail={"error": "invalid_capability_request", "message": str(exc)}
    )


def _settings_response(
    db: ControlDB, organization_id: str, tier: str
) -> CollectionSettingsResponse:
    saved = db.get_org_collection_settings(organization_id)
    enabled = saved if saved is not None else builtin_default()
    ceiling = tier_ceiling(tier)
    return CollectionSettingsResponse(
        organization_id=organization_id,
        source="organization" if saved is not None else "default",
        tier=tier,
        enabled_providers=sorted(enabled),
        effective_providers=sorted(enabled & ceiling),
        not_entitled=sorted(enabled - ceiling),
        providers=[
            ProviderCapabilityInfo(
                provider=info.name,
                capability=info.capability,
                intensity=info.intensity,
                required=info.required,
                entitled=info.required or info.name in ceiling,
            )
            for info in sorted(provider_catalog().values(), key=lambda i: i.name)
        ],
    )


@router.get("/{organization_id}/collection-settings", response_model=CollectionSettingsResponse)
def get_collection_settings(
    organization_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> CollectionSettingsResponse:
    db = _db(request)
    _require_role(db, auth.account_id, organization_id)
    return _settings_response(db, organization_id, account_tier(db, auth.account_id))


@router.put("/{organization_id}/collection-settings", response_model=CollectionSettingsResponse)
def update_collection_settings(
    organization_id: str,
    body: UpdateCollectionSettingsRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CollectionSettingsResponse:
    """Replaces the organization's default provider set. Owner-only. A
    provider outside the tier is rejected with a typed 403, never dropped
    silently. Saving the same set again changes nothing and adds no audit
    entry."""
    db = _db(request)
    if not role_can_modify_scope(_require_role(db, auth.account_id, organization_id)):
        raise HTTPException(status_code=403, detail="Owner role required")
    try:
        requested = validate_requested(body.enabled_providers)
    except CapabilityRequestError as exc:
        raise invalid_request_error(exc) from exc
    tier = account_tier(db, auth.account_id)
    blocked = not_entitled(requested, tier)
    if blocked:
        raise entitlement_error(tier, blocked)
    saved = db.get_org_collection_settings(organization_id)
    db.set_org_collection_settings(
        organization_id=organization_id,
        actor_account_id=auth.account_id,
        providers=requested,
        previous=saved if saved is not None else builtin_default(),
    )
    return _settings_response(db, organization_id, tier)


@router.get(
    "/{organization_id}/collection-settings/audit",
    response_model=list[CapabilityAuditResponse],
)
def list_collection_audit(
    organization_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[CapabilityAuditResponse]:
    """Every default change and per-scan override, newest first."""
    db = _db(request)
    _require_role(db, auth.account_id, organization_id)
    return [
        CapabilityAuditResponse(
            audit_id=row.audit_id,
            actor_account_id=row.actor_account_id,
            scan_id=row.scan_id,
            # The table's CHECK constraint only allows these two values.
            action=cast(Literal["org_default_updated", "scan_override"], row.action),
            before=None if row.before is None else list(row.before),
            after=list(row.after),
            created_at=row.created_at,
        )
        for row in db.list_capability_audit(organization_id, limit=limit, offset=offset)
    ]
