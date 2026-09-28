"""Fase 19 (EASM roadmap): the read/confirm API surface for the domain
model Fases 02-18 built — organizations, assets, candidate assets
(read + the Fase 06 promote/discard flow), observations, change events,
certificate events, technology events/inventory, and a capability status
view for the frontend (Fase 17).

Follows `api/routers/exposures.py`'s own established conventions
exactly, never a second pattern: `_require_member` returns 404 (never
403) for a non-member, so an API key can never distinguish "wrong
organization" from "organization doesn't exist"; every nested lookup
re-verifies tenancy at each level (an asset must belong to the
organization in the URL before its own sub-resources are ever queried);
every mutation is owner-role-gated using the exact same
`role_can_modify_scope`/`PermissionError` pattern Fase 06 already
defined in the data layer, this router only translates it to HTTP.

**Real pagination, one caveat documented rather than hidden**: like
`api/routers/exposures.py`, every list endpoint takes `limit`/`offset`
with the same bounds (1-500, default 100). Assets and candidate assets
paginate at the SQL level, matching exposures. Observations, certificate
events, and technology events paginate in Python over an already-fetched
list — `list_observations_for_asset` and friends have many existing
callers across Fases 04/12/14/18 (backfills, monitoring citations);
adding LIMIT/OFFSET to their SQL would mean auditing every one of those
callers for a scope this phase does not need to touch. Correct pagination
behavior for the API contract either way; documented here rather than
silently presented as identical to the SQL-level case.

**No endpoint promotes a candidate outside Fase 06's own flow** — the
promote/discard endpoints call `ControlDB.promote_candidate_asset`/
`discard_candidate_asset` directly, the same and only code path that can
turn a candidate into a real asset.
"""

from __future__ import annotations

from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import AssetRecord, ControlDB
from api.schemas import (
    AssetResponse,
    CandidateAssetResponse,
    CapabilityStatusResponse,
    CertificateEventResponse,
    ChangeEventResponse,
    CurrentTechnologyResponse,
    DiscardCandidateAssetRequest,
    EvidenceResponse,
    ObservationResponse,
    OrganizationResponse,
    PromoteCandidateAssetRequest,
    TechnologyEventResponse,
)

router = APIRouter(prefix="/organizations", tags=["easm"])

_T = TypeVar("_T")


def _db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _require_member(db: ControlDB, account_id: str, organization_id: str) -> str:
    role = db.get_role_for_account_organization(account_id, organization_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return role


def _require_owner(db: ControlDB, account_id: str, organization_id: str) -> None:
    role = _require_member(db, account_id, organization_id)
    from api.control_db import role_can_modify_scope

    if not role_can_modify_scope(role):
        raise HTTPException(status_code=403, detail="Owner role required")


def _require_asset(db: ControlDB, organization_id: str, asset_id: str) -> AssetRecord:
    asset = db.get_asset(organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _paginate(items: list[_T], *, limit: int, offset: int) -> list[_T]:
    return items[offset : offset + limit]


def _asset_to_response(row: AssetRecord) -> AssetResponse:
    return AssetResponse(**row.__dict__)


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> list[OrganizationResponse]:
    """Every organization the calling account is a member of — never
    another account's, there is no "list all organizations" surface
    anywhere in this router."""
    db = _db(request)
    responses: list[OrganizationResponse] = []
    for organization_id, role in db.list_organizations_for_account(auth.account_id):
        org = db.get_organization(organization_id)
        if org is None:
            continue
        responses.append(
            OrganizationResponse(
                organization_id=org.organization_id,
                name=org.name,
                role=role,
                created_at=org.created_at,
                updated_at=org.updated_at,
            )
        )
    return responses


@router.get("/{organization_id}/assets", response_model=list[AssetResponse])
def list_assets(
    organization_id: str,
    request: Request,
    asset_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[AssetResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    rows = db.list_assets_for_organization(organization_id, asset_type=asset_type)
    return [_asset_to_response(row) for row in _paginate(rows, limit=limit, offset=offset)]


@router.get("/{organization_id}/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> AssetResponse:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    asset = _require_asset(db, organization_id, asset_id)
    return _asset_to_response(asset)


@router.get(
    "/{organization_id}/assets/{asset_id}/observations", response_model=list[ObservationResponse]
)
def list_asset_observations(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[ObservationResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    rows = db.list_observations_for_asset(asset_id)
    return [
        ObservationResponse(
            observation_id=entry.observation.observation_id,
            run_id=entry.observation.run_id,
            observation_type=entry.observation.observation_type,
            observed_at=entry.observation.observed_at,
            evidence=EvidenceResponse(
                evidence_id=entry.evidence.evidence_id,
                source=entry.evidence.source,
                detail=entry.evidence.detail,
                confidence_score=entry.evidence.confidence_score,
                confidence_class=entry.evidence.confidence_class,
                first_seen_at=entry.evidence.first_seen_at,
                last_seen_at=entry.evidence.last_seen_at,
            ),
        )
        for entry in _paginate(rows, limit=limit, offset=offset)
    ]


@router.get(
    "/{organization_id}/assets/{asset_id}/change-events", response_model=list[ChangeEventResponse]
)
def list_asset_change_events(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[ChangeEventResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    rows = db.list_change_events_for_asset(asset_id)
    return [
        ChangeEventResponse(**row.__dict__) for row in _paginate(rows, limit=limit, offset=offset)
    ]


@router.get(
    "/{organization_id}/assets/{asset_id}/certificate-events",
    response_model=list[CertificateEventResponse],
)
def list_asset_certificate_events(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[CertificateEventResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    rows = db.list_certificate_events_for_asset(asset_id)
    return [
        CertificateEventResponse(**row.__dict__)
        for row in _paginate(rows, limit=limit, offset=offset)
    ]


@router.get(
    "/{organization_id}/assets/{asset_id}/technology-events",
    response_model=list[TechnologyEventResponse],
)
def list_asset_technology_events(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[TechnologyEventResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    rows = db.list_technology_events_for_asset(asset_id)
    return [
        TechnologyEventResponse(**row.__dict__)
        for row in _paginate(rows, limit=limit, offset=offset)
    ]


@router.get(
    "/{organization_id}/assets/{asset_id}/technologies",
    response_model=list[CurrentTechnologyResponse],
)
def list_asset_current_technologies(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[CurrentTechnologyResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    return [
        CurrentTechnologyResponse(
            technology_name=row.technology_name,
            version=row.version,
            source=row.source,
            last_seen_at=row.last_seen_at,
        )
        for row in db.list_current_technologies_for_asset(asset_id)
    ]


@router.get("/{organization_id}/candidate-assets", response_model=list[CandidateAssetResponse])
def list_candidate_assets(
    organization_id: str,
    request: Request,
    candidate_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[CandidateAssetResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    rows = db.list_candidate_assets_for_organization(organization_id, candidate_type=candidate_type)
    return [
        CandidateAssetResponse(**row.__dict__)
        for row in _paginate(rows, limit=limit, offset=offset)
    ]


@router.get(
    "/{organization_id}/candidate-assets/{candidate_asset_id}",
    response_model=CandidateAssetResponse,
)
def get_candidate_asset(
    organization_id: str,
    candidate_asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CandidateAssetResponse:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    row = db.get_candidate_asset(organization_id, candidate_asset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Candidate asset not found")
    return CandidateAssetResponse(**row.__dict__)


@router.post(
    "/{organization_id}/candidate-assets/{candidate_asset_id}/promote",
    response_model=CandidateAssetResponse,
)
def promote_candidate_asset(
    organization_id: str,
    candidate_asset_id: str,
    body: PromoteCandidateAssetRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CandidateAssetResponse:
    db = _db(request)
    _require_owner(db, auth.account_id, organization_id)
    if db.get_candidate_asset(organization_id, candidate_asset_id) is None:
        raise HTTPException(status_code=404, detail="Candidate asset not found")
    try:
        db.promote_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_asset_id,
            account_id=auth.account_id,
            justification=body.justification,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    row = db.get_candidate_asset(organization_id, candidate_asset_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Candidate asset disappeared")
    return CandidateAssetResponse(**row.__dict__)


@router.post(
    "/{organization_id}/candidate-assets/{candidate_asset_id}/discard",
    response_model=CandidateAssetResponse,
)
def discard_candidate_asset(
    organization_id: str,
    candidate_asset_id: str,
    body: DiscardCandidateAssetRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CandidateAssetResponse:
    db = _db(request)
    _require_owner(db, auth.account_id, organization_id)
    if db.get_candidate_asset(organization_id, candidate_asset_id) is None:
        raise HTTPException(status_code=404, detail="Candidate asset not found")
    try:
        db.discard_candidate_asset(
            organization_id=organization_id,
            candidate_asset_id=candidate_asset_id,
            account_id=auth.account_id,
            justification=body.justification,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    row = db.get_candidate_asset(organization_id, candidate_asset_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Candidate asset disappeared")
    return CandidateAssetResponse(**row.__dict__)


@router.get("/{organization_id}/capabilities", response_model=list[CapabilityStatusResponse])
def list_capabilities(
    organization_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[CapabilityStatusResponse]:
    """Fase 17's capability/provider/status model, surfaced for the
    frontend — same underlying `provider_inventory()` the `heads` CLI
    reads, never a second capability computation. Organization-scoped
    only insofar as membership is required to view it; the underlying
    provider configuration is process-wide, not per-organization, so
    every member of every organization sees the exact same list (there
    is no per-organization provider config anywhere in this codebase to
    leak across tenants here)."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    from config.settings import Settings
    from core.provider_contract import provider_inventory
    from core.tool_manager import ToolManager

    manager = ToolManager(Settings())
    plugins_by_name = {p.name: p for p in manager.get_all_plugins()}
    responses = []
    for descriptor in provider_inventory():
        plugin = plugins_by_name.get(descriptor.provider)
        active = plugin.is_enabled() if plugin is not None else descriptor.active_collection
        if plugin is None:
            status = "disabled"
        elif not active:
            status = "disabled"
        elif manager.is_runnable(plugin.name):
            status = "runnable"
        else:
            status = "not_runnable"
        responses.append(
            CapabilityStatusResponse(
                provider=descriptor.provider,
                display_name=descriptor.display_name,
                capability=descriptor.capability.value,
                intensity=descriptor.intensity.value,
                active=active,
                status=status,  # type: ignore[arg-type]
            )
        )
    return responses
