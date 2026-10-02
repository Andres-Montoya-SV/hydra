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
with the same bounds (1-500, default 100). Assets paginate at the SQL
level, matching exposures — **fixed in Productization Phase 02**; before
that this docstring's own claim was false for assets:
`list_assets_for_organization` had no `LIMIT`/`OFFSET` at all, and this
router's `_paginate` was Python-slicing an already-fully-fetched,
unbounded result set on every single request. `list_assets_for_organization`
now takes optional `limit`/`offset` (default `None`/no SQL LIMIT, so
every pre-existing internal caller — certificate/technology/change
backfills, `list_assets_running_technology` — keeps getting the complete,
unbounded set it always has) while the router always passes an explicit
`limit`; `list_candidate_assets_for_organization` got the same fix in
Roadmap v2. Observations,
certificate events, and technology events paginate in Python over an
already-fetched list — `list_observations_for_asset` and friends have
many existing callers across Fases 04/12/14/18 (backfills, monitoring
citations); adding LIMIT/OFFSET to their SQL would mean auditing every
one of those callers for a scope this phase does not need to touch.
Correct pagination behavior for the API contract either way; documented
here rather than silently presented as identical to the SQL-level case.

**No endpoint promotes a candidate outside Fase 06's own flow** — the
promote/discard endpoints call `ControlDB.promote_candidate_asset`/
`discard_candidate_asset` directly, the same and only code path that can
turn a candidate into a real asset.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Literal, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api import entitlements
from api import security_audit as audit
from api.auth import AuthContext, require_api_key
from api.control_db import (
    AssetRecord,
    ControlDB,
    LastOwnerError,
    LimitReachedError,
    RelationshipRecord,
)
from api.errors import ApiError
from api.routers.org_access import control_db as _db
from api.routers.org_access import require_member as _require_member
from api.routers.org_access import require_owner as _require_owner
from api.schemas import (
    AddOrganizationMemberRequest,
    AnalystProvenanceResponse,
    AssetIdentifierResponse,
    AssetResponse,
    CandidateAssetResponse,
    CapabilityStatusResponse,
    CertificateEventResponse,
    ChangeEventResponse,
    CreateOrganizationRequest,
    CurrentCertificateResponse,
    CurrentTechnologyResponse,
    DiscardCandidateAssetRequest,
    EvidenceResponse,
    FacetCountResponse,
    GeoLocationResponse,
    InventoryFacetsResponse,
    NetworkIntelligenceResponse,
    ObservationResponse,
    OrganizationMemberResponse,
    OrganizationResponse,
    PromoteCandidateAssetRequest,
    RawObservationResponse,
    RawToolProvenanceResponse,
    RelationshipEvidenceResponse,
    RelationshipResponse,
    TechnologyEventResponse,
    VisualChangeResponse,
    VisualIntelligenceResponse,
    VisualReferenceResponse,
)
from core.assets import HttpService

router = APIRouter(prefix="/organizations", tags=["easm"])

_T = TypeVar("_T")


def _require_member_manager(db: ControlDB, account_id: str, organization_id: str) -> None:
    """Fase 02 built `role_can_manage_members` specifically for this —
    a distinct check from `role_can_modify_scope`'s "can change
    authorized scope," even though both happen to be owner-only today.
    Using the semantically-correct one here (rather than reusing
    `_require_owner`) means a future role split (e.g., an admin role
    that can manage members but not scope) needs no change at this call
    site."""
    role = _require_member(db, account_id, organization_id)
    from api.control_db import role_can_manage_members

    if not role_can_manage_members(role):
        raise ApiError(403, "Owner role required", code="owner_role_required")


def _require_asset(db: ControlDB, organization_id: str, asset_id: str) -> AssetRecord:
    asset = db.get_asset(organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _paginate(items: list[_T], *, limit: int, offset: int) -> list[_T]:
    return items[offset : offset + limit]


def _asset_to_response(row: AssetRecord) -> AssetResponse:
    return AssetResponse(**row.__dict__)


def _parse_json_object(raw: str) -> dict[str, object]:
    """Defensive against a stray malformed/non-object JSON string ending
    up in a stored `data_json`/`metadata_json` column — returns `{}`
    rather than ever raising a 500 for a product-facing read endpoint."""
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _relationship_to_response(row: RelationshipRecord) -> RelationshipResponse:
    return RelationshipResponse(
        relationship_id=row.relationship_id,
        source_entity=row.source_entity,
        relationship_type=row.relationship_type,
        target_entity=row.target_entity,
        source_asset_id=row.source_asset_id,
        target_asset_id=row.target_asset_id,
        confidence=row.confidence,
        strength=row.strength,
        data=_parse_json_object(row.data_json),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        last_seen_run_id=row.last_seen_run_id,
    )


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


@router.post("", response_model=OrganizationResponse, status_code=201)
def create_organization(
    body: CreateOrganizationRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> OrganizationResponse:
    """A SECOND (or later) organization for the calling account — its own
    1:1 default organization already exists from account creation
    (Fase 02), this is the "consultant onboarding a new client" case.
    `ControlDB.create_owned_organization` writes the organization and the
    caller's owner role in one transaction, within the account's
    organization entitlement (Phase 12a)."""
    db = _db(request)
    limits = entitlements.account_limits(db, auth.account_id)
    try:
        organization_id = db.create_owned_organization(
            account_id=auth.account_id, name=body.name, limit=limits.max_organizations
        )
    except LimitReachedError as exc:
        raise entitlements.from_limit_reached(limits.tier, exc) from exc
    org = db.get_organization(organization_id)
    if org is None:
        # Unreachable in practice (just inserted, same request, same
        # connection) — a real exception rather than `assert` so this
        # isn't stripped under `python -O` and reads clearly as a defensive
        # check, not a static rule to silence.
        raise RuntimeError(f"organization {organization_id!r} vanished immediately after creation")
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ORGANIZATION_CREATED,
            actor_account_id=auth.account_id,
            subject_account_id=auth.account_id,
            organization_id=organization_id,
            target=("organization", organization_id),
        ),
    )
    return OrganizationResponse(
        organization_id=org.organization_id,
        name=org.name,
        role="owner",
        created_at=org.created_at,
        updated_at=org.updated_at,
    )


@router.get("/{organization_id}/members", response_model=list[OrganizationMemberResponse])
def list_organization_members(
    organization_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[OrganizationMemberResponse]:
    """Any member (owner or viewer) can see who else has access — this is
    read visibility, not a mutation, so `_require_member` (not
    `_require_owner`) is the right gate."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    return [
        OrganizationMemberResponse(account_id=account_id, role=role, created_at=created_at)
        for account_id, role, created_at in db.list_members_for_organization(organization_id)
    ]


@router.post("/{organization_id}/members", response_model=OrganizationMemberResponse)
def add_organization_member(
    organization_id: str,
    body: AddOrganizationMemberRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> OrganizationMemberResponse:
    """Owner-only, via `role_can_manage_members` (Fase 02 built this
    exact check; this is its first real caller). Grants a role by
    `account_id`, not by email/invite — there is no invite-by-email flow
    in this system yet; the caller must already know the target
    account's id (e.g. from their own `POST /accounts` response). A real
    invite flow is a reasonable future addition, not built here to keep
    this change small and additive rather than inventing a new
    onboarding concept."""
    db = _db(request)
    _require_member_manager(db, auth.account_id, organization_id)
    if not db.account_exists(body.account_id):
        raise HTTPException(status_code=404, detail="Account not found")
    previous = db.get_role_for_account_organization(body.account_id, organization_id)
    limits = entitlements.account_limits(db, auth.account_id)
    try:
        db.add_member_within_limit(
            account_id=body.account_id,
            organization_id=organization_id,
            role=body.role,
            limit=limits.max_members_per_organization,
        )
    except LimitReachedError as exc:
        raise entitlements.from_limit_reached(limits.tier, exc) from exc
    if previous != body.role:
        _audit_member(
            db,
            request,
            audit.MEMBER_ADDED if previous is None else audit.MEMBER_ROLE_CHANGED,
            auth.account_id,
            organization_id,
            body.account_id,
            {"role": body.role, "previous_role": previous},
        )
    role, created_at = next(
        (r, c)
        for a, r, c in db.list_members_for_organization(organization_id)
        if a == body.account_id
    )
    return OrganizationMemberResponse(account_id=body.account_id, role=role, created_at=created_at)


@router.delete("/{organization_id}/members/{account_id}", status_code=204)
def remove_organization_member(
    organization_id: str,
    account_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> None:
    """Owner-only (`role_can_manage_members`), and refuses to remove an
    organization's last owner (`ControlDB.remove_account_organization_role`
    raises `LastOwnerError`, translated to a 409 here) — an organization
    with zero owners could never be administered again. An owner may
    remove themselves as long as at least one other owner remains."""
    db = _db(request)
    _require_member_manager(db, auth.account_id, organization_id)
    previous = db.get_role_for_account_organization(account_id, organization_id)
    try:
        db.remove_account_organization_role(account_id=account_id, organization_id=organization_id)
    except LastOwnerError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if previous is not None:
        _audit_member(
            db,
            request,
            audit.MEMBER_REMOVED,
            auth.account_id,
            organization_id,
            account_id,
            {"previous_role": previous},
        )


def _audit_member(
    db: ControlDB,
    request: Request,
    action: str,
    actor_account_id: str,
    organization_id: str,
    member_account_id: str,
    details: dict[str, str | None],
) -> None:
    audit.record(
        db,
        request,
        audit.AuditEvent(
            action,
            actor_account_id=actor_account_id,
            subject_account_id=member_account_id,
            organization_id=organization_id,
            target=("account", member_account_id),
            details=details,
        ),
    )


@router.get("/{organization_id}/assets", response_model=list[AssetResponse])
def list_assets(
    organization_id: str,
    request: Request,
    asset_type: str | None = None,
    q: str | None = Query(
        default=None, description="Case-insensitive substring match on identity_key"
    ),
    sort: Literal["first_seen_at", "last_seen_at"] = "first_seen_at",
    order: Literal["asc", "desc"] = "asc",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[AssetResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    rows = db.list_assets_for_organization(
        organization_id,
        asset_type=asset_type,
        q=q,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )
    return [_asset_to_response(row) for row in rows]


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


@router.get(
    "/{organization_id}/assets/{asset_id}/certificate",
    response_model=CurrentCertificateResponse | None,
)
def get_asset_current_certificate(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CurrentCertificateResponse | None:
    """Productization Phase 02: the certificate-event history endpoint
    above already answers "how did this asset's certificate change over
    time"; this answers the simpler, more common "what certificate does
    it have right now" — the same "current state, derived from the most
    recent run" pattern `.../technologies` already established, over
    `OBSERVATION_TYPE_CERTIFICATE_PRESENT` rather than
    `OBSERVATION_TYPE_TECHNOLOGY_DETECTED`. `None` (not 404) for an
    asset that exists but has never had a parseable certificate
    observation — a domain asset with no HTTPS presence is a normal,
    expected state, not an error."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    record = db.get_current_certificate_for_asset(asset_id)
    if record is None:
        return None
    return CurrentCertificateResponse(
        fingerprint_sha256=record.fingerprint_sha256,
        subject=record.subject,
        issuer=record.issuer,
        not_before=record.not_before,
        not_after=record.not_after,
        sans=record.sans,
        observed_at=record.observed_at,
    )


@router.get(
    "/{organization_id}/assets/{asset_id}/identifiers",
    response_model=list[AssetIdentifierResponse],
)
def list_asset_identifiers(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[AssetIdentifierResponse]:
    """Productization Phase 02's explicit "identifiers" requirement —
    e.g. a domain asset's resolved IPs (`ControlDB.list_identifiers_for_asset`,
    already written by Fase 03's own asset reconciliation on every real
    scan; this is its first API surface)."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    return [
        AssetIdentifierResponse(
            identifier_type=row.identifier_type,
            identifier_value=row.identifier_value,
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
        )
        for row in db.list_identifiers_for_asset(asset_id)
    ]


def _asset_run_store(request: Request, organization_id: str, asset: AssetRecord):  # noqa: ANN202
    """`(store, domain, run_id)` for a host asset's most recent run: the
    recon.db of the account whose scan produced that run. `None` when
    there is nothing to read (non-host asset, no run, db missing). Never
    creates a database as a side effect of a read."""
    if asset.asset_type != "domain" or not asset.last_seen_run_id:
        return None
    account_id = _db(request).account_for_run(organization_id, asset.last_seen_run_id)
    if account_id is None:
        return None
    from api.tenancy import account_db_path
    from core.store import AssetStore

    path = account_db_path(request.app.state.api_settings, account_id)
    if not path.exists():
        return None
    domain = asset.identity_key.split(":", 1)[1]
    return AssetStore(path), domain, asset.last_seen_run_id


def _latest_host(request: Request, organization_id: str, asset: AssetRecord):  # noqa: ANN202
    """The host as the asset's most recent run recorded it, or `None`."""
    located = _asset_run_store(request, organization_id, asset)
    if located is None:
        return None
    store, domain, run_id = located
    return store.get_host(run_id, domain)


@router.get(
    "/{organization_id}/assets/{asset_id}/network",
    response_model=NetworkIntelligenceResponse,
)
def get_asset_network(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> NetworkIntelligenceResponse:
    """Network & Geo Intelligence: who owns the asset's IPs (ASN, BGP
    prefix, hosting provider, via Team Cymru) and where they are (offline
    geo lookup — no IP ever leaves the machine), with the geo database's
    freshness so stale data is visible."""
    from core.geoip import GEOIP_MAX_AGE_DAYS

    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    asset = _require_asset(db, organization_id, asset_id)
    host = _latest_host(request, organization_id, asset)
    geo = None
    if host is not None and host.geo_source:
        age = host.geo_db_age_days
        geo = GeoLocationResponse(
            country=host.country,
            region=host.region,
            city=host.city,
            latitude=host.latitude,
            longitude=host.longitude,
            source=host.geo_source,
            database_age_days=age,
            stale=age is None or age > GEOIP_MAX_AGE_DAYS,
        )
    return NetworkIntelligenceResponse(
        asset_id=asset_id,
        run_id=asset.last_seen_run_id,
        ips=list(host.ips) if host is not None else [],
        asn=host.asn if host is not None else None,
        asn_org=host.asn_org if host is not None else None,
        network_cidr=host.cidr if host is not None else None,
        hosting_provider=host.provider if host is not None else None,
        geo=geo,
    )


@router.get(
    "/{organization_id}/assets/{asset_id}/visual",
    response_model=VisualIntelligenceResponse,
)
def get_asset_visual(
    organization_id: str,
    asset_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> VisualIntelligenceResponse:
    """Visual Intelligence: what the asset's web pages looked like on its
    most recent run (title, favicon hash, screenshot reference) and the
    significant visual changes since this organization's previous run of
    the same target. See `core/visual.py` for what counts as a change."""
    from core.visual import SIGNIFICANCE_RULES, visual_changes

    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    asset = _require_asset(db, organization_id, asset_id)
    response = VisualIntelligenceResponse(
        asset_id=asset_id,
        run_id=asset.last_seen_run_id,
        references=[],
        changes=[],
        significance_rules=list(SIGNIFICANCE_RULES),
    )
    located = _asset_run_store(request, organization_id, asset)
    if located is None:
        return response
    store, domain, run_id = located
    current = store.get_http_services(run_id, host=domain)
    response.references = [_visual_reference(service) for service in current]
    previous_run_id = store.find_previous_run(run_id)
    # The account's recon.db may hold runs of its other organizations.
    if previous_run_id and db.account_for_run(organization_id, previous_run_id):
        response.previous_run_id = previous_run_id
        previous = store.get_http_services(previous_run_id, host=domain)
        response.changes = [
            VisualChangeResponse(**asdict(change), reason=change.reason())
            for change in visual_changes(previous, current)
        ]
    return response


def _visual_reference(service: HttpService) -> VisualReferenceResponse:
    return VisualReferenceResponse(
        url=service.url,
        status_code=service.status_code,
        title=service.title,
        favicon_hash=service.favicon_hash,
        screenshot_artifact=service.screenshot_path,
    )


@router.get(
    "/{organization_id}/analyst/assets/{asset_id}/provenance",
    response_model=AnalystProvenanceResponse,
)
def get_asset_raw_provenance(
    organization_id: str,
    asset_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    auth: AuthContext = Depends(require_api_key),
) -> AnalystProvenanceResponse:
    """Analyst/debug namespace: every observation with its raw provider
    name and evidence detail, plus the per-tool provenance the asset's most
    recent run recorded. The product-facing explanation of the same asset
    is `GET .../explanations/asset/{asset_id}`."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    asset = _require_asset(db, organization_id, asset_id)
    observations = [
        RawObservationResponse(
            observation_id=o.observation.observation_id,
            observation_type=o.observation.observation_type,
            run_id=o.observation.run_id,
            observed_at=o.observation.observed_at,
            source=o.evidence.source,
            detail=o.evidence.detail,
            confidence_score=o.evidence.confidence_score,
            confidence_class=o.evidence.confidence_class,
        )
        for o in db.list_observations_for_asset(asset_id, newest=limit)
    ]
    located = _asset_run_store(request, organization_id, asset)
    tool_provenance = []
    if located is not None:
        store, domain, run_id = located
        tool_provenance = [
            RawToolProvenanceResponse(**row)
            for row in store.get_provenance(run_id, domain, limit=limit)
        ]
    return AnalystProvenanceResponse(
        asset_id=asset_id,
        observations=observations,
        run_id=located[2] if located is not None else None,
        tool_provenance=tool_provenance,
    )


@router.get("/{organization_id}/inventory/facets", response_model=InventoryFacetsResponse)
def get_inventory_facets(
    organization_id: str,
    request: Request,
    top: int = Query(default=25, ge=1, le=200),
    auth: AuthContext = Depends(require_api_key),
) -> InventoryFacetsResponse:
    """Inventory counts for filters and dashboards: assets by type,
    exposures by status and severity, candidates by review status, and
    the `top` most common current technologies and open ports."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    facets = db.inventory_facets(organization_id, top=top)
    return InventoryFacetsResponse(
        assets_by_type=facets.assets_by_type,
        exposures_by_status=facets.exposures_by_status,
        candidates_by_review_status=facets.candidates_by_review_status,
        technologies=[FacetCountResponse(value=v, count=c) for v, c in facets.technologies],
        open_ports=[FacetCountResponse(value=v, count=c) for v, c in facets.open_ports],
    )


@router.get("/{organization_id}/relationships", response_model=list[RelationshipResponse])
def list_relationships(
    organization_id: str,
    request: Request,
    relationship_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[RelationshipResponse]:
    """Productization Phase 03: the first API surface over Fase 07's
    relationship graph — real SQL-level pagination from the start (see
    `ControlDB.list_relationships_for_organization`'s own docstring for
    why this one didn't need the `limit=None` backward-compatibility
    case `list_assets_for_organization` needed in Phase 02)."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    rows = db.list_relationships_for_organization(
        organization_id, relationship_type=relationship_type, limit=limit, offset=offset
    )
    return [_relationship_to_response(row) for row in rows]


@router.get(
    "/{organization_id}/relationships/{relationship_id}/evidence",
    response_model=list[RelationshipEvidenceResponse],
)
def list_relationship_evidence(
    organization_id: str,
    relationship_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[RelationshipEvidenceResponse]:
    """The "why are these two entities related" answer — every piece of
    mechanically-resolved evidence behind this one relationship, each
    with its own human-readable `reason` and structured `metadata`
    (e.g. the shared certificate fingerprint or IP address that produced
    it), never a raw database row."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    if db.get_relationship(organization_id, relationship_id) is None:
        raise HTTPException(status_code=404, detail="Relationship not found")
    return [
        RelationshipEvidenceResponse(
            relationship_evidence_id=row.relationship_evidence_id,
            run_id=row.run_id,
            source=row.source,
            collector=row.collector,
            reason=row.reason,
            metadata=_parse_json_object(row.metadata_json),
            observed_at=row.observed_at,
        )
        for row in db.list_relationship_evidence(organization_id, relationship_id)
    ]


@router.get(
    "/{organization_id}/assets/{asset_id}/relationships", response_model=list[RelationshipResponse]
)
def list_asset_relationships(
    organization_id: str,
    asset_id: str,
    request: Request,
    depth: int = Query(default=1, ge=1, le=8),
    auth: AuthContext = Depends(require_api_key),
) -> list[RelationshipResponse]:
    """The asset-centric view of the same graph: every relationship
    reachable from this one asset within `depth` hops — reuses
    `ControlDB.relationship_neighborhood` exactly (already bounded,
    already tenant-scoped, already tested as of Fase 07; this is its
    first API surface). Silently caps at that method's own `max_edges`
    ceiling rather than erroring — a very densely connected asset
    returns a large-but-bounded page, never an unbounded one."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    _require_asset(db, organization_id, asset_id)
    edges, _truncated = db.relationship_neighborhood(organization_id, asset_id, max_depth=depth)
    return [_relationship_to_response(row) for row in edges]


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
    rows = db.list_candidate_assets_for_organization(
        organization_id, candidate_type=candidate_type, limit=limit, offset=offset
    )
    return [CandidateAssetResponse(**row.__dict__) for row in rows]


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
