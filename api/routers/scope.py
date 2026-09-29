"""Organization scope exclusions (Productization Roadmap v2) and the
known / candidate / authorized / observed / excluded classification of a
host.

An exclusion is the organization's explicit instruction that a host (or a
path under it) must never be actively collected against. Every API scan of
the organization applies them, on top of SCOPE_FILE, through the same
`!pattern` machinery the scope engine already enforces; a scan whose own
target is excluded is refused. Read by any member; changed only by an
owner; removal is a soft delete, so the history stays.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from api.auth import AuthContext, require_api_key
from api.control_db import (
    ControlDB,
    DuplicateExclusionError,
    ScopeExclusionRecord,
    role_can_modify_scope,
)
from api.schemas import (
    AddScopeExclusionRequest,
    RemoveScopeExclusionRequest,
    ScopeClassificationResponse,
    ScopeExclusionResponse,
)
from api.scope_classification import classify_host
from core.assets import normalize_domain
from core.scope import normalize_exclusion_pattern

router = APIRouter(prefix="/organizations", tags=["scope"])


def _db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _require_role(db: ControlDB, account_id: str, organization_id: str) -> str:
    role = db.get_role_for_account_organization(account_id, organization_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return role


def _require_owner(db: ControlDB, account_id: str, organization_id: str) -> None:
    if not role_can_modify_scope(_require_role(db, account_id, organization_id)):
        raise HTTPException(status_code=403, detail="Owner role required")


def _response(record: ScopeExclusionRecord) -> ScopeExclusionResponse:
    fields = asdict(record)
    fields.pop("organization_id")
    return ScopeExclusionResponse(**fields)


@router.get("/{organization_id}/scope/exclusions", response_model=list[ScopeExclusionResponse])
def list_exclusions(
    organization_id: str,
    request: Request,
    include_removed: bool = False,
    auth: AuthContext = Depends(require_api_key),
) -> list[ScopeExclusionResponse]:
    db = _db(request)
    _require_role(db, auth.account_id, organization_id)
    records = db.list_scope_exclusions(organization_id, include_removed=include_removed)
    return [_response(record) for record in records]


@router.post(
    "/{organization_id}/scope/exclusions",
    response_model=ScopeExclusionResponse,
    status_code=201,
)
def add_exclusion(
    organization_id: str,
    body: AddScopeExclusionRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ScopeExclusionResponse:
    db = _db(request)
    _require_owner(db, auth.account_id, organization_id)
    try:
        pattern = normalize_exclusion_pattern(body.pattern)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_exclusion_pattern", "message": str(exc)}
        ) from exc
    try:
        record = db.add_scope_exclusion(
            organization_id=organization_id,
            account_id=auth.account_id,
            pattern=pattern,
            reason=body.reason.strip(),
        )
    except DuplicateExclusionError as exc:
        raise HTTPException(status_code=409, detail="Exclusion already active") from exc
    return _response(record)


@router.delete("/{organization_id}/scope/exclusions/{exclusion_id}", status_code=204)
def remove_exclusion(
    organization_id: str,
    exclusion_id: str,
    body: RemoveScopeExclusionRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    db = _db(request)
    _require_owner(db, auth.account_id, organization_id)
    removed = db.remove_scope_exclusion(
        organization_id=organization_id,
        exclusion_id=exclusion_id,
        account_id=auth.account_id,
        reason=body.reason.strip(),
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    return Response(status_code=204)


@router.get("/{organization_id}/scope/classify", response_model=ScopeClassificationResponse)
def classify(
    organization_id: str,
    request: Request,
    host: str = Query(min_length=1, max_length=253),
    auth: AuthContext = Depends(require_api_key),
) -> ScopeClassificationResponse:
    db = _db(request)
    _require_role(db, auth.account_id, organization_id)
    normalized = normalize_domain(host)
    if not normalized:
        raise HTTPException(status_code=422, detail="Not a valid hostname")
    return ScopeClassificationResponse(**asdict(classify_host(db, organization_id, normalized)))
