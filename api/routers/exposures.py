"""Read-only tenant-scoped Exposure API."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, ExposureRecord
from api.schemas import ExposureEvidenceResponse, ExposureHistoryResponse, ExposureResponse

router = APIRouter(prefix="/organizations", tags=["exposures"])


def _db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _require_member(db: ControlDB, account_id: str, organization_id: str) -> None:
    if db.get_role_for_account_organization(account_id, organization_id) is None:
        raise HTTPException(status_code=404, detail="Organization not found")


def _to_response(row: ExposureRecord) -> ExposureResponse:
    return ExposureResponse(**row.__dict__)


@router.get("/{organization_id}/exposures", response_model=list[ExposureResponse])
def list_exposures(
    organization_id: str,
    request: Request,
    status: Literal["open", "reopened", "resolved"] | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    asset_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[ExposureResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    return [
        _to_response(row)
        for row in db.list_exposures_for_organization(
            organization_id,
            status=status,
            severity=severity,
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )
    ]


@router.get("/{organization_id}/exposures/{exposure_id}", response_model=ExposureResponse)
def get_exposure(
    organization_id: str,
    exposure_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ExposureResponse:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    row = db.get_exposure_for_organization(organization_id, exposure_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return _to_response(row)


@router.get(
    "/{organization_id}/exposures/{exposure_id}/evidence",
    response_model=list[ExposureEvidenceResponse],
)
def list_evidence(
    organization_id: str,
    exposure_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[ExposureEvidenceResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    if db.get_exposure_for_organization(organization_id, exposure_id) is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return [
        ExposureEvidenceResponse(
            exposure_evidence_id=row.exposure_evidence_id,
            exposure_id=row.exposure_id,
            run_id=row.run_id,
            finding_id=row.finding_id,
            observed_at=row.observed_at,
        )
        for row in db.list_exposure_evidence(organization_id, exposure_id)
    ]


@router.get(
    "/{organization_id}/exposures/{exposure_id}/history",
    response_model=list[ExposureHistoryResponse],
)
def list_history(
    organization_id: str,
    exposure_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[ExposureHistoryResponse]:
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    if db.get_exposure_for_organization(organization_id, exposure_id) is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return [
        ExposureHistoryResponse(
            event_id=row.event_id,
            exposure_id=row.exposure_id,
            event_type=row.event_type,  # type: ignore[arg-type]
            happened_at=row.happened_at,
            run_id=row.run_id,
            reason=row.reason,
        )
        for row in db.list_exposure_history(organization_id, exposure_id)
    ]
