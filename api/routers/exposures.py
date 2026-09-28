"""Read-only tenant-scoped Exposure API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, ExposureRecord
from api.schemas import (
    ExposureEvidenceResponse,
    ExposureHistoryResponse,
    ExposureReportEntryResponse,
    ExposureReportHistoryEventResponse,
    ExposureResponse,
    ExposureRiskResponse,
    ResolveExposureRequest,
)
from core.client_report.exposure_report import exposure_history_report_data
from core.risk_scoring import classify_exposure_risk

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


@router.get(
    "/{organization_id}/reports/exposures",
    response_model=list[ExposureReportEntryResponse],
)
def get_exposure_report(
    organization_id: str,
    request: Request,
    status: Literal["open", "reopened", "resolved"] | None = None,
    auth: AuthContext = Depends(require_api_key),
) -> list[ExposureReportEntryResponse]:
    """Fase 21: the client-report-facing view of exposures WITH their
    full cross-run history — never just a current-run snapshot. See
    `core/client_report/exposure_report.py`'s own docstring for why this
    exists alongside (not instead of) the existing per-run report
    pipeline."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    entries = exposure_history_report_data(db, organization_id, status=status)
    return [
        ExposureReportEntryResponse(
            exposure_id=entry.exposure_id,
            asset_id=entry.asset_id,
            title=entry.title,
            severity=entry.severity,
            status=entry.status,
            first_seen_at=entry.first_seen_at,
            last_seen_at=entry.last_seen_at,
            history=[
                ExposureReportHistoryEventResponse(
                    event_type=event.event_type,  # type: ignore[arg-type]
                    happened_at=event.happened_at,
                    run_id=event.run_id,
                    reason=event.reason,
                )
                for event in entry.history
            ],
            risk_level=entry.risk_level,
            risk_reasons=list(entry.risk_reasons),
        )
        for entry in entries
    ]


@router.get(
    "/{organization_id}/exposures/{exposure_id}/risk",
    response_model=ExposureRiskResponse,
)
def get_exposure_risk(
    organization_id: str,
    exposure_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ExposureRiskResponse:
    """Fase 21: deterministic, explainable risk/criticality — never a
    black-box score. See `core/risk_scoring.py`'s own docstring for the
    exact rule; this endpoint only serializes its output."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    factors = db.risk_factors_for_exposure(organization_id, exposure_id)
    if factors is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    classification = classify_exposure_risk(factors)
    return ExposureRiskResponse(
        exposure_id=exposure_id,
        level=classification.level.value,  # type: ignore[arg-type]
        reasons=list(classification.reasons),
    )


@router.post(
    "/{organization_id}/exposures/{exposure_id}/resolve",
    response_model=ExposureResponse,
)
def resolve_exposure(
    organization_id: str,
    exposure_id: str,
    body: ResolveExposureRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ExposureResponse:
    db = _db(request)
    role = db.get_role_for_account_organization(auth.account_id, organization_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if role != "owner":
        raise HTTPException(status_code=403, detail="Owner role required")
    if db.get_exposure_for_organization(organization_id, exposure_id) is None:
        raise HTTPException(status_code=404, detail="Exposure not found")

    changed = db.resolve_exposure(
        organization_id=organization_id,
        exposure_id=exposure_id,
        resolved_at=datetime.now(timezone.utc).isoformat(),
        resolution_reason=body.reason.strip(),
    )
    if not changed:
        raise HTTPException(status_code=409, detail="Exposure is already resolved")

    row = db.get_exposure_for_organization(organization_id, exposure_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Exposure disappeared")
    return _to_response(row)
