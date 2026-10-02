"""Tenant-scoped Exposure API: inventory, evidence, history, risk, and the
two explicit, audited lifecycle transitions (resolve, reopen). Absence of
a finding in a later scan never resolves anything — see
`ControlDB.upsert_exposure`'s docstring."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, ExposureEvidenceRecord, ExposureRecord
from api.errors import ApiError
from api.routers.org_access import control_db as _db
from api.routers.org_access import require_member as _require_member
from api.schemas import (
    ExposureEvidenceResponse,
    ExposureFindingResponse,
    ExposureHistoryResponse,
    ExposureReportEntryResponse,
    ExposureReportHistoryEventResponse,
    ExposureResponse,
    ExposureRiskResponse,
    ReopenExposureRequest,
    ResolveExposureRequest,
    RiskFactorResponse,
)
from api.settings import APISettings
from api.tenancy import account_db_path
from core.client_report.exposure_report import exposure_history_report_data
from core.risk_scoring import classify_exposure_risk
from core.store import AssetStore

router = APIRouter(prefix="/organizations", tags=["exposures"])


def _require_owner_and_exposure(
    db: ControlDB, account_id: str, organization_id: str, exposure_id: str
) -> None:
    """Lifecycle mutations are owner-only; a non-member and an unknown
    exposure are both a 404, so neither reveals what exists."""
    if _require_member(db, account_id, organization_id) != "owner":
        raise ApiError(403, "Owner role required", code="owner_role_required")
    if db.get_exposure_for_organization(organization_id, exposure_id) is None:
        raise HTTPException(status_code=404, detail="Exposure not found")


def _to_response(row: ExposureRecord) -> ExposureResponse:
    return ExposureResponse(**row.__dict__)


def _finding_lookup(
    api_settings: APISettings,
) -> Callable[[ExposureEvidenceRecord], ExposureFindingResponse | None]:
    """Resolves each evidence row's `finding_id` against the recon.db of the
    account whose scan produced it. Opens each account's store at most once,
    and never creates a database that doesn't already exist."""
    stores: dict[str, AssetStore | None] = {}

    def lookup(row: ExposureEvidenceRecord) -> ExposureFindingResponse | None:
        if row.account_id not in stores:
            path = account_db_path(api_settings, row.account_id)
            stores[row.account_id] = AssetStore(path) if path.exists() else None
        store = stores[row.account_id]
        finding = None if store is None else store.get_finding(row.run_id, row.finding_id)
        if finding is None:
            return None
        return ExposureFindingResponse(
            host=str(finding["host"]),
            url=_opt_str(finding.get("url")),
            name=_opt_str(finding.get("name")),
            severity=_opt_str(finding.get("severity")),
            description=_opt_str(finding.get("description")),
            confidence_score=_opt_int(finding.get("confidence_score")),
            discovered_at=_opt_str(finding.get("discovered_at")),
        )

    return lookup


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def _opt_int(value: object) -> int | None:
    """A raw SQLite value that isn't a real integer is dropped, not coerced
    into a misleading number."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


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
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[ExposureEvidenceResponse]:
    """Why this exposure exists: each run that observed it, plus the actual
    detector result (what matched, where) — not just an opaque finding id."""
    db = _db(request)
    _require_member(db, auth.account_id, organization_id)
    if db.get_exposure_for_organization(organization_id, exposure_id) is None:
        raise HTTPException(status_code=404, detail="Exposure not found")
    rows = db.list_exposure_evidence(organization_id, exposure_id, limit=limit, offset=offset)
    lookup = _finding_lookup(request.app.state.api_settings)
    return [
        ExposureEvidenceResponse(
            exposure_evidence_id=row.exposure_evidence_id,
            exposure_id=row.exposure_id,
            run_id=row.run_id,
            finding_id=row.finding_id,
            observed_at=row.observed_at,
            finding=lookup(row),
        )
        for row in rows
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
        factors=[RiskFactorResponse(**asdict(f)) for f in classification.factors],
        unknowns=list(classification.unknowns),
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
    _require_owner_and_exposure(db, auth.account_id, organization_id, exposure_id)

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


@router.post(
    "/{organization_id}/exposures/{exposure_id}/reopen",
    response_model=ExposureResponse,
)
def reopen_exposure(
    organization_id: str,
    exposure_id: str,
    body: ReopenExposureRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ExposureResponse:
    """Undo a resolution that turned out to be wrong. Same owner-only gate
    as resolve; the reason is recorded as a 'reopened' history event, and
    the earlier 'resolved' event stays in history untouched."""
    db = _db(request)
    _require_owner_and_exposure(db, auth.account_id, organization_id, exposure_id)

    changed = db.reopen_exposure(
        organization_id=organization_id,
        exposure_id=exposure_id,
        reopened_at=datetime.now(timezone.utc).isoformat(),
        reason=body.reason.strip(),
    )
    if not changed:
        raise HTTPException(status_code=409, detail="Only a resolved exposure can be reopened")

    row = db.get_exposure_for_organization(organization_id, exposure_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Exposure disappeared")
    return _to_response(row)
