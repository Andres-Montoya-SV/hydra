"""`POST /scans/{scan_id}/reportability-estimate` /
`POST /scans/{scan_id}/reportability-assessment` — `assess-reportability`
over HTTP (docs/PAID_API_DESIGN.md Part E.1), tier-gated per Part B.

**The Free-tier gate is the very first thing every route here does** —
before even resolving `scan_id` — and returns exactly `404`, never
`403`: from a Free account's perspective this route must be
indistinguishable from one that was never registered at all
(`api/tiers.py`'s own docstring explains why a `403` would leak more
than a `404` does).
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request

from api import reportability_orchestrator as orchestrator
from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.schemas import (
    ReportabilityAssessmentRequest,
    ReportabilityAssessmentResponse,
    ReportabilityEstimateRequest,
    ReportabilityEstimateResponse,
)
from api.settings import APISettings
from api.tenancy import account_db_path, account_settings

router = APIRouter(prefix="/scans", tags=["reportability"])

_DEFAULT_MAX_FINDINGS_PER_BATCH = 50


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _require_reportability_feature_or_404(control_db: ControlDB, account_id: str):
    subscription = subscriptions.get_or_create_subscription(control_db, account_id)
    limits = subscriptions.effective_limits(subscription)
    feature_limits = subscriptions.llm_feature_limits(limits, "reportability")
    if feature_limits is None:
        # Identical to FastAPI's own 404 for an undefined route — see
        # this module's docstring for why 403 would be the wrong choice.
        raise HTTPException(status_code=404, detail="Not Found")
    return limits, feature_limits


def _owned_scan_or_404(control_db: ControlDB, scan_id: str, account_id: str):
    scan = control_db.get_owned_scan(scan_id, account_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status!r}, not completed yet")
    return scan


@router.post(
    "/{scan_id}/reportability-estimate",
    response_model=ReportabilityEstimateResponse,
)
async def reportability_estimate(
    scan_id: str,
    body: ReportabilityEstimateRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ReportabilityEstimateResponse:
    control_db = _control_db(request)
    limits, feature_limits = _require_reportability_feature_or_404(control_db, auth.account_id)
    _owned_scan_or_404(control_db, scan_id, auth.account_id)

    settings = account_settings(_api_settings(request), auth.account_id)
    provider_name = body.provider or settings.reportability_provider
    decision = subscriptions.resolve_adversarial_provider(feature_limits, body.adversarial_provider)

    try:
        estimate = await orchestrator.compute_estimate(
            db_path=account_db_path(_api_settings(request), auth.account_id),
            run_id=scan_id,
            rules_text=body.program_rules_text,
            provider_name=provider_name,
            adversarial_provider_name=decision.used_adversarial_provider,
            degraded_from_adversarial=decision.degraded,
            severity=body.severity,
            host=body.host,
            limit=body.limit or _DEFAULT_MAX_FINDINGS_PER_BATCH,
        )
    except orchestrator.ReportabilityOrchestratorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    ok, reason = subscriptions.check_llm_budget(
        control_db,
        auth.account_id,
        feature="reportability",
        feature_limits=feature_limits,
        additional_cost_usd=estimate.estimated_cost_usd,
    )
    if not ok:
        raise HTTPException(status_code=402, detail=reason)

    record = control_db.create_cost_estimate(
        account_id=auth.account_id,
        scan_id=scan_id,
        feature="reportability",
        provider=provider_name,
        adversarial_provider=estimate.adversarial_provider,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
        estimated_cost_usd=estimate.estimated_cost_usd,
        params_json=subscriptions.dump_params(
            {
                "rules_text": estimate.rules_text,
                "severity": estimate.severity,
                "host": estimate.host,
                "provider": provider_name,
                "adversarial_provider": estimate.adversarial_provider,
            }
        ),
    )
    return ReportabilityEstimateResponse(
        estimate_id=record.estimate_id,
        estimated_cost_usd=estimate.estimated_cost_usd,
        expires_at=record.expires_at,
        findings_count=estimate.findings_count,
        provider=provider_name,
        adversarial_provider=estimate.adversarial_provider,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
    )


@router.post(
    "/{scan_id}/reportability-assessment",
    response_model=ReportabilityAssessmentResponse,
)
async def reportability_assessment(
    scan_id: str,
    body: ReportabilityAssessmentRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ReportabilityAssessmentResponse:
    control_db = _control_db(request)
    _require_reportability_feature_or_404(control_db, auth.account_id)
    _owned_scan_or_404(control_db, scan_id, auth.account_id)

    if not body.confirm:
        raise HTTPException(
            status_code=400, detail="confirm must be explicitly true to spend API credits."
        )
    estimate = control_db.get_valid_cost_estimate(
        body.estimate_id,
        auth.account_id,
        scan_id=scan_id,
        feature="reportability",
    )
    if estimate is None:
        raise HTTPException(
            status_code=400,
            detail="estimate_id is missing, expired, already used, or does not match this scan.",
        )

    params = json.loads(estimate.params_json)

    try:
        outcome = await orchestrator.run_assessment(
            db_path=account_db_path(_api_settings(request), auth.account_id),
            output_dir=account_db_path(_api_settings(request), auth.account_id).parent / scan_id,
            run_id=scan_id,
            rules_text=params["rules_text"],
            provider_name=estimate.provider,
            adversarial_provider_name=estimate.adversarial_provider,
            severity=params["severity"],
            host=params["host"],
        )
    except orchestrator.ReportabilityOrchestratorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    control_db.consume_cost_estimate(estimate.estimate_id)
    subscriptions.record_llm_spend(
        control_db, auth.account_id, feature="reportability", amount_usd=estimate.estimated_cost_usd
    )

    return ReportabilityAssessmentResponse(
        assessed_count=outcome.assessed_count,
        eligible_count=outcome.eligible_count,
        not_eligible_count=outcome.not_eligible_count,
        uncertain_count=outcome.uncertain_count,
        cross_validated=outcome.cross_validated,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
        actual_cost_usd=estimate.estimated_cost_usd,
    )
