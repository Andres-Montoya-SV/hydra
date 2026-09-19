"""`POST /scans/{scan_id}/hypotheses-estimate` /
`POST /scans/{scan_id}/hypotheses-assessment` — `suggest-hypotheses` over
HTTP, tier-gated (Free AND Medium get `404` — Pro/Ultra only, per the
task's own table). See `api/routers/reportability.py`'s module docstring
for why the gate is a `404`, checked before scan_id is even resolved.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api import hypotheses_orchestrator as orchestrator
from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.schemas import (
    HypothesesAssessmentRequest,
    HypothesesAssessmentResponse,
    HypothesesEstimateRequest,
    HypothesesEstimateResponse,
)
from api.settings import APISettings
from api.tenancy import account_db_path, account_settings

router = APIRouter(prefix="/scans", tags=["hypotheses"])

_DEFAULT_MAX_RELATIONSHIPS_PER_BATCH = 200


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _require_hypotheses_feature_or_404(control_db: ControlDB, account_id: str):
    subscription = subscriptions.get_or_create_subscription(control_db, account_id)
    limits = subscriptions.effective_limits(subscription)
    feature_limits = subscriptions.llm_feature_limits(limits, "hypotheses")
    if feature_limits is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return limits, feature_limits


def _owned_completed_scan_or_404(control_db: ControlDB, scan_id: str, account_id: str):
    scan = control_db.get_owned_scan(scan_id, account_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status!r}, not completed yet")
    return scan


@router.post("/{scan_id}/hypotheses-estimate", response_model=HypothesesEstimateResponse)
async def hypotheses_estimate(
    scan_id: str,
    body: HypothesesEstimateRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> HypothesesEstimateResponse:
    control_db = _control_db(request)
    limits, feature_limits = _require_hypotheses_feature_or_404(control_db, auth.account_id)
    _owned_completed_scan_or_404(control_db, scan_id, auth.account_id)

    settings = account_settings(_api_settings(request), auth.account_id)
    provider_name = body.provider or settings.hypothesis_provider
    decision = subscriptions.resolve_adversarial_provider(feature_limits, body.adversarial_provider)

    try:
        estimate = await orchestrator.compute_estimate(
            db_path=account_db_path(_api_settings(request), auth.account_id),
            run_id=scan_id,
            provider_name=provider_name,
            adversarial_provider_name=decision.used_adversarial_provider,
            degraded_from_adversarial=decision.degraded,
            limit=body.limit or _DEFAULT_MAX_RELATIONSHIPS_PER_BATCH,
        )
    except orchestrator.HypothesesOrchestratorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    ok, reason = subscriptions.check_llm_budget(
        control_db,
        auth.account_id,
        feature="hypotheses",
        feature_limits=feature_limits,
        additional_cost_usd=estimate.estimated_cost_usd,
    )
    if not ok:
        raise HTTPException(status_code=402, detail=reason)

    record = control_db.create_cost_estimate(
        account_id=auth.account_id,
        scan_id=scan_id,
        feature="hypotheses",
        provider=provider_name,
        adversarial_provider=estimate.adversarial_provider,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
        estimated_cost_usd=estimate.estimated_cost_usd,
        params_json=subscriptions.dump_params(
            {"provider": provider_name, "adversarial_provider": estimate.adversarial_provider}
        ),
    )
    return HypothesesEstimateResponse(
        estimate_id=record.estimate_id,
        estimated_cost_usd=estimate.estimated_cost_usd,
        expires_at=record.expires_at,
        relationships_count=estimate.relationships_count,
        provider=provider_name,
        adversarial_provider=estimate.adversarial_provider,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
    )


@router.post("/{scan_id}/hypotheses-assessment", response_model=HypothesesAssessmentResponse)
async def hypotheses_assessment(
    scan_id: str,
    body: HypothesesAssessmentRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> HypothesesAssessmentResponse:
    control_db = _control_db(request)
    _require_hypotheses_feature_or_404(control_db, auth.account_id)
    _owned_completed_scan_or_404(control_db, scan_id, auth.account_id)

    if not body.confirm:
        raise HTTPException(
            status_code=400, detail="confirm must be explicitly true to spend API credits."
        )
    estimate = control_db.get_valid_cost_estimate(
        body.estimate_id, auth.account_id, scan_id=scan_id, feature="hypotheses"
    )
    if estimate is None:
        raise HTTPException(
            status_code=400,
            detail="estimate_id is missing, expired, already used, or does not match this scan.",
        )

    try:
        outcome = await orchestrator.run_assessment(
            db_path=account_db_path(_api_settings(request), auth.account_id),
            run_id=scan_id,
            provider_name=estimate.provider,
            adversarial_provider_name=estimate.adversarial_provider,
            limit=_DEFAULT_MAX_RELATIONSHIPS_PER_BATCH,
        )
    except orchestrator.HypothesesOrchestratorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    control_db.consume_cost_estimate(estimate.estimate_id)
    subscriptions.record_llm_spend(
        control_db, auth.account_id, feature="hypotheses", amount_usd=estimate.estimated_cost_usd
    )

    return HypothesesAssessmentResponse(
        hypotheses_count=outcome.hypotheses_count,
        trustworthy_count=outcome.trustworthy_count,
        degraded_from_adversarial=estimate.degraded_from_adversarial,
        actual_cost_usd=estimate.estimated_cost_usd,
    )
