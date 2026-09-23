"""`POST /domains/{domain}/monitoring` / `GET .../monitoring` /
`DELETE .../monitoring` — "Hydra API — Continuous Monitoring for Verified
Domains." Opt-in only (never implied by verifying a domain), per-domain,
gated by the exact same domain-verification and tier machinery
`api/routers/scans.py` and `api/routers/domains.py` already use — this
router adds no second authorization system.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.domain_verification import classify_scan_gate, normalize_domain
from api.schemas import MonitoringStatusResponse, SetMonitoringRequest
from api.settings import APISettings

router = APIRouter(prefix="/domains", tags=["monitoring"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _require_verified_domain_or_403(control_db: ControlDB, account_id: str, domain: str) -> None:
    """The same Part A gate `api/routers/scans.py::_require_verified_domain_or_403`
    enforces on a manual scan — monitoring is not a lesser-authorized
    action than a one-off scan; opting a domain into monitoring without
    ever having verified it would let an account get Hydra to
    auto-scan a domain it doesn't control on a schedule, which is
    strictly worse than the one-off case Part A already exists to
    prevent."""
    status, _ = classify_scan_gate(
        domain,
        active_verifications=control_db.get_verified_domains_for_account(account_id),
        all_verifications=control_db.get_all_verifications_for_account(account_id),
    )
    if status != "covered":
        raise HTTPException(
            status_code=403,
            detail=(
                f"Domain {domain!r} is not currently verified for this account. "
                f"POST /domains {{'domain': '{domain}'}} to verify it before enabling monitoring."
            ),
        )


@router.post("/{domain}/monitoring", response_model=MonitoringStatusResponse, status_code=201)
def set_monitoring(
    domain: str,
    body: SetMonitoringRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> MonitoringStatusResponse:
    control_db = _control_db(request)
    api_settings = _api_settings(request)
    domain = normalize_domain(domain)

    _require_verified_domain_or_403(control_db, auth.account_id, domain)

    if body.speed2:
        subscription = subscriptions.get_or_create_subscription(control_db, auth.account_id)
        limits = subscriptions.effective_limits(subscription)
        if not limits.monitoring_speed2:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"The {limits.tier!r} tier does not include Speed 2 (weekly active) "
                    "monitoring. Upgrade to Pro or Ultra to enable it, or omit "
                    '"speed2" to use Speed 1 (daily passive) monitoring only.'
                ),
            )

    record = control_db.create_or_update_monitored_domain(
        account_id=auth.account_id,
        domain=domain,
        speed2_enabled=body.speed2,
        passive_interval_hours=api_settings.monitoring_passive_interval_hours,
        active_interval_hours=api_settings.monitoring_active_interval_hours,
    )
    return _to_response(record)


@router.get("/{domain}/monitoring", response_model=MonitoringStatusResponse)
def get_monitoring(
    domain: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> MonitoringStatusResponse:
    domain = normalize_domain(domain)
    record = _control_db(request).get_monitored_domain(auth.account_id, domain)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{domain!r} is not being monitored")
    return _to_response(record)


@router.delete("/{domain}/monitoring", status_code=204)
def delete_monitoring(
    domain: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> None:
    domain = normalize_domain(domain)
    deleted = _control_db(request).delete_monitored_domain(auth.account_id, domain)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"{domain!r} is not being monitored")


def _to_response(record) -> MonitoringStatusResponse:  # noqa: ANN001 - MonitoredDomainRecord
    return MonitoringStatusResponse(
        domain=record.domain,
        status=record.status,
        speed2_enabled=record.speed2_enabled,
        last_passive_run_at=record.last_passive_run_at,
        last_active_run_at=record.last_active_run_at,
        next_passive_due_at=record.next_passive_due_at,
        next_active_due_at=record.next_active_due_at,
        last_asset_count=record.last_asset_count,
        needs_review=record.needs_review,
    )
