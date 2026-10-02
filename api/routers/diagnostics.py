"""`GET /account/diagnostics` (Productization Phase 13a): one response a
customer can hand to support, or read themselves, that explains why the
account may not be working as expected.

Scoped to the calling account only, like everything under `/account`. It
never contains a secret: no key material, verification tokens or
integration credentials. The recent scans are the account's own scans.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, ScanRecord, SubscriptionRecord
from api.edge import current_request_id
from api.schemas import DiagnosticsResponse, DiagnosticsScan
from api.security import is_currently_valid
from api.version import API_VERSION, HYDRA_VERSION, build_commit

router = APIRouter(prefix="/account", tags=["account"])

RECENT_SCANS = 10


def _recent_scans(control_db: ControlDB, account_id: str) -> list[DiagnosticsScan]:
    scans: list[ScanRecord] = [
        scan
        for organization_id, _ in control_db.list_organizations_for_account(account_id)
        for scan in control_db.list_scans_for_organization(organization_id)
        if scan.account_id == account_id
    ]
    recent = sorted(scans, key=lambda s: s.created_at, reverse=True)[:RECENT_SCANS]
    return [
        DiagnosticsScan(
            scan_id=s.scan_id,
            domain=s.domain,
            status=s.status,
            trigger_source=s.trigger_source,
            created_at=s.created_at,
            updated_at=s.updated_at,
            retry_count=s.retry_count,
            error_message=s.error_message,
        )
        for s in recent
    ]


def _hints(response: DiagnosticsResponse, subscription: SubscriptionRecord) -> list[str]:
    hints = []
    if not response.email_verified:
        hints.append(
            "Email not verified: scans are refused until it is. "
            "POST /accounts/resend-verification for a new link."
        )
    if subscription.status == "suspended":
        hints.append(
            "Account suspended for non-payment: read-only until billing is resolved "
            "via POST /account/subscription."
        )
    elif subscription.status == "past_due":
        hints.append(
            f"Payment past due since {subscription.grace_period_started_at}: everything "
            "keeps working until the grace period ends."
        )
    if response.scans_used_this_period >= response.scans_per_month:
        hints.append("This month's scans are used up; the quota resets next month.")
    if response.verified_domains == 0:
        hints.append("No verified domain yet: POST /domains to start verifying one.")
    if response.unscannable_verified_domains:
        hints.append(
            f"{len(response.unscannable_verified_domains)} verified domain(s) are beyond "
            "the tier's limit and can't be scanned until the account upgrades."
        )
    if response.monitored_domains_paused:
        hints.append(
            f"{response.monitored_domains_paused} monitored domain(s) are paused: "
            "their verification lapsed. Re-verify them to resume monitoring."
        )
    return hints


@router.get("/diagnostics", response_model=DiagnosticsResponse)
def get_diagnostics(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> DiagnosticsResponse:
    control_db: ControlDB = request.app.state.control_db
    account = control_db.get_account(auth.account_id)
    keys = control_db.list_keys_for_account(auth.account_id)
    key = next(k for k in keys if k.key_id == auth.key_id)
    subscription = subscriptions.get_or_create_subscription(control_db, auth.account_id)
    limits = subscriptions.effective_limits(subscription)
    usage = control_db.get_monthly_usage(auth.account_id, subscriptions.current_period_key())
    monitored = control_db.list_monitored_domains_for_account(auth.account_id)
    response = DiagnosticsResponse(
        request_id=current_request_id(),
        server_time=datetime.now(timezone.utc).isoformat(),
        version=HYDRA_VERSION,
        api_version=API_VERSION,
        build_commit=build_commit(),
        account_id=auth.account_id,
        email_verified=account is None or account.email is None or account.is_email_verified,
        key_id=key.key_id,
        key_expires_at=key.expires_at,
        active_keys=sum(1 for k in keys if is_currently_valid(k)),
        tier=subscription.tier,
        subscription_status=subscription.status,
        scans_used_this_period=usage.scans_used,
        scans_per_month=limits.scans_per_month,
        organizations=len(control_db.list_organizations_for_account(auth.account_id)),
        verified_domains=len(control_db.get_verified_domains_for_account(auth.account_id)),
        unscannable_verified_domains=subscriptions.unscannable_domains(
            control_db, auth.account_id, limits
        ),
        monitored_domains=len(monitored),
        monitored_domains_paused=sum(
            1 for m in monitored if m.status == "paused_verification_lapsed"
        ),
        recent_scans=_recent_scans(control_db, auth.account_id),
    )
    response.hints = _hints(response, subscription)
    return response
