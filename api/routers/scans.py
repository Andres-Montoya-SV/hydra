"""`POST /scans` / `GET /scans/{id}` / `GET /scans/{id}/report` /
`POST /scans/{id}/client-report` — docs/PAID_API_DESIGN.md Part E.

Every route here depends on `require_api_key` and then re-checks scan
ownership via `ControlDB.get_owned_scan` before touching anything — the
Part F.3 double-check applies uniformly, not just to the plain status
endpoint. A `scan_id` that exists but belongs to a different account
returns 404, identical to a `scan_id` that doesn't exist at all — never
403, which would confirm the scan's existence to a non-owner.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import asdict
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from api import entitlements, subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, DomainVerificationRecord, ScanRecord
from api.domain_verification import normalize_domain
from api.errors import ApiError
from api.monitoring import DEGRADED_OUTCOMES
from api.schemas import (
    ClientReportRequest,
    CreateScanRequest,
    CreateScanResponse,
    ProviderOutcome,
    ProviderRunOutcomeResponse,
    ScanChangeSummaryResponse,
    ScanCollectionResponse,
    ScanStatusResponse,
)
from api.settings import APISettings
from api.tenancy import account_settings
from api.tiers import TierLimits
from core.exceptions import ValidationError
from utils.security import confine_path, validate_run_id

logger = logging.getLogger("hydra.api.scans")

router = APIRouter(prefix="/scans", tags=["scans"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


def _api_settings(request: Request) -> APISettings:
    return request.app.state.api_settings  # type: ignore[no-any-return]


def _owned_scan_or_404(control_db: ControlDB, scan_id: str, account_id: str) -> ScanRecord:
    scan = control_db.get_owned_scan(scan_id, account_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _require_verified_domain_or_403(
    control_db: ControlDB, account_id: str, domain: str, limits: TierLimits
) -> None:
    """Part A's non-negotiable gate (docs/PAID_API_DESIGN.md) — lives
    directly in `create_scan` below, on the exact same mandatory
    `account_id` every other account-scoped lookup in this file already
    requires, rather than as a separate dependency/middleware layer a
    future route could add without remembering to include it."""
    status, record = subscriptions.domain_scan_gate(control_db, account_id, domain, limits)
    if status == "covered":
        return
    if status == "over_limit":  # verified, but beyond the tier's N (Phase 12b)
        cap = limits.max_concurrent_verified_domains
        raise entitlements.entitlement_error(limits.tier, "verified_domains", cap or 0)
    if status == "expired":
        expired = cast(DomainVerificationRecord, record)
        raise ApiError(
            403,
            f"Verification for {expired.domain!r} expired on {expired.expires_at}. "
            f"POST /domains {{'domain': '{expired.domain}'}} to re-verify before scanning.",
            code="domain_verification_expired",
        )
    raise ApiError(
        403,
        f"Domain {domain!r} is not verified for this account. "
        f"POST /domains {{'domain': '{domain}'}} to start verification, then "
        "POST /domains/{domain}/verify.",
        code="domain_not_verified",
    )


def _require_verified_email_or_403(control_db: ControlDB, account_id: str) -> None:
    """Hallazgo 1's other half (the rate limit is at `POST /accounts`
    itself): an account exists and can authenticate the moment it's
    created, but may not RUN anything until its email is confirmed —
    checked first, before quota/billing/domain gates, since "is this
    even a confirmed account" is the more fundamental question. A
    pre-Round-4 account with no email on file at all (`email is None`)
    is treated as already verified — there was nothing to confirm when
    it was created, and retroactively locking out every existing account
    the moment this shipped would be a real, unannounced regression for
    already-onboarded users, not a security fix."""
    account = control_db.get_account(account_id)
    if account is not None and account.email is not None and not account.is_email_verified:
        raise ApiError(
            403,
            "This account's email address has not been verified yet. Check your inbox "
            "for the verification link, or POST /accounts/resend-verification for a new one.",
            code="email_not_verified",
        )


def _require_billing_and_quota_ok(control_db: ControlDB, account_id: str):
    """Part B/D's gate, in the exact same place and spirit as Round 2's
    domain-verification gate above — reused, not duplicated as a second
    "quota check" layer a future route could forget to call. Billing
    status is checked first (`402`, distinct from a quota `403`): an
    account with a lapsed payment shouldn't be told "quota exceeded" when
    the real reason is unrelated to how many scans it has run."""
    subscription = subscriptions.get_or_create_subscription(control_db, account_id)
    if subscriptions.access_blocked_by_billing(subscription):
        raise ApiError(
            402,
            "This account's subscription is suspended (payment past due beyond the "
            f"{subscriptions.GRACE_PERIOD_DAYS}-day grace period). Resolve billing via "
            "POST /account/subscription to resume scanning.",
            code="account_suspended",
        )
    limits = subscriptions.effective_limits(subscription)
    # A cheap early refusal; the authoritative, atomic one is
    # `reserve_scan`, right before the scan is created.
    ok, reason = subscriptions.check_scan_quota(control_db, account_id, limits)
    if not ok:
        raise ApiError(403, reason, code="scan_quota_exceeded")
    return limits


def _validated_capability_override(
    control_db: ControlDB, account_id: str, providers: list[str]
) -> frozenset[str]:
    """A per-scan provider override, checked before anything is written or
    any quota is spent: only an owner of the scan's organization may
    override, the providers must exist and be toggleable (422), and every
    one must be within the account's tier (typed 403, never dropped)."""
    from api.collection_capabilities import (
        CapabilityRequestError,
        not_entitled,
        validate_requested,
    )
    from api.control_db import role_can_modify_scope
    from api.routers.collection import account_tier, entitlement_error, invalid_request_error

    organization_id = control_db.default_organization_id_for_account(account_id)
    role = control_db.get_role_for_account_organization(account_id, organization_id)
    if not role_can_modify_scope(role):
        raise HTTPException(status_code=403, detail="Owner role required to override providers")
    try:
        requested = validate_requested(providers)
    except CapabilityRequestError as exc:
        raise invalid_request_error(exc) from exc
    tier = account_tier(control_db, account_id)
    blocked = not_entitled(requested, tier)
    if blocked:
        raise entitlement_error(tier, blocked)
    return requested


def _require_not_excluded(control_db: ControlDB, account_id: str, domain: str) -> None:
    """A target the organization explicitly excluded is refused up front
    (the pipeline would refuse it too), before any quota is spent."""
    from api.scope_classification import excluding_pattern

    organization_id = control_db.default_organization_id_for_account(account_id)
    exclusions = {
        e.pattern: e.exclusion_id for e in control_db.list_scope_exclusions(organization_id)
    }
    exclusion_id = excluding_pattern(domain, exclusions)
    if exclusion_id is not None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "target_excluded",
                "exclusion_id": exclusion_id,
                "message": f"{domain} is excluded from this organization's scope.",
            },
        )


@router.post("", response_model=CreateScanResponse, status_code=202)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CreateScanResponse:
    control_db = _control_db(request)
    api_settings = _api_settings(request)

    _require_verified_email_or_403(control_db, auth.account_id)
    limits = _require_billing_and_quota_ok(control_db, auth.account_id)
    domain = normalize_domain(body.domain)
    _require_verified_domain_or_403(control_db, auth.account_id, domain, limits)
    _require_not_excluded(control_db, auth.account_id, domain)
    override = (
        None
        if body.providers is None
        else _validated_capability_override(control_db, auth.account_id, body.providers)
    )

    ok, reason = subscriptions.reserve_scan(control_db, auth.account_id, limits)
    if not ok:
        raise ApiError(403, reason, code="scan_quota_exceeded")
    scan_id = secrets.token_hex(16)
    db_path = str(account_settings(api_settings, auth.account_id).project_root)
    try:
        control_db.create_scan(
            scan_id=scan_id,
            account_id=auth.account_id,
            domain=domain,
            db_path=db_path,
            collection_profile=body.profile,
            capability_override=override,
        )
    except Exception:
        subscriptions.release_scan(control_db, auth.account_id)
        raise

    # The request returns immediately with "queued" — the row just sits
    # in the `scans` table. `api/scan_worker.py`'s worker loop (running
    # continuously in the background, started in api/main.py's
    # lifespan) is what actually claims and executes it, on its own
    # poll cycle — this request handler never spawns the scan directly
    # anymore. See that module's own docstring for the full durable-
    # queue design (this is what makes a scan survive this process
    # restarting mid-execution, which a directly-spawned asyncio task
    # here never could).
    return CreateScanResponse(scan_id=scan_id, status="queued")


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ScanStatusResponse:
    scan = _owned_scan_or_404(_control_db(request), scan_id, auth.account_id)
    return ScanStatusResponse(
        scan_id=scan.scan_id,
        domain=scan.domain,
        status=scan.status,  # type: ignore[arg-type]
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        error_message=scan.error_message,
        collection_profile=scan.collection_profile,
        capability_override=(
            None if scan.capability_override is None else list(scan.capability_override)
        ),
        effective_providers=(
            None if scan.effective_providers is None else list(scan.effective_providers)
        ),
    )


@router.get("/{scan_id}/summary", response_model=ScanChangeSummaryResponse)
def get_scan_summary(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ScanChangeSummaryResponse:
    """What this scan changed for its organization: assets observed, new /
    changed / disappeared / reappeared, exposures first seen and their
    lifecycle events, certificate and technology events, and new
    candidates. All zeros until the scan has completed and been processed."""
    control_db = _control_db(request)
    scan = _owned_scan_or_404(control_db, scan_id, auth.account_id)
    organization_id = scan.organization_id or ""
    summary = control_db.run_change_summary(organization_id, scan_id)
    outcomes = control_db.list_provider_run_outcomes(organization_id, scan_id)
    return ScanChangeSummaryResponse(
        scan_id=scan_id,
        status=scan.status,
        degraded=any(row.outcome in DEGRADED_OUTCOMES for row in outcomes),
        **asdict(summary),
    )


@router.get("/{scan_id}/collection", response_model=ScanCollectionResponse)
def get_scan_collection(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> ScanCollectionResponse:
    """How each collector actually did on this scan. A scan's own status
    only says the pipeline finished; this says whether every collector
    ran cleanly, so a failed collector is never mistaken for "nothing
    found". Empty (and not degraded) for a scan that hasn't completed,
    since outcomes are recorded only once a scan finishes."""
    import modules  # noqa: F401 - registers every plugin for the inventory
    from core.provider_contract import FailureClass, provider_inventory

    control_db = _control_db(request)
    scan = _owned_scan_or_404(control_db, scan_id, auth.account_id)
    rows = (
        control_db.list_provider_run_outcomes(scan.organization_id, scan_id)
        if scan.organization_id
        else []
    )
    capability_of = {d.provider: d.capability.value for d in provider_inventory()}
    outcomes = [
        ProviderRunOutcomeResponse(
            provider=row.provider,
            capability=capability_of.get(row.provider, "uncategorized"),
            # record_provider_run_outcomes rejects anything outside this
            # Literal's values at write time, so the stored value is one of them.
            outcome=cast(ProviderOutcome, row.outcome),
            output_lines=row.output_lines,
            recorded_at=row.recorded_at,
            failure_class=cast(FailureClass | None, row.failure_class),
        )
        for row in rows
    ]
    return ScanCollectionResponse(
        scan_id=scan_id,
        degraded=any(o.outcome in DEGRADED_OUTCOMES for o in outcomes),
        outcomes=outcomes,
    )


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> dict:
    control_db = _control_db(request)
    scan = _owned_scan_or_404(control_db, scan_id, auth.account_id)
    if scan.status != "completed":
        raise ApiError(
            409, f"Scan is {scan.status!r}, not completed yet", code="scan_not_completed"
        )

    settings = account_settings(_api_settings(request), auth.account_id)
    output_root = settings.project_root / settings.output_directory
    try:
        validate_run_id(scan_id)
        summary_path = confine_path(output_root / scan_id / "summary.json", output_root)
    except ValidationError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    if not summary_path.is_file():
        # Phase 11g: not a server fault. The scan is known but its files are
        # gone (retention, tenant deletion, cleanup), so 410 Gone. It is
        # still logged, since an unexpected loss is worth seeing.
        logger.warning("Scan %s is completed but its summary.json is missing", scan_id)
        raise HTTPException(
            status_code=410, detail="This scan's report files are no longer available"
        )
    return json.loads(summary_path.read_text(encoding="utf-8"))


@router.post("/{scan_id}/client-report")
def post_client_report(
    scan_id: str,
    body: ClientReportRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    from core.client_report.cli import cmd_client_report

    control_db = _control_db(request)
    subscription = subscriptions.get_or_create_subscription(control_db, auth.account_id)
    limits = subscriptions.effective_limits(subscription)
    ok, reason = subscriptions.check_report_options(
        limits, report_format=body.format, language=body.language, white_label=body.white_label
    )
    if not ok:
        raise HTTPException(status_code=403, detail=reason)

    scan = _owned_scan_or_404(control_db, scan_id, auth.account_id)
    if scan.status != "completed":
        raise ApiError(
            409, f"Scan is {scan.status!r}, not completed yet", code="scan_not_completed"
        )

    settings = account_settings(_api_settings(request), auth.account_id)
    output_root = settings.project_root / settings.output_directory
    try:
        validate_run_id(scan_id)
        run_dir = confine_path(output_root / scan_id, output_root)
    except ValidationError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc

    branding: str | None = None
    if body.white_label:
        # Already confirmed Ultra-tier-eligible by check_report_options
        # above — this is purely "did they actually configure a name
        # yet," never a second tier check. A silent fallback to
        # unbranded output would be a real, avoidable surprise for a
        # reseller paying specifically for their OWN identity to appear
        # here — a clear 422 beats guessing what they meant.
        branding = subscription.white_label_company_name
        if not branding:
            raise HTTPException(
                status_code=422,
                detail="white_label=true but no branding is configured for this account — "
                "set one first via PUT /account/branding.",
            )

    rc = cmd_client_report(
        settings, scan_id, output_format=body.format, language=body.language, branding=branding
    )
    if rc != 0:
        raise HTTPException(status_code=500, detail="client-report generation failed")
    content: str | bytes
    if body.format == "docx":
        content = (run_dir / "client_report.docx").read_bytes()
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        content = (run_dir / "client_report.md").read_text(encoding="utf-8")
        media_type = "text/markdown"
    return Response(content=content, media_type=media_type)
