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

import asyncio
import json
import secrets
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from api import subscriptions
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, DomainVerificationRecord, ScanRecord
from api.domain_verification import classify_scan_gate, normalize_domain
from api.scan_orchestrator import execute_scan
from api.schemas import (
    ClientReportRequest,
    CreateScanRequest,
    CreateScanResponse,
    ScanStatusResponse,
)
from api.settings import APISettings
from api.tenancy import account_settings

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


def _require_verified_domain_or_403(control_db: ControlDB, account_id: str, domain: str) -> None:
    """Part A's non-negotiable gate (docs/PAID_API_DESIGN.md) — lives
    directly in `create_scan` below, on the exact same mandatory
    `account_id` every other account-scoped lookup in this file already
    requires, rather than as a separate dependency/middleware layer a
    future route could add without remembering to include it."""
    status, record = classify_scan_gate(
        domain,
        active_verifications=control_db.get_verified_domains_for_account(account_id),
        all_verifications=control_db.get_all_verifications_for_account(account_id),
    )
    if status == "covered":
        return
    if status == "expired":
        expired = cast(DomainVerificationRecord, record)
        raise HTTPException(
            status_code=403,
            detail=(
                f"Verification for {expired.domain!r} expired on {expired.expires_at}. "
                f"POST /domains {{'domain': '{expired.domain}'}} to re-verify before scanning."
            ),
        )
    raise HTTPException(
        status_code=403,
        detail=(
            f"Domain {domain!r} is not verified for this account. "
            f"POST /domains {{'domain': '{domain}'}} to start verification, then "
            "POST /domains/{domain}/verify."
        ),
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
        raise HTTPException(
            status_code=402,
            detail="This account's subscription is suspended (payment past due beyond the "
            f"{subscriptions.GRACE_PERIOD_DAYS}-day grace period). Resolve billing via "
            "POST /account/subscription to resume scanning.",
        )
    limits = subscriptions.effective_limits(subscription)
    ok, reason = subscriptions.check_scan_quota(control_db, account_id, limits)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    return limits


@router.post("", response_model=CreateScanResponse, status_code=202)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CreateScanResponse:
    control_db = _control_db(request)
    api_settings = _api_settings(request)

    _require_billing_and_quota_ok(control_db, auth.account_id)
    domain = normalize_domain(body.domain)
    _require_verified_domain_or_403(control_db, auth.account_id, domain)

    scan_id = secrets.token_hex(16)
    db_path = str(account_settings(api_settings, auth.account_id).project_root)
    control_db.create_scan(
        scan_id=scan_id, account_id=auth.account_id, domain=domain, db_path=db_path
    )
    control_db.increment_scan_usage(auth.account_id, subscriptions.current_period_key())

    # Fire-and-forget: the request returns immediately with "queued";
    # the scan itself (~25 minutes) runs as a background asyncio task in
    # this same process. See api/scan_orchestrator.py's module docstring
    # for this round's single-process scope note.
    task = asyncio.create_task(
        execute_scan(
            api_settings=api_settings,
            control_db=control_db,
            account_id=auth.account_id,
            scan_id=scan_id,
            domain=domain,
        )
    )
    request.app.state.background_tasks.add(task)
    task.add_done_callback(request.app.state.background_tasks.discard)

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
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status!r}, not completed yet")

    settings = account_settings(_api_settings(request), auth.account_id)
    summary_path = settings.project_root / settings.output_directory / scan_id / "summary.json"
    if not summary_path.is_file():
        raise HTTPException(status_code=500, detail="Scan completed but summary.json is missing")
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
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status!r}, not completed yet")

    settings = account_settings(_api_settings(request), auth.account_id)
    rc = cmd_client_report(settings, scan_id, output_format=body.format, language=body.language)
    if rc != 0:
        raise HTTPException(status_code=500, detail="client-report generation failed")

    run_dir = settings.project_root / settings.output_directory / scan_id
    content: str | bytes
    if body.format == "docx":
        content = (run_dir / "client_report.docx").read_bytes()
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        content = (run_dir / "client_report.md").read_text(encoding="utf-8")
        media_type = "text/markdown"
    return Response(content=content, media_type=media_type)
