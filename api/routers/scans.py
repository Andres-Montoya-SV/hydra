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

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, ScanRecord
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


@router.post("", response_model=CreateScanResponse, status_code=202)
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> CreateScanResponse:
    control_db = _control_db(request)
    api_settings = _api_settings(request)

    scan_id = secrets.token_hex(16)
    db_path = str(account_settings(api_settings, auth.account_id).project_root)
    control_db.create_scan(
        scan_id=scan_id, account_id=auth.account_id, domain=body.domain, db_path=db_path
    )

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
            domain=body.domain,
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
