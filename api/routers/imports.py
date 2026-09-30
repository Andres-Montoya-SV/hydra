"""Import scan reports produced outside Hydra (Nmap XML, Masscan JSON) into
an organization (Fase 11's data layer, now reachable through the API).

`Imported != Authorized`: every imported host becomes a candidate (or
corroborating evidence on an asset the organization already owns), never
an authorized target. Owner-only, since it adds data to the organization;
any member can list past imports.

The report is the raw request body (`Content-Type: application/xml` or
`application/json`), read in chunks and refused past
`MAX_ARTIFACT_BYTES` before it is ever fully buffered. The parsers are
hardened against hostile input (defusedxml, no decompression).
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB
from api.nmap_masscan_import import (
    MAX_ARTIFACT_BYTES,
    HostImportSummary,
    ImportValidationError,
    import_masscan_json,
    import_nmap_xml,
)
from api.routers.org_access import control_db, require_member, require_owner
from api.schemas import ImportBatchResponse, ImportSummaryResponse

router = APIRouter(prefix="/organizations", tags=["imports"])

ImportSource = Literal["nmap", "masscan"]


async def read_bounded_body(request: Request, limit: int) -> bytes:
    """The request body, or 413 as soon as it exceeds `limit` bytes."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"Report exceeds {limit} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(status_code=413, detail=f"Report exceeds {limit} bytes")
    return bytes(body)


def _summary_response(source: ImportSource, summary: HostImportSummary) -> ImportSummaryResponse:
    ingest = summary.ingest
    return ImportSummaryResponse(
        source=source,
        dry_run=summary.dry_run,
        already_imported=summary.already_imported,
        hosts_parsed=summary.hosts_parsed,
        hosts_skipped_invalid_ip=summary.hosts_skipped_invalid_ip,
        batch_id=ingest.batch_id if ingest else None,
        observations_recorded_on_known_assets=(
            ingest.observations_recorded_on_known_assets if ingest else 0
        ),
        candidates_created=ingest.candidates_created if ingest else 0,
        candidates_touched=ingest.candidates_touched if ingest else 0,
        malformed_drafts_skipped=ingest.malformed_drafts_skipped if ingest else 0,
    )


def _run_import(
    source: ImportSource,
    db: ControlDB,
    organization_id: str,
    account_id: str,
    raw: bytes,
    dry_run: bool,
) -> HostImportSummary:
    reference = f"api-upload:{source}"
    if source == "nmap":
        return import_nmap_xml(
            control_db=db,
            organization_id=organization_id,
            account_id=account_id,
            xml_bytes=raw,
            raw_artifact_reference=reference,
            dry_run=dry_run,
        )
    return import_masscan_json(
        control_db=db,
        organization_id=organization_id,
        account_id=account_id,
        json_bytes=raw,
        raw_artifact_reference=reference,
        dry_run=dry_run,
    )


@router.post("/{organization_id}/imports/{source}", response_model=ImportSummaryResponse)
async def import_scan_report(
    organization_id: str,
    source: ImportSource,
    request: Request,
    dry_run: bool = False,
    auth: AuthContext = Depends(require_api_key),
) -> ImportSummaryResponse:
    """`dry_run=true` parses and validates the report and reports what it
    found without writing anything. Re-importing the same bytes is safe
    and writes nothing new (`already_imported`)."""
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    raw = await read_bounded_body(request, MAX_ARTIFACT_BYTES)
    try:
        summary = _run_import(source, db, organization_id, auth.account_id, raw, dry_run)
    except ImportValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_import", "message": str(exc)}
        ) from exc
    return _summary_response(source, summary)


@router.get("/{organization_id}/imports", response_model=list[ImportBatchResponse])
def list_imports(
    organization_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[ImportBatchResponse]:
    """Every import batch (API uploads and other external sources), oldest
    first."""
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    return [
        ImportBatchResponse(
            batch_id=batch.batch_id,
            source=batch.source,
            imported_at=batch.imported_at,
            imported_by_account_id=batch.account_id,
            artifact_sha256=batch.artifact_hash,
        )
        for batch in db.list_observation_batches_for_organization(
            organization_id, limit=limit, offset=offset
        )
    ]
