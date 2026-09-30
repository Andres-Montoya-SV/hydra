"""GET /organizations/{org}/exports/{assets|exposures}?format=csv|ndjson:
the organization's full asset or exposure inventory as a streamed file
(see `api/exports.py`). Any member may export what they can already read.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from api.auth import AuthContext, require_api_key
from api.exports import Dataset, ExportFormat, stream_csv, stream_ndjson
from api.routers.org_access import control_db, require_member

router = APIRouter(prefix="/organizations", tags=["exports"])

_MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "ndjson": "application/x-ndjson"}


@router.get("/{organization_id}/exports/{dataset}")
def export_dataset(
    organization_id: str,
    dataset: Dataset,
    request: Request,
    # Public query parameter `format`; named differently in Python so it
    # doesn't shadow the built-in.
    export_format: ExportFormat = Query(default="csv", alias="format"),
    auth: AuthContext = Depends(require_api_key),
) -> StreamingResponse:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    stream = stream_csv if export_format == "csv" else stream_ndjson
    return StreamingResponse(
        stream(db, organization_id, dataset),
        media_type=_MEDIA_TYPES[export_format],
        headers={
            "Content-Disposition": f'attachment; filename="{dataset}.{export_format}"',
            "Cache-Control": "no-store",
        },
    )
