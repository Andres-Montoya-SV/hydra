"""Productization Phase 13b: feedback from beta customers.

- `POST /feedback`: any authenticated account, a suspended one included
  (it stays a way to reach us). Plain text, at most 4000 characters, at
  most `DAILY_LIMIT` per account per 24 hours. Stored with the request id
  and the release, so a report can be matched to the server log.
- `GET /admin/feedback`: operators only (everyone else 404), newest first.
  Reading it is itself recorded.

The audit log records that feedback was sent, never its text.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from api import security_audit as audit
from api.auth import AuthContext, require_api_key, require_operator
from api.edge import current_request_id
from api.routers.delivery_logs import Page, page
from api.routers.org_access import control_db
from api.schemas import FeedbackRequest, FeedbackResponse
from api.version import HYDRA_VERSION

router = APIRouter(tags=["feedback"])

DAILY_LIMIT = 20


@router.post("/feedback", response_model=FeedbackResponse, status_code=201)
def submit_feedback(
    body: FeedbackRequest, request: Request, auth: AuthContext = Depends(require_api_key)
) -> FeedbackResponse:
    db = control_db(request)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    if db.count_recent_feedback(auth.account_id, since=since) >= DAILY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"At most {DAILY_LIMIT} feedback messages per 24 hours. Try again later.",
            headers={"Retry-After": "3600"},
        )
    record = db.create_feedback(
        account_id=auth.account_id,
        category=body.category,
        message=body.message,
        request_id=current_request_id(),
        hydra_version=HYDRA_VERSION,
    )
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.FEEDBACK_SUBMITTED,
            actor_account_id=auth.account_id,
            subject_account_id=auth.account_id,
            target=("feedback", record.feedback_id),
            details={"category": record.category},
        ),
    )
    return FeedbackResponse(**asdict(record))


@router.get("/admin/feedback", response_model=list[FeedbackResponse])
def list_feedback(
    request: Request,
    paging: Page = Depends(page),
    operator: AuthContext = Depends(require_operator),
) -> list[FeedbackResponse]:
    db = control_db(request)
    items = db.list_feedback(limit=paging.limit, offset=paging.offset)
    audit.record(
        db,
        request,
        audit.AuditEvent(
            audit.ADMIN_FEEDBACK_LISTED,
            actor_type="operator",
            actor_account_id=operator.account_id,
            details={"count": len(items)},
        ),
    )
    return [FeedbackResponse(**asdict(item)) for item in items]
