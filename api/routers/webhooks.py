"""`POST /webhooks` / `GET /webhooks` / `DELETE /webhooks/{webhook_id}` —
outbound webhook registration. Standard account-scoped auth/ownership,
the exact same `require_api_key` + Part F.3 double-check every other
account-scoped router in this codebase already uses — this router adds
no second authorization system.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, WebhookRecord
from api.schemas import RegisterWebhookRequest, WebhookCreatedResponse, WebhookResponse
from api.webhooks import (
    EVENT_TYPES,
    MAX_WEBHOOKS_PER_ACCOUNT,
    generate_webhook_secret,
    validate_webhook_destination,
    validate_webhook_url_scheme,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _control_db(request: Request) -> ControlDB:
    return request.app.state.control_db  # type: ignore[no-any-return]


@router.post("", response_model=WebhookCreatedResponse, status_code=201)
async def register_webhook(
    body: RegisterWebhookRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> WebhookCreatedResponse:
    control_db = _control_db(request)

    unknown_events = set(body.event_types) - EVENT_TYPES
    if unknown_events:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event type(s): {sorted(unknown_events)}. Valid: {sorted(EVENT_TYPES)}.",
        )

    ok, reason = validate_webhook_url_scheme(body.url)
    if not ok:
        raise HTTPException(status_code=422, detail=reason)

    # A real, enforced cap BEFORE the (slower) real DNS/SSRF check below —
    # cheapest rejection first, same "fail fast on the free check" order
    # every other gated endpoint in this codebase already uses.
    if control_db.count_webhooks_for_account(auth.account_id) >= MAX_WEBHOOKS_PER_ACCOUNT:
        raise HTTPException(
            status_code=403,
            detail=f"This account already has the maximum of {MAX_WEBHOOKS_PER_ACCOUNT} "
            "webhooks registered. Delete one before registering another.",
        )

    allowed, reason, _connect_ip = await validate_webhook_destination(body.url)
    if not allowed:
        raise HTTPException(status_code=422, detail=reason)

    record = control_db.create_webhook(
        account_id=auth.account_id,
        url=body.url,
        secret=generate_webhook_secret(),
        event_types=tuple(body.event_types),
    )
    return WebhookCreatedResponse(**_to_response_fields(record), secret=record.secret)


@router.get("", response_model=list[WebhookResponse])
def list_webhooks(
    request: Request, auth: AuthContext = Depends(require_api_key)
) -> list[WebhookResponse]:
    records = _control_db(request).list_webhooks_for_account(auth.account_id)
    return [WebhookResponse(**_to_response_fields(r)) for r in records]


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> None:
    deleted = _control_db(request).delete_webhook(webhook_id, auth.account_id)
    if not deleted:
        # Part F.3: a webhook_id belonging to a different account reads
        # identically to one that doesn't exist — never a 403, which
        # would confirm its existence to a non-owner.
        raise HTTPException(status_code=404, detail=f"{webhook_id!r} not found")


def _to_response_fields(record: WebhookRecord) -> dict:
    return {
        "webhook_id": record.webhook_id,
        "url": record.url,
        "event_types": list(record.event_types),
        "status": record.status,
        "consecutive_failures": record.consecutive_failures,
        "last_delivery_at": record.last_delivery_at,
        "last_success_at": record.last_success_at,
        "last_error": record.last_error,
        "created_at": record.created_at,
    }
