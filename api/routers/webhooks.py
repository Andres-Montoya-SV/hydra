"""`POST /webhooks` / `GET /webhooks` / `DELETE /webhooks/{webhook_id}` —
outbound webhook registration. Standard account-scoped auth/ownership,
the exact same `require_api_key` + Part F.3 double-check every other
account-scoped router in this codebase already uses — this router adds
no second authorization system.
"""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from api import entitlements
from api import security_audit as audit
from api.auth import AuthContext, require_api_key
from api.control_db import ControlDB, LimitReachedError, WebhookRecord
from api.routers.delivery_logs import Page, delivery_responses, page
from api.schemas import (
    DeliveryResponse,
    RegisterWebhookRequest,
    WebhookCreatedResponse,
    WebhookResponse,
)
from api.webhooks import (
    EVENT_TYPES,
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

    # The webhook entitlement (Phase 12a) before the slower DNS/SSRF check.
    limits = entitlements.account_limits(control_db, auth.account_id)
    count = control_db.count_webhooks_for_account(auth.account_id)
    entitlements.refuse_if_full(limits, "webhooks", count)

    allowed, reason, _connect_ip = await validate_webhook_destination(body.url)
    if not allowed:
        raise HTTPException(status_code=422, detail=reason)

    try:
        record = control_db.create_webhook(
            account_id=auth.account_id,
            url=body.url,
            secret=generate_webhook_secret(),
            event_types=tuple(body.event_types),
            kind=body.kind,
            limit=limits.max_integrations,
        )
    except LimitReachedError as exc:
        raise entitlements.from_limit_reached(limits.tier, exc) from exc
    _audit_webhook(
        control_db,
        request,
        audit.WEBHOOK_CREATED,
        auth.account_id,
        record.webhook_id,
        # The host only: Slack/Teams URLs carry a secret in their path.
        {"host": urlparse(body.url).hostname, "kind": body.kind},
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
    control_db = _control_db(request)
    deleted = control_db.delete_webhook(webhook_id, auth.account_id)
    if not deleted:
        # Part F.3: a webhook_id belonging to a different account reads
        # identically to one that doesn't exist — never a 403, which
        # would confirm its existence to a non-owner.
        raise HTTPException(status_code=404, detail=f"{webhook_id!r} not found")
    _audit_webhook(control_db, request, audit.WEBHOOK_DELETED, auth.account_id, webhook_id)


@router.get("/{webhook_id}/deliveries", response_model=list[DeliveryResponse])
def list_deliveries(
    webhook_id: str,
    request: Request,
    paging: Page = Depends(page),
    auth: AuthContext = Depends(require_api_key),
) -> list[DeliveryResponse]:
    """Productization Phase 08: this webhook's delivery log, newest first."""
    control_db = _control_db(request)
    if control_db.get_webhook(webhook_id, auth.account_id) is None:
        raise HTTPException(status_code=404, detail=f"{webhook_id!r} not found")
    return delivery_responses(
        control_db.list_deliveries_for_webhook(
            webhook_id, auth.account_id, limit=paging.limit, offset=paging.offset
        )
    )


@router.post("/{webhook_id}/deliveries/{delivery_id}/redeliver", status_code=202)
def redeliver(
    webhook_id: str,
    delivery_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    """Queues a dead (or already delivered) delivery again, due now. The
    receiver gets the same event id, so it can recognize a repeat."""
    control_db = _control_db(request)
    if not control_db.redeliver(webhook_id, delivery_id, auth.account_id):
        raise HTTPException(status_code=404, detail="Delivery not found or already queued")
    _audit_webhook(
        control_db,
        request,
        audit.WEBHOOK_REDELIVERED,
        auth.account_id,
        webhook_id,
        {"delivery_id": delivery_id},
    )
    return Response(status_code=202)


def _audit_webhook(
    control_db: ControlDB,
    request: Request,
    action: str,
    account_id: str,
    webhook_id: str,
    details: dict[str, object] | None = None,
) -> None:
    audit.record(
        control_db,
        request,
        audit.AuditEvent(
            action,
            actor_account_id=account_id,
            subject_account_id=account_id,
            target=("webhook", webhook_id),
            details=details,
        ),
    )


def _to_response_fields(record: WebhookRecord) -> dict:
    return {
        "webhook_id": record.webhook_id,
        "url": record.url,
        "kind": record.kind,
        "event_types": list(record.event_types),
        "status": record.status,
        "consecutive_failures": record.consecutive_failures,
        "last_delivery_at": record.last_delivery_at,
        "last_success_at": record.last_success_at,
        "last_error": record.last_error,
        "created_at": record.created_at,
    }
