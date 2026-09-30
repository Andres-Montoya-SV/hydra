"""Productization Phase 08b: ticketing integrations (Jira, Linear,
ServiceNow) for an organization — see `api/ticketing.py`.

Any member can list integrations and their delivery logs; only an owner
can connect or remove one. The credential is write-only: sealed before it
is stored, never returned, never logged. Connecting one requires the
server's HYDRA_API_SECRETS_KEYS (503 otherwise), and a customer-supplied
Jira / ServiceNow host must pass the same SSRF gate as a webhook URL.
"""

from __future__ import annotations

from typing import Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from api.auth import AuthContext, require_api_key
from api.control_db import TicketingIntegrationRecord
from api.routers.org_access import control_db, require_member, require_owner
from api.schemas import (
    CreateTicketingIntegrationRequest,
    DeliveryResponse,
    TicketingIntegrationResponse,
    TicketingProvider,
)
from api.secrets_box import SecretsUnavailableError
from api.ticketing import TicketingConfigError, validate
from api.webhooks import validate_webhook_destination

router = APIRouter(prefix="/organizations", tags=["integrations"])

MAX_INTEGRATIONS_PER_ORGANIZATION = 10


def _response(record: TicketingIntegrationRecord) -> TicketingIntegrationResponse:
    return TicketingIntegrationResponse(
        integration_id=record.integration_id,
        provider=cast(TicketingProvider, record.provider),
        name=record.name,
        config=record.config,
        event_types=list(record.event_types),
        status=cast(Literal["active", "disabled"], record.status),
        consecutive_failures=record.consecutive_failures,
        last_error=record.last_error,
        created_by_account_id=record.created_by_account_id,
        created_at=record.created_at,
    )


async def _check_destination(config: dict[str, str]) -> None:
    for key in ("site_url", "instance_url"):
        if key in config:
            allowed, reason, _ip = await validate_webhook_destination(config[key])
            if not allowed:
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_integration", "message": reason}
                )


@router.get("/{organization_id}/integrations", response_model=list[TicketingIntegrationResponse])
def list_integrations(
    organization_id: str, request: Request, auth: AuthContext = Depends(require_api_key)
) -> list[TicketingIntegrationResponse]:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    return [_response(r) for r in db.list_ticketing_integrations(organization_id)]


@router.post(
    "/{organization_id}/integrations",
    response_model=TicketingIntegrationResponse,
    status_code=201,
)
async def create_integration(
    organization_id: str,
    body: CreateTicketingIntegrationRequest,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> TicketingIntegrationResponse:
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    try:
        config = validate(body.provider, body.config, body.credential)
    except TicketingConfigError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_integration", "message": str(exc)}
        ) from exc
    active = [r for r in db.list_ticketing_integrations(organization_id) if r.status == "active"]
    if len(active) >= MAX_INTEGRATIONS_PER_ORGANIZATION:
        raise HTTPException(status_code=403, detail="Integration limit reached")
    await _check_destination(config)
    try:
        record = db.create_ticketing_integration(
            organization_id=organization_id,
            actor_account_id=auth.account_id,
            provider=body.provider,
            name=body.name.strip(),
            config=config,
            credential=body.credential,
            event_types=tuple(dict.fromkeys(body.event_types)),
        )
    except SecretsUnavailableError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "secrets_key_not_configured",
                "message": "The server has no HYDRA_API_SECRETS_KEYS; credentials can't be "
                "stored safely.",
            },
        ) from exc
    return _response(record)


@router.delete("/{organization_id}/integrations/{integration_id}", status_code=204)
def remove_integration(
    organization_id: str,
    integration_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> Response:
    """Disables it and erases its credential; tickets it created stay linked."""
    db = control_db(request)
    require_owner(db, auth.account_id, organization_id)
    if not db.remove_ticketing_integration(organization_id, integration_id):
        raise HTTPException(status_code=404, detail="Integration not found")
    return Response(status_code=204)


@router.get(
    "/{organization_id}/integrations/{integration_id}/deliveries",
    response_model=list[DeliveryResponse],
)
def list_integration_deliveries(
    organization_id: str,
    integration_id: str,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_api_key),
) -> list[DeliveryResponse]:
    db = control_db(request)
    require_member(db, auth.account_id, organization_id)
    if db.get_ticketing_integration(organization_id, integration_id) is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return [
        DeliveryResponse.model_validate(row, from_attributes=True)
        for row in db.list_deliveries_for_ticketing(integration_id, limit=limit, offset=offset)
    ]
