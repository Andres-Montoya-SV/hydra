"""Productization Phase 08b: native ticketing destinations — Jira Cloud,
Linear and ServiceNow, one module each behind a common interface
(`base.Provider`).

An organization owner connects one (non-secret `config` + a `credential`
that is sealed at rest and never returned); it subscribes to exposure
events on the canonical outbox (`api/integration_worker.py`). For each
exposure it creates exactly one ticket and links it back to the exposure's
remediation record.

Requests go through `api/webhooks.py::post_json_safely`: a customer-
supplied Jira / ServiceNow host is checked against the SSRF / DNS-
rebinding gate on every attempt, exactly like a webhook URL. A provider's
HTTP 429 is honored: its numeric Retry-After delays the next attempt.
"""

from __future__ import annotations

import json
from typing import cast

from api.ticketing import jira, linear, servicenow
from api.ticketing.base import (
    Provider,
    RateLimitedError,
    TicketingConfigError,
    TicketRequest,
)
from api.webhooks import post_json_safely

__all__ = [
    "LINEAR_API_URL",
    "TICKETING_EVENT_TYPES",
    "RateLimitedError",
    "TicketRequest",
    "TicketingConfigError",
    "build_request",
    "create_ticket",
    "parse_response",
    "validate",
]

# The exposure events a ticketing integration can subscribe to.
TICKETING_EVENT_TYPES = frozenset({"exposure.opened", "exposure.reopened"})
LINEAR_API_URL = linear.API_URL

PROVIDERS: dict[str, Provider] = {
    "jira": cast(Provider, jira),
    "linear": cast(Provider, linear),
    "servicenow": cast(Provider, servicenow),
}


def _provider(name: str) -> Provider:
    if name not in PROVIDERS:
        raise TicketingConfigError(f"unknown provider {name!r}")
    return PROVIDERS[name]


def validate(provider: str, config: dict[str, str], credential: dict[str, str]) -> dict[str, str]:
    """Checks both shapes; returns the normalized config."""
    module = _provider(provider)
    for field, required, given in (
        ("config", module.REQUIRED_CONFIG, config),
        ("credential", module.REQUIRED_CREDENTIAL, credential),
    ):
        missing = [key for key in required if not str(given.get(key, "")).strip()]
        if missing:
            raise TicketingConfigError(f"{field} is missing: {', '.join(missing)}")
    return module.normalize({key: str(value).strip() for key, value in config.items()})


def build_request(
    provider: str,
    config: dict[str, str],
    credential: dict[str, str],
    event_type: str,
    data: dict[str, object],
) -> TicketRequest:
    return _provider(provider).build(config, credential, event_type, data)


def parse_response(
    provider: str,
    config: dict[str, str],
    status: int,
    content: bytes,
    retry_after: int | None = None,
) -> tuple[str, str]:
    """`(ticket key, ticket URL)`, or ValueError naming what went wrong
    (RateLimitedError for a 429). Never includes credentials."""
    if status == 429:
        raise RateLimitedError(retry_after)
    if not 200 <= status < 300:
        raise ValueError(f"HTTP {status}")
    try:
        payload = json.loads(content or b"{}")
    except json.JSONDecodeError as exc:
        raise ValueError("response is not JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("response is not a JSON object")
    return _provider(provider).parse(config, payload)


async def create_ticket(
    provider: str,
    config: dict[str, str],
    credential: dict[str, str],
    event_type: str,
    data: dict[str, object],
    *,
    verify: bool = True,
) -> tuple[str, str]:
    """Creates the ticket; `(key, url)`, or ValueError on any failure."""
    request = build_request(provider, config, credential, event_type, data)
    response = await post_json_safely(
        request.url, body=request.body, headers=request.headers, verify=verify
    )
    if response.status is None:
        raise ValueError(response.error)
    return parse_response(provider, config, response.status, response.content, response.retry_after)
