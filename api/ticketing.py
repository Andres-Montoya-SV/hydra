"""Productization Phase 08b: native ticketing destinations — Jira Cloud,
Linear, and ServiceNow.

An organization owner connects one (non-secret `config` + a `credential`
that is sealed at rest and never returned); it subscribes to exposure
events on the canonical outbox (`api/integration_worker.py`). For each
exposure it creates exactly one ticket, links it back to the exposure's
remediation record, and never creates a second one for the same exposure.

Requests go through `api/webhooks.py::post_json_safely`: a customer-
supplied Jira / ServiceNow host is checked against the SSRF / DNS-
rebinding gate on every attempt, exactly like a webhook URL.

Each provider is three pure functions — validate, build the request, parse
the response — so the wire format is unit-tested against the providers'
documented request/response shapes without calling the real services:
- Jira Cloud REST v3 `POST {site}/rest/api/3/issue` (basic auth: account
  email + API token), description in Atlassian Document Format;
- Linear GraphQL `issueCreate` at `https://api.linear.app/graphql`
  (personal API key in `Authorization`);
- ServiceNow Table API `POST {instance}/api/now/table/incident` (basic
  auth), severity mapped to urgency.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from api.webhooks import post_json_safely

Provider = Literal["jira", "linear", "servicenow"]

# The exposure events a ticketing integration can subscribe to.
TICKETING_EVENT_TYPES = frozenset({"exposure.opened", "exposure.reopened"})

LINEAR_API_URL = "https://api.linear.app/graphql"

_REQUIRED_CONFIG: dict[str, tuple[str, ...]] = {
    "jira": ("site_url", "project_key"),
    "linear": ("team_id",),
    "servicenow": ("instance_url",),
}
_REQUIRED_CREDENTIAL: dict[str, tuple[str, ...]] = {
    "jira": ("email", "api_token"),
    "linear": ("api_key",),
    "servicenow": ("username", "password"),
}
_SERVICENOW_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3"}


class TicketingConfigError(ValueError):
    """Invalid provider configuration or credential shape."""


@dataclass(frozen=True)
class TicketRequest:
    url: str
    headers: dict[str, str]
    body: bytes


def validate(provider: str, config: dict[str, str], credential: dict[str, str]) -> dict[str, str]:
    """Checks both shapes; returns the normalized config."""
    if provider not in _REQUIRED_CONFIG:
        raise TicketingConfigError(f"unknown provider {provider!r}")
    for field, required in (("config", _REQUIRED_CONFIG), ("credential", _REQUIRED_CREDENTIAL)):
        given = config if field == "config" else credential
        missing = [key for key in required[provider] if not str(given.get(key, "")).strip()]
        if missing:
            raise TicketingConfigError(f"{field} is missing: {', '.join(missing)}")
    normalized = {key: str(value).strip() for key, value in config.items()}
    for key in ("site_url", "instance_url"):
        if key in normalized:
            normalized[key] = _https_base(normalized[key], key)
    if provider == "jira" and not re.fullmatch(r"[A-Z][A-Z0-9_]{1,29}", normalized["project_key"]):
        raise TicketingConfigError("project_key must look like a Jira project key, e.g. SEC")
    return normalized


def _https_base(url: str, field: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise TicketingConfigError(f"{field} must be an https:// base URL")
    return f"https://{parsed.netloc}{parsed.path.rstrip('/')}"


def _title(data: dict[str, object]) -> str:
    return f"[Hydra] {data.get('title') or 'Exposure'} ({data.get('severity', 'unknown')})"


def _text(event_type: str, data: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Hydra {event_type.replace('exposure.', 'exposure ')}.",
            f"Severity: {data.get('severity', 'unknown')}",
            f"Exposure: {data.get('exposure_id', '')}",
            f"Asset: {data.get('asset_id', '')}",
        ]
    )


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def build_request(
    provider: str,
    config: dict[str, str],
    credential: dict[str, str],
    event_type: str,
    data: dict[str, object],
) -> TicketRequest:
    if provider == "jira":
        return _jira_request(config, credential, event_type, data)
    if provider == "linear":
        return _linear_request(config, credential, event_type, data)
    return _servicenow_request(config, credential, event_type, data)


def _jira_request(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in _text(event_type, data).splitlines()
    ]
    body = {
        "fields": {
            "project": {"key": config["project_key"]},
            "summary": _title(data)[:250],
            "issuetype": {"name": config.get("issue_type") or "Task"},
            "labels": ["hydra"],
            "description": {"type": "doc", "version": 1, "content": paragraphs},
        }
    }
    return TicketRequest(
        url=f"{config['site_url']}/rest/api/3/issue",
        headers={
            "Authorization": _basic(credential["email"], credential["api_token"]),
            "Accept": "application/json",
        },
        body=json.dumps(body).encode(),
    )


_LINEAR_MUTATION = (
    "mutation IssueCreate($input: IssueCreateInput!) { "
    "issueCreate(input: $input) { success issue { identifier url } } }"
)


def _linear_request(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    body = {
        "query": _LINEAR_MUTATION,
        "variables": {
            "input": {
                "teamId": config["team_id"],
                "title": _title(data),
                "description": _text(event_type, data),
            }
        },
    }
    return TicketRequest(
        url=LINEAR_API_URL,
        headers={"Authorization": credential["api_key"]},
        body=json.dumps(body).encode(),
    )


def _servicenow_request(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    body = {
        "short_description": _title(data)[:160],
        "description": _text(event_type, data),
        "urgency": _SERVICENOW_URGENCY.get(str(data.get("severity")), "3"),
    }
    return TicketRequest(
        url=f"{config['instance_url']}/api/now/table/incident",
        headers={
            "Authorization": _basic(credential["username"], credential["password"]),
            "Accept": "application/json",
        },
        body=json.dumps(body).encode(),
    )


def parse_response(
    provider: str, config: dict[str, str], status: int, content: bytes
) -> tuple[str, str]:
    """`(ticket key, ticket URL)` from a provider response, or ValueError
    naming what went wrong (never including credentials)."""
    if not 200 <= status < 300:
        raise ValueError(f"HTTP {status}")
    try:
        payload = json.loads(content or b"{}")
    except json.JSONDecodeError as exc:
        raise ValueError("response is not JSON") from exc
    if provider == "jira":
        key = str(payload.get("key") or "")
        return _require(key, "Jira issue key"), f"{config['site_url']}/browse/{key}"
    if provider == "linear":
        created = (payload.get("data") or {}).get("issueCreate") or {}
        issue = created.get("issue") or {}
        if payload.get("errors") or not created.get("success"):
            raise ValueError("Linear rejected the issue")
        return (
            _require(str(issue.get("identifier") or ""), "Linear identifier"),
            _require(str(issue.get("url") or ""), "Linear URL"),
        )
    result = payload.get("result") or {}
    sys_id = _require(str(result.get("sys_id") or ""), "ServiceNow sys_id")
    number = str(result.get("number") or sys_id)
    return number, f"{config['instance_url']}/nav_to.do?uri=incident.do?sys_id={sys_id}"


def _require(value: str, what: str) -> str:
    if not value:
        raise ValueError(f"response has no {what}")
    return value


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
    status, content, error = await post_json_safely(
        request.url, body=request.body, headers=request.headers, verify=verify
    )
    if status is None:
        raise ValueError(error)
    return parse_response(provider, config, status, content)
