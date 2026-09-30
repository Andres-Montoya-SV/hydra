"""ServiceNow: Table API `POST {instance_url}/api/now/table/incident`,
basic auth, urgency derived from the exposure's severity."""

from __future__ import annotations

import json

from api.ticketing.base import TicketRequest, basic_auth, https_base, require, text, title

REQUIRED_CONFIG = ("instance_url",)
REQUIRED_CREDENTIAL = ("username", "password")

_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3"}


def normalize(config: dict[str, str]) -> dict[str, str]:
    return {**config, "instance_url": https_base(config["instance_url"], "instance_url")}


def build(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    body = {
        "short_description": title(data)[:160],
        "description": text(event_type, data),
        "urgency": _URGENCY.get(str(data.get("severity")), "3"),
    }
    return TicketRequest(
        url=f"{config['instance_url']}/api/now/table/incident",
        headers={
            "Authorization": basic_auth(credential["username"], credential["password"]),
            "Accept": "application/json",
        },
        body=json.dumps(body).encode(),
    )


def parse(config: dict[str, str], payload: dict[str, object]) -> tuple[str, str]:
    result = payload.get("result")
    result = result if isinstance(result, dict) else {}
    sys_id = require(result.get("sys_id"), "ServiceNow sys_id")
    number = str(result.get("number") or sys_id)
    return number, f"{config['instance_url']}/nav_to.do?uri=incident.do?sys_id={sys_id}"
