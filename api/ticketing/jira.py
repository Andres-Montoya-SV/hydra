"""Jira Cloud: REST v3 `POST {site_url}/rest/api/3/issue`, basic auth with
the account email and an API token, description in Atlassian Document
Format."""

from __future__ import annotations

import json
import re

from api.ticketing.base import (
    TicketingConfigError,
    TicketRequest,
    basic_auth,
    https_base,
    require,
    text,
    title,
)

REQUIRED_CONFIG = ("site_url", "project_key")
REQUIRED_CREDENTIAL = ("email", "api_token")


def normalize(config: dict[str, str]) -> dict[str, str]:
    config = {**config, "site_url": https_base(config["site_url"], "site_url")}
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,29}", config["project_key"]):
        raise TicketingConfigError("project_key must look like a Jira project key, e.g. SEC")
    return config


def build(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in text(event_type, data).splitlines()
    ]
    body = {
        "fields": {
            "project": {"key": config["project_key"]},
            "summary": title(data)[:250],
            "issuetype": {"name": config.get("issue_type") or "Task"},
            "labels": ["hydra"],
            "description": {"type": "doc", "version": 1, "content": paragraphs},
        }
    }
    return TicketRequest(
        url=f"{config['site_url']}/rest/api/3/issue",
        headers={
            "Authorization": basic_auth(credential["email"], credential["api_token"]),
            "Accept": "application/json",
        },
        body=json.dumps(body).encode(),
    )


def parse(config: dict[str, str], payload: dict[str, object]) -> tuple[str, str]:
    key = require(payload.get("key"), "Jira issue key")
    return key, f"{config['site_url']}/browse/{key}"
