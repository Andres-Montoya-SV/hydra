"""Linear: GraphQL `issueCreate` at https://api.linear.app/graphql, with a
personal API key in `Authorization`."""

from __future__ import annotations

import json

from api.ticketing.base import TicketRequest, require, text, title

API_URL = "https://api.linear.app/graphql"
REQUIRED_CONFIG = ("team_id",)
REQUIRED_CREDENTIAL = ("api_key",)

_MUTATION = (
    "mutation IssueCreate($input: IssueCreateInput!) { "
    "issueCreate(input: $input) { success issue { identifier url } } }"
)


def normalize(config: dict[str, str]) -> dict[str, str]:
    return config


def build(
    config: dict[str, str], credential: dict[str, str], event_type: str, data: dict[str, object]
) -> TicketRequest:
    body = {
        "query": _MUTATION,
        "variables": {
            "input": {
                "teamId": config["team_id"],
                "title": title(data),
                "description": text(event_type, data),
            }
        },
    }
    return TicketRequest(
        url=API_URL,
        headers={"Authorization": credential["api_key"]},
        body=json.dumps(body).encode(),
    )


def parse(config: dict[str, str], payload: dict[str, object]) -> tuple[str, str]:
    data = payload.get("data")
    created = data.get("issueCreate") if isinstance(data, dict) else None
    if payload.get("errors") or not isinstance(created, dict) or not created.get("success"):
        raise ValueError("Linear rejected the issue")
    issue = created.get("issue")
    if not isinstance(issue, dict):
        raise ValueError("response has no Linear issue")
    return require(issue.get("identifier"), "Linear identifier"), require(
        issue.get("url"), "Linear URL"
    )
