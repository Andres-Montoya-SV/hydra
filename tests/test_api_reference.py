"""Productization Phase 13d: the API reference is generated from the code
(`python -m api.openapi_docs`) and must never drift from it."""

from __future__ import annotations

import json
from pathlib import Path

from _org_helpers import api_client

from api.openapi_docs import generated_files

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = {
    ("get", "/health"),
    ("get", "/ready"),
    ("get", "/version"),
    ("post", "/accounts"),
    ("post", "/accounts/verify-email"),
    ("post", "/webhooks/wompi"),
}


def _spec() -> dict:
    return json.loads((ROOT / "docs/api/openapi.json").read_text())


def test_the_committed_reference_matches_the_code() -> None:
    for path, content in generated_files().items():
        assert (
            path.read_text() == content
        ), f"{path.relative_to(ROOT)} is out of date: run `python -m api.openapi_docs`"


def test_the_served_document_is_the_committed_one(tmp_path: Path) -> None:
    with api_client(tmp_path) as client:
        served = client.get("/openapi.json").json()
    assert served == _spec()


def test_auth_and_errors_are_declared_on_every_operation() -> None:
    spec = _spec()
    public = set()
    for path, operations in spec["paths"].items():
        for method, operation in operations.items():
            assert {"4XX", "5XX"} <= set(operation["responses"]), (method, path)
            names = {p["name"] for p in operation.get("parameters", [])}
            assert "X-API-Key" not in names, (method, path)  # a security scheme instead
            if not operation.get("security"):
                public.add((method, path))
    assert public == PUBLIC
    assert spec["components"]["securitySchemes"]["ApiKeyAuth"]["name"] == "X-API-Key"
    error = spec["components"]["schemas"]["ErrorResponse"]["properties"]["error"]
    assert set(error["required"]) == {"code", "message", "request_id", "retryable"}


def test_path_level_fields_and_missing_summaries_are_tolerated() -> None:
    from api.openapi_docs import improve, render_reference

    base = {
        "openapi": "3.1.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/x": {
                "summary": "a path-level field, not an operation",
                "parameters": [{"name": "id", "in": "path", "required": True}],
                "get": {"summary": None, "responses": {}},
            }
        },
    }
    spec = improve(base)
    assert set(spec["paths"]["/x"]["get"]["responses"]) == {"4XX", "5XX"}
    assert spec["paths"]["/x"]["summary"] == "a path-level field, not an operation"
    assert "| `GET` | `/x` | public |  |" in render_reference(spec)
