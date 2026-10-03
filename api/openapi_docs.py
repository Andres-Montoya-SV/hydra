"""Productization Phase 13d: the API reference, generated from the app.

`GET /openapi.json` (and `/docs`) is FastAPI's description of every route,
improved here in three ways so it is a complete contract on its own:

- **Authentication** is the `ApiKeyAuth` security scheme (the `X-API-Key`
  header) on every route that needs it, instead of an optional header
  parameter repeated on each.
- **Errors**: every operation declares `4XX` and `5XX` responses with the
  one error shape every failure has (`ErrorResponse`, Phase 13a).
- **The description** points to the guides that explain the concepts
  (set on the app, `api/main.py`).

`python -m api.openapi_docs` writes the committed copies:
`docs/api/openapi.json` and the readable `docs/API_REFERENCE.md`. A test
fails when either is out of date with the code, so the reference can't
drift from what the API does.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from api.errors import STATUS_CODES
from api.version import API_VERSION

ROOT = Path(__file__).resolve().parent.parent
OPENAPI_PATH = ROOT / "docs" / "api" / "openapi.json"
REFERENCE_PATH = ROOT / "docs" / "API_REFERENCE.md"

DESCRIPTION = (
    "Hydra's external attack surface management API: verify the domains you "
    "own, scan and monitor them, and get assets, exposures and changes, each "
    "explained by its evidence.\n\n"
    "- Authenticate with your API key in the `X-API-Key` header.\n"
    "- Every error has the same shape (`ErrorResponse`): branch on "
    "`error.code`, quote `error.request_id` to support, and retry only when "
    "`error.retryable` is true.\n"
    "- Guides: docs/runbooks/CUSTOMER_GUIDE.md (getting started), "
    "docs/productization/13a_errors_and_diagnostics.md (error codes and "
    "retries)."
)

_ERROR_SCHEMA: dict[str, Any] = {
    "title": "ErrorResponse",
    "type": "object",
    "required": ["detail", "error"],
    "properties": {
        "detail": {"description": "The endpoint's own detail: a string or an object."},
        "error": {
            "type": "object",
            "required": ["code", "message", "request_id", "retryable"],
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Stable and machine-readable; see the error-code table.",
                    "examples": sorted(STATUS_CODES.values()),
                },
                "message": {"type": "string"},
                "request_id": {"type": "string", "description": "Equals X-Request-ID."},
                "retryable": {"type": "boolean"},
            },
        },
    },
}
_ERROR_RESPONSE = {
    "description": "Error",
    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
}


def _is_api_key_header(parameter: dict[str, Any]) -> bool:
    return parameter.get("in") == "header" and parameter.get("name") == "X-API-Key"


def _improve_operation(operation: dict[str, Any]) -> None:
    parameters = operation.get("parameters", [])
    if any(_is_api_key_header(p) for p in parameters):
        operation["parameters"] = [p for p in parameters if not _is_api_key_header(p)]
        if not operation["parameters"]:
            del operation["parameters"]
        operation["security"] = [{"ApiKeyAuth": []}]
    responses = operation.setdefault("responses", {})
    responses.setdefault("4XX", _ERROR_RESPONSE)
    responses.setdefault("5XX", _ERROR_RESPONSE)


def improve(base: dict[str, Any]) -> dict[str, Any]:
    """FastAPI's generated document, plus the auth scheme, the error shape
    on every operation and the contract version. Never modifies `base`."""
    spec = copy.deepcopy(base)
    spec["info"]["x-api-version"] = API_VERSION
    components = spec.setdefault("components", {})
    components.setdefault("schemas", {})["ErrorResponse"] = copy.deepcopy(_ERROR_SCHEMA)
    components["securitySchemes"] = {
        "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    }
    for operations in spec["paths"].values():
        for operation in operations.values():
            _improve_operation(operation)
    return spec


class HydraAPI(FastAPI):
    """FastAPI, serving the improved document at `/openapi.json` and
    `/docs`. FastAPI caches its own document (and rebuilds it when routes
    change); this rebuilds the improved one only when that happens."""

    _cache: tuple[dict[str, Any], dict[str, Any]] | None = None  # (base, improved)

    def openapi(self) -> dict[str, Any]:
        base = super().openapi()
        if self._cache is None or self._cache[0] is not base:
            self._cache = (base, improve(base))
        return self._cache[1]


# --- the readable reference ------------------------------------------------


def _row(method: str, path: str, operation: dict[str, Any]) -> str:
    auth = "key" if operation.get("security") else "public"
    summary = operation.get("summary", "").replace("|", "\\|")
    return f"| `{method.upper()}` | `{path}` | {auth} | {summary} |"


def render_reference(spec: dict[str, Any]) -> str:
    """Endpoints grouped by tag, in a stable order."""
    groups: dict[str, list[str]] = {}
    for path in sorted(spec["paths"]):
        for method, operation in sorted(spec["paths"][path].items()):
            tag = (operation.get("tags") or ["other"])[0]
            groups.setdefault(tag, []).append(_row(method, path, operation))
    lines = [
        "# Hydra API Reference",
        "",
        "<!-- Generated by `python -m api.openapi_docs` from the code; do not edit. -->",
        "",
        f"Release {spec['info']['version']}, API contract version "
        f"{spec['info']['x-api-version']}. The full machine-readable contract "
        "is [`docs/api/openapi.json`](api/openapi.json) (also served at "
        "`GET /openapi.json`, browsable at `/docs`).",
        "",
        "- **Auth**: `key` routes need the `X-API-Key` header; `public` routes don't.",
        "- **Errors**: every route can answer `4XX`/`5XX` with the one error shape; "
        "see [error codes and retries](productization/13a_errors_and_diagnostics.md).",
        "- **Getting started**: [customer guide](runbooks/CUSTOMER_GUIDE.md).",
        "",
        f"{sum(len(rows) for rows in groups.values())} operations.",
    ]
    for tag in sorted(groups):
        lines += ["", f"## {tag}", "", "| Method | Path | Auth | Summary |", "|---|---|---|---|"]
        lines += groups[tag]
    return "\n".join(lines) + "\n"


def generated_files() -> dict[Path, str]:
    from api.main import create_app
    from api.settings import APISettings

    with tempfile.TemporaryDirectory() as data_dir:
        spec = create_app(APISettings(data_dir=Path(data_dir))).openapi()
    return {
        OPENAPI_PATH: json.dumps(spec, indent=2, sort_keys=True) + "\n",
        REFERENCE_PATH: render_reference(spec),
    }


def main() -> int:
    for path, content in generated_files().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        sys.stdout.write(f"wrote {path.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
