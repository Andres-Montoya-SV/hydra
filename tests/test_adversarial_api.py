"""Productization Phase 11g: adversarial re-test of every product endpoint.

The routes are enumerated from the real application (not a hand-kept
list), so an endpoint added later gets every attack below automatically.
Only the exceptions are listed by hand: the routes that are public on
purpose, and the operator-only ones.

Attacks, per route:
- **no API key** → 401;
- **another tenant's valid key, pointed at a victim's real ids**
  (BOLA/IDOR) → never a success, never a 403 that would confirm the object
  exists, never a server error;
- **a non-operator on operator routes** → 404 (the admin surface is not
  discoverable);
- **hostile path values** (SQL injection, traversal, NUL, oversized) →
  never a server error, never a success;
- **privileged fields smuggled into request bodies** (mass assignment) →
  ignored.

Every response, even an error, carries the security headers (11a).
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from _verified_account import create_verified_account
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from test_api_easm import _seed_account_with_domain_asset, _seed_candidate
from test_api_exposure_operations import _seed_exposure

from api.control_db import ControlDB
from api.main import create_app
from api.settings import APISettings

# Reachable without an API key, on purpose.
PUBLIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/ready"),
        ("POST", "/accounts"),
        ("POST", "/accounts/verify-email"),
        ("POST", "/accounts/resend-verification"),
        ("POST", "/webhooks/wompi"),  # authenticated by Wompi's signature instead
    }
)
# An operator account's key only (Phase 11b); everyone else gets 404.
OPERATOR: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/admin/security-events"),
        ("GET", "/admin/wompi/unmatched"),
        ("POST", "/admin/wompi/reconcile"),
        ("GET", "/metrics"),
    }
)

_PARAM = re.compile(r"{([a-z_]+)(?::[a-z]+)?}")
_HOSTILE = (
    "' OR '1'='1",
    "1; DROP TABLE accounts--",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%00",
    "x" * 4096,
)


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    route: APIRoute

    @property
    def params(self) -> list[str]:
        return _PARAM.findall(self.path)

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


def _flatten(routes: list[Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Every route, through FastAPI's lazily-included routers."""
    for item in routes:
        if type(item).__name__ == "_IncludedRouter":
            sub_prefix = getattr(item.include_context, "prefix", "") or ""
            yield from _flatten(item.original_router.routes, prefix + sub_prefix)
        else:
            yield prefix + item.path, item


def _api_routes() -> list[Route]:
    app = create_app(APISettings(data_dir=Path("/nonexistent-route-listing")))
    found: list[Route] = []
    for path, route in _flatten(app.routes):
        if isinstance(route, APIRoute):
            found.extend(Route(method, path, route) for method in sorted(route.methods or ()))
    return sorted(found, key=str)


ROUTES = _api_routes()
PROTECTED = [r for r in ROUTES if (r.method, r.path) not in PUBLIC]
TENANT = [r for r in PROTECTED if (r.method, r.path) not in OPERATOR]


def _minimal_body(route: APIRoute) -> Any:
    """A schema-shaped body, so a request reaches the endpoint's own checks
    instead of stopping at validation."""
    if route.body_field is None:
        return None
    schema = route.body_field.field_info.annotation
    model_schema = getattr(schema, "model_json_schema", None)
    if model_schema is None:
        return {}
    spec = model_schema()
    definitions = spec.get("$defs", {})
    return _value_for(spec, definitions)


def _value_for(spec: dict[str, Any], definitions: dict[str, Any]) -> Any:
    if "$ref" in spec:
        return _value_for(definitions[spec["$ref"].rsplit("/", 1)[-1]], definitions)
    if "enum" in spec:
        return spec["enum"][0]
    if "anyOf" in spec:
        return _value_for(next(s for s in spec["anyOf"] if s.get("type") != "null"), definitions)
    kind = spec.get("type")
    if kind == "object":
        properties = spec.get("properties", {})
        return {
            name: _value_for(properties[name], definitions) for name in spec.get("required", [])
        }
    if kind == "array":
        return [_value_for(spec.get("items", {}), definitions)] if spec.get("minItems") else []
    return {"integer": 1, "number": 1, "boolean": False}.get(
        kind or "", "victim.example" if "domain" in str(spec) else "x" * spec.get("minLength", 1)
    )


# Bodies a schema walk can't infer (a model-level rule), so the request
# reaches the endpoint's authorization check instead of stopping at 422.
_BODY_OVERRIDES: dict[str, Any] = {
    "/organizations/{organization_id}/remediation/bulk": lambda v: {
        "exposure_ids": [v.get("exposure_id", "x")],
        "transition": {"to_state": "in_progress"},
    },
}


def _query(route: APIRoute, values: dict[str, str]) -> dict[str, str]:
    """Required query parameters, so validation doesn't stop the request."""
    return {
        param.name: values.get(param.name, values.get("domain", "x"))
        for param in route.dependant.query_params
        if param.field_info.is_required()
    }


def _call(client: TestClient, route: Route, values: dict[str, str], key: str | None) -> Any:
    path = route.path
    for name in route.params:
        path = path.replace("{" + name + "}", values.get(name, "missing-" + name), 1)
    headers = {"X-API-Key": key} if key else {}
    override = _BODY_OVERRIDES.get(route.path)
    body = override(values) if override else _minimal_body(route.route)
    query = _query(route.route, values)
    if body is None:
        return client.request(route.method, path, headers=headers, params=query)
    return client.request(route.method, path, headers=headers, params=query, json=body)


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """A victim tenant with real objects, an attacker tenant, and a plain
    (non-operator) account."""
    tmp_path = tmp_path_factory.mktemp("adversarial")
    settings = APISettings(
        data_dir=tmp_path / "api",
        max_concurrent_scans=0,
        account_creation_rate_limit_per_ip_per_day=100,
        rate_limit_per_minute=100_000,
    )
    with TestClient(create_app(settings)) as client:
        db: ControlDB = client.app.state.control_db
        victim_key, victim, org, asset = _seed_account_with_domain_asset(
            client, email="victim@example.com", domain="victim.example"
        )
        exposure = _seed_exposure(client, victim, org, run_id="victim-run")
        candidate = _seed_candidate(client, organization_id=org, account_id=victim)
        exclusion = db.add_scope_exclusion(
            organization_id=org, account_id=victim, pattern="mta.victim.example", reason="r"
        ).exclusion_id
        scan = db.list_scans_for_organization(org)[0].scan_id
        webhook = db.create_webhook(
            account_id=victim,
            url="https://hooks.victim.example/x",
            secret=secrets.token_hex(16),
            event_types=("monitoring.changed",),
            organization_id=org,
        ).webhook_id
        attacker_key, _ = create_verified_account(client)
        yield {
            "client": client,
            "db": db,
            "victim_key": victim_key,
            "attacker_key": attacker_key,
            "values": {
                "organization_id": org,
                "asset_id": asset,
                "exposure_id": exposure,
                "candidate_asset_id": candidate,
                "exclusion_id": exclusion,
                "scan_id": scan,
                "webhook_id": webhook,
                "key_id": db.list_keys_for_account(victim)[0].key_id,
                "account_id": victim,
                "domain": "victim.example",
                "integration_id": secrets.token_hex(16),
                "relationship_id": secrets.token_hex(16),
                "delivery_id": secrets.token_hex(16),
                "subject_type": "exposure",
                "subject_id": exposure,
                "source": "nmap",
                "dataset": "assets",
            },
        }


def _headers_present(response: Any) -> None:
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert "x-request-id" in response.headers


class TestInventory:
    def test_the_route_inventory_is_complete_and_the_exceptions_exist(self) -> None:
        listed = {(r.method, r.path) for r in ROUTES}
        assert len(listed) >= 100
        assert PUBLIC <= listed and OPERATOR <= listed  # no stale exception


@pytest.mark.parametrize("route", PROTECTED, ids=str)
def test_no_key_is_401(world: dict[str, Any], route: Route) -> None:
    response = _call(world["client"], route, world["values"], None)
    assert response.status_code == 401, response.text
    _headers_present(response)


@pytest.mark.parametrize("route", sorted(OPERATOR), ids=" ".join)
def test_operator_routes_are_404_for_everyone_else(
    world: dict[str, Any], route: tuple[str, str]
) -> None:
    method, path = route
    response = world["client"].request(method, path, headers={"X-API-Key": world["victim_key"]})
    assert response.status_code == 404


# Account-scoped routes keyed by a domain answer for the CALLER's own
# verification of that domain: "not verified by you" (403) reveals nothing
# about the victim.
_DOMAIN_FORBIDDEN_OK = {"domain"}


@pytest.mark.parametrize("route", [r for r in TENANT if r.params], ids=str)
def test_another_tenant_never_reaches_the_victims_objects(
    world: dict[str, Any], route: Route
) -> None:
    response = _call(world["client"], route, world["values"], world["attacker_key"])
    allowed = {404}
    if set(route.params) & _DOMAIN_FORBIDDEN_OK:
        allowed |= {403}
    assert response.status_code in allowed, (response.status_code, response.text[:300])
    _headers_present(response)


@pytest.mark.parametrize("route", [r for r in TENANT if r.params], ids=str)
@pytest.mark.parametrize("payload", _HOSTILE, ids=lambda p: p[:20])
def test_hostile_path_values_never_succeed_or_crash(
    world: dict[str, Any], route: Route, payload: str
) -> None:
    hostile = {name: payload for name in route.params}
    response = _call(world["client"], route, hostile, world["attacker_key"])
    assert response.status_code < 500, response.text[:300]
    assert not 200 <= response.status_code < 300, (response.status_code, response.text[:300])


class TestMassAssignment:
    def test_privileged_fields_in_bodies_are_ignored(self, world: dict[str, Any]) -> None:
        client, db = world["client"], world["db"]
        victim_org = world["values"]["organization_id"]
        headers = {"X-API-Key": world["attacker_key"]}

        created = client.post(
            "/organizations",
            headers=headers,
            json={"name": "Mine", "organization_id": victim_org, "role": "owner"},
        )
        assert created.status_code == 201
        assert created.json()["organization_id"] != victim_org
        # Still not a member of the victim's organization.
        assert client.get(f"/organizations/{victim_org}/assets", headers=headers).status_code == 404

        account = client.post(
            "/accounts", json={"email": "sneaky@example.com", "is_operator": True}
        ).json()
        assert not db.is_operator(account["account_id"])

        exclusion = client.post(
            f"/organizations/{created.json()['organization_id']}/scope/exclusions",
            headers=headers,
            json={
                "pattern": "x.mine.example",
                "reason": "r",
                "organization_id": victim_org,
            },
        )
        assert exclusion.status_code in (200, 201)
        victim_patterns = db.active_exclusion_patterns(victim_org)
        assert "x.mine.example" not in victim_patterns


class TestTheVictimsIdsAreReal:
    """The cross-tenant 404s above prove isolation only if the same request
    succeeds for the victim."""

    @pytest.mark.parametrize(
        "path",
        [
            "/organizations/{organization_id}/assets/{asset_id}",
            "/organizations/{organization_id}/exposures/{exposure_id}",
            "/organizations/{organization_id}/candidate-assets/{candidate_asset_id}",
            "/organizations/{organization_id}/scope/exclusions",
            "/scans/{scan_id}",
            "/webhooks/{webhook_id}/deliveries",
        ],
    )
    def test_victim_reads_succeed(self, world: dict[str, Any], path: str) -> None:
        concrete = path.format(**world["values"])
        response = world["client"].get(concrete, headers={"X-API-Key": world["victim_key"]})
        assert response.status_code == 200, (path, response.text[:200])


@pytest.mark.parametrize("route", [r for r in TENANT if r.method == "GET"], ids=str)
def test_the_victims_own_reads_never_fail_on_the_server(
    world: dict[str, Any], route: Route
) -> None:
    """Every GET with the victim's real ids. A 5xx here is a bug even when
    the caller is entitled (this sweep found the 500 on a scan whose report
    files were gone)."""
    response = _call(world["client"], route, world["values"], world["victim_key"])
    assert response.status_code < 500, (str(route), response.text[:300])
    _headers_present(response)


def test_a_report_whose_files_are_gone_is_410_not_500(world: dict[str, Any]) -> None:
    scan = world["values"]["scan_id"]
    response = world["client"].get(
        f"/scans/{scan}/report", headers={"X-API-Key": world["victim_key"]}
    )
    assert response.status_code == 410
