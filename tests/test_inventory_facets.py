"""GET /organizations/{org}/inventory/facets. Data comes from real scans
replayed through the real asset backfill. The technology facet is computed
in SQL, so it is checked against the existing per-asset Python derivation
(`list_current_technologies_for_asset`) on the same data."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from _org_helpers import api_client, verified_owner
from fastapi.testclient import TestClient

from api.asset_backfill import backfill_assets_for_organization
from api.control_db import _port_facet
from api.tenancy import account_db_path
from core.assets import Host as HostRecord
from core.assets import HttpService, Port, ScanRun, TechnologyFinding
from core.store import AssetStore


def _tech(name: str, version: str | None = None) -> TechnologyFinding:
    return TechnologyFinding(name=name, source="httpx", confidence=80, version=version)


def _host(domain: str, techs: list[TechnologyFinding], ports: list[int]) -> HostRecord:
    return HostRecord(
        domain=domain,
        discovery_sources=["dnsx"],
        http_services=[HttpService(url=f"https://{domain}/", host=domain, technologies=techs)],
        ports=[Port(host=domain, port=p) for p in ports],
    )


def _scan(
    client: TestClient, account_id: str, org: str, run_id: str, day: int, hosts: list[HostRecord]
) -> None:
    db = client.app.state.control_db
    settings = client.app.state.api_settings
    db.create_scan(
        scan_id=run_id,
        account_id=account_id,
        domain="example.com",
        db_path="x",
        organization_id=org,
    )
    store = AssetStore(account_db_path(settings, account_id))
    store.create_run(ScanRun(run_id=run_id, started_at=f"2026-09-{day:02d}T00:00:00+00:00"))
    for host in hosts:
        store.upsert_host(run_id, host)
    db.update_scan_status(run_id, "completed")
    backfill_assets_for_organization(control_db=db, api_settings=settings, organization_id=org)


def _seed(client: TestClient) -> tuple[dict[str, str], str]:
    headers, account_id, org = verified_owner(client)
    _scan(
        client,
        account_id,
        org,
        "run-1",
        1,
        [
            _host("a.example.com", [_tech("nginx", "1.2"), _tech("php")], [443, 80]),
            _host("b.example.com", [_tech("nginx")], [443]),
        ],
    )
    # a.example.com's later run no longer shows php: php is not current.
    _scan(
        client,
        account_id,
        org,
        "run-2",
        2,
        [
            _host("a.example.com", [_tech("nginx", "1.3")], [443]),
        ],
    )
    return headers, org


class TestFacets:
    def test_counts_by_type_technology_and_port(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, org = _seed(client)

            body = client.get(f"/organizations/{org}/inventory/facets", headers=headers).json()

            assert body["assets_by_type"]["domain"] == 2
            assert body["technologies"] == [{"value": "nginx", "count": 2}]
            assert {p["value"]: p["count"] for p in body["open_ports"]} == {
                "443/tcp": 2,
                "80/tcp": 1,
            }

    def test_sql_technology_facet_matches_the_per_asset_derivation(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, org = _seed(client)
            db = client.app.state.control_db

            expected = Counter(
                name
                for asset in db.list_assets_for_organization(org)
                for name in {
                    t.technology_name
                    for t in db.list_current_technologies_for_asset(asset.asset_id)
                }
            )
            body = client.get(f"/organizations/{org}/inventory/facets", headers=headers).json()

            assert {t["value"]: t["count"] for t in body["technologies"]} == dict(expected)

    def test_top_limits_each_ranked_list(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, org = _seed(client)

            body = client.get(
                f"/organizations/{org}/inventory/facets", headers=headers, params={"top": 1}
            ).json()

            assert body["open_ports"] == [{"value": "443/tcp", "count": 2}]
            assert len(body["technologies"]) == 1

    def test_ipv6_port_hosts_are_parsed_from_the_right(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            _, _, org = verified_owner(client)
            db = client.app.state.control_db
            with db._connect() as conn:
                conn.execute(
                    "INSERT INTO assets (asset_id, organization_id, asset_type, identity_key, "
                    "first_seen_at, last_seen_at) VALUES ('p6', ?, 'port', "
                    "'port:2001:db8::1:8443:tcp', 'x', 'x')",
                    (org,),
                )
                assert _port_facet(conn, org, 10) == [("8443/tcp", 1)]

    def test_empty_organization_and_foreign_account(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, org = _seed(client)
            empty_headers, _, empty_org = verified_owner(client)

            empty = client.get(
                f"/organizations/{empty_org}/inventory/facets", headers=empty_headers
            ).json()
            foreign = client.get(f"/organizations/{org}/inventory/facets", headers=empty_headers)

            assert empty["technologies"] == empty["open_ports"] == []
            assert foreign.status_code == 404
