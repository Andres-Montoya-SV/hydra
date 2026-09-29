"""Network & Geo Intelligence (Roadmap v2, Phase 02 addition): offline geo
enrichment layered on the existing Team Cymru ASN lookup.

Every test uses a real MaxMind-format file built by tests/_mmdb_writer.py
and read by the real `maxminddb` reader — never a mocked reader."""

from __future__ import annotations

import importlib.util
import secrets
import socket
import sys
import time
from pathlib import Path

import pytest
from _mmdb_writer import write_mmdb
from fastapi.testclient import TestClient

from api.main import create_app
from api.settings import APISettings
from api.tenancy import account_db_path
from config.settings import Settings
from core.assets import Host, ScanRun
from core.geoip import GEOIP_MAX_AGE_DAYS, open_geoip
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import ASNParser
from core.store import AssetStore
from modules.asn_lookup import AsnLookupPlugin
from utils.files import read_jsonl, write_jsonl

# `maxminddb` is an optional runtime dependency (requirements-optional.txt):
# the Python-version CI matrix runs without it, the Docker job with it.
needs_reader = pytest.mark.skipif(
    importlib.util.find_spec("maxminddb") is None, reason="maxminddb not installed"
)

SAN_JOSE = {
    "country": {"iso_code": "US"},
    "subdivisions": [{"names": {"en": "California"}}],
    "city": {"names": {"en": "San Jose"}},
    "location": {"latitude": 37.33, "longitude": -121.89},
}


def _db(tmp_path: Path, *, age_days: int = 3) -> Path:
    path = tmp_path / "geo.mmdb"
    write_mmdb(
        path,
        network="192.0.2.0/24",
        record=SAN_JOSE,
        database_type="GeoLite2-City",
        build_epoch=int(time.time()) - age_days * 86400,
    )
    return path


class TestGeoDatabase:
    @needs_reader
    def test_lookup_returns_location_and_provenance(self, tmp_path: Path) -> None:
        geo = open_geoip(_db(tmp_path, age_days=3))
        assert geo is not None

        location = geo.lookup("192.0.2.77")

        assert location is not None
        assert (location.country, location.region, location.city) == (
            "US",
            "California",
            "San Jose",
        )
        assert geo.info.source().startswith("GeoLite2-City@")
        assert geo.info.age_days() == 3

    @needs_reader
    def test_unknown_or_invalid_ip_is_none(self, tmp_path: Path) -> None:
        geo = open_geoip(_db(tmp_path))
        assert geo is not None
        assert geo.lookup("198.51.100.1") is None
        assert geo.lookup("not-an-ip") is None

    def test_unset_missing_or_corrupt_database_is_none_never_an_error(self, tmp_path: Path) -> None:
        corrupt = tmp_path / "corrupt.mmdb"
        corrupt.write_bytes(b"not a maxmind database")
        assert open_geoip(None) is None
        assert open_geoip(tmp_path / "missing.mmdb") is None
        assert open_geoip(corrupt) is None


def test_without_the_reader_library_geo_is_skipped_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from modules.asn_lookup import _add_geo

    monkeypatch.setitem(sys.modules, "maxminddb", None)  # import now raises ImportError
    path = _db(tmp_path)
    records = [{"ip": "192.0.2.10", "asn": "64500"}]

    assert open_geoip(path) is None
    assert _add_geo(records, str(path)) == [{"ip": "192.0.2.10", "asn": "64500"}]


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("geo lookup attempted a network call")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@needs_reader
class TestZeroNetwork:
    def test_opening_and_looking_up_never_touches_the_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _db(tmp_path)
        _no_network(monkeypatch)

        geo = open_geoip(path)

        assert geo is not None
        assert geo.lookup("192.0.2.5") is not None


class TestAsnLookupEnrichment:
    @needs_reader
    async def test_geo_fields_reach_the_host_and_geo_country_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        write_jsonl(output_dir / "dnsx_records.jsonl", [{"host": "a.test", "a": ["192.0.2.10"]}])
        context = PipelineContext(output_dir=output_dir, targets=[DomainTarget(domain="a.test")])
        context.collection_scope = CollectionScope.from_seeds(["a.test"])

        async def cymru(_ips: list[str]) -> list[dict[str, str]]:
            # Registry country deliberately differs from where the IP is.
            return [
                {
                    "asn": "64500",
                    "ip": "192.0.2.10",
                    "bgp_prefix": "192.0.2.0/24",
                    "country": "NL",
                    "registry": "ripe",
                    "allocated": "",
                    "as_name": "EXAMPLE",
                }
            ]

        monkeypatch.setattr("modules.asn_lookup._query_cymru", cymru)
        settings = Settings(project_root=tmp_path)
        settings.geoip_db_path = str(_db(tmp_path))

        await AsnLookupPlugin(settings).run(context, output_dir / "resolved.txt")
        hosts, _ = ASNParser().parse(output_dir)

        assert read_jsonl(output_dir / "asn.jsonl")[0]["city"] == "San Jose"
        host = next(h for h in hosts if h.domain == "a.test")
        assert (host.country, host.region, host.city, host.asn) == (
            "US",
            "California",
            "San Jose",
            "64500",
        )
        assert host.geo_source and host.geo_db_age_days == 3

    def test_merge_carries_geo_fields_together(self) -> None:
        base = Host(domain="a.test")
        base.merge_from(
            Host(
                domain="a.test",
                city="San Jose",
                region="California",
                geo_source="G@d",
                geo_db_age_days=1,
                latitude=1.0,
                longitude=2.0,
            )
        )
        # A later partial without geo provenance never clobbers the lookup.
        base.merge_from(Host(domain="a.test", asn="64500"))

        assert (base.city, base.region, base.geo_source, base.latitude, base.asn) == (
            "San Jose",
            "California",
            "G@d",
            1.0,
            "64500",
        )


def _seed_domain_asset(client: TestClient, host: Host) -> tuple[dict[str, str], str, str]:
    from api.asset_backfill import backfill_assets_for_organization

    account = client.post("/accounts", json={"email": f"geo-{secrets.token_hex(4)}@x.test"}).json()
    db = client.app.state.control_db
    api_settings: APISettings = client.app.state.api_settings
    org = db.list_organizations_for_account(account["account_id"])[0][0]
    db.create_scan(
        scan_id="run-geo",
        account_id=account["account_id"],
        domain="a.test",
        db_path="x",
        organization_id=org,
    )
    store = AssetStore(account_db_path(api_settings, account["account_id"]))
    store.create_run(ScanRun(run_id="run-geo", started_at="2026-09-01T00:00:00+00:00"))
    store.upsert_host("run-geo", host)
    db.update_scan_status("run-geo", "completed")
    backfill_assets_for_organization(control_db=db, api_settings=api_settings, organization_id=org)
    asset = db.get_asset_by_identity(
        organization_id=org, asset_type="domain", identity_key="domain:a.test"
    )
    return {"X-API-Key": account["api_key"]}, org, asset.asset_id


def _geo_host(age_days: int | None) -> Host:
    return Host(
        domain="a.test",
        ips=["192.0.2.10"],
        asn="64500",
        asn_org="EXAMPLE",
        cidr="192.0.2.0/24",
        provider="EXAMPLE",
        country="US",
        region="California",
        city="San Jose",
        latitude=37.33,
        longitude=-121.89,
        geo_source="GeoLite2-City@2026-09-26",
        geo_db_age_days=age_days,
    )


class TestNetworkEndpoint:
    def test_returns_ownership_and_fresh_geo(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, org, asset_id = _seed_domain_asset(client, _geo_host(3))

            body = client.get(
                f"/organizations/{org}/assets/{asset_id}/network", headers=headers
            ).json()

            assert (body["asn"], body["network_cidr"], body["run_id"]) == (
                "64500",
                "192.0.2.0/24",
                "run-geo",
            )
            assert body["geo"]["city"] == "San Jose"
            assert body["geo"]["stale"] is False

    def test_an_old_database_is_flagged_stale(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, org, asset_id = _seed_domain_asset(client, _geo_host(GEOIP_MAX_AGE_DAYS + 15))

            body = client.get(
                f"/organizations/{org}/assets/{asset_id}/network", headers=headers
            ).json()

            assert body["geo"]["stale"] is True

    def test_no_geo_enrichment_is_null_not_a_guess(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            headers, org, asset_id = _seed_domain_asset(
                client, Host(domain="a.test", ips=["192.0.2.10"], asn="64500")
            )

            body = client.get(
                f"/organizations/{org}/assets/{asset_id}/network", headers=headers
            ).json()

            assert body["asn"] == "64500"
            assert body["geo"] is None

    def test_foreign_account_gets_404(self, tmp_path: Path) -> None:
        with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
            _, org, asset_id = _seed_domain_asset(client, _geo_host(3))
            foreign = client.post("/accounts", json={"email": "geo-foreign@x.test"}).json()

            resp = client.get(
                f"/organizations/{org}/assets/{asset_id}/network",
                headers={"X-API-Key": foreign["api_key"]},
            )

            assert resp.status_code == 404
