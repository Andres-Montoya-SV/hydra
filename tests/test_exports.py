"""GET /organizations/{org}/exports/{assets|exposures}?format=csv|ndjson."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from _org_helpers import api_client, verified_owner
from fastapi.testclient import TestClient

from api import exports
from api.asset_identity import ReconciliationDecision
from api.exports import neutralize_cell
from api.exposure_identity import exposure_from_finding


def _seed_assets(client: TestClient, org: str, count: int) -> None:
    client.app.state.control_db.apply_asset_reconciliation(
        organization_id=org,
        run_id="seed",
        decisions=[
            ReconciliationDecision(
                asset_id=f"{org}-a{i:02d}",
                asset_type="domain",
                identity_key=f"domain:h{i}.example.com",
                is_new=True,
                identifiers=(),
            )
            for i in range(count)
        ],
        observed_at="2026-09-01T00:00:00+00:00",
    )


def _seed_exposure(client: TestClient, account_id: str, org: str, title: str) -> None:
    db = client.app.state.control_db
    db.create_scan(
        scan_id=f"scan-{org}",
        account_id=account_id,
        domain="example.com",
        db_path="x",
        organization_id=org,
    )
    finding = {
        "host": "h0.example.com",
        "template_id": "t1",
        "severity": "high",
        "source": "nuclei",
        "url": "https://h0.example.com/x",
        "name": title,
    }
    draft = exposure_from_finding(finding, asset_id=f"{org}-a00")
    assert draft is not None
    db.upsert_exposure(
        organization_id=org, account_id=account_id, run_id=f"scan-{org}", finding_id=1, draft=draft
    )


def _export(
    client: TestClient, headers: dict[str, str], org: str, dataset: str, fmt: str
):  # noqa: ANN202
    return client.get(
        f"/organizations/{org}/exports/{dataset}", headers=headers, params={"format": fmt}
    )


class TestFormats:
    def test_assets_as_csv(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            _seed_assets(client, org, 3)

            resp = _export(client, headers, org, "assets", "csv")
            rows = list(csv.DictReader(io.StringIO(resp.text)))

            assert resp.headers["content-type"].startswith("text/csv")
            assert resp.headers["content-disposition"] == 'attachment; filename="assets.csv"'
            assert [r["identity_key"] for r in rows] == [
                "domain:h0.example.com",
                "domain:h1.example.com",
                "domain:h2.example.com",
            ]

    def test_exposures_as_ndjson(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            _seed_assets(client, org, 1)
            _seed_exposure(client, account_id, org, "Admin exposed")

            resp = _export(client, headers, org, "exposures", "ndjson")
            rows = [json.loads(line) for line in resp.text.splitlines()]

            assert resp.headers["content-type"] == "application/x-ndjson"
            assert [(r["title"], r["severity"], r["status"]) for r in rows] == [
                ("Admin exposed", "high", "open")
            ]

    def test_an_empty_organization_exports_a_header_only(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            assert _export(client, headers, org, "assets", "csv").text.strip() == ",".join(
                exports.ASSET_FIELDS
            )
            assert _export(client, headers, org, "exposures", "ndjson").text == ""


class TestCsvInjection:
    @pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"])
    def test_formula_prefixes_are_neutralized(self, value: str) -> None:
        assert neutralize_cell(value) == "'" + value

    def test_ordinary_values_are_untouched(self) -> None:
        assert [neutralize_cell(v) for v in ("Admin", "a-b", 3, None)] == ["Admin", "a-b", 3, None]

    def test_a_hostile_title_reaches_the_csv_neutralized(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            _seed_assets(client, org, 1)
            _seed_exposure(client, account_id, org, '=HYPERLINK("http://evil.test","x")')

            rows = list(
                csv.DictReader(io.StringIO(_export(client, headers, org, "exposures", "csv").text))
            )

            assert rows[0]["title"] == '\'=HYPERLINK("http://evil.test","x")'


class TestPagingAndTenancy:
    def test_every_row_exactly_once_across_pages(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(exports, "PAGE_SIZE", 2)
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            _seed_assets(client, org, 5)

            lines = _export(client, headers, org, "assets", "ndjson").text.splitlines()

            ids = [json.loads(line)["asset_id"] for line in lines]
            assert ids == sorted(ids) and len(set(ids)) == 5

    def test_other_organizations_rows_never_appear(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)
            other_headers, _, other_org = verified_owner(client)
            _seed_assets(client, org, 2)
            _seed_assets(client, other_org, 3)

            mine = _export(client, headers, org, "assets", "ndjson").text.splitlines()
            foreign = _export(client, other_headers, org, "assets", "csv")

            assert all(json.loads(line)["asset_id"].startswith(org) for line in mine)
            assert len(mine) == 2
            assert foreign.status_code == 404

    def test_unknown_dataset_or_format_is_422(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, _, org = verified_owner(client)

            assert _export(client, headers, org, "secrets", "csv").status_code == 422
            assert _export(client, headers, org, "assets", "xlsx").status_code == 422
