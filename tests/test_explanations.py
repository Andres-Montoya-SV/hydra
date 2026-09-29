"""Roadmap Phase 03 completion: one explanation shape for assets,
exposures and relationships, attributed to Hydra capabilities (never tool
names), plus the analyst raw-provenance endpoint that does carry them."""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi.testclient import TestClient
from test_api_exposure_operations import _FINDING, _account, _seed_exposure
from test_api_relationships import _seed_org_with_one_relationship

from api.asset_backfill import backfill_assets_for_organization
from api.explanations import EVIDENCE_LIMIT, capability_of
from api.exposure_identity import exposure_from_finding
from api.main import create_app
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, ScanRun
from core.provenance import record_observation
from core.store import AssetStore

SHAPE = {
    "subject_type",
    "subject_id",
    "claim",
    "status",
    "confidence",
    "first_observed_at",
    "last_observed_at",
    "reasons",
    "evidence",
    "evidence_total",
}
RAW_TOOLS = {"dnsx", "httpx", "subfinder", "nuclei", "ctlogs", "amass"}


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(APISettings(data_dir=tmp_path / "api")))


def _seed_asset(client: TestClient, run_id: str = "run-x") -> tuple[dict[str, str], str, str]:
    account = client.post("/accounts", json={"email": f"x-{secrets.token_hex(4)}@x.test"}).json()
    db = client.app.state.control_db
    settings: APISettings = client.app.state.api_settings
    org = db.list_organizations_for_account(account["account_id"])[0][0]
    db.create_scan(
        scan_id=run_id,
        account_id=account["account_id"],
        domain="a.test",
        db_path="x",
        organization_id=org,
    )
    store = AssetStore(account_db_path(settings, account["account_id"]))
    store.create_run(ScanRun(run_id=run_id, started_at="2026-09-01T00:00:00+00:00"))
    host = Host(domain="a.test", ips=["192.0.2.1"], discovery_sources=["subfinder"])
    host.add_provenance(
        record_observation(
            tool="dnsx",
            field="a",
            value="192.0.2.1",
            confidence=90,
            artifact_path="/srv/hydra/out/dnsx.jsonl",
        )
    )
    store.upsert_host(run_id, host)
    db.update_scan_status(run_id, "completed")
    backfill_assets_for_organization(control_db=db, api_settings=settings, organization_id=org)
    asset = db.get_asset_by_identity(
        organization_id=org, asset_type="domain", identity_key="domain:a.test"
    )
    return {"X-API-Key": account["api_key"]}, org, asset.asset_id


def _explain(
    client: TestClient, headers: dict[str, str], org: str, kind: str, sid: str
):  # noqa: ANN202
    return client.get(f"/organizations/{org}/explanations/{kind}/{sid}", headers=headers)


class TestCapabilityAttribution:
    def test_tools_map_to_capabilities_and_unknowns_never_guess(self) -> None:
        assert capability_of("dnsx") == "dns"
        assert capability_of("nuclei") == "http"
        assert capability_of("definitely-not-a-provider") == "uncategorized"


class TestSharedShape:
    def test_asset_explanation(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, org, asset_id = _seed_asset(client)

            body = _explain(client, headers, org, "asset", asset_id).json()

            assert set(body) == SHAPE
            assert body["claim"] == "a.test is a domain asset of this organization"
            assert body["reasons"][0] == "observed in 1 scan(s)"
            assert body["evidence_total"] >= 1
            assert body["evidence"][0]["run_id"] == "run-x"
            assert not {e["capability"] for e in body["evidence"]} & RAW_TOOLS

    def test_exposure_explanation_carries_its_risk_reasons(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "explain-exp@example.com")
            exposure_id = _seed_exposure(client, account_id, org)

            body = _explain(client, {"X-API-Key": key}, org, "exposure", exposure_id).json()

            assert set(body) == SHAPE
            assert body["status"] == "open"
            assert body["reasons"][0].startswith("risk level ")
            assert "base severity is high" in body["reasons"]
            assert body["evidence"][0]["capability"] == "http"
            assert body["evidence_total"] == 1

    def test_relationship_explanation(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, org, relationship_id = _seed_org_with_one_relationship(
                client, email="explain-rel@example.com"
            )

            body = _explain(client, {"X-API-Key": key}, org, "relationship", relationship_id)

            assert body.status_code == 200
            assert set(body.json()) == SHAPE
            assert body.json()["evidence_total"] == len(body.json()["evidence"]) >= 1

    def test_evidence_is_bounded_to_the_newest(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "explain-many@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            db = client.app.state.control_db
            draft = exposure_from_finding(_FINDING, asset_id="asset-example")
            for i in range(EVIDENCE_LIMIT + 4):
                db.create_scan(
                    scan_id=f"run-{i:02d}",
                    account_id=account_id,
                    organization_id=org,
                    domain="example.com",
                    db_path="x",
                )
                db.upsert_exposure(
                    organization_id=org,
                    account_id=account_id,
                    run_id=f"run-{i:02d}",
                    finding_id=1,
                    draft=draft,
                    observed_at=f"2026-09-27T00:{i:02d}:00+00:00",
                )

            body = _explain(client, {"X-API-Key": key}, org, "exposure", exposure_id).json()

            assert body["evidence_total"] == EVIDENCE_LIMIT + 5
            assert len(body["evidence"]) == EVIDENCE_LIMIT
            assert body["evidence"][0]["run_id"] == f"run-{EVIDENCE_LIMIT + 3:02d}"


class TestTenancy:
    def test_foreign_unknown_and_invalid_subjects(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, org, asset_id = _seed_asset(client)
            foreign, _, _ = _seed_asset(client, "run-foreign")

            assert _explain(client, foreign, org, "asset", asset_id).status_code == 404
            assert _explain(client, headers, org, "exposure", asset_id).status_code == 404
            assert _explain(client, headers, org, "finding", asset_id).status_code == 422
            raw = client.get(
                f"/organizations/{org}/analyst/assets/{asset_id}/provenance", headers=foreign
            )
            assert raw.status_code == 404


class TestAnalystProvenance:
    def test_raw_names_and_records_live_only_here(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            headers, org, asset_id = _seed_asset(client)

            body = client.get(
                f"/organizations/{org}/analyst/assets/{asset_id}/provenance", headers=headers
            ).json()

            assert body["run_id"] == "run-x"
            assert body["observations"]
            dnsx = next(p for p in body["tool_provenance"] if p["tool"] == "dnsx")
            assert (dnsx["value"], dnsx["artifact"]) == ("192.0.2.1", "dnsx.jsonl")
