"""GET /scans/{id}/summary: what one scan changed, as counts, built from the
real per-run EASM tables (the scan goes through execute_scan and the real
EASM backfill; only the collection pipeline is stubbed)."""

from __future__ import annotations

from pathlib import Path

import pytest
from _org_helpers import api_client, verified_owner
from fastapi.testclient import TestClient

from api.candidate_assets import CandidateAssetDraft
from api.exposure_identity import exposure_from_finding
from api.scan_orchestrator import execute_scan
from api.tenancy import account_db_path
from core.assets import Finding, Host, ScanRun
from core.models import PipelineContext, ToolInfo, ToolStatus
from core.store import AssetStore

DOMAIN = "example.com"
FINDING = {
    "host": DOMAIN,
    "template_id": "admin-exposed",
    "severity": "high",
    "source": "nuclei",
    "url": "https://example.com/admin",
    "name": "Admin exposed",
}


def _pipeline(outcome: ToolStatus):  # noqa: ANN202
    async def run(settings, *, domain, targets_file, run_id):  # noqa: ANN001, ANN202
        info = ToolInfo(
            name="ctlogs", display_name="ctlogs", required=False, enabled=True, status=outcome
        )
        return 0, PipelineContext(errors=[], tool_states={"ctlogs": info})

    return run


async def _completed_scan(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    account_id: str,
    org: str,
    scan_id: str,
    outcome: ToolStatus = ToolStatus.SUCCESS_WITH_RESULTS,
) -> None:
    db = client.app.state.control_db
    settings = client.app.state.api_settings
    db.create_scan(
        scan_id=scan_id, account_id=account_id, domain=DOMAIN, db_path="x", organization_id=org
    )
    store = AssetStore(account_db_path(settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-09-29T00:00:00+00:00"))
    store.upsert_host(
        scan_id,
        Host(
            domain=DOMAIN,
            discovery_sources=["dnsx"],
            findings=[Finding(**FINDING, description="x")],
        ),
    )
    monkeypatch.setattr("app._run_headless_pipeline", _pipeline(outcome))
    monkeypatch.setattr("app._external_mode_preflight", lambda a, s: True)
    await execute_scan(
        api_settings=settings, control_db=db, account_id=account_id, scan_id=scan_id, domain=DOMAIN
    )


def _add_candidate(client: TestClient, org: str, run_id: str) -> None:
    client.app.state.control_db.upsert_candidate_asset(
        organization_id=org,
        run_id=run_id,
        draft=CandidateAssetDraft(
            candidate_type="DOMAIN",
            normalized_value="new.partner.example",
            display_value="new.partner.example",
            scope_status="OUT_OF_SCOPE",
            collection_status="DISCOVERED",
            authorization_status="DENY",
            reason="shared certificate",
            depth=1,
            priority=50,
            collector="ctlogs",
            source_entity_id="",
            parent_indicator_id=None,
            lineage_reference=run_id,
        ),
    )


def _add_exposure(client: TestClient, account_id: str, org: str, run_id: str) -> None:
    db = client.app.state.control_db
    asset = db.list_assets_for_organization(org)[0]
    draft = exposure_from_finding(FINDING, asset_id=asset.asset_id)
    assert draft is not None
    db.upsert_exposure(
        organization_id=org, account_id=account_id, run_id=run_id, finding_id=1, draft=draft
    )


class TestScanSummary:
    async def test_a_first_scan_reports_what_it_introduced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            await _completed_scan(client, monkeypatch, account_id, org, "scan-1")
            _add_candidate(client, org, "scan-1")
            _add_exposure(client, account_id, org, "scan-1")

            body = client.get("/scans/scan-1/summary", headers=headers).json()

            assert body == {
                "scan_id": "scan-1",
                "status": "completed",
                "degraded": False,
                "assets_observed": 1,
                "asset_lifecycle": {"new": 1},
                "exposures_first_seen": 1,
                "exposure_events": {"observed": 1},
                "certificate_events": {},
                "technology_events": {},
                "candidates_first_seen": 1,
            }

    async def test_a_degraded_scan_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            await _completed_scan(
                client, monkeypatch, account_id, org, "scan-d", ToolStatus.UNAVAILABLE
            )

            body = client.get("/scans/scan-d/summary", headers=headers).json()

            assert (body["status"], body["degraded"]) == ("completed", True)

    def test_a_queued_scan_is_all_zeros(self, tmp_path: Path) -> None:
        with api_client(tmp_path) as client:
            headers, account_id, org = verified_owner(client)
            client.app.state.control_db.create_scan(
                scan_id="scan-q",
                account_id=account_id,
                domain=DOMAIN,
                db_path="x",
                organization_id=org,
            )

            body = client.get("/scans/scan-q/summary", headers=headers).json()

            assert body["status"] == "queued"
            assert (body["assets_observed"], body["asset_lifecycle"]) == (0, {})

    async def test_another_accounts_scan_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with api_client(tmp_path) as client:
            _, account_id, org = verified_owner(client)
            await _completed_scan(client, monkeypatch, account_id, org, "scan-x")
            foreign, _, _ = verified_owner(client)

            assert client.get("/scans/scan-x/summary", headers=foreign).status_code == 404
