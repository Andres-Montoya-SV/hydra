"""Exposure API isolation and workflow tests."""

from pathlib import Path

from fastapi.testclient import TestClient

from api.asset_identity import ReconciliationDecision
from api.exposure_identity import exposure_from_finding
from api.main import create_app
from api.settings import APISettings


def _seed_exposure(client: TestClient, *, email: str) -> tuple[str, str, str, str]:
    account = client.post("/accounts", json={"email": email}).json()
    api_key = account["api_key"]
    account_id = account["account_id"]
    db = client.app.state.control_db
    organization_id, _ = db.list_organizations_for_account(account_id)[0]
    db.apply_asset_reconciliation(
        organization_id=organization_id,
        run_id="seed",
        decisions=[
            ReconciliationDecision(
                asset_id="asset-example",
                asset_type="domain",
                identity_key="domain:example.com",
                is_new=True,
                identifiers=(),
            )
        ],
        observed_at="2026-09-26T00:00:00+00:00",
    )
    db.create_scan(
        scan_id="run-exposure",
        account_id=account_id,
        organization_id=organization_id,
        domain="example.com",
        db_path="unused",
    )
    draft = exposure_from_finding(
        {
            "host": "example.com",
            "template_id": "admin-exposed",
            "severity": "high",
            "source": "nuclei",
            "url": "https://example.com/admin",
            "name": "Admin interface exposed",
        },
        asset_id="asset-example",
    )
    assert draft is not None
    exposure_id, _, _ = db.upsert_exposure(
        organization_id=organization_id,
        account_id=account_id,
        run_id="run-exposure",
        finding_id=1,
        draft=draft,
        observed_at="2026-09-26T00:01:00+00:00",
    )
    return api_key, account_id, organization_id, exposure_id


def test_owner_can_read_history_and_resolve_exposure(tmp_path: Path) -> None:
    with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
        api_key, _, org, exposure_id = _seed_exposure(
            client, email="exposure-api-owner@example.com"
        )
        headers = {"X-API-Key": api_key}

        listed = client.get(f"/organizations/{org}/exposures", headers=headers)
        assert listed.status_code == 200
        assert [row["exposure_id"] for row in listed.json()] == [exposure_id]

        evidence = client.get(
            f"/organizations/{org}/exposures/{exposure_id}/evidence",
            headers=headers,
        )
        assert evidence.status_code == 200
        assert len(evidence.json()) == 1

        history = client.get(
            f"/organizations/{org}/exposures/{exposure_id}/history",
            headers=headers,
        )
        assert history.status_code == 200
        assert [row["event_type"] for row in history.json()] == ["observed"]

        resolved = client.post(
            f"/organizations/{org}/exposures/{exposure_id}/resolve",
            headers=headers,
            json={"reason": "Remediation verified by owner"},
        )
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "resolved"


def test_foreign_account_cannot_probe_exposure_ids(tmp_path: Path) -> None:
    with TestClient(create_app(APISettings(data_dir=tmp_path / "api"))) as client:
        _, _, org, exposure_id = _seed_exposure(client, email="exposure-api-owner2@example.com")
        foreign = client.post(
            "/accounts", json={"email": "exposure-api-foreign@example.com"}
        ).json()
        headers = {"X-API-Key": foreign["api_key"]}

        for suffix in (
            "",
            f"/{exposure_id}",
            f"/{exposure_id}/evidence",
            f"/{exposure_id}/history",
        ):
            response = client.get(
                f"/organizations/{org}/exposures{suffix}",
                headers=headers,
            )
            assert response.status_code == 404

        resolve = client.post(
            f"/organizations/{org}/exposures/{exposure_id}/resolve",
            headers=headers,
            json={"reason": "should never be allowed"},
        )
        assert resolve.status_code == 404
