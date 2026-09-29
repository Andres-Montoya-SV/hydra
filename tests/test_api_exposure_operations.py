"""Productization Phase 04 — exposure operations: evidence that explains
itself (the real detector result behind each `finding_id`), an audited
manual reopen, and the role/replay/input edges of both lifecycle
transitions. `tests/test_api_exposures.py` keeps covering the pre-existing
read surface and resolve happy path."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.asset_identity import ReconciliationDecision
from api.exposure_identity import exposure_from_finding
from api.main import create_app
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Finding, Host
from core.store import AssetStore, ScanRun

_FINDING = {
    "host": "example.com",
    "template_id": "admin-exposed",
    "severity": "high",
    "source": "nuclei",
    "url": "https://example.com/admin",
    "name": "Admin interface exposed",
}


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(APISettings(data_dir=tmp_path / "api")))


def _account(client: TestClient, email: str) -> tuple[str, str, str]:
    body = client.post("/accounts", json={"email": email}).json()
    org, _ = client.app.state.control_db.list_organizations_for_account(body["account_id"])[0]
    return body["api_key"], body["account_id"], org


def _write_real_finding(client: TestClient, account_id: str, run_id: str) -> int:
    """A genuine findings row in the account's own recon.db, as a scan leaves."""
    store = AssetStore(account_db_path(client.app.state.api_settings, account_id))
    store.create_run(ScanRun(run_id=run_id, started_at="2026-09-26T00:00:00+00:00"))
    store.upsert_host(
        run_id,
        Host(domain="example.com", findings=[Finding(**_FINDING, description="Login page")]),
    )
    return int(store.get_findings(run_id)[0]["id"])


def _seed_asset(db, org: str) -> None:  # type: ignore[no-untyped-def]
    db.apply_asset_reconciliation(
        organization_id=org,
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


def _seed_exposure(
    client: TestClient, account_id: str, org: str, *, run_id: str = "run-1", real: bool = True
) -> str:
    db = client.app.state.control_db
    if db.get_asset(org, "asset-example") is None:
        _seed_asset(db, org)
    db.create_scan(
        scan_id=run_id,
        account_id=account_id,
        organization_id=org,
        domain="example.com",
        db_path="x",
    )
    finding_id = _write_real_finding(client, account_id, run_id) if real else 1
    draft = exposure_from_finding(_FINDING, asset_id="asset-example")
    assert draft is not None
    exposure_id, _, _ = db.upsert_exposure(
        organization_id=org,
        account_id=account_id,
        run_id=run_id,
        finding_id=finding_id,
        draft=draft,
        observed_at="2026-09-26T00:01:00+00:00",
    )
    return exposure_id


class TestEvidenceExplainsItself:
    def test_evidence_includes_the_real_detector_result(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ev-real@example.com")
            exposure_id = _seed_exposure(client, account_id, org)

            body = client.get(
                f"/organizations/{org}/exposures/{exposure_id}/evidence",
                headers={"X-API-Key": key},
            ).json()

            assert len(body) == 1
            finding = body[0]["finding"]
            assert finding["host"] == "example.com"
            assert finding["url"] == "https://example.com/admin"
            assert finding["name"] == "Admin interface exposed"
            assert finding["severity"] == "high"
            assert finding["description"] == "Login page"

    def test_unreadable_finding_is_null_and_no_database_is_created(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ev-null@example.com")
            exposure_id = _seed_exposure(client, account_id, org, real=False)
            recon_db = account_db_path(client.app.state.api_settings, account_id)
            assert not recon_db.exists()

            resp = client.get(
                f"/organizations/{org}/exposures/{exposure_id}/evidence",
                headers={"X-API-Key": key},
            )

            assert resp.status_code == 200
            assert resp.json()[0]["finding"] is None
            # A read endpoint must never create an empty recon.db as a side effect.
            assert not recon_db.exists()

    def test_evidence_is_paginated(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ev-page@example.com")
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            _seed_exposure(client, account_id, org, run_id="run-2")
            url = f"/organizations/{org}/exposures/{exposure_id}/evidence"
            headers = {"X-API-Key": key}

            first = client.get(url, headers=headers, params={"limit": 1, "offset": 0}).json()
            second = client.get(url, headers=headers, params={"limit": 1, "offset": 1}).json()

            assert len(first) == 1 and len(second) == 1
            assert first[0]["run_id"] != second[0]["run_id"]


class TestReopen:
    def test_reopen_after_resolve_is_audited_and_keeps_history(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "reopen@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            base = f"/organizations/{org}/exposures/{exposure_id}"
            headers = {"X-API-Key": key}
            client.post(f"{base}/resolve", headers=headers, json={"reason": "patched"})

            resp = client.post(f"{base}/reopen", headers=headers, json={"reason": "still exposed"})

            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "reopened"
            assert body["resolved_at"] is None and body["resolution_reason"] is None
            history = client.get(f"{base}/history", headers=headers).json()
            assert [(h["event_type"], h["reason"]) for h in history][1:] == [
                ("resolved", "patched"),
                ("reopened", "still exposed"),
            ]

    def test_reopening_a_non_resolved_exposure_is_409(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "reopen-open@example.com")
            exposure_id = _seed_exposure(client, account_id, org)

            resp = client.post(
                f"/organizations/{org}/exposures/{exposure_id}/reopen",
                headers={"X-API-Key": key},
                json={"reason": "no-op"},
            )

            assert resp.status_code == 409

    def test_replayed_reopen_does_not_add_a_second_event(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "reopen-replay@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            base = f"/organizations/{org}/exposures/{exposure_id}"
            headers = {"X-API-Key": key}
            client.post(f"{base}/resolve", headers=headers, json={"reason": "patched"})

            first = client.post(f"{base}/reopen", headers=headers, json={"reason": "again"})
            second = client.post(f"{base}/reopen", headers=headers, json={"reason": "again"})

            assert (first.status_code, second.status_code) == (200, 409)
            history = client.get(f"{base}/history", headers=headers).json()
            assert [h["event_type"] for h in history].count("reopened") == 1

    def test_a_reopened_exposure_can_be_resolved_again(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "reopen-cycle@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            base = f"/organizations/{org}/exposures/{exposure_id}"
            headers = {"X-API-Key": key}
            client.post(f"{base}/resolve", headers=headers, json={"reason": "patched"})
            client.post(f"{base}/reopen", headers=headers, json={"reason": "not really"})

            resp = client.post(f"{base}/resolve", headers=headers, json={"reason": "patched v2"})

            assert resp.status_code == 200
            assert resp.json()["resolution_reason"] == "patched v2"


class TestLifecycleAuthorizationAndInput:
    def test_viewer_cannot_resolve_or_reopen(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            owner_key, account_id, org = _account(client, "life-owner@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            viewer_key, viewer_id, _ = _account(client, "life-viewer@example.com")
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            base = f"/organizations/{org}/exposures/{exposure_id}"
            viewer = {"X-API-Key": viewer_key}

            resolve = client.post(f"{base}/resolve", headers=viewer, json={"reason": "x"})
            client.post(f"{base}/resolve", headers={"X-API-Key": owner_key}, json={"reason": "y"})
            reopen = client.post(f"{base}/reopen", headers=viewer, json={"reason": "x"})

            assert (resolve.status_code, reopen.status_code) == (403, 403)
            # The viewer's attempts changed nothing: still resolved by the owner.
            state = client.get(base, headers=viewer).json()
            assert (state["status"], state["resolution_reason"]) == ("resolved", "y")

    def test_foreign_account_cannot_reopen(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            _, account_id, org = _account(client, "life-target@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            foreign_key, _, _ = _account(client, "life-foreign@example.com")

            resp = client.post(
                f"/organizations/{org}/exposures/{exposure_id}/reopen",
                headers={"X-API-Key": foreign_key},
                json={"reason": "attempted by an outsider"},
            )

            assert resp.status_code == 404

    def test_blank_reason_is_422_not_500(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "life-blank@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            base = f"/organizations/{org}/exposures/{exposure_id}"
            headers = {"X-API-Key": key}

            resolve = client.post(f"{base}/resolve", headers=headers, json={"reason": "   "})
            client.post(f"{base}/resolve", headers=headers, json={"reason": "ok"})
            reopen = client.post(f"{base}/reopen", headers=headers, json={"reason": "  "})

            assert (resolve.status_code, reopen.status_code) == (422, 422)


class TestEvidencePagingAndCoercion:
    def test_evidence_pages_at_the_sql_level_and_none_stays_unbounded(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            _, account_id, org = _account(client, "ev-sql@example.com")
            exposure_id = _seed_exposure(client, account_id, org, run_id="run-1")
            _seed_exposure(client, account_id, org, run_id="run-2")
            db = client.app.state.control_db

            everything = db.list_exposure_evidence(org, exposure_id)
            page = db.list_exposure_evidence(org, exposure_id, limit=1, offset=1)

            assert len(everything) == 2
            assert [row.run_id for row in page] == [everything[1].run_id]

    def test_non_integer_confidence_is_dropped_not_coerced(self) -> None:
        from api.routers.exposures import _opt_int, _opt_str

        assert _opt_int(80) == 80
        assert _opt_int("80") is None
        assert _opt_int(True) is None
        assert _opt_int(None) is None
        assert _opt_str(None) is None
        assert _opt_str("x") == "x"
