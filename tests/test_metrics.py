"""Productization Phase 11d: GET /metrics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from api import operators
from api.control_db import ControlDB
from api.main import create_app
from api.settings import APISettings


@pytest.fixture
def client(tmp_path: Path) -> Any:
    settings = APISettings(data_dir=tmp_path / "api", max_concurrent_scans=0)
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _operator(client: TestClient) -> dict[str, str]:
    key, account_id = create_verified_account(client)
    operators.set_operator(client.app.state.control_db, account_id, True)
    return {"X-API-Key": key}


def _samples(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    return {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(text)
        for sample in family.samples
    }


class TestAccess:
    def test_operators_only(self, client: TestClient) -> None:
        assert client.get("/metrics").status_code == 401
        key, _ = create_verified_account(client)
        assert client.get("/metrics", headers={"X-API-Key": key}).status_code == 404
        response = client.get("/metrics", headers=_operator(client))
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")


class TestContent:
    def test_requests_are_counted_by_route_template_never_by_raw_path(
        self, client: TestClient
    ) -> None:
        headers = _operator(client)
        client.get("/health")
        client.get("/organizations/org-123/assets", headers=headers)  # 404 for a non-member
        client.get("/definitely/not/a/route/abc123")

        samples = _samples(client.get("/metrics", headers=headers).text)

        def requests(route: str, status: str) -> float:
            key = (
                "hydra_http_requests_total",
                (("method", "GET"), ("route", route), ("status", status)),
            )
            return samples.get(key, 0.0)

        assert requests("/health", "200") >= 1
        assert requests("/organizations/{organization_id}/assets", "404") == 1
        assert requests("unmatched", "404") == 1
        assert not any("org-123" in str(labels) or "abc123" in str(labels) for _, labels in samples)

    def test_state_gauges(self, client: TestClient) -> None:
        db: ControlDB = client.app.state.control_db
        headers = _operator(client)
        key, account_id = create_verified_account(client)
        org = db.default_organization_id_for_account(account_id)
        db.create_scan(
            scan_id="s1",
            account_id=account_id,
            domain="example.com",
            db_path="x",
            organization_id=org,
        )
        client.delete("/account", headers={"X-API-Key": key})

        samples = _samples(client.get("/metrics", headers=headers).text)

        assert samples[("hydra_control_db_up", ())] == 1.0
        assert samples[("hydra_scans", (("status", "queued"),))] == 1.0
        assert samples[("hydra_pending_tenant_deletions", (("kind", "account"),))] == 1.0
        loops = {
            dict(labels).get("loop")
            for name, labels in samples
            if name == "hydra_loop_seconds_since_alive"
        }
        assert "scan_worker" in loops

    def test_an_unreachable_database_is_reported_not_raised(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        headers = _operator(client)

        def down(self: ControlDB) -> dict[str, int]:
            raise OSError("database unreachable")

        monkeypatch.setattr(ControlDB, "scan_status_counts", down)
        response = client.get("/metrics", headers=headers)
        assert response.status_code == 200
        assert _samples(response.text)[("hydra_control_db_up", ())] == 0.0
