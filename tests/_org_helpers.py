"""Shared fixtures-as-functions for organization-scoped API tests."""

from __future__ import annotations

from pathlib import Path

from _verified_account import create_verified_account
from fastapi.testclient import TestClient

from api.main import create_app
from api.settings import APISettings


def api_client(tmp_path: Path) -> TestClient:
    """`max_concurrent_scans=0`: queued scans are never executed, so nothing
    touches the network."""
    return TestClient(create_app(APISettings(data_dir=tmp_path / "api", max_concurrent_scans=0)))


def verified_owner(client: TestClient) -> tuple[dict[str, str], str, str]:
    """(auth headers, account id, default organization id) of a new account
    with a verified email."""
    api_key, account_id = create_verified_account(client)
    org = client.app.state.control_db.list_organizations_for_account(account_id)[0][0]
    return {"X-API-Key": api_key}, account_id, org


class RecordingSender:
    """An email sender that records monitoring alerts instead of sending."""

    def __init__(self) -> None:
        self.alerts: list[list[str]] = []

    def send_monitoring_alert(
        self, *, to, account_id, summary_lines, truncated_count
    ):  # noqa: ANN001, ANN201
        self.alerts.append(summary_lines)
