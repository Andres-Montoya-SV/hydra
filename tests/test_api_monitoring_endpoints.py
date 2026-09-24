"""`POST /domains/{domain}/monitoring` / `GET .../monitoring` /
`DELETE .../monitoring` — end-to-end through the real FastAPI app
(`TestClient`), the same "seed the precondition via the real ControlDB
methods, exercise the real endpoint under test" split
`tests/_verified_domain.py` already established for the scan-gate tests.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from _verified_account import create_verified_account  # noqa: E402
from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402

DOMAIN = "monitoring-test.example"


@pytest.fixture
def client(tmp_path: Path):
    settings = APISettings(data_dir=tmp_path / "api_data")
    with TestClient(create_app(settings)) as c:
        yield c


def _auth(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


class TestOptIn:
    def test_opting_into_monitoring_an_unverified_domain_is_403(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))
        assert resp.status_code == 403

    def test_opting_into_speed1_only_on_a_verified_domain_succeeds(
        self, client: TestClient
    ) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")

        resp = client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))

        assert resp.status_code == 201
        body = resp.json()
        assert body["domain"] == DOMAIN
        assert body["speed2_enabled"] is False
        assert body["status"] == "active"

    def test_free_tier_cannot_opt_into_speed2(self, client: TestClient) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        # create_verified_account's account defaults to 'free'.

        resp = client.post(
            f"/domains/{DOMAIN}/monitoring", json={"speed2": True}, headers=_auth(api_key)
        )

        assert resp.status_code == 403
        assert "does not include" in resp.json()["detail"]

    def test_pro_tier_can_opt_into_speed2(self, client: TestClient) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")

        resp = client.post(
            f"/domains/{DOMAIN}/monitoring", json={"speed2": True}, headers=_auth(api_key)
        )

        assert resp.status_code == 201
        assert resp.json()["speed2_enabled"] is True

    def test_reposting_toggles_speed2_without_creating_a_second_row(
        self, client: TestClient
    ) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")

        client.post(f"/domains/{DOMAIN}/monitoring", json={"speed2": True}, headers=_auth(api_key))
        resp = client.post(
            f"/domains/{DOMAIN}/monitoring", json={"speed2": False}, headers=_auth(api_key)
        )

        assert resp.status_code == 201
        assert resp.json()["speed2_enabled"] is False
        rows = client.app.state.control_db.list_monitored_domains_for_account(account_id)
        assert len(rows) == 1


class TestGetAndDelete:
    def test_get_on_a_domain_never_monitored_is_404(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))
        assert resp.status_code == 404

    def test_get_after_opting_in_reflects_the_current_state(self, client: TestClient) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))

        resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))

        assert resp.status_code == 200
        assert resp.json()["domain"] == DOMAIN

    def test_delete_opts_out_and_a_subsequent_get_is_404(self, client: TestClient) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))

        delete_resp = client.delete(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))
        get_resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))

        assert delete_resp.status_code == 204
        assert get_resp.status_code == 404

    def test_delete_on_a_domain_never_monitored_is_404(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.delete(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))
        assert resp.status_code == 404


class TestAcknowledge:
    def _opt_in_and_flag_needs_review(self, client: TestClient) -> tuple[str, str]:
        """Returns (api_key, account_id) for a Pro-tier account with
        `DOMAIN` opted in and directly marked `needs_review` — the
        worker-level mechanism that actually PRODUCES this state
        (`api/monitoring_worker.py`) is already covered end-to-end by
        `tests/test_monitoring_worker.py`; this router test's subject is
        the acknowledge ENDPOINT, so seeding the precondition directly
        via `ControlDB` (the same split every other router test file
        uses for its own precondition) keeps it focused."""
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))
        control_db = client.app.state.control_db
        with sqlite3.connect(control_db.db_path) as conn:
            conn.execute(
                "UPDATE monitored_domains SET status = 'needs_review', needs_review = 1 "
                "WHERE account_id = ? AND domain = ?",
                (account_id, DOMAIN),
            )
        return api_key, account_id

    def test_acknowledge_clears_a_flagged_domain(self, client: TestClient) -> None:
        api_key, _account_id = self._opt_in_and_flag_needs_review(client)

        resp = client.post(f"/domains/{DOMAIN}/monitoring/acknowledge", headers=_auth(api_key))

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "active"
        assert body["needs_review"] is False

    def test_acknowledge_on_a_domain_not_flagged_is_409(self, client: TestClient) -> None:
        api_key, account_id = create_verified_account(client)
        seed_verified_domain(client, account_id, DOMAIN)
        client.app.state.control_db.set_tier(account_id, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key))

        resp = client.post(f"/domains/{DOMAIN}/monitoring/acknowledge", headers=_auth(api_key))

        assert resp.status_code == 409

    def test_acknowledge_on_a_domain_never_monitored_is_404(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.post(f"/domains/{DOMAIN}/monitoring/acknowledge", headers=_auth(api_key))
        assert resp.status_code == 404

    def test_a_different_accounts_key_cannot_acknowledge_someone_elses_domain(
        self, client: TestClient
    ) -> None:
        _api_key_a, _account_a = self._opt_in_and_flag_needs_review(client)
        api_key_b, _account_b = create_verified_account(client)

        resp = client.post(f"/domains/{DOMAIN}/monitoring/acknowledge", headers=_auth(api_key_b))

        assert resp.status_code == 404

    def test_get_after_acknowledge_reflects_the_cleared_state(self, client: TestClient) -> None:
        api_key, _account_id = self._opt_in_and_flag_needs_review(client)
        client.post(f"/domains/{DOMAIN}/monitoring/acknowledge", headers=_auth(api_key))

        resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key))

        assert resp.status_code == 200
        assert resp.json()["status"] == "active"
        assert resp.json()["needs_review"] is False


class TestMultiTenantIsolation:
    def test_account_b_cannot_see_account_as_monitored_domain(self, client: TestClient) -> None:
        api_key_a, account_a = create_verified_account(client)
        seed_verified_domain(client, account_a, DOMAIN)
        client.app.state.control_db.set_tier(account_a, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key_a))

        api_key_b, _account_b = create_verified_account(client)
        resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key_b))

        assert resp.status_code == 404
