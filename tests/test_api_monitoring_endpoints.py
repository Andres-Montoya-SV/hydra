"""`POST /domains/{domain}/monitoring` / `GET .../monitoring` /
`DELETE .../monitoring` — end-to-end through the real FastAPI app
(`TestClient`), the same "seed the precondition via the real ControlDB
methods, exercise the real endpoint under test" split
`tests/_verified_domain.py` already established for the scan-gate tests.
"""

from __future__ import annotations

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


class TestMultiTenantIsolation:
    def test_account_b_cannot_see_account_as_monitored_domain(self, client: TestClient) -> None:
        api_key_a, account_a = create_verified_account(client)
        seed_verified_domain(client, account_a, DOMAIN)
        client.app.state.control_db.set_tier(account_a, "pro")
        client.post(f"/domains/{DOMAIN}/monitoring", json={}, headers=_auth(api_key_a))

        api_key_b, _account_b = create_verified_account(client)
        resp = client.get(f"/domains/{DOMAIN}/monitoring", headers=_auth(api_key_b))

        assert resp.status_code == 404
