"""`POST /webhooks` / `GET /webhooks` / `DELETE /webhooks/{id}` — end to
end through the real FastAPI app (`TestClient`), the same pattern every
other account-scoped router's own test file already uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from _verified_account import create_verified_account  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402
from api.webhooks import MAX_WEBHOOKS_PER_ACCOUNT  # noqa: E402


@pytest.fixture
def client(tmp_path: Path):
    settings = APISettings(data_dir=tmp_path / "api_data")
    with TestClient(create_app(settings)) as c:
        yield c


def _auth(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


class TestRegistration:
    def test_registering_a_valid_https_webhook_succeeds(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)

        resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )

        assert resp.status_code == 201
        body = resp.json()
        assert body["url"] == "https://example.com/hook"
        assert body["status"] == "active"
        assert body["consecutive_failures"] == 0
        assert len(body["secret"]) > 20  # a real, non-trivial generated secret

    def test_the_secret_is_never_returned_again_by_get(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        create_resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )
        webhook_id = create_resp.json()["webhook_id"]

        list_resp = client.get("/webhooks", headers=_auth(api_key))

        assert list_resp.status_code == 200
        listed = next(w for w in list_resp.json() if w["webhook_id"] == webhook_id)
        assert "secret" not in listed

    def test_http_scheme_is_rejected(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.post(
            "/webhooks",
            json={"url": "http://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/hook",
            "https://localhost/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.5/hook",
        ],
    )
    def test_private_loopback_and_metadata_urls_are_rejected_at_registration(
        self, client: TestClient, url: str
    ) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.post(
            "/webhooks",
            json={"url": url, "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )
        assert resp.status_code == 422

    def test_an_unknown_event_type_is_rejected(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["something.made_up"]},
            headers=_auth(api_key),
        )
        assert resp.status_code == 422

    def test_the_per_account_cap_is_enforced(self, client: TestClient) -> None:
        # A real, resolvable hostname — registration performs a genuine
        # DNS/SSRF check, so a made-up per-iteration subdomain
        # (`example{i}.com`) would fail on DNS resolution alone, not the
        # cap this test actually targets. Nothing stops an account from
        # registering the same URL more than once; only the count matters.
        api_key, _ = create_verified_account(client)
        for i in range(MAX_WEBHOOKS_PER_ACCOUNT):
            resp = client.post(
                "/webhooks",
                json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
                headers=_auth(api_key),
            )
            assert resp.status_code == 201, f"registration {i} unexpectedly failed"

        over_cap = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )
        assert over_cap.status_code == 403


class TestListAndDelete:
    def test_delete_removes_the_webhook(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        create_resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key),
        )
        webhook_id = create_resp.json()["webhook_id"]

        delete_resp = client.delete(f"/webhooks/{webhook_id}", headers=_auth(api_key))
        list_resp = client.get("/webhooks", headers=_auth(api_key))

        assert delete_resp.status_code == 204
        assert list_resp.json() == []

    def test_delete_on_an_unknown_id_is_404(self, client: TestClient) -> None:
        api_key, _ = create_verified_account(client)
        resp = client.delete("/webhooks/does-not-exist", headers=_auth(api_key))
        assert resp.status_code == 404


class TestMultiTenantIsolation:
    def test_account_b_cannot_see_account_as_webhooks(self, client: TestClient) -> None:
        api_key_a, _ = create_verified_account(client)
        client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key_a),
        )

        api_key_b, _ = create_verified_account(client)
        resp = client.get("/webhooks", headers=_auth(api_key_b))

        assert resp.status_code == 200
        assert resp.json() == []

    def test_account_b_cannot_delete_account_as_webhook(self, client: TestClient) -> None:
        api_key_a, _ = create_verified_account(client)
        create_resp = client.post(
            "/webhooks",
            json={"url": "https://example.com/hook", "event_types": ["monitoring.changed"]},
            headers=_auth(api_key_a),
        )
        webhook_id = create_resp.json()["webhook_id"]

        api_key_b, _ = create_verified_account(client)
        delete_resp = client.delete(f"/webhooks/{webhook_id}", headers=_auth(api_key_b))

        assert delete_resp.status_code == 404
        # Still there for the real owner — the delete truly never
        # touched account A's row.
        still_there = client.get("/webhooks", headers=_auth(api_key_a))
        assert len(still_there.json()) == 1
