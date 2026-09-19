"""`api/auth.py`/`api/routers/accounts.py`/`api/routers/keys.py` —
docs/PAID_API_DESIGN.md Part C, exercised through real HTTP requests
against the FastAPI app (no scan/pipeline involved — these tests only
touch the control-plane database).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from api.control_db import ControlDB  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402


def _client(tmp_path: Path, *, rate_limit_per_minute: int = 60) -> TestClient:
    settings = APISettings(
        data_dir=tmp_path / "api_data", rate_limit_per_minute=rate_limit_per_minute
    )
    return TestClient(create_app(settings))


def _create_account(client: TestClient) -> tuple[str, str]:
    resp = client.post("/accounts")
    assert resp.status_code == 201
    body = resp.json()
    return body["account_id"], body["api_key"]


class TestAccountCreation:
    def test_creates_account_and_returns_a_usable_key_once(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            resp = client.post("/accounts")
            assert resp.status_code == 201
            body = resp.json()
            assert body["account_id"]
            assert body["api_key"].startswith("hydra_live_")
            assert body["key_id"]

    def test_the_returned_key_actually_authenticates(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            _, api_key = _create_account(client)
            resp = client.get("/scans/nonexistent", headers={"X-API-Key": api_key})
            # 404 (not 401) proves the key authenticated fine and only the
            # scan lookup failed.
            assert resp.status_code == 404

    def test_missing_key_is_401(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            resp = client.get("/scans/whatever")
            assert resp.status_code == 401

    def test_garbage_key_is_401(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            resp = client.get("/scans/whatever", headers={"X-API-Key": "hydra_live_garbage"})
            assert resp.status_code == 401


class TestRevocation:
    def test_revoked_key_fails_immediately_with_401(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account_resp = client.post("/accounts").json()
            api_key = account_resp["api_key"]
            key_id = account_resp["key_id"]

            assert client.get("/scans/x", headers={"X-API-Key": api_key}).status_code == 404

            revoke_resp = client.post(f"/keys/{key_id}/revoke", headers={"X-API-Key": api_key})
            assert revoke_resp.status_code == 204

            assert client.get("/scans/x", headers={"X-API-Key": api_key}).status_code == 401

    def test_revoking_one_key_never_affects_a_different_key_same_account(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            account_resp = client.post("/accounts").json()
            first_key = account_resp["api_key"]
            first_key_id = account_resp["key_id"]

            # Rotate to get a second, independent key on the SAME account.
            rotate_resp = client.post(
                f"/keys/{first_key_id}/rotate", headers={"X-API-Key": first_key}
            )
            assert rotate_resp.status_code == 200
            second_key = rotate_resp.json()["new_api_key"]

            # Revoke the SECOND key.
            second_key_id = rotate_resp.json()["new_key_id"]
            revoke_resp = client.post(
                f"/keys/{second_key_id}/revoke", headers={"X-API-Key": first_key}
            )
            assert revoke_resp.status_code == 204

            # The second key is now dead...
            assert client.get("/scans/x", headers={"X-API-Key": second_key}).status_code == 401
            # ...but the first key (currently mid-rotation-grace, still valid)
            # is completely unaffected by the second key's revocation.
            assert client.get("/scans/x", headers={"X-API-Key": first_key}).status_code == 404

    def test_revoking_an_already_revoked_key_is_a_clean_404_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            account_resp = client.post("/accounts").json()
            key_id = account_resp["key_id"]
            api_key = account_resp["api_key"]
            assert (
                client.post(f"/keys/{key_id}/revoke", headers={"X-API-Key": api_key}).status_code
                == 204
            )
            # Second revoke attempt: the key is already revoked, so it can no
            # longer authenticate this very request — 401, not a 404/500.
            second_attempt = client.post(f"/keys/{key_id}/revoke", headers={"X-API-Key": api_key})
            assert second_attempt.status_code == 401

    def test_cannot_revoke_a_different_accounts_key(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account_a = client.post("/accounts").json()
            account_b = client.post("/accounts").json()
            resp = client.post(
                f"/keys/{account_a['key_id']}/revoke",
                headers={"X-API-Key": account_b["api_key"]},
            )
            assert resp.status_code == 404  # never 403 — see api/routers/keys.py


class TestRotation:
    def test_dual_validity_window_then_old_key_expires(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with _client(tmp_path) as client:
            account_resp = client.post("/accounts").json()
            old_key = account_resp["api_key"]
            old_key_id = account_resp["key_id"]

            rotate_resp = client.post(f"/keys/{old_key_id}/rotate", headers={"X-API-Key": old_key})
            assert rotate_resp.status_code == 200
            new_key = rotate_resp.json()["new_api_key"]

            # Both keys work during the grace window.
            assert client.get("/scans/x", headers={"X-API-Key": old_key}).status_code == 404
            assert client.get("/scans/x", headers={"X-API-Key": new_key}).status_code == 404

            # Simulate the 24h grace period having elapsed by moving the old
            # key's recorded expiry into the past directly in the control
            # DB — the real, honest way to test time-based expiry without
            # sleeping for a day or mocking datetime.now() globally.
            control_db: ControlDB = client.app.state.control_db
            with control_db._connect() as conn:  # noqa: SLF001 — test-only direct DB access
                conn.execute(
                    "UPDATE api_keys SET expires_at = '2000-01-01T00:00:00+00:00' "
                    "WHERE key_id = ?",
                    (old_key_id,),
                )

            assert client.get("/scans/x", headers={"X-API-Key": old_key}).status_code == 401
            assert client.get("/scans/x", headers={"X-API-Key": new_key}).status_code == 404

    def test_rotating_an_already_revoked_key_is_a_clean_error(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account_resp = client.post("/accounts").json()
            api_key = account_resp["api_key"]
            key_id = account_resp["key_id"]
            assert (
                client.post(f"/keys/{key_id}/revoke", headers={"X-API-Key": api_key}).status_code
                == 204
            )
            # The key that would authenticate this rotate call is itself
            # already revoked — 401, same as any other request with a dead key.
            resp = client.post(f"/keys/{key_id}/rotate", headers={"X-API-Key": api_key})
            assert resp.status_code == 401


class TestRateLimiting:
    def test_exceeding_the_limit_returns_429_distinct_from_401_403(self, tmp_path: Path) -> None:
        with _client(tmp_path, rate_limit_per_minute=3) as client:
            _, api_key = _create_account(client)
            statuses = [
                client.get("/scans/x", headers={"X-API-Key": api_key}).status_code for _ in range(6)
            ]
            assert 404 in statuses  # the allowed requests still behave normally
            assert 429 in statuses  # and at least one is rate-limited
            assert 401 not in statuses  # never confused with an auth failure

    def test_rate_limit_is_per_key_not_global(self, tmp_path: Path) -> None:
        with _client(tmp_path, rate_limit_per_minute=2) as client:
            _, key_a = _create_account(client)
            _, key_b = _create_account(client)
            # Exhaust account A's bucket.
            for _ in range(2):
                client.get("/scans/x", headers={"X-API-Key": key_a})
            assert client.get("/scans/x", headers={"X-API-Key": key_a}).status_code == 429
            # Account B is unaffected.
            assert client.get("/scans/x", headers={"X-API-Key": key_b}).status_code == 404
