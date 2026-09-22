"""Hallazgo 1 (frontend-team review): `POST /accounts` per-IP rate
limiting and email verification gating `POST /scans` — end-to-end
through the real FastAPI app. The five required test scenarios all live
here: rate limiting under/over the ceiling, an unverified account's
scan attempt rejected with a clear message, a verified account working
exactly as before, and (folded in as directly-related coverage) the
duplicate-email/expired-token/resend paths this fix's own design
depends on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from _verified_account import unique_email  # noqa: E402
from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402

DOMAIN = "account-verification-test.example"


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    settings = APISettings(data_dir=tmp_path / "api_data", **overrides)
    return TestClient(create_app(settings))


class TestAccountCreationRateLimiting:
    """Task 5, test 1."""

    def test_below_the_limit_creates_accounts_normally(self, tmp_path: Path) -> None:
        with _client(tmp_path, account_creation_rate_limit_per_ip_per_day=3) as client:
            for _ in range(3):
                resp = client.post("/accounts", json={"email": unique_email()})
                assert resp.status_code == 201

    def test_above_the_limit_is_rejected_with_a_clear_message(self, tmp_path: Path) -> None:
        with _client(tmp_path, account_creation_rate_limit_per_ip_per_day=3) as client:
            for _ in range(3):
                assert client.post("/accounts", json={"email": unique_email()}).status_code == 201

            resp = client.post("/accounts", json={"email": unique_email()})
            assert resp.status_code == 429
            assert "too many accounts" in resp.json()["detail"].lower()

    def test_a_failed_duplicate_email_attempt_still_counts_against_the_limit(
        self, tmp_path: Path
    ) -> None:
        """Otherwise probing for already-registered emails would never
        count against the rate limit — closing that loophole."""
        with _client(tmp_path, account_creation_rate_limit_per_ip_per_day=2) as client:
            email = unique_email()
            assert client.post("/accounts", json={"email": email}).status_code == 201
            duplicate = client.post("/accounts", json={"email": email})
            assert duplicate.status_code == 409

            # The limit (2) is now exhausted: 1 success + 1 failed
            # duplicate attempt, both recorded.
            resp = client.post("/accounts", json={"email": unique_email()})
            assert resp.status_code == 429

    def test_duplicate_email_is_rejected_independent_of_rate_limiting(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            email = unique_email()
            assert client.post("/accounts", json={"email": email}).status_code == 201
            resp = client.post("/accounts", json={"email": email})
            assert resp.status_code == 409


class TestEmailVerificationGatesScanning:
    """Task 5, tests 2 and 3."""

    def test_unverified_account_cannot_scan(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            account_id = account["account_id"]
            seed_verified_domain(client, account_id, DOMAIN)

            resp = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
            assert resp.status_code == 403
            assert "email" in resp.json()["detail"].lower()
            assert "verif" in resp.json()["detail"].lower()

    def test_verified_account_scans_exactly_as_before_no_regression(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            account_id = account["account_id"]

            token = client.app.state.control_db.get_account(account_id).email_verification_token
            verify = client.post("/accounts/verify-email", json={"token": token})
            assert verify.status_code == 200
            assert verify.json()["status"] == "verified"

            seed_verified_domain(client, account_id, DOMAIN)
            resp = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": api_key})
            assert resp.status_code == 202

    def test_verify_email_twice_the_second_time_the_token_is_already_consumed(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            account_id = account["account_id"]
            token = client.app.state.control_db.get_account(account_id).email_verification_token

            assert client.post("/accounts/verify-email", json={"token": token}).status_code == 200
            second = client.post("/accounts/verify-email", json={"token": token})
            assert second.status_code == 404

    def test_an_invalid_token_is_rejected(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            resp = client.post("/accounts/verify-email", json={"token": "not-a-real-token"})
            assert resp.status_code == 404

    def test_an_expired_token_is_rejected_with_a_distinct_message(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            account_id = account["account_id"]
            with client.app.state.control_db._connect() as conn:  # noqa: SLF001 - test-only
                conn.execute(
                    "UPDATE accounts SET email_verification_token_expires_at = "
                    "'2000-01-01T00:00:00+00:00' WHERE account_id = ?",
                    (account_id,),
                )
            token = client.app.state.control_db.get_account(account_id).email_verification_token
            resp = client.post("/accounts/verify-email", json={"token": token})
            assert resp.status_code == 400
            assert "expired" in resp.json()["detail"].lower()

    def test_resend_verification_issues_a_new_working_token(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            account_id = account["account_id"]
            old_token = client.app.state.control_db.get_account(account_id).email_verification_token

            resend = client.post("/accounts/resend-verification", headers={"X-API-Key": api_key})
            assert resend.status_code == 200

            new_token = client.app.state.control_db.get_account(account_id).email_verification_token
            assert new_token != old_token

            # The OLD token no longer works...
            assert (
                client.post("/accounts/verify-email", json={"token": old_token}).status_code == 404
            )
            # ...but the NEW one does.
            verify = client.post("/accounts/verify-email", json={"token": new_token})
            assert verify.status_code == 200

    def test_resend_verification_on_an_already_verified_account_is_rejected(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            account = client.post("/accounts", json={"email": unique_email()}).json()
            api_key = account["api_key"]
            client.app.state.control_db.mark_email_verified(account["account_id"])

            resp = client.post("/accounts/resend-verification", headers={"X-API-Key": api_key})
            assert resp.status_code == 400

    def test_a_pre_fix_account_with_no_email_on_file_is_treated_as_already_verified(
        self, tmp_path: Path
    ) -> None:
        """Backward compatibility: an account created before this fix
        shipped (no email column populated at all) must not be
        retroactively locked out of scanning — only an account that
        genuinely HAS an email on file and hasn't confirmed it is
        gated."""
        with _client(tmp_path) as client:
            legacy_account_id = client.app.state.control_db.create_account()
            client.app.state.control_db.create_default_subscription(legacy_account_id, tier="free")
            from api.security import generate_raw_key, hash_for_storage, lookup_hash_for

            raw_key, prefix = generate_raw_key()
            client.app.state.control_db.insert_api_key(
                key_id="legacy-key",
                account_id=legacy_account_id,
                lookup_hash=lookup_hash_for(raw_key),
                verify_hash=hash_for_storage(raw_key),
                prefix=prefix,
            )
            seed_verified_domain(client, legacy_account_id, DOMAIN)

            resp = client.post("/scans", json={"domain": DOMAIN}, headers={"X-API-Key": raw_key})
            assert resp.status_code == 202
