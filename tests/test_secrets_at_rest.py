"""Productization Phase 08b: third-party secrets sealed at rest
(api/secrets_box.py)."""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

import pytest
from _verified_account import create_verified_account
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from api.control_db import ControlDB
from api.main import create_app
from api.secrets_box import (
    SEALED_PREFIX,
    SecretBox,
    SecretsUnavailableError,
    box_from_keys,
    reveal,
)
from api.settings import APISettings
from api.webhooks import generate_webhook_secret, sign_payload, verify_signature

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()


class TestSecretBox:
    def test_round_trip_is_sealed_and_opaque(self) -> None:
        box = SecretBox([KEY_A])

        sealed = box.seal("hunter2-token")

        assert sealed.startswith(SEALED_PREFIX) and "hunter2" not in sealed
        assert box.reveal(sealed) == "hunter2-token"
        assert box.seal("hunter2-token") != sealed  # random IV each time

    def test_legacy_plaintext_passes_through(self) -> None:
        assert reveal("plain-old-secret", None) == "plain-old-secret"
        assert SecretBox([KEY_A]).reveal("plain-old-secret") == "plain-old-secret"

    def test_a_sealed_value_fails_closed_without_the_right_key(self) -> None:
        sealed = SecretBox([KEY_A]).seal("x")

        with pytest.raises(SecretsUnavailableError):
            reveal(sealed, None)
        with pytest.raises(SecretsUnavailableError):
            SecretBox([KEY_B]).reveal(sealed)

    def test_rotation_new_key_first_still_reads_old_values(self) -> None:
        old = SecretBox([KEY_A]).seal("rotated")
        rotated = SecretBox([KEY_B, KEY_A])

        assert rotated.reveal(old) == "rotated"
        assert SecretBox([KEY_B]).reveal(rotated.seal("new")) == "new"

    def test_configuration_parsing(self) -> None:
        assert box_from_keys(None) is None and box_from_keys(" , ") is None
        assert box_from_keys(f"{KEY_B}, {KEY_A}") is not None
        with pytest.raises(ValueError, match="Fernet keys"):
            box_from_keys("not-a-fernet-key")


def _account(db: ControlDB) -> str:
    return db.create_account(email=f"sec-{secrets.token_hex(4)}@example.com")


def _raw_secrets(db: ControlDB) -> list[str]:
    with sqlite3.connect(db.db_path) as conn:
        return [row[0] for row in conn.execute("SELECT secret FROM webhooks ORDER BY rowid")]


class TestWebhookSecretsAtRest:
    def test_new_secrets_are_sealed_on_disk_and_plain_in_records(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db", secret_box=SecretBox([KEY_A]))
        secret = generate_webhook_secret()

        created = db.create_webhook(
            account_id=_account(db),
            url="https://example.com/h",
            secret=secret,
            event_types=("monitoring.changed",),
        )

        stored = _raw_secrets(db)[0]
        assert stored.startswith(SEALED_PREFIX) and secret not in stored
        assert db.get_webhook(created.webhook_id, created.account_id).secret == secret

    def test_legacy_plaintext_is_sealed_once_at_startup(self, tmp_path: Path) -> None:
        path = tmp_path / "control.db"
        legacy = ControlDB(path)  # no key: stored in plaintext, as before
        account_id = _account(legacy)
        secret = generate_webhook_secret()
        hook = legacy.create_webhook(
            account_id=account_id,
            url="https://example.com/h",
            secret=secret,
            event_types=("monitoring.changed",),
        )

        keyed = ControlDB(path, secret_box=SecretBox([KEY_A]))
        first, second = keyed.seal_plaintext_secrets(), keyed.seal_plaintext_secrets()

        assert (first, second) == (1, 0)
        assert _raw_secrets(keyed)[0].startswith(SEALED_PREFIX)
        body = b'{"event": "monitoring.changed"}'
        signing_secret = keyed.get_webhook(hook.webhook_id, account_id).secret
        assert verify_signature(secret, body, sign_payload(signing_secret, body))

    def test_without_a_key_nothing_changes(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "control.db")
        secret = generate_webhook_secret()
        db.create_webhook(
            account_id=_account(db),
            url="https://example.com/h",
            secret=secret,
            event_types=("monitoring.changed",),
        )

        assert db.seal_plaintext_secrets() == 0
        assert _raw_secrets(db) == [secret]


class TestAppStartup:
    def test_a_bad_key_fails_startup(self, tmp_path: Path) -> None:
        app = create_app(APISettings(data_dir=tmp_path / "api", secrets_keys="garbage"))
        with pytest.raises(ValueError, match="Fernet keys"), TestClient(app):
            pass

    def test_registration_returns_the_secret_once_and_stores_it_sealed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def public(url: str):
            return True, "", "93.184.215.14"

        monkeypatch.setattr("api.routers.webhooks.validate_webhook_destination", public)
        settings = APISettings(
            data_dir=tmp_path / "api", secrets_keys=KEY_A, max_concurrent_scans=0
        )
        with TestClient(create_app(settings)) as client:
            key, _ = create_verified_account(client)
            created = client.post(
                "/webhooks",
                headers={"X-API-Key": key},
                json={"url": "https://hooks.example.com/x", "event_types": ["monitoring.changed"]},
            ).json()
            listed = client.get("/webhooks", headers={"X-API-Key": key}).json()

            stored = _raw_secrets(client.app.state.control_db)[0]
            assert len(created["secret"]) == 64
            assert created["secret"] not in stored and stored.startswith(SEALED_PREFIX)
            assert "secret" not in listed[0]
