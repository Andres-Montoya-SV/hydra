"""`api/main.py::create_app`'s email-provider selection
(`ConsoleEmailSender` vs. `PostmarkEmailSender`) and
`api/settings.py::validate_email_provider_config`'s startup-time
fail-loudly check — via `APISettings` overrides, never real environment
mutation that could leak across tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from api.email_sender import ConsoleEmailSender, PostmarkEmailSender  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import APISettings, EmailProviderMisconfiguredError  # noqa: E402


class TestZeroConfigDefault:
    def test_no_postmark_env_vars_selects_console_email_sender(self, tmp_path: Path) -> None:
        """This is THE regression to guard against: the existing suite,
        and every real local-dev/test setup with no Postmark
        configuration, must keep getting exactly this — unchanged from
        before Postmark support existed."""
        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            assert isinstance(client.app.state.email_sender, ConsoleEmailSender)

    def test_zero_config_account_creation_still_works_end_to_end(self, tmp_path: Path) -> None:
        settings = APISettings(data_dir=tmp_path / "api_data")
        with TestClient(create_app(settings)) as client:
            resp = client.post("/accounts", json={"email": "zero-config@example.com"})
            assert resp.status_code == 201


class TestPostmarkSelectedWhenFullyConfigured:
    def test_both_vars_set_selects_postmark_email_sender(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            postmark_server_token="postmark-server-token-placeholder",  # noqa: S106
            email_from_address="noreply@example.com",
        )
        with TestClient(create_app(settings)) as client:
            assert isinstance(client.app.state.email_sender, PostmarkEmailSender)

    def test_default_from_name_is_hydra(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            postmark_server_token="postmark-server-token-placeholder",  # noqa: S106
            email_from_address="noreply@example.com",
        )
        assert settings.email_from_name == "Hydra"


class TestPartialConfigurationFailsLoudlyAtStartup:
    def test_token_without_from_address_raises_naming_the_missing_var(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            postmark_server_token="postmark-server-token-placeholder",  # noqa: S106
        )
        with pytest.raises(EmailProviderMisconfiguredError, match="HYDRA_API_EMAIL_FROM"):
            create_app(settings)

    def test_from_address_without_token_raises_naming_the_missing_var(self, tmp_path: Path) -> None:
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            email_from_address="noreply@example.com",
        )
        with pytest.raises(EmailProviderMisconfiguredError, match="POSTMARK_SERVER_TOKEN"):
            create_app(settings)

    def test_the_app_never_boots_at_all_on_partial_config(self, tmp_path: Path) -> None:
        """Not a half-configured app that fails on the first request —
        create_app() itself must never return."""
        settings = APISettings(
            data_dir=tmp_path / "api_data",
            postmark_server_token="postmark-server-token-placeholder",  # noqa: S106
        )
        with pytest.raises(EmailProviderMisconfiguredError):
            create_app(settings)
        # No control.db should even have been created — the failure
        # happens before ControlDB is ever constructed.
        assert not (tmp_path / "api_data" / "control.db").exists()
