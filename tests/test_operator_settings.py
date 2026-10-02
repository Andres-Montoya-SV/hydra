"""Productization Phase 11f: the operator pipeline settings API scans use."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

import api.operator_settings as operator_module
from api.collection_capabilities import enabled_in_settings
from api.control_db import ControlDB
from api.operator_settings import ACCOUNT_ONLY, INHERITED, TOGGLES
from api.scan_orchestrator import _scan_settings
from api.settings import APISettings, load_api_settings
from config.settings import Settings
from core.exceptions import ConfigurationError


@pytest.fixture
def clean_operator_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """No .env and no toggle variables: only what a test sets."""
    empty = tmp_path / "operator.env"
    empty.write_text("")
    monkeypatch.setattr(operator_module, "_ENV_FILE", empty)
    for toggle in TOGGLES:
        monkeypatch.delenv(toggle.upper(), raising=False)
    return monkeypatch


def _scan(tmp_path: Path) -> tuple[APISettings, ControlDB, str, str]:
    api_settings = APISettings(data_dir=tmp_path / "api")
    db = ControlDB(api_settings.control_db_path)
    account = db.create_account(email="ops@example.com")
    db.create_default_subscription(account)
    org = db.default_organization_id_for_account(account)
    db.create_scan(
        scan_id="scan-1",
        account_id=account,
        domain="example.com",
        db_path=str(api_settings.data_dir),
        organization_id=org,
    )
    return api_settings, db, account, "scan-1"


def _settings_for(tmp_path: Path) -> Settings:
    api_settings, db, account, scan = _scan(tmp_path)
    return _scan_settings(api_settings, db, account_id=account, scan_id=scan, passive=False)


class TestClassification:
    def test_every_settings_field_is_classified_exactly_once(self) -> None:
        fields = {f.name for f in dataclasses.fields(Settings)}
        assert INHERITED | ACCOUNT_ONLY | TOGGLES == fields
        assert not (INHERITED & ACCOUNT_ONLY or INHERITED & TOGGLES or ACCOUNT_ONLY & TOGGLES)

    def test_credentials_scope_and_identity_are_never_inherited(self) -> None:
        for name in (
            "securitytrails_api_key",
            "github_token",
            "urlhaus_api_key",
            "wpscan_api_token",
            "anthropic_api_key",
            "scope_file",
            "owned_domains",
            "x_hackerone_researcher",
            "custom_http_headers",
            "output_directory",
        ):
            assert name in ACCOUNT_ONLY, name


class TestInheritance:
    def test_operator_infrastructure_and_safety_reach_api_scans(
        self, tmp_path: Path, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        clean_operator_env.setenv("RATE_LIMIT", "7")
        clean_operator_env.setenv("TIMEOUT", "41")
        clean_operator_env.setenv("OUTBOUND_PROXY_URL", "http://egress.internal:3128")
        tool = tmp_path / "tools" / "subfinder"
        tool.parent.mkdir()
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        clean_operator_env.setenv("SUBFINDER_PATH", str(tool))

        settings = _settings_for(tmp_path)

        assert settings.rate_limit == 7 and settings.timeout == 41
        assert settings.outbound_proxy_url == "http://egress.internal:3128"
        assert settings.subfinder_path == tool

    def test_scope_identity_and_credentials_never_do(
        self, tmp_path: Path, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        clean_operator_env.setenv("X_HACKERONE_RESEARCHER", "operator-handle")
        clean_operator_env.setenv("SECURITYTRAILS_API_KEY", "st-operator-key")
        clean_operator_env.setenv("GITHUB_TOKEN", "ghp_operator")
        clean_operator_env.setenv("OWNED_DOMAINS", "operator.example")
        clean_operator_env.setenv("OUTPUT_DIRECTORY", "/srv/operator-output")

        settings = _settings_for(tmp_path)
        defaults = Settings()

        assert settings.x_hackerone_researcher == defaults.x_hackerone_researcher
        assert settings.securitytrails_api_key is None and settings.github_token is None
        assert settings.owned_domains == defaults.owned_domains
        assert str(settings.output_directory) == str(defaults.output_directory)
        assert tmp_path in settings.project_root.parents  # still the account's own root


class TestToggles:
    def test_the_operator_can_switch_a_tool_off_but_never_on(
        self, tmp_path: Path, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        baseline = enabled_in_settings(_settings_for(tmp_path / "baseline"))
        assert baseline, "the scan's profile and tier select some providers"
        off = sorted(baseline)[0]
        never = sorted(p for p in ("naabu", "ffuf", "param_fuzz") if p not in baseline)[0]
        clean_operator_env.setenv(f"ENABLE_{off.upper()}", "false")
        clean_operator_env.setenv(f"ENABLE_{never.upper()}", "true")

        enabled = enabled_in_settings(_settings_for(tmp_path / "operator"))

        assert enabled == baseline - {off}

    def test_the_recorded_effective_providers_reflect_the_switch(
        self, tmp_path: Path, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        api_settings, db, account, scan = _scan(tmp_path)
        provider = sorted(
            enabled_in_settings(
                _scan_settings(api_settings, db, account_id=account, scan_id=scan, passive=False)
            )
        )[0]
        clean_operator_env.setenv(f"ENABLE_{provider.upper()}", "0")
        _scan_settings(api_settings, db, account_id=account, scan_id=scan, passive=False)
        record = db.get_owned_scan(scan, account)
        assert record is not None and provider not in (record.effective_providers or ())

    def test_interactsh_can_only_be_switched_off(
        self, tmp_path: Path, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        # Off for API scans by default; the operator's "true" doesn't change that.
        clean_operator_env.setenv("NUCLEI_ENABLE_INTERACTSH", "true")
        assert (
            _settings_for(tmp_path).nuclei_enable_interactsh is Settings().nuclei_enable_interactsh
        )
        # And where it is on, the operator's "false" switches it off.
        clean_operator_env.setenv("NUCLEI_ENABLE_INTERACTSH", "false")
        settings = Settings()
        settings.nuclei_enable_interactsh = True
        assert "nuclei_enable_interactsh" in operator_module.apply_operator_disables(settings)
        assert settings.nuclei_enable_interactsh is False


class TestStartup:
    def test_a_malformed_operator_value_stops_startup(
        self, clean_operator_env: pytest.MonkeyPatch
    ) -> None:
        clean_operator_env.setenv("ENABLE_NUCLEI", "perhaps")
        with pytest.raises(ConfigurationError):
            load_api_settings()
