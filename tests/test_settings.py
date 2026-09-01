"""Tests for configuration parsing and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.exceptions import ConfigurationError


class TestSettings:
    def test_default_settings_valid(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root)
        assert settings.validate() == []

    def test_validate_or_raise(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root)
        settings.validate_or_raise()

    def test_invalid_log_level(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, log_level="VERBOSE")
        errors = settings.validate()
        assert any("LOG_LEVEL" in e for e in errors)

    def test_invalid_output_format(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, default_output_format="xml")
        errors = settings.validate()
        assert any("DEFAULT_OUTPUT_FORMAT" in e for e in errors)

    def test_to_safe_dict_excludes_secrets(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            x_hackerone_researcher="secret-user",
            custom_http_headers={"X-HackerOne-Researcher": "secret-user"},
        )
        safe = settings.to_safe_dict()
        assert "secret-user" not in str(safe)
        assert safe["has_researcher_header"] is True

    def test_from_env_parses_booleans(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ENABLE_NAABU", "true")
        settings = Settings.from_env(project_root=project_root)
        assert settings.enable_naabu is True

    def test_from_env_rejects_invalid_bool(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ENABLE_NAABU", "maybe")
        with pytest.raises(ConfigurationError):
            Settings.from_env(project_root=project_root)

    def test_from_env_parses_headers_json(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_CUSTOM_HEADERS", '{"X-Test": "value"}')
        settings = Settings.from_env(project_root=project_root)
        assert settings.custom_http_headers["X-Test"] == "value"

    def test_from_env_parses_researcher_attribution_header(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("RESEARCHER_ATTRIBUTION_HEADER", "X-HackerOne-Research: my_h1_handle")
        settings = Settings.from_env(project_root=project_root)
        assert settings.researcher_attribution_header == {"X-HackerOne-Research": "my_h1_handle"}
        assert settings.merged_headers()["X-HackerOne-Research"] == "my_h1_handle"

    def test_researcher_attribution_header_rejects_missing_colon(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("RESEARCHER_ATTRIBUTION_HEADER", "not-a-header-value")
        with pytest.raises(ConfigurationError):
            Settings.from_env(project_root=project_root)

    def test_researcher_attribution_header_suppressed_under_strict_opsec(
        self, project_root: Path
    ) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
            researcher_attribution_header={"X-HackerOne-Research": "my_h1_handle"},
        )
        assert settings.merged_headers() == {}

    def test_to_safe_dict_flags_researcher_attribution_header_without_leaking_value(
        self, project_root: Path
    ) -> None:
        settings = Settings(
            project_root=project_root,
            researcher_attribution_header={"X-HackerOne-Research": "my_h1_handle"},
        )
        safe = settings.to_safe_dict()
        assert "my_h1_handle" not in str(safe)
        assert safe["has_researcher_attribution_header"] is True

    def test_researcher_header_validation(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("X_HACKERONE_RESEARCHER", "bad user!")
        with pytest.raises(ConfigurationError):
            Settings.from_env(project_root=project_root)

    def test_get_run_output_dir_confined(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root)
        run_dir = settings.get_run_output_dir("test_run")
        assert run_dir.is_relative_to(project_root / "output")

    def test_strict_opsec_fails_closed_without_proxy(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, strict_opsec=True)
        assert any("OUTBOUND_PROXY_URL" in error for error in settings.validate())

    def test_strict_opsec_suppresses_identifying_headers(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
            user_agent="hydra/1.0",
            custom_http_headers={"X-HackerOne-Researcher": "secret-user"},
        )
        assert settings.validate() == []
        assert settings.merged_headers() == {}
        assert "hydra" not in settings.effective_user_agent().lower()
        assert "proxy.example" not in str(settings.to_safe_dict())
