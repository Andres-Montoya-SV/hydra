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

    def test_webhook_url_accepts_well_formed_value(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WEBHOOK_URL", "https://hooks.slack.com/services/ABC")
        settings = Settings.from_env(project_root=project_root)
        assert settings.webhook_url == "https://hooks.slack.com/services/ABC"

    def test_webhook_url_rejects_trailing_text_after_a_space(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Catalog item 8 (docs/VERIFICATION_AGENT_DESIGN.md): an unquoted
        WEBHOOK_URL with trailing text pasted after a stray space used to
        be silently accepted (a bare .strip()) — now fails closed at load
        time instead of failing silently, later, when the webhook fires."""
        monkeypatch.setenv("WEBHOOK_URL", "https://hooks.slack.com/services/ABC typo")
        with pytest.raises(ConfigurationError, match="WEBHOOK_URL"):
            Settings.from_env(project_root=project_root)

    def test_webhook_url_unset_is_none(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WEBHOOK_URL", raising=False)
        settings = Settings.from_env(project_root=project_root)
        assert settings.webhook_url is None

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

    def test_attribution_user_agent_appended_to_effective_user_agent(
        self, project_root: Path
    ) -> None:
        settings = Settings(
            project_root=project_root,
            user_agent="hydra/1.0",
            attribution_user_agent="bugcrowd; cosmiccashew",
        )
        ua = settings.effective_user_agent()
        assert ua.startswith("hydra/1.0")
        assert "bugcrowd; cosmiccashew" in ua

    def test_attribution_user_agent_absent_by_default(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, user_agent="hydra/1.0")
        assert settings.effective_user_agent() == "hydra/1.0"
        assert settings.attribution_user_agent_suffix() == ""

    def test_attribution_user_agent_suppressed_under_strict_opsec(self, project_root: Path) -> None:
        """Same suppression precedent as researcher_attribution_header:
        strict OPSEC means non-attributable probing, the opposite intent of
        program-mandated self-identification — the two must not combine."""
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
            attribution_user_agent="bugcrowd; cosmiccashew",
        )
        assert settings.attribution_user_agent_suffix() == ""
        assert "bugcrowd" not in settings.effective_user_agent()

    def test_attribution_user_agent_coexists_with_researcher_header(
        self, project_root: Path
    ) -> None:
        """A program requiring both mechanisms at once (header + UA) must
        get both — the two settings are independent."""
        settings = Settings(
            project_root=project_root,
            user_agent="hydra/1.0",
            attribution_user_agent="bugcrowd; cosmiccashew",
            researcher_attribution_header={"X-HackerOne-Research": "my_h1_handle"},
        )
        assert "bugcrowd" in settings.effective_user_agent()
        assert settings.merged_headers()["X-HackerOne-Research"] == "my_h1_handle"

    def test_attribution_user_agent_rejects_crlf_injection(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ATTRIBUTION_USER_AGENT", "bugcrowd\r\nX-Injected: evil")
        with pytest.raises(ConfigurationError):
            Settings.from_env(project_root=project_root)

    def test_attribution_user_agent_not_leaked_in_safe_dict(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            attribution_user_agent="bugcrowd; cosmiccashew",
        )
        safe = settings.to_safe_dict()
        assert "cosmiccashew" not in str(safe)
        assert safe["has_attribution_user_agent"] is True
