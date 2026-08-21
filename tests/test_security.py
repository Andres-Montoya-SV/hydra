"""Tests for security utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.exceptions import ConfigurationError, ValidationError
from utils.security import (
    atomic_write_text,
    confine_path,
    escape_html,
    relative_output_path,
    sanitize_log_message,
    validate_binary_path,
    validate_header_name,
    validate_header_value,
    validate_log_level,
    validate_positive_int,
    validate_run_id,
    validate_safe_filename,
)


class TestLogSanitization:
    def test_redacts_api_keys(self) -> None:
        msg = "config api_key=supersecret123"
        assert "supersecret" not in sanitize_log_message(msg)
        assert "[REDACTED]" in sanitize_log_message(msg)

    def test_redacts_bearer_tokens(self) -> None:
        msg = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        result = sanitize_log_message(msg)
        assert "eyJhbGci" not in result

    def test_redacts_subprocess_headers(self) -> None:
        msg = "Executing: httpx -H X-HackerOne-Researcher: secretuser"
        result = sanitize_log_message(msg)
        assert "secretuser" not in result

    def test_redacts_proxy_credentials_and_home_path(self) -> None:
        msg = f"proxy http://analyst:password@proxy.example {Path.home()}/targets.txt"
        result = sanitize_log_message(msg)
        assert "analyst" not in result
        assert "password" not in result
        assert str(Path.home()) not in result


class TestHtmlEscape:
    def test_escapes_script_tags(self) -> None:
        assert "<script>" not in escape_html("<script>alert(1)</script>")


class TestPathSecurity:
    def test_confine_path_rejects_traversal(self, tmp_path: Path) -> None:
        base = tmp_path / "base"
        base.mkdir()
        with pytest.raises(ValidationError):
            confine_path(base / ".." / "outside", base)

    def test_atomic_write(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        atomic_write_text(target, "hello")
        assert target.read_text(encoding="utf-8") == "hello"
        assert not target.with_suffix(".txt.tmp").exists()
        assert target.stat().st_mode & 0o777 == 0o600

    def test_relative_output_path_strips_run_dir(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "Users" / "testuser" / "secret-project" / "output" / "run1"
        output_dir.mkdir(parents=True)
        artifact = output_dir / "param_fuzz_raw" / "example.com.txt"
        artifact.parent.mkdir()
        artifact.write_text("ok", encoding="utf-8")
        rel = relative_output_path(artifact, output_dir)
        assert rel == "param_fuzz_raw/example.com.txt"
        assert "testuser" not in rel
        assert "secret-project" not in rel

    def test_scrub_local_paths_removes_home_and_run_dir(self, tmp_path: Path) -> None:
        from utils.security import scrub_local_paths

        output_dir = tmp_path / "output" / "run1"
        output_dir.mkdir(parents=True)
        blob = f"$ dnsx -l {output_dir}/wildcard_canaries.txt\n"
        cleaned = scrub_local_paths(blob, output_dir)
        assert str(output_dir) not in cleaned
        assert "<run>/wildcard_canaries.txt" in cleaned


class TestBinaryValidation:
    def test_bare_name_allowed(self) -> None:
        assert validate_binary_path(Path("subfinder")) == Path("subfinder")

    def test_missing_absolute_path_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_binary_path(Path("/nonexistent/tool-binary"))


class TestHeaderValidation:
    def test_valid_header(self) -> None:
        assert validate_header_name("X-Custom") == "X-Custom"

    def test_rejects_crlf_in_value(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_header_value("value\r\nInjected: header")

    def test_rejects_invalid_name(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_header_name("bad name")


class TestRunId:
    def test_valid(self) -> None:
        validate_run_id("baseline_001")

    def test_invalid_chars(self) -> None:
        with pytest.raises(ValidationError):
            validate_run_id("bad/id")


class TestSafeFilename:
    def test_valid(self) -> None:
        validate_safe_filename("subdomains.txt")

    def test_rejects_path_separator(self) -> None:
        with pytest.raises(ValidationError):
            validate_safe_filename("../etc/passwd")


class TestConfigInts:
    def test_in_range(self) -> None:
        assert validate_positive_int(50, "THREADS") == 50

    def test_out_of_range(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_positive_int(0, "THREADS")


class TestLogLevel:
    def test_valid(self) -> None:
        assert validate_log_level("debug") == "DEBUG"

    def test_invalid(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_log_level("VERBOSE")
