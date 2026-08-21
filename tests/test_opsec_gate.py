"""Tests for OPSEC DNS-leak check, summary, and STRICT_OPSEC gate."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.exceptions import ConfigurationError
from core.opsec_check import (
    OpsecCheck,
    check_dns_leak,
    enforce_opsec_gate,
    summarize_checks,
)
from core.tool_manager import ToolManager


def test_summarize_checks_safe_and_unsafe() -> None:
    ok = [
        OpsecCheck("a", "pass", "ok"),
        OpsecCheck("b", "warn", "hmm"),
        OpsecCheck("c", "info", "note"),
    ]
    text = summarize_checks(ok)
    assert "2 pass" not in text
    assert "1 pass" in text
    assert "1 warn" in text
    assert "0 fail" in text
    assert "safe to proceed" in text

    bad = ok + [OpsecCheck("d", "fail", "nope")]
    assert "do not proceed" in summarize_checks(bad)
    assert "1 fail" in summarize_checks(bad)


def test_check_dns_leak_informational_when_strict_and_resolves(
    project_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        project_root=project_root,
        strict_opsec=True,
        outbound_proxy_url="http://proxy.example:8080",
    )
    with patch(
        "core.opsec_check.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("1.1.1.1", 443))]
    ):
        result = check_dns_leak(settings)
    assert result.level == "warn"
    assert "Informational" in result.message or "informational" in result.message.lower()


def test_check_dns_leak_inconclusive_on_failure(project_root: Path) -> None:
    settings = Settings(project_root=project_root)
    with patch("core.opsec_check.socket.getaddrinfo", side_effect=OSError("nxdomain")):
        result = check_dns_leak(settings)
    assert result.level == "info"
    assert "Inconclusive" in result.message


def test_enforce_opsec_gate_raises_on_fail(project_root: Path) -> None:
    settings = Settings(project_root=project_root, strict_opsec=True)
    manager = ToolManager(settings)
    with pytest.raises(ConfigurationError, match="gate failed"):
        enforce_opsec_gate(settings, manager)


def test_enforce_opsec_gate_passes_when_not_strict(project_root: Path) -> None:
    settings = Settings(project_root=project_root, strict_opsec=False)
    manager = ToolManager(settings)
    enforce_opsec_gate(settings, manager)
