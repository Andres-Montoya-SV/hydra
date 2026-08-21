"""Tests for STRICT_OPSEC pre-flight diagnostics (`hydra check-opsec`)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from config.settings import Settings
from core import opsec_check
from core.opsec_check import (
    check_blocked_plugins,
    check_configuration,
    check_httpx_strict_args,
    check_identity_headers,
    check_proxy_functional,
    check_proxy_reachability,
    run_diagnostics,
)
from core.tool_manager import ToolManager


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _n: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestCheckConfiguration:
    def test_warns_when_strict_disabled(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root)
        checks = check_configuration(settings)
        assert len(checks) == 1
        assert checks[0].level == "warn"

    def test_fails_without_proxy(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, strict_opsec=True)
        checks = check_configuration(settings)
        assert any(c.level == "fail" for c in checks)

    def test_passes_with_proxy(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
        )
        checks = check_configuration(settings)
        assert all(c.level == "pass" for c in checks)
        assert any("proxy.example" in c.message for c in checks)


class TestProxyReachability:
    def test_pass_when_listening(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            result = check_proxy_reachability(f"http://127.0.0.1:{port}", timeout=2)
            assert result.level == "pass"
        finally:
            server.close()

    def test_fail_when_nothing_listening(self) -> None:
        # Bind to get a genuinely free ephemeral port, then close it immediately
        # so nothing is listening there when the check connects.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        result = check_proxy_reachability(f"http://127.0.0.1:{port}", timeout=2)
        assert result.level == "fail"

    def test_fail_on_unparseable_host(self) -> None:
        result = check_proxy_reachability("http://:8080", timeout=1)
        assert result.level == "fail"


class TestProxyFunctional:
    def test_pass_reports_observed_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(opsec_check, "open_url", lambda *a, **k: _FakeResponse(b"203.0.113.5"))
        result = check_proxy_functional("http://proxy.example:8080", "hydra/1.0")
        assert result.level == "pass"
        assert "203.0.113.5" in result.message

    def test_fail_when_request_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*_a: object, **_k: object) -> None:
            raise OSError("connection refused")

        monkeypatch.setattr(opsec_check, "open_url", _raise)
        result = check_proxy_functional("http://proxy.example:8080", "hydra/1.0")
        assert result.level == "fail"

    def test_warn_on_empty_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(opsec_check, "open_url", lambda *a, **k: _FakeResponse(b""))
        result = check_proxy_functional("http://proxy.example:8080", "hydra/1.0")
        assert result.level == "warn"


class TestHttpxStrictArgs:
    def test_not_applicable_when_strict_disabled(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root)
        result = check_httpx_strict_args(settings)
        assert result.level == "info"

    def test_passes_when_strict_and_proxied(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
        )
        result = check_httpx_strict_args(settings)
        assert result.level == "pass"


class TestBlockedPlugins:
    def test_reports_info_when_not_strict(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, enable_naabu=True)
        manager = ToolManager(settings)
        result = check_blocked_plugins(settings, manager)
        assert result.level == "info"
        assert "naabu" in result.message

    def test_reports_pass_when_strict(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
            enable_naabu=True,
        )
        manager = ToolManager(settings)
        result = check_blocked_plugins(settings, manager)
        assert result.level == "pass"
        assert "skipped" in result.message


class TestIdentityHeaders:
    def test_flags_researcher_header_when_strict(self, project_root: Path) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
            x_hackerone_researcher="handle",
        )
        # merged_headers() already suppresses headers under strict mode, so this
        # check should find nothing to flag.
        result = check_identity_headers(settings)
        assert result.level == "pass"

    def test_reports_info_when_not_strict(self, project_root: Path) -> None:
        settings = Settings(project_root=project_root, x_hackerone_researcher="handle")
        result = check_identity_headers(settings)
        assert result.level == "info"
        assert "X-HackerOne-Researcher" in result.message


class TestRunDiagnostics:
    @pytest.mark.asyncio
    async def test_skip_network_avoids_live_probes(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
        )
        manager = ToolManager(settings)

        def _fail_if_called(*_a: object, **_k: object) -> None:
            raise AssertionError("network probe should not run with skip_network=True")

        monkeypatch.setattr(opsec_check, "check_proxy_reachability", _fail_if_called)
        checks = await run_diagnostics(settings, manager, skip_network=True)
        assert any(c.name == "Proxy network probes" for c in checks)

    @pytest.mark.asyncio
    async def test_reveal_direct_ip_only_runs_when_opted_in(
        self, project_root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            project_root=project_root,
            strict_opsec=True,
            outbound_proxy_url="http://proxy.example:8080",
        )
        manager = ToolManager(settings)
        monkeypatch.setattr(
            opsec_check,
            "check_proxy_reachability",
            lambda *a, **k: opsec_check.OpsecCheck(
                name="Proxy TCP reachability", level="pass", message="ok"
            ),
        )
        monkeypatch.setattr(
            opsec_check,
            "check_proxy_functional",
            lambda *a, **k: opsec_check.OpsecCheck(
                name="Proxy functional test", level="pass", message="ok"
            ),
        )
        checks = await run_diagnostics(settings, manager, reveal_direct_ip=False)
        assert not any(c.name == "Direct (non-proxied) egress IP" for c in checks)
