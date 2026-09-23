"""Tests for dependency management subsystem."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from core.dependencies.discovery import BinaryDiscovery
from core.dependencies.models import InstallKind, ToolHealth
from core.dependencies.registry import TOOL_REGISTRY, get_tool_definition, install_hint_for
from core.dependencies.service import DependencyService
from core.dependencies.validation import HealthValidator
from core.discovery.tool_discovery import DiscoveredTool, ToolDiscovery
from core.platform import detect_platform


class TestRegistry:
    def test_mandatory_tools_registered(self) -> None:
        for name in ("subfinder", "dnsx", "httpx"):
            assert name in TOOL_REGISTRY
            assert TOOL_REGISTRY[name].required

    def test_go_tools_allow_smoke_test(self) -> None:
        anew = get_tool_definition("anew")
        assert anew.allow_smoke_test
        assert not anew.version_commands

    def test_sslyze_and_wafw00f_are_pip_installable(self) -> None:
        for name in ("sslyze", "wafw00f"):
            defn = get_tool_definition(name)
            assert defn.install_pip == name
            methods = defn.install_methods()
            assert any(m.kind is InstallKind.PIP for m in methods)
            assert install_hint_for(defn, is_macos=True, is_linux=False) == f"pip install {name}"

    def test_theharvester_has_no_fabricated_install_category(self) -> None:
        """Genuinely none of homebrew/apt/go/pip fit (requires Python
        3.14, managed by uv, cloned from source) — must use the real
        MANUAL category with a specific instruction, never a guessed fit
        into an existing one."""
        defn = get_tool_definition("theharvester")
        assert defn.install_homebrew is None
        assert defn.install_apt is None
        assert defn.install_go is None
        assert defn.install_pip is None
        assert defn.install_manual is not None
        assert "uv sync" in defn.install_manual
        hint = install_hint_for(defn, is_macos=True, is_linux=False)
        assert hint == defn.install_manual

    def test_three_new_modules_registered_with_capabilities(self) -> None:
        assert "email_personnel_osint" in TOOL_REGISTRY["theharvester"].capabilities
        assert "tls_posture" in TOOL_REGISTRY["sslyze"].capabilities
        assert "waf_detection" in TOOL_REGISTRY["wafw00f"].capabilities


class TestBinaryDiscovery:
    def test_prefers_which_over_cellar(self) -> None:
        platform = detect_platform()
        discovery = BinaryDiscovery(platform)
        defn = get_tool_definition("python3")
        result = discovery.discover(defn, Path(sys.executable))
        assert result.found
        assert result.path is not None
        assert "Cellar" not in str(result.path) or result.source == "homebrew-cellar"

    def test_missing_binary(self) -> None:
        discovery = BinaryDiscovery(detect_platform())
        defn = get_tool_definition("totally-missing-tool-xyz")
        result = discovery.discover(defn, Path("totally-missing-tool-xyz"))
        assert not result.found


class TestHealthValidator:
    @pytest.mark.asyncio
    async def test_python_executable_without_version_requirement(self) -> None:
        validator = HealthValidator()
        defn = get_tool_definition("python3")
        result = await validator.validate(Path(sys.executable), defn)
        assert result.can_execute

    @pytest.mark.asyncio
    async def test_version_not_required_for_health(self) -> None:
        validator = HealthValidator()
        defn = get_tool_definition("anew")
        # anew may or may not be installed — test logic with python as smoke-testable
        result = await validator.validate(Path(sys.executable), defn)
        assert result.can_execute
        # version may be None — that is OK
        assert result.version is None or isinstance(result.version, str)

    @pytest.mark.asyncio
    async def test_probe_and_smoke_test_do_not_leak_secrets_to_the_child(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Hardening round 2, Task 5: `_run_probe`/`_smoke_test` spawn a
        real subprocess for every tool version/health check — they must
        route through `utils.subprocess.child_process_env()` the same as
        `run_command`, not the full parent environment (which carries
        Settings.from_env()'s real secrets). A script masquerading as the
        probed "tool" writes any leaked secret to a file `validate()` never
        reads, so a leak fails the test even though `validate()`'s own
        return value can't see the child's environment directly.
        """
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-leak-canary")
        leak_file = tmp_path / "leaked.txt"
        fake_tool = tmp_path / "fake-tool"
        fake_tool.write_text(
            "#!/bin/sh\n"
            f'echo "$ANTHROPIC_API_KEY" > "{leak_file}"\n'
            "echo fake-tool-version-1.0.0\n"
        )
        fake_tool.chmod(0o755)

        validator = HealthValidator()
        defn = get_tool_definition("anew")  # any Go-style, version-optional defn works
        await validator.validate(fake_tool, defn)

        assert leak_file.exists()
        assert leak_file.read_text().strip() == ""


class TestDependencyService:
    @pytest.mark.asyncio
    async def test_analyze_python(self) -> None:
        service = DependencyService({"python3": Path(sys.executable)})
        reports = await service.analyze_all()
        report = reports["python3"]
        assert report.health in (ToolHealth.HEALTHY, ToolHealth.DEGRADED)
        assert report.can_execute

    @pytest.mark.asyncio
    async def test_cache_reused(self) -> None:
        service = DependencyService({"python3": Path(sys.executable)})
        first = await service.analyze_all()
        second = await service.analyze_all()
        assert first is second

    @pytest.mark.asyncio
    async def test_missing_tool(self) -> None:
        service = DependencyService({"missing": Path("missing-tool-xyz")})
        reports = await service.analyze_all()
        assert reports["missing"].health == ToolHealth.MISSING
        assert reports["missing"].recommendation is not None


class TestLegacyAdapter:
    @pytest.mark.asyncio
    async def test_discover_python(self) -> None:
        discovery = ToolDiscovery()
        result = await discovery.discover("python3", Path(sys.executable))
        assert result.is_usable
        assert result.health in (ToolHealth.HEALTHY, ToolHealth.DEGRADED)

    @pytest.mark.asyncio
    async def test_discover_missing(self) -> None:
        discovery = ToolDiscovery()
        result = await discovery.discover("nonexistent-tool-xyz", Path("nonexistent-tool-xyz"))
        assert not result.is_usable
        assert result.health == ToolHealth.MISSING

    def test_from_report_adapter(self) -> None:
        from core.dependencies.models import ToolReport

        report = ToolReport(
            name="httpx",
            display_name="httpx",
            required=True,
            health=ToolHealth.HEALTHY,
            configured_path="httpx",
            can_execute=True,
            status_reason="OK",
        )
        legacy = DiscoveredTool.from_report(report)
        assert legacy.is_usable
        assert legacy.health == ToolHealth.HEALTHY
