"""Tests for dependency management subsystem."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from core.dependencies.discovery import BinaryDiscovery
from core.dependencies.models import ToolHealth
from core.dependencies.registry import TOOL_REGISTRY, get_tool_definition
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
