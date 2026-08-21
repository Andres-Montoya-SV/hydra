"""Executable discovery — backward-compatible facade over the dependency subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core.dependencies.models import ToolHealth, ToolReport
from core.dependencies.service import DependencyService
from core.platform import PlatformInfo, detect_platform


class ToolAvailability(str, Enum):
    """Legacy availability enum — maps to ToolHealth."""

    AVAILABLE = "available"
    NOT_IN_PATH = "not_in_path"
    NOT_EXECUTABLE = "not_executable"
    NOT_FOUND = "not_found"
    PROBE_FAILED = "probe_failed"


@dataclass
class DiscoveredTool:
    """Legacy discovery result — adapter from ToolReport."""

    name: str
    configured: str
    absolute_path: Path | None = None
    version: str | None = None
    availability: ToolAvailability = ToolAvailability.NOT_FOUND
    in_path: bool = False
    can_execute: bool = False
    probe_flag: str | None = None
    probe_exit_code: int | None = None
    search_paths_tried: list[str] = field(default_factory=list)
    path_fix_hint: str | None = None
    install_hint: str = ""
    health: ToolHealth = ToolHealth.MISSING
    status_reason: str = ""
    recommendation: str | None = None
    capabilities: list[str] = field(default_factory=list)

    @property
    def is_usable(self) -> bool:
        return self.health in (ToolHealth.HEALTHY, ToolHealth.DEGRADED) and self.can_execute

    @property
    def status_symbol(self) -> str:
        if self.health == ToolHealth.HEALTHY:
            return "✓"
        if self.health == ToolHealth.DEGRADED:
            return "⚠"
        return "✗"

    @classmethod
    def from_report(cls, report: ToolReport) -> DiscoveredTool:
        availability = _health_to_availability(report)
        discovery = report.discovery
        validation = report.validation
        return cls(
            name=report.name,
            configured=report.configured_path,
            absolute_path=report.resolved_path,
            version=report.version,
            availability=availability,
            in_path=report.in_path,
            can_execute=report.can_execute,
            probe_flag=validation.probe_command if validation else None,
            probe_exit_code=validation.probe_exit_code if validation else None,
            search_paths_tried=discovery.candidates_tried if discovery else [],
            path_fix_hint=report.recommendation if report.health == ToolHealth.DEGRADED else None,
            install_hint=report.install_hint,
            health=report.health,
            status_reason=report.status_reason,
            recommendation=report.recommendation,
            capabilities=sorted(report.capabilities.all_capabilities),
        )


def _health_to_availability(report: ToolReport) -> ToolAvailability:
    if report.health == ToolHealth.HEALTHY:
        return ToolAvailability.AVAILABLE
    if report.health == ToolHealth.DEGRADED:
        return ToolAvailability.NOT_IN_PATH
    if report.resolved_path and not report.can_execute:
        if report.status_reason.startswith("Binary found but not executable"):
            return ToolAvailability.NOT_EXECUTABLE
        return ToolAvailability.PROBE_FAILED
    return ToolAvailability.NOT_FOUND


class ToolDiscovery:
    """Legacy wrapper — delegates to DependencyService."""

    def __init__(self, platform_info: PlatformInfo | None = None) -> None:
        self.platform = platform_info or detect_platform()
        self._service: DependencyService | None = None

    def search_directories(self) -> list[Path]:
        return list(self.platform.path_dirs) + [
            d
            for d in (
                self.platform.gobin,
                self.platform.gopath_bin,
                self.platform.home / "go" / "bin",
                self.platform.homebrew_bin,
                Path("/usr/local/bin"),
                Path("/usr/bin"),
            )
            if d is not None and d.is_dir()
        ]

    async def discover(
        self,
        name: str,
        configured: Path,
        *,
        install_hint: str = "",
    ) -> DiscoveredTool:
        service = DependencyService({name: configured}, platform=self.platform)
        from core.dependencies.registry import get_tool_definition

        defn = get_tool_definition(name)
        report = await service.analyze_tool(defn, configured)
        if install_hint and not report.install_hint:
            report.install_hint = install_hint
        return DiscoveredTool.from_report(report)

    async def discover_many(
        self,
        tools: dict[str, tuple[Path, str]],
    ) -> dict[str, DiscoveredTool]:
        tool_paths = {name: path for name, (path, _) in tools.items()}
        service = DependencyService(tool_paths, platform=self.platform)
        reports = await service.analyze_all()
        result: dict[str, DiscoveredTool] = {}
        for name, report in reports.items():
            hint = tools.get(name, (None, ""))[1]
            if hint and not report.install_hint:
                report.install_hint = hint
            result[name] = DiscoveredTool.from_report(report)
        return result


async def probe_binary_executable(path: Path) -> bool:
    """Check if a binary is executable — version flags not required."""
    from core.dependencies.registry import get_tool_definition
    from core.dependencies.validation import HealthValidator

    validator = HealthValidator(smoke_timeout=3.0)
    defn = get_tool_definition(path.name)
    result = await validator.validate(path, defn)
    return result.can_execute
