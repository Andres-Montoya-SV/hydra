"""Discovery, validation, and lifecycle management of recon plugins."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

from core.dependencies.models import ToolHealth, ToolReport
from core.dependencies.service import DependencyService
from core.discovery.tool_discovery import DiscoveredTool
from core.exceptions import ToolNotFoundError
from core.logger import get_logger
from core.models import PipelineContext, ToolStatus
from core.plugin_base import ReconPlugin

if TYPE_CHECKING:
    from config.settings import Settings

logger = get_logger("tool_manager")


class ToolManager:
    """Manages plugin discovery, dependency analysis, and instantiation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._plugins: dict[str, ReconPlugin] = {}
        self._reports: dict[str, ToolReport] = {}
        self._discovered: dict[str, DiscoveredTool] = {}
        self._discover_plugins()
        self._dependency_service = DependencyService(
            settings.all_tool_paths(),
            required_tools=frozenset(p.name for p in self.get_mandatory_plugins()),
        )

    def _discover_plugins(self) -> None:
        import modules  # noqa: F401

        package_path = Path(modules.__file__).parent
        for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
            if module_name.startswith("_"):
                continue
            importlib.import_module(f"modules.{module_name}")

        for plugin_cls in ReconPlugin.all_plugins():
            instance = plugin_cls(self.settings)
            self._plugins[instance.name] = instance

    @property
    def dependency_service(self) -> DependencyService:
        return self._dependency_service

    def get_plugin(self, name: str) -> ReconPlugin | None:
        return self._plugins.get(name)

    def get_all_plugins(self) -> list[ReconPlugin]:
        return sorted(self._plugins.values(), key=lambda p: p.stage_order)

    def get_mandatory_plugins(self) -> list[ReconPlugin]:
        return [p for p in self.get_all_plugins() if p.required]

    def get_enabled_plugins(self) -> list[ReconPlugin]:
        return [p for p in self.get_all_plugins() if p.is_enabled()]

    async def discover_all_tools(self, *, force_refresh: bool = False) -> dict[str, DiscoveredTool]:
        """Run phased dependency analysis for all configured tools (cached)."""
        self._reports = await self._dependency_service.analyze_all(force_refresh=force_refresh)
        self._discovered = {
            name: DiscoveredTool.from_report(report) for name, report in self._reports.items()
        }
        return self._discovered

    def get_report(self, name: str) -> ToolReport | None:
        return self._reports.get(name) or self._dependency_service.get_cached(name)

    def get_discovered(self, name: str) -> DiscoveredTool | None:
        return self._discovered.get(name)

    def get_resolved_binary(self, name: str, fallback: Path) -> Path:
        report = self._reports.get(name) or self._dependency_service.get_cached(name)
        if report and report.resolved_path and report.is_runnable:
            return report.resolved_path
        discovered = self._discovered.get(name)
        if discovered and discovered.is_usable and discovered.absolute_path:
            return discovered.absolute_path
        return fallback

    async def validate_tools(self, context: PipelineContext) -> bool:
        """Check tool availability — execution is not blocked by missing version metadata."""
        await self.discover_all_tools()
        mandatory_ok = True

        for plugin in self.get_all_plugins():
            info = plugin.build_tool_info()
            context.tool_states[plugin.name] = info

            if not plugin.is_enabled():
                info.status = ToolStatus.SKIPPED
                continue

            if not plugin.external_dependency:
                info.status = ToolStatus.READY
                logger.info("%s → built-in capability", plugin.name)
                continue

            report = self._reports.get(plugin.name)
            discovered = self._discovered.get(plugin.name)

            if report is None or discovered is None:
                info.status = ToolStatus.MISSING
                continue

            info.install_hint = report.install_hint

            if report.is_runnable:
                info.status = ToolStatus.READY
                info.version = report.version
                context.resolved_binaries[plugin.name] = report.resolved_path  # type: ignore[arg-type]

                if report.health == ToolHealth.DEGRADED and report.recommendation:
                    context.add_warning(
                        f"{plugin.display_name}: {report.status_reason}. "
                        f"Fix: {report.recommendation}"
                    )
                # Full install paths (Homebrew Cellar, ~/go/bin, etc.) reveal local
                # machine layout; keep those at DEBUG and log only the binary name
                # at INFO so routine run logs stay shareable.
                logger.info("%s → ready (%s)", plugin.name, report.status_reason)
                logger.debug("%s resolved to %s", plugin.name, report.resolved_path)
            else:
                if plugin.required:
                    info.status = ToolStatus.MISSING
                    mandatory_ok = False
                    fix = report.recommendation or report.install_hint
                    context.add_error(f"{plugin.display_name}: {report.status_reason}. {fix}")
                else:
                    info.status = ToolStatus.SKIPPED
                    if report.health == ToolHealth.MISSING:
                        context.add_warning(f"{plugin.display_name}: {report.status_reason}")

        return mandatory_ok

    async def ensure_mandatory_tools(self) -> None:
        """Raise only when mandatory tools cannot execute — not when version is unknown."""
        missing: list[tuple[str, str]] = []
        for plugin in self.get_mandatory_plugins():
            if not plugin.is_enabled():
                continue
            report = self._reports.get(plugin.name)
            if not report or not report.is_runnable:
                hint = report.install_hint if report else plugin.get_install_hint()
                missing.append((plugin.name, hint))

        if missing:
            name, hint = missing[0]
            details = "; ".join(f"{n}: not runnable" for n, _ in missing)
            raise ToolNotFoundError(name, f"{hint}. Missing: {details}")

    def is_runnable(self, plugin_name: str) -> bool:
        """Return True if plugin should execute (healthy or degraded, can execute)."""
        plugin = self._plugins.get(plugin_name)
        if not plugin or not plugin.is_enabled():
            return False
        if not plugin.external_dependency:
            return True
        report = self._reports.get(plugin_name)
        if report:
            return report.is_runnable
        discovered = self._discovered.get(plugin_name)
        return bool(discovered and discovered.is_usable)
