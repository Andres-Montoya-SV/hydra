"""Dependency service — orchestrates discovery, validation, capability detection with caching."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from core.dependencies.capabilities import CapabilityDetector
from core.dependencies.discovery import BinaryDiscovery
from core.dependencies.models import (
    DiscoveryResult,
    ToolDefinition,
    ToolHealth,
    ToolReport,
    ValidationResult,
)
from core.dependencies.registry import get_tool_definition, install_hint_for
from core.dependencies.validation import HealthValidator
from core.platform import PlatformInfo, detect_platform


class DependencyService:
    """First-class dependency manager with cached, phased analysis."""

    def __init__(
        self,
        tool_paths: dict[str, Path],
        *,
        platform: PlatformInfo | None = None,
        required_tools: frozenset[str] | None = None,
    ) -> None:
        self.tool_paths = tool_paths
        self.platform = platform or detect_platform()
        self.required_tools = required_tools or frozenset({"subfinder", "dnsx", "httpx"})
        self._discovery = BinaryDiscovery(self.platform)
        self._validator = HealthValidator()
        self._capabilities = CapabilityDetector()
        self._cache: dict[str, ToolReport] | None = None
        self._cache_key: str | None = None

    def cache_key(self) -> str:
        path_env = os.environ.get("PATH", "")
        parts = [path_env] + [f"{k}={v}" for k, v in sorted(self.tool_paths.items())]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    async def analyze_all(self, *, force_refresh: bool = False) -> dict[str, ToolReport]:
        """Run full dependency analysis for all configured tools."""
        key = self.cache_key()
        if not force_refresh and self._cache is not None and self._cache_key == key:
            return self._cache

        reports: dict[str, ToolReport] = {}
        for name, configured in self.tool_paths.items():
            defn = get_tool_definition(name)
            required = name in self.required_tools or defn.required
            reports[name] = await self.analyze_tool(defn, configured, required=required)

        self._cache = reports
        self._cache_key = key
        return reports

    async def analyze_tool(
        self,
        defn: ToolDefinition,
        configured: Path,
        *,
        required: bool | None = None,
    ) -> ToolReport:
        """Run three-phase analysis for a single tool."""
        is_required = defn.required if required is None else required
        install_hint = install_hint_for(
            defn,
            is_macos=self.platform.is_macos,
            is_linux=self.platform.is_linux,
        )

        # Phase 1 + 2: Try candidates until one passes validation (handles httpx vs python-httpx)
        candidates = self._discovery.discover_candidates(defn, configured)
        discovery: DiscoveryResult | None = None
        validation: ValidationResult | None = None

        for candidate in candidates:
            if not candidate.path or not os.access(candidate.path, os.X_OK):
                continue
            validation = await self._validator.validate_at_path(candidate.path, defn)
            if validation.can_execute:
                discovery = candidate
                break

        if discovery is None or validation is None or not validation.can_execute:
            fallback = self._discovery.discover(defn, configured)
            reason = "Binary not found in PATH or known install locations"
            if fallback.found:
                reason = "Binary found but failed health checks (including identity verification)"
            return ToolReport(
                name=defn.name,
                display_name=defn.display_name,
                required=is_required,
                health=ToolHealth.MISSING,
                configured_path=str(configured),
                resolved_path=fallback.path if fallback.found else None,
                status_reason=reason,
                recommendation=f"Install: {install_hint}",
                install_hint=install_hint,
                discovery=fallback if fallback.found else DiscoveryResult(found=False),
                validation=validation,
            )

        # Phase 3: Capabilities
        caps = self._capabilities.detect(defn, validation)

        # Classify health — version is NOT required for HEALTHY
        if discovery.in_path:
            health = ToolHealth.HEALTHY
            reason = self._healthy_reason(discovery, validation)
            recommendation = None
        else:
            health = ToolHealth.DEGRADED
            reason = f"Found at {discovery.path} ({discovery.source}) but not in PATH"
            recommendation = f'export PATH="{discovery.path.parent}:$PATH"'

        if discovery.is_cellar_path and discovery.in_path:
            reason += " (via Homebrew Cellar — consider using brew link)"

        return ToolReport(
            name=defn.name,
            display_name=defn.display_name,
            required=is_required,
            health=health,
            configured_path=str(configured),
            resolved_path=discovery.path,
            version=validation.version,
            in_path=discovery.in_path,
            can_execute=True,
            capabilities=caps,
            discovery=discovery,
            validation=validation,
            status_reason=reason,
            recommendation=recommendation,
            install_hint=install_hint,
        )

    def get_cached(self, name: str) -> ToolReport | None:
        if self._cache:
            return self._cache.get(name)
        return None

    def invalidate_cache(self) -> None:
        self._cache = None
        self._cache_key = None

    def mandatory_satisfied(self, reports: dict[str, ToolReport] | None = None) -> bool:
        reports = reports or self._cache or {}
        for name in self.required_tools:
            report = reports.get(name)
            if not report or not report.is_runnable:
                return False
        return True

    @staticmethod
    def _healthy_reason(discovery, validation) -> str:
        parts = [f"Executable at {discovery.path} ({discovery.source})"]
        if validation.version:
            parts.append(f"version {validation.version}")
        elif not validation.version_obtained:
            parts.append("version unknown (not required)")
        return "; ".join(parts)
