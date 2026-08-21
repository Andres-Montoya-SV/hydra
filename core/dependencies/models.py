"""Dependency subsystem data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ToolHealth(str, Enum):
    """Overall tool dependency status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    MISSING = "missing"


class InstallKind(str, Enum):
    """Supported installation methods."""

    HOMEBREW = "homebrew"
    APT = "apt"
    GO = "go"


@dataclass(frozen=True)
class InstallMethod:
    """Platform-specific installation instruction."""

    kind: InstallKind
    package: str

    def command(self) -> str:
        if self.kind == InstallKind.HOMEBREW:
            return f"brew install {self.package}"
        if self.kind == InstallKind.APT:
            return f"sudo apt install {self.package}"
        return f"go install -v {self.package}"


@dataclass(frozen=True)
class ToolDefinition:
    """Registry entry describing how to discover, validate, and install a tool."""

    name: str
    display_name: str
    required: bool = False
    binary_name: str = ""
    version_commands: tuple[tuple[str, ...], ...] = ()
    health_commands: tuple[tuple[str, ...], ...] = (
        ("-h",),
        ("--help",),
        ("-help",),
    )
    capabilities: frozenset[str] = frozenset()
    install_homebrew: str | None = None
    install_apt: str | None = None
    install_go: str | None = None
    allow_smoke_test: bool = True
    path_denylist: tuple[str, ...] = ()
    identity_markers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.binary_name:
            object.__setattr__(self, "binary_name", self.name)

    def install_methods(self) -> list[InstallMethod]:
        methods: list[InstallMethod] = []
        if self.install_homebrew:
            methods.append(InstallMethod(InstallKind.HOMEBREW, self.install_homebrew))
        if self.install_apt:
            methods.append(InstallMethod(InstallKind.APT, self.install_apt))
        if self.install_go:
            methods.append(InstallMethod(InstallKind.GO, self.install_go))
        return methods


@dataclass
class DiscoveryResult:
    """Phase 1 — binary location discovery."""

    found: bool
    path: Path | None = None
    source: str = "not_found"
    in_path: bool = False
    is_symlink: bool = False
    is_cellar_path: bool = False
    candidates_tried: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Phase 2 — executability and optional version metadata."""

    can_execute: bool
    version: str | None = None
    probe_command: str | None = None
    probe_exit_code: int | None = None
    version_obtained: bool = False
    notes: list[str] = field(default_factory=list)
    probe_output: str = ""


@dataclass
class CapabilityResult:
    """Phase 3 — declared and detected capabilities."""

    declared: frozenset[str] = frozenset()
    detected: frozenset[str] = frozenset()

    @property
    def all_capabilities(self) -> frozenset[str]:
        return self.declared | self.detected


@dataclass
class ToolReport:
    """Complete dependency analysis for a single tool."""

    name: str
    display_name: str
    required: bool
    health: ToolHealth
    configured_path: str
    resolved_path: Path | None = None
    version: str | None = None
    in_path: bool = False
    can_execute: bool = False
    capabilities: CapabilityResult = field(default_factory=CapabilityResult)
    discovery: DiscoveryResult | None = None
    validation: ValidationResult | None = None
    status_reason: str = ""
    recommendation: str | None = None
    install_hint: str = ""

    @property
    def is_runnable(self) -> bool:
        return self.health in (ToolHealth.HEALTHY, ToolHealth.DEGRADED) and self.can_execute

    @property
    def status_symbol(self) -> str:
        if self.health == ToolHealth.HEALTHY:
            return "✓"
        if self.health == ToolHealth.DEGRADED:
            return "⚠"
        return "✗"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "health": self.health.value,
            "resolved_path": str(self.resolved_path) if self.resolved_path else None,
            "version": self.version,
            "in_path": self.in_path,
            "can_execute": self.can_execute,
            "status_reason": self.status_reason,
            "recommendation": self.recommendation,
            "capabilities": sorted(self.capabilities.all_capabilities),
        }
