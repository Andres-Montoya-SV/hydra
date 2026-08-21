"""Domain models for reconnaissance pipeline state and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class ToolStatus(str, Enum):
    """Lifecycle status of a recon tool during execution."""

    PENDING = "pending"
    CHECKING = "checking"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    MISSING = "missing"


class PipelineStage(str, Enum):
    """Ordered stages in the default reconnaissance pipeline."""

    VALIDATE = "validate"
    SUBFINDER = "subfinder"
    DEDUPE = "dedupe"
    DNSX = "dnsx"
    HTTPX = "httpx"
    OPTIONAL = "optional"
    METADATA = "metadata"
    OUTPUT = "output"
    DISPLAY = "display"


@dataclass
class ToolInfo:
    """Metadata and runtime state for a recon plugin."""

    name: str
    display_name: str
    required: bool
    enabled: bool
    status: ToolStatus = ToolStatus.PENDING
    version: str | None = None
    install_hint: str = ""
    error_message: str | None = None
    duration_seconds: float = 0.0
    output_lines: int = 0
    timeouts: int = 0
    rate_limits: int = 0
    retries: int = 0


@dataclass
class DomainTarget:
    """A validated reconnaissance target domain."""

    domain: str
    source: str = "cli"


@dataclass
class PipelineContext:
    """Shared mutable state passed through the reconnaissance pipeline."""

    targets: list[DomainTarget] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    alive_urls: list[str] = field(default_factory=list)
    httpx_results: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    output_dir: Path = field(default_factory=Path)
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tool_states: dict[str, ToolInfo] = field(default_factory=dict)
    current_stage: PipelineStage = PipelineStage.VALIDATE
    current_phase: str = "Validation"
    current_tool: str | None = None
    current_target: str | None = None
    total_timeouts: int = 0
    total_rate_limits: int = 0
    total_retries: int = 0
    total_skipped: int = 0
    interrupted: bool = False
    resolved_binaries: dict[str, Path] = field(default_factory=dict)
    run_id: str = ""
    store_warnings: list[str] = field(default_factory=list)
    registry: Any = None  # HostRegistry — populated during pipeline
    finalized: bool = False  # set once _finalize_to_store + reporter.generate have run

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


@dataclass
class RunSummary:
    """Aggregated statistics for a completed reconnaissance run."""

    targets_count: int
    subdomains_count: int
    resolved_count: int
    alive_count: int
    duration_seconds: float
    tools_run: list[str]
    tools_failed: list[str]
    tools_skipped: list[str]
    errors: list[str]
    warnings: list[str]
    output_dir: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets_count": self.targets_count,
            "subdomains_count": self.subdomains_count,
            "resolved_count": self.resolved_count,
            "alive_count": self.alive_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "tools_run": self.tools_run,
            "tools_failed": self.tools_failed,
            "tools_skipped": self.tools_skipped,
            "errors": self.errors,
            "warnings": self.warnings,
            "output_dir": self.output_dir,
            "timestamp": self.timestamp,
        }
