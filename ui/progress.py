"""Progress tracking for the reconnaissance TUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn

from core.models import PipelineContext, PipelineStage

STAGE_LABELS = {
    PipelineStage.VALIDATE: "Validation",
    PipelineStage.SUBFINDER: "Discovery",
    PipelineStage.DEDUPE: "Deduplication",
    PipelineStage.DNSX: "DNS Resolution",
    PipelineStage.HTTPX: "HTTP Probing",
    PipelineStage.OPTIONAL: "Enrichment",
    PipelineStage.METADATA: "Intelligence Engine",
    PipelineStage.OUTPUT: "Reporting",
    PipelineStage.DISPLAY: "Complete",
}

# Weighted stage durations for ETA estimation (relative cost)
STAGE_WEIGHTS: dict[PipelineStage, float] = {
    PipelineStage.VALIDATE: 0.03,
    PipelineStage.SUBFINDER: 0.30,
    PipelineStage.DEDUPE: 0.02,
    PipelineStage.DNSX: 0.20,
    PipelineStage.HTTPX: 0.25,
    PipelineStage.OPTIONAL: 0.12,
    PipelineStage.METADATA: 0.04,
    PipelineStage.OUTPUT: 0.03,
    PipelineStage.DISPLAY: 0.01,
}

STAGE_ORDER = list(PipelineStage)


@dataclass
class ProgressState:
    """Mutable progress state for the dashboard."""

    current_stage: PipelineStage = PipelineStage.VALIDATE
    stage_message: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    log_messages: list[tuple[str, str]] = field(default_factory=list)
    max_logs: int = 100

    def add_log(self, level: str, message: str) -> None:
        self.log_messages.append((level, message))
        if len(self.log_messages) > self.max_logs:
            self.log_messages = self.log_messages[-self.max_logs :]

    @property
    def stage_index(self) -> int:
        try:
            return STAGE_ORDER.index(self.current_stage)
        except ValueError:
            return 0

    @property
    def progress_fraction(self) -> float:
        """Weighted progress fraction based on stage costs."""
        completed_weight = sum(STAGE_WEIGHTS.get(s, 0.0) for s in STAGE_ORDER[: self.stage_index])
        current_weight = STAGE_WEIGHTS.get(self.current_stage, 0.0) * 0.5
        return min(1.0, completed_weight + current_weight)

    def elapsed_seconds(self) -> float:
        return (datetime.utcnow() - self.started_at).total_seconds()

    def eta_seconds(self) -> float | None:
        """Estimate remaining seconds based on weighted progress."""
        fraction = self.progress_fraction
        if fraction <= 0.0:
            return None
        elapsed = self.elapsed_seconds()
        if fraction >= 1.0:
            return 0.0
        total_estimated = elapsed / fraction
        return max(0.0, total_estimated - elapsed)


def create_progress() -> Progress:
    """Create a Rich progress bar instance."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        expand=True,
    )


def update_progress_task(progress: Progress, task_id: TaskID, context: PipelineContext) -> None:
    """Update progress bar from pipeline context."""
    state_idx = (
        STAGE_ORDER.index(context.current_stage) if context.current_stage in STAGE_ORDER else 0
    )
    pct = ((state_idx + 1) / len(STAGE_ORDER)) * 100
    label = STAGE_LABELS.get(context.current_stage, context.current_stage.value)
    progress.update(task_id, completed=pct, description=label)
