"""Terminal UI dashboard for reconnaissance framework."""

from __future__ import annotations

import asyncio
import signal
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config.settings import Settings
from core.logger import setup_logging
from core.models import PipelineContext, PipelineStage, RunSummary
from core.reporter import ReportGenerator
from core.runner import PipelineRunner
from ui.progress import STAGE_LABELS, STAGE_ORDER, ProgressState
from ui.tables import (
    build_alive_services_table,
    build_errors_panel,
    build_statistics_table,
    build_targets_table,
    build_tool_status_table,
)

if TYPE_CHECKING:
    pass

console = Console()

# ANSI-compatible status spinners
_SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_RISK_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _fmt_eta(eta: float | None) -> str:
    if eta is None:
        return "—"
    if eta < 60:
        return f"~{int(eta)}s"
    minutes = int(eta // 60)
    secs = int(eta % 60)
    return f"~{minutes}m{secs:02d}s"


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m{secs:02d}s"


class Dashboard:
    """Rich-based terminal dashboard for reconnaissance runs."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.progress_state = ProgressState()
        self.context: PipelineContext | None = None
        self.summary: RunSummary | None = None
        self._runner: PipelineRunner | None = None
        self._tick: int = 0  # for spinner animation

    def _on_stage_change(
        self, context: PipelineContext, stage: PipelineStage, message: str
    ) -> None:
        self.context = context
        self.progress_state.current_stage = stage
        self.progress_state.stage_message = message
        if message:
            self.progress_state.add_log("INFO", message)

    def _on_log(self, level: str, message: str) -> None:
        self.progress_state.add_log(level, message)

    # ------------------------------------------------------------------
    # Layout structure
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )
        layout["left"].split_column(
            Layout(name="progress", size=9),
            Layout(name="telemetry", size=8),
            Layout(name="tools"),
        )
        layout["right"].split_column(
            Layout(name="logs", size=16),
            Layout(name="results"),
        )
        return layout

    # ------------------------------------------------------------------
    # Panel renderers
    # ------------------------------------------------------------------

    def _render_header(self) -> Panel:
        ctx = self.context
        spinner = _SPINNERS[self._tick % len(_SPINNERS)]
        is_done = ctx and ctx.current_stage == PipelineStage.DISPLAY

        # Title row
        title = Text()
        title.append("◈ HYDRA", style="bold white")
        if self.settings.program_name:
            title.append(f"  ·  {self.settings.program_name}", style="bold cyan")
        if self.settings.program_platform:
            title.append(f"  [{self.settings.program_platform}]", style="dim cyan")

        # Phase row
        phase_text = Text()
        phase_label = self.progress_state.stage_message or STAGE_LABELS.get(
            self.progress_state.current_stage, "Initializing"
        )

        if is_done:
            phase_text.append("✓  ", style="bold green")
            phase_text.append("Complete", style="bold green")
        else:
            phase_text.append(f"{spinner}  ", style="bold yellow")
            phase_text.append(
                ctx.current_phase if ctx else "Initializing",
                style="bold yellow",
            )
            if phase_label and ctx and phase_label != ctx.current_phase:
                phase_text.append(f"  ›  {phase_label}", style="dim")

        if ctx and ctx.current_tool:
            phase_text.append(f"  ›  {ctx.current_tool}", style="bold magenta")
        if ctx and ctx.current_target:
            phase_text.append(f"  ›  {ctx.current_target}", style="dim cyan")

        return Panel(
            Group(title, phase_text),
            style="blue",
            border_style="bold blue",
            padding=(0, 1),
        )

    def _render_progress(self) -> Panel:
        fraction = self.progress_state.progress_fraction
        bar_width = 36
        filled = int(bar_width * fraction)
        empty = bar_width - filled

        elapsed = self.progress_state.elapsed_seconds()
        eta = self.progress_state.eta_seconds()

        text = Text()

        # Gradient progress bar
        text.append("  ")
        text.append("█" * filled, style="bold green")
        text.append("░" * empty, style="dim white")
        text.append(f"  {fraction * 100:.0f}%\n", style="bold white")

        # Timing row
        text.append("\n  Elapsed  ", style="dim")
        text.append(_fmt_elapsed(elapsed), style="bold white")
        text.append("   ETA  ", style="dim")
        text.append(_fmt_eta(eta), style="bold cyan" if eta else "dim")

        # Stage breadcrumb
        text.append("\n\n  ")
        for i, stage in enumerate(STAGE_ORDER):
            is_current = stage == self.progress_state.current_stage
            is_done_stage = STAGE_ORDER.index(stage) < self.progress_state.stage_index
            label = STAGE_LABELS[stage][:4]
            if is_done_stage:
                text.append(f"✓ {label}", style="green")
            elif is_current:
                text.append(f"▶ {label}", style="bold yellow")
            else:
                text.append(f"· {label}", style="dim")
            if i < len(STAGE_ORDER) - 1:
                text.append(" › ", style="dim")

        return Panel(
            text,
            title="[bold]Pipeline Progress[/bold]",
            border_style="green",
        )

    def _render_telemetry(self) -> Panel:
        ctx = self.context

        def _stat(label: str, val: str | int, style: str = "white") -> Text:
            t = Text()
            t.append(f"  {label:<16}", style="dim")
            t.append(str(val), style=style)
            t.append("\n")
            return t

        content = Text()
        if ctx:
            # Discovery stats
            content.append_text(_stat("Targets", len(ctx.targets), "bold white"))
            content.append_text(_stat("Subdomains", len(ctx.subdomains), "bold cyan"))
            content.append_text(_stat("Resolved", len(ctx.resolved), "bold green"))
            content.append_text(_stat("Alive HTTP", len(ctx.alive_urls), "bold green"))
            content.append("\n")
            # Execution health
            content.append_text(
                _stat("Timeouts", ctx.total_timeouts, "bold red" if ctx.total_timeouts else "dim")
            )
            content.append_text(
                _stat(
                    "Rate Limits",
                    ctx.total_rate_limits,
                    "bold yellow" if ctx.total_rate_limits else "dim",
                )
            )
            content.append_text(
                _stat("Retries", ctx.total_retries, "yellow" if ctx.total_retries else "dim")
            )
            content.append_text(
                _stat("Skipped", ctx.total_skipped, "dim" if not ctx.total_skipped else "yellow")
            )
            content.append_text(
                _stat("Errors", len(ctx.errors), "bold red" if ctx.errors else "dim")
            )
        else:
            content.append("  Waiting for pipeline...", style="dim")

        return Panel(
            content,
            title="[bold]Live Telemetry[/bold]",
            border_style="cyan",
        )

    def _render_tools(self) -> Panel:
        if self.context:
            return Panel(build_tool_status_table(self.context), border_style="magenta")
        return Panel("Checking tools...", title="Tool Status", border_style="dim")

    def _render_logs(self) -> Panel:
        lines = Text()
        messages = self.progress_state.log_messages[-20:]
        if not messages:
            lines.append("  Waiting for logs...\n", style="dim")
        for level, msg in messages:
            style_map = {
                "ERROR": "bold red",
                "WARNING": "bold yellow",
                "DEBUG": "dim",
                "INFO": "white",
            }
            icon_map = {
                "ERROR": "✗",
                "WARNING": "⚠",
                "DEBUG": "·",
                "INFO": "›",
            }
            icon = icon_map.get(level, "·")
            style = style_map.get(level, "white")
            # Truncate long lines to fit panel
            short_msg = msg[:100] + ("…" if len(msg) > 100 else "")
            lines.append(f"  {icon} {short_msg}\n", style=style)
        return Panel(lines, title="[bold]Live Feed[/bold]", border_style="dim white")

    def _render_results(self) -> Panel:
        if self.context and self.context.httpx_results:
            return Panel(
                build_alive_services_table(self.context, limit=15),
                title="[bold]Live Services[/bold]",
                border_style="blue",
            )
        if self.context and self.context.targets:
            return Panel(build_targets_table(self.context), border_style="dim blue")
        return Panel("Results will appear here...", title="Results", border_style="dim")

    def _render_footer(self) -> Panel:
        ctx = self.context
        output = str(ctx.output_dir) if ctx else str(self.settings.output_directory)
        run_id = f"  Run: [cyan]{ctx.run_id}[/cyan]  " if ctx and ctx.run_id else ""
        text = Text.from_markup(
            f"  {run_id}  Output: [dim]{output}[/dim]  ·  Press [bold]Ctrl+C[/bold] to interrupt"
        )
        return Panel(text, style="dim", padding=(0, 0))

    def _update_layout(self, layout: Layout) -> None:
        self._tick += 1
        layout["header"].update(self._render_header())
        layout["progress"].update(self._render_progress())
        layout["telemetry"].update(self._render_telemetry())
        layout["tools"].update(self._render_tools())
        layout["logs"].update(self._render_logs())
        layout["results"].update(self._render_results())
        layout["footer"].update(self._render_footer())

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        domain: str | None = None,
        targets_file: Path | None = None,
        run_id: str | None = None,
    ) -> PipelineContext:
        """Run pipeline with live dashboard."""
        setup_logging(
            self.settings.log_level,
            self.settings.project_root / self.settings.logs_directory,
        )

        self._runner = PipelineRunner(
            self.settings,
            on_stage_change=self._on_stage_change,
            on_log=self._on_log,
        )

        layout = self._build_layout()
        loop = asyncio.get_event_loop()

        def handle_signal() -> None:
            if self._runner:
                self._runner.cancel()
            self.progress_state.add_log("WARNING", "Interrupt received — stopping cleanly…")

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, handle_signal)
            except NotImplementedError:
                pass

        async def pipeline_task() -> PipelineContext:
            return await self._runner.run(
                domain=domain,
                targets_file=targets_file,
                run_id=run_id,
            )

        pipeline_coro = asyncio.create_task(pipeline_task())

        with Live(layout, console=console, refresh_per_second=8, screen=True):
            while not pipeline_coro.done():
                self._update_layout(layout)
                await asyncio.sleep(0.125)

            context = await pipeline_coro
            self.context = context
            reporter = ReportGenerator(self.settings)
            self.summary = reporter.build_summary(context)
            self._update_layout(layout)
            await asyncio.sleep(1.5)  # let user see the final state

        return context

    # ------------------------------------------------------------------
    # Post-run report
    # ------------------------------------------------------------------

    def print_final_report(self, context: PipelineContext) -> None:
        """Print final report after live dashboard closes."""
        reporter = ReportGenerator(self.settings)
        summary = reporter.build_summary(context)

        console.print()
        console.rule("[bold green]◈  Reconnaissance Complete")
        console.print()

        # Summary grid
        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(build_statistics_table(summary), build_tool_status_table(context))
        console.print(grid)
        console.print()

        if context.httpx_results:
            console.print(build_alive_services_table(context, limit=30))
            console.print()

        if context.errors or context.warnings:
            console.print(build_errors_panel(context))
            console.print()

        # Telemetry summary
        telem = Table(title="Execution Telemetry", show_header=False, box=None)
        telem.add_column(style="dim", width=18)
        telem.add_column(style="bold white")
        telem.add_row("Timeouts", str(context.total_timeouts) if context.total_timeouts else "none")
        telem.add_row(
            "Rate limits hit",
            str(context.total_rate_limits) if context.total_rate_limits else "none",
        )
        telem.add_row("Retries", str(context.total_retries) if context.total_retries else "none")
        telem.add_row(
            "Skipped tools", str(context.total_skipped) if context.total_skipped else "none"
        )
        console.print(Panel(telem, title="[bold]Telemetry[/bold]", border_style="cyan"))
        console.print()

        console.print(
            Panel(
                f"[green]Output directory:[/green] {context.output_dir}\n"
                f"[green]Reports:[/green]          {self.settings.project_root / self.settings.reports_directory}\n"
                f"[green]Logs:[/green]             {self.settings.project_root / self.settings.logs_directory}",
                title="[bold]Output Locations[/bold]",
                border_style="green",
            )
        )


async def run_with_dashboard(
    settings: Settings,
    domain: str | None = None,
    targets_file: Path | None = None,
    run_id: str | None = None,
) -> PipelineContext:
    """Convenience function to run recon with dashboard."""
    dashboard = Dashboard(settings)
    context = await dashboard.run(domain=domain, targets_file=targets_file, run_id=run_id)
    dashboard.print_final_report(context)
    return context
