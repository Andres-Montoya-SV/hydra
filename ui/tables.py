"""Rich table builders for reconnaissance results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.table import Table

from core.models import PipelineContext, RunSummary, ToolStatus

if TYPE_CHECKING:
    from core.store import AssetStore

STATUS_STYLES = {
    ToolStatus.PENDING: "dim",
    ToolStatus.CHECKING: "cyan",
    ToolStatus.READY: "green",
    ToolStatus.RUNNING: "bold yellow",
    ToolStatus.COMPLETED: "bold green",
    ToolStatus.SKIPPED: "dim",
    ToolStatus.FAILED: "bold red",
    ToolStatus.MISSING: "red",
}


def build_tool_status_table(context: PipelineContext) -> Table:
    """Build a table showing tool status."""
    table = Table(title="Tool Status", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Required")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Duration")
    table.add_column("Output")

    for _name, info in sorted(context.tool_states.items()):
        style = STATUS_STYLES.get(info.status, "")
        table.add_row(
            info.display_name,
            "Yes" if info.required else "No",
            f"[{style}]{info.status.value}[/{style}]" if style else info.status.value,
            info.version or "-",
            f"{info.duration_seconds:.1f}s" if info.duration_seconds else "-",
            str(info.output_lines) if info.output_lines else "-",
        )

    return table


def build_statistics_table(summary: RunSummary) -> Table:
    """Build a statistics summary table."""
    table = Table(title="Statistics", show_header=True, header_style="bold green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Targets", str(summary.targets_count))
    table.add_row("Subdomains", str(summary.subdomains_count))
    table.add_row("Resolved", str(summary.resolved_count))
    table.add_row("Alive HTTP", str(summary.alive_count))
    table.add_row("Duration", f"{summary.duration_seconds:.1f}s")
    table.add_row("Tools Run", str(len(summary.tools_run)))
    table.add_row("Errors", str(len(summary.errors)))
    table.add_row("Warnings", str(len(summary.warnings)))

    return table


def build_alive_services_table(context: PipelineContext, limit: int = 25) -> Table:
    """Build a table of live HTTP services from httpx results."""
    table = Table(title=f"Live Services (top {limit})", show_header=True, header_style="bold blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Status")
    table.add_column("Title", overflow="fold")
    table.add_column("Tech", overflow="fold")

    for idx, rec in enumerate(context.httpx_results[:limit], 1):
        url = rec.get("url", "")
        status = str(rec.get("status_code", ""))
        title = str(rec.get("title", ""))[:50]
        tech_list = rec.get("tech", [])
        tech = ", ".join(tech_list[:3]) if isinstance(tech_list, list) else ""

        status_style = (
            "green" if status.startswith("2") else "yellow" if status.startswith("3") else "red"
        )
        table.add_row(
            str(idx),
            url,
            f"[{status_style}]{status}[/{status_style}]",
            title,
            tech,
        )

    if not context.httpx_results:
        table.add_row("-", "No live services found", "-", "-", "-")

    return table


def build_errors_panel(context: PipelineContext) -> Table:
    """Build error and warning panel."""
    table = Table(title="Errors & Warnings", show_header=True)
    table.add_column("Level")
    table.add_column("Message", overflow="fold")

    for err in context.errors:
        table.add_row("[red]ERROR[/red]", err)
    for warn in context.warnings:
        table.add_row("[yellow]WARN[/yellow]", warn)

    if not context.errors and not context.warnings:
        table.add_row("[green]OK[/green]", "No issues detected")

    return table


def build_targets_table(context: PipelineContext) -> Table:
    """Build targets table."""
    table = Table(title="Targets", show_header=True)
    table.add_column("Domain", style="cyan")
    table.add_column("Source", style="dim")

    for target in context.targets:
        table.add_row(target.domain, target.source)

    return table


def verification_summary_line(counts: dict[str, int]) -> str:
    """The one-line terminal summary (design Part 3, item 4): e.g.
    'Verification: 2 confirmed, 0 pending, 1 finding invalidated and
    excluded from report.' Shared by the Rich panel below and the
    plain-text --no-ui path (app.py::cmd_run) so both render identically.
    """
    invalidated = counts.get("invalidated", 0)
    noun = "finding" if invalidated == 1 else "findings"
    return (
        f"Verification: {counts.get('confirmed', 0)} confirmed, "
        f"{counts.get('pending', 0)} pending, "
        f"{invalidated} {noun} invalidated and excluded from report"
    )


def build_verification_panel(context: PipelineContext, store: AssetStore | None) -> Table:
    """Verification agent summary for the run-completion table (design Part
    3, item 4) — visible in the terminal at completion, not only in
    summary.json / the `verification-flags` CLI command.
    """
    table = Table(title="Verification", show_header=False, box=None)
    table.add_column(style="dim", width=18)
    table.add_column(style="bold white")

    if not store or not context.run_id:
        table.add_row("Status", "[dim]not available (no store for this run)[/dim]")
        return table

    from core.verification.grounding import (
        partition_verification_flags_by_host,
        summarize_verification_flags,
    )

    flags = store.get_verification_flags(context.run_id)
    counts = summarize_verification_flags(flags)
    style = "yellow" if counts["invalidated"] or counts["pending"] else "green"
    table.add_row("Summary", f"[{style}]{verification_summary_line(counts)}[/{style}]")

    if counts["invalidated"]:
        invalidated_hosts, _ = partition_verification_flags_by_host(flags)
        for host, host_flags in list(invalidated_hosts.items())[:10]:
            for f in host_flags:
                table.add_row("", f"[red]✗[/red] {host}: {f.get('claim', '')}")

    return table
