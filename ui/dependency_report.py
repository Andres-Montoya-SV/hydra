"""Dependency health report for terminal display."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.dependencies.models import ToolHealth, ToolReport
from core.discovery.tool_discovery import DiscoveredTool

_HEALTH_STYLE = {
    ToolHealth.HEALTHY: "green",
    ToolHealth.DEGRADED: "yellow",
    ToolHealth.MISSING: "red",
}

_HEALTH_LABEL = {
    ToolHealth.HEALTHY: "Healthy",
    ToolHealth.DEGRADED: "Degraded",
    ToolHealth.MISSING: "Missing",
}


def render_dependency_report(
    tools: dict[str, DiscoveredTool | ToolReport],
    *,
    required_only: bool = False,
    enabled_only: bool = False,
    enabled_names: frozenset[str] | None = None,
) -> None:
    """Print phased dependency health report."""
    console = Console()
    table = Table(
        title="Dependency Report",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Health", width=10)
    table.add_column("Tool", width=14)
    table.add_column("Version", overflow="fold", max_width=20)
    table.add_column("Location", overflow="fold", max_width=40)
    table.add_column("Why", overflow="fold")
    table.add_column("Fix", overflow="fold", max_width=35)

    healthy = degraded = missing = 0

    items: list[tuple[str, ToolReport]] = []
    for name, entry in sorted(tools.items()):
        report = entry if isinstance(entry, ToolReport) else _discovered_to_report(entry)
        if enabled_only and enabled_names and name not in enabled_names:
            continue
        if required_only and not report.required:
            continue
        items.append((name, report))

    for _name, report in items:
        if report.health == ToolHealth.HEALTHY:
            healthy += 1
        elif report.health == ToolHealth.DEGRADED:
            degraded += 1
        else:
            missing += 1

        style = _HEALTH_STYLE.get(report.health, "white")
        label = _HEALTH_LABEL.get(report.health, report.health.value)
        version = report.version or "—"
        location = str(report.resolved_path) if report.resolved_path else "—"
        fix = report.recommendation or (
            "—" if report.health == ToolHealth.HEALTHY else report.install_hint
        )

        table.add_row(
            f"[{style}]{label}[/{style}]",
            report.display_name or report.name,
            version,
            location,
            report.status_reason or "—",
            fix if report.health != ToolHealth.HEALTHY else "—",
        )

    summary = (
        f"[green]{healthy} healthy[/green] · "
        f"[yellow]{degraded} degraded[/yellow] · "
        f"[red]{missing} missing[/red]"
    )
    console.print(Panel(table, subtitle=summary, border_style="blue"))


def _discovered_to_report(discovered: DiscoveredTool) -> ToolReport:
    from core.dependencies.models import CapabilityResult

    return ToolReport(
        name=discovered.name,
        display_name=discovered.name,
        required=False,
        health=discovered.health,
        configured_path=discovered.configured,
        resolved_path=discovered.absolute_path,
        version=discovered.version,
        in_path=discovered.in_path,
        can_execute=discovered.can_execute,
        capabilities=CapabilityResult(detected=frozenset(discovered.capabilities)),
        status_reason=discovered.status_reason,
        recommendation=discovered.recommendation,
        install_hint=discovered.install_hint,
    )
