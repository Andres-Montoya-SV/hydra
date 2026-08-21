"""Terminal rendering for `hydra check-opsec` diagnostics."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.opsec_check import OpsecCheck

_LEVEL_STYLE = {
    "pass": "green",
    "warn": "yellow",
    "fail": "red",
    "info": "cyan",
}

_LEVEL_LABEL = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
    "info": "INFO",
}


def render_opsec_report(checks: list[OpsecCheck]) -> None:
    """Print the strict-OPSEC diagnostic report and a residual-risk reminder."""
    console = Console()
    table = Table(
        title="Strict OPSEC Diagnostic",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Result", width=6)
    table.add_column("Check", max_width=28)
    table.add_column("Detail", overflow="fold")
    table.add_column("Remediation", overflow="fold", max_width=40)

    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for check in checks:
        counts[check.level] = counts.get(check.level, 0) + 1
        style = _LEVEL_STYLE.get(check.level, "white")
        label = _LEVEL_LABEL.get(check.level, check.level.upper())
        table.add_row(
            f"[{style}]{label}[/{style}]",
            check.name,
            check.message,
            check.remediation or "—",
        )

    summary = (
        f"[green]{counts['pass']} pass[/green] · "
        f"[yellow]{counts['warn']} warn[/yellow] · "
        f"[red]{counts['fail']} fail[/red] · "
        f"[cyan]{counts['info']} info[/cyan]"
    )
    console.print(Panel(table, subtitle=summary, border_style="blue"))

    if any(c.level == "fail" for c in checks):
        console.print(
            "[bold red]Strict OPSEC checks FAILED.[/bold red] "
            "Fix the items above before running a proxy-routed scan."
        )
    else:
        console.print(
            "[bold]Result:[/bold] Strict OPSEC checks passed for this configuration.\n"
            "This is exposure [italic]reduction[/italic], not anonymity — the proxy "
            "operator, target-side fingerprinting, passive intel providers, and "
            "endpoint compromise can still correlate activity. See README § Strict "
            "OPSEC mode for the full list of residual risks."
        )
