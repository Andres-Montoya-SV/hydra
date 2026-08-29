#!/usr/bin/env python3
"""Hydra — attack surface intelligence CLI entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
import traceback
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config.settings import Settings
from core.exceptions import ConfigurationError, ReconError, ValidationError
from core.heads import HEAD_BLURBS, print_banner
from core.logger import get_logger, setup_logging
from core.runner import PipelineRunner
from core.tool_manager import ToolManager
from ui.dashboard import run_with_dashboard
from utils.security import confine_path, validate_env_file
from utils.validators import sanitize_run_id


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="hydra",
        description="Hydra attack surface intelligence framework",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Hydra 1.0.0",
    )
    parser.add_argument(
        "-e",
        "--env",
        type=Path,
        default=None,
        help="Path to .env file (default: ./.env or ./config/.env)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the startup ASCII banner (also: HYDRA_NO_BANNER=1)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run reconnaissance pipeline")
    run_parser.add_argument("-d", "--domain", help="Single target domain (e.g. example.com)")
    run_parser.add_argument(
        "-f",
        "--file",
        type=Path,
        dest="targets_file",
        help="File with target domains (one per line)",
    )
    run_parser.add_argument("--no-ui", action="store_true", help="Run without terminal UI")
    run_parser.add_argument("--run-id", help="Custom run identifier for output directory")
    run_parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the startup ASCII banner (also: HYDRA_NO_BANNER=1)",
    )

    subparsers.add_parser("check-tools", help="Check availability of recon tools")
    subparsers.add_parser("list-plugins", help="List registered tool plugins")
    subparsers.add_parser(
        "heads",
        help="List Hydra heads (plugins) with opt-in status and a one-line role",
    )
    subparsers.add_parser("validate-config", help="Validate configuration and exit")

    opsec_parser = subparsers.add_parser(
        "check-opsec",
        help="Verify STRICT_OPSEC proxy reachability and behavior before a real scan",
    )
    opsec_parser.add_argument(
        "--reveal-direct-ip",
        action="store_true",
        help=(
            "Also make one non-proxied request to a public IP-echo service, so you "
            "can visually compare it against the proxied egress IP. Opt-in only: "
            "this deliberately sends one request from this machine's real address."
        ),
    )
    opsec_parser.add_argument(
        "--gate",
        action="store_true",
        help="Exit non-zero if any check is fail (same as default). Kept for scripts.",
    )
    opsec_parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Check configuration only; do not make live network requests.",
    )

    investigate = subparsers.add_parser(
        "investigate",
        help="Query persisted intelligence for a domain (no rescan)",
    )
    investigate.add_argument("domain", nargs="?", default="", help="Domain indicator")
    investigate.add_argument("--entity", help="Explicit entity value (same as domain)")
    investigate.add_argument("--run-id", help="Run to query (default: latest)")

    graph_p = subparsers.add_parser("graph", help="Show intelligence-graph neighborhood")
    graph_p.add_argument("domain", help="Domain to center the graph on")
    graph_p.add_argument("--run-id", help="Run to query (default: latest)")

    rel_p = subparsers.add_parser("relationships", help="List evidence-backed relationships")
    rel_p.add_argument("domain")
    rel_p.add_argument("--run-id")

    ev_p = subparsers.add_parser(
        "evidence",
        help="Show evidence for a domain or a relationship id (no rescan)",
    )
    ev_p.add_argument("domain", help="Domain or 32-char relationship_id")
    ev_p.add_argument("--run-id")

    cert_p = subparsers.add_parser("certificates", help="Certificates linked to a domain")
    cert_p.add_argument("domain")
    cert_p.add_argument("--run-id")

    ind_p = subparsers.add_parser("indicators", help="Indicator-queue rows for a domain")
    ind_p.add_argument("domain")
    ind_p.add_argument("--run-id")

    explain_p = subparsers.add_parser(
        "explain-collection",
        help="Reconstruct why an indicator was (or wasn't) collected, from SQLite alone (no rescan)",
    )
    explain_p.add_argument(
        "identifier", help="indicator_id, collection_attempt_id, or raw indicator value"
    )
    explain_p.add_argument("--run-id")

    diff_p = subparsers.add_parser(
        "diff",
        help="Field-level diff of two persisted runs, or latest two finished runs for a domain",
    )
    diff_p.add_argument("run_a", help="Previous run id, or domain when used alone")
    diff_p.add_argument("run_b", nargs="?", default=None, help="Current run id")

    return parser


def load_settings(env_arg: Path | None) -> Settings:
    """Load application settings from the environment.

    Values are parsed and type/format-checked (booleans, ints, headers, paths)
    but full cross-field validation is deliberately deferred to the caller via
    `settings.validate()` / `validate_or_raise()`. This lets diagnostic commands
    (`check-opsec`, `validate-config`) inspect a settings object that fails
    validation — e.g. STRICT_OPSEC=true with no proxy configured — instead of
    being unable to run at all.

    Args:
        env_arg: Optional explicit .env path from CLI.

    Returns:
        Parsed (not yet validated) Settings instance.

    Raises:
        ConfigurationError: If a value cannot be parsed at all (bad bool/int/header).
        ValidationError: If env file path is unsafe.
    """
    env_file: Path | None = None
    if env_arg is not None:
        env_file = validate_env_file(env_arg, _PROJECT_ROOT)
    else:
        for candidate in (_PROJECT_ROOT / ".env", _PROJECT_ROOT / "config" / ".env"):
            if candidate.exists():
                env_file = validate_env_file(candidate, _PROJECT_ROOT)
                break

    return Settings.from_env(env_file, project_root=_PROJECT_ROOT)


def _validate_cli_paths(args: argparse.Namespace) -> None:
    """Validate CLI path arguments before execution."""
    if getattr(args, "targets_file", None) is not None:
        confine_path(args.targets_file, _PROJECT_ROOT, must_exist=True)
    if getattr(args, "run_id", None) is not None:
        sanitize_run_id(args.run_id)


async def cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    """Execute the reconnaissance pipeline."""
    if not args.domain and not args.targets_file:
        print("Error: Provide --domain or --file", file=sys.stderr)
        return 1

    _validate_cli_paths(args)

    if args.no_ui:
        setup_logging(settings.log_level, settings.project_root / settings.logs_directory)
        from ui.dependency_report import render_dependency_report

        manager = ToolManager(settings)
        reports = await manager.dependency_service.analyze_all()
        enabled = frozenset(p.name for p in manager.get_all_plugins() if p.is_enabled()) | {
            "subfinder",
            "dnsx",
            "httpx",
        }
        render_dependency_report(reports, enabled_only=True, enabled_names=enabled)

        app_logger = get_logger("app")
        app_logger.info("Starting pipeline: %s", settings.to_safe_dict())

        runner = PipelineRunner(settings)
        context = await runner.run(
            domain=args.domain,
            targets_file=args.targets_file,
            run_id=args.run_id,
        )
        if context.errors:
            for err in context.errors:
                app_logger.error(err)
        print(f"\nComplete. Output: {context.output_dir}")
        print(
            f"Subdomains: {len(context.subdomains)} | "
            f"Resolved: {len(context.resolved)} | "
            f"Alive: {len(context.alive_urls)}"
        )
        return 1 if context.errors else 0

    context = await run_with_dashboard(
        settings,
        domain=args.domain,
        targets_file=args.targets_file,
        run_id=args.run_id,
    )
    return 1 if context.errors else 0


async def cmd_check_tools(settings: Settings) -> int:
    """Check tool availability and print dependency health report."""
    setup_logging(settings.log_level, settings.project_root / settings.logs_directory)
    from ui.dependency_report import render_dependency_report

    manager = ToolManager(settings)
    reports = await manager.dependency_service.analyze_all()
    render_dependency_report(reports)

    return 0 if manager.dependency_service.mandatory_satisfied(reports) else 1


def cmd_list_plugins(settings: Settings) -> int:
    """List registered plugins."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    manager = ToolManager(settings)

    table = Table(title="Registered Plugins")
    table.add_column("Name")
    table.add_column("Display Name")
    table.add_column("Capability")
    table.add_column("Produces")
    table.add_column("Required")
    table.add_column("Enabled")
    table.add_column("Stage Order")

    for plugin in manager.get_all_plugins():
        table.add_row(
            plugin.name,
            plugin.display_name,
            plugin.capability or "—",
            ",".join(plugin.produces) or "—",
            "Yes" if plugin.required else "No",
            "Yes" if plugin.is_enabled() else "No",
            str(plugin.stage_order),
        )

    console.print(table)
    return 0


def cmd_heads(settings: Settings) -> int:
    """List every registered plugin as a Hydra 'head'."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    manager = ToolManager(settings)

    table = Table(title="Hydra Heads")
    table.add_column("Head")
    table.add_column("Active")
    table.add_column("Opt-in")
    table.add_column("Role")

    for plugin in manager.get_all_plugins():
        enabled = plugin.is_enabled()
        opt_in = "no" if plugin.required else "yes"
        blurb = HEAD_BLURBS.get(plugin.name, plugin.display_name)
        table.add_row(
            plugin.name,
            "yes" if enabled else "no",
            opt_in,
            f"{plugin.name} — {blurb}",
        )

    console.print(table)
    return 0


def cmd_validate_config(settings: Settings) -> int:
    """Validate and print the configuration summary."""
    from rich.console import Console
    from rich.pretty import Pretty

    console = Console()
    errors = settings.validate()
    if errors:
        console.print("[bold red]Configuration is invalid:[/bold red]")
        for error in errors:
            console.print(f"  - {error}")
    else:
        console.print("[green]Configuration is valid.[/green]")
    console.print(Pretty(settings.to_safe_dict()))
    return 1 if errors else 0


def cmd_intel(args: argparse.Namespace, settings: Settings) -> int:
    """Query the SQLite intelligence store without running reconnaissance."""
    from core.intel.cli import (
        cmd_certificates,
        cmd_diff_runs,
        cmd_evidence,
        cmd_explain_collection,
        cmd_graph,
        cmd_indicators,
        cmd_investigate,
        cmd_relationships,
        default_db,
    )

    db_path = default_db(settings.project_root, settings.output_directory)
    if not db_path.exists():
        print(f"Error: intelligence database not found: {db_path}", file=sys.stderr)
        return 1
    run_id = getattr(args, "run_id", None)
    if args.command == "diff":
        run_b = getattr(args, "run_b", None)
        if not args.run_a:
            print("Error: provide DOMAIN or RUN_A RUN_B", file=sys.stderr)
            return 1
        return cmd_diff_runs(db_path, args.run_a, run_b)
    domain = getattr(args, "entity", None) or getattr(args, "domain", "")
    if args.command == "investigate":
        if not domain:
            print("Error: provide DOMAIN or --entity", file=sys.stderr)
            return 1
        return cmd_investigate(db_path, domain, run_id, getattr(args, "entity", None))
    if args.command == "graph":
        return cmd_graph(db_path, domain, run_id)
    if args.command == "relationships":
        return cmd_relationships(db_path, domain, run_id)
    if args.command == "evidence":
        return cmd_evidence(db_path, domain, run_id)
    if args.command == "certificates":
        return cmd_certificates(db_path, domain, run_id)
    if args.command == "indicators":
        return cmd_indicators(db_path, domain, run_id)
    if args.command == "explain-collection":
        return cmd_explain_collection(db_path, args.identifier, run_id)
    return 1


async def cmd_check_opsec(settings: Settings, *, reveal_direct_ip: bool, skip_network: bool) -> int:
    """Run STRICT_OPSEC pre-flight diagnostics and print a report."""
    from core.opsec_check import run_diagnostics, summarize_checks
    from ui.opsec_report import render_opsec_report

    manager = ToolManager(settings)
    checks = await run_diagnostics(
        settings,
        manager,
        reveal_direct_ip=reveal_direct_ip,
        skip_network=skip_network,
    )
    render_opsec_report(checks)
    print(summarize_checks(checks))
    return 1 if any(c.level == "fail" for c in checks) else 0


def main() -> int:
    """Application entry point with global error handling."""
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    try:
        settings = load_settings(args.env)
        settings.ensure_directories()

        if args.command == "run":
            # Fail closed only for real scans — diagnostic commands must still
            # be able to run against an invalid configuration to explain it.
            settings.validate_or_raise()
            return asyncio.run(cmd_run(args, settings))
        if args.command == "check-tools":
            return asyncio.run(cmd_check_tools(settings))
        if args.command == "list-plugins":
            return cmd_list_plugins(settings)
        if args.command == "heads":
            return cmd_heads(settings)
        if args.command == "validate-config":
            return cmd_validate_config(settings)
        if args.command == "check-opsec":
            return asyncio.run(
                cmd_check_opsec(
                    settings,
                    reveal_direct_ip=args.reveal_direct_ip,
                    skip_network=args.skip_network,
                )
            )
        if args.command in {
            "investigate",
            "graph",
            "relationships",
            "evidence",
            "certificates",
            "indicators",
            "explain-collection",
            "diff",
        }:
            return cmd_intel(args, settings)
        return 1

    except (ConfigurationError, ValidationError, ReconError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(
            "An unexpected error occurred. Run with LOG_LEVEL=DEBUG for details.", file=sys.stderr
        )
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
