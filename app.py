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
from core.models import PipelineContext
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
    run_parser.add_argument(
        "--external",
        action="store_true",
        help=(
            "Force external-target-mode conservative defaults (lower rate limits; "
            "confirm before running active modules) regardless of OWNED_DOMAINS. "
            "Applied automatically when the target isn't in OWNED_DOMAINS."
        ),
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

    # Coherence pass: every `--run-id` below uses the exact same help text
    # `investigate` already established ("Run to query (default:
    # latest)") — previously several of these commands left both `domain`
    # and `--run-id` with no help text at all, so `--help` showed only the
    # bare argument name.
    graph_p = subparsers.add_parser("graph", help="Show intelligence-graph neighborhood")
    graph_p.add_argument("domain", help="Domain to center the graph on")
    graph_p.add_argument("--run-id", help="Run to query (default: latest)")

    rel_p = subparsers.add_parser("relationships", help="List evidence-backed relationships")
    rel_p.add_argument("domain", help="Domain to list relationships for")
    rel_p.add_argument("--run-id", help="Run to query (default: latest)")

    ev_p = subparsers.add_parser(
        "evidence",
        help="Show evidence for a domain or a relationship id (no rescan)",
    )
    ev_p.add_argument("domain", help="Domain or 32-char relationship_id")
    ev_p.add_argument("--run-id", help="Run to query (default: latest)")

    cert_p = subparsers.add_parser("certificates", help="Certificates linked to a domain")
    cert_p.add_argument("domain", help="Domain to list certificates for")
    cert_p.add_argument("--run-id", help="Run to query (default: latest)")

    ind_p = subparsers.add_parser("indicators", help="Indicator-queue rows for a domain")
    ind_p.add_argument("domain", help="Domain to list indicator-queue rows for")
    ind_p.add_argument("--run-id", help="Run to query (default: latest)")

    explain_p = subparsers.add_parser(
        "explain-collection",
        help="Reconstruct why an indicator was (or wasn't) collected, from SQLite alone (no rescan)",
    )
    explain_p.add_argument(
        "identifier", help="indicator_id, collection_attempt_id, or raw indicator value"
    )
    explain_p.add_argument("--run-id", help="Run to query (default: latest)")

    diff_p = subparsers.add_parser(
        "diff",
        help="Field-level diff of two persisted runs, or latest two finished runs for a domain",
    )
    diff_p.add_argument("run_a", help="Previous run id, or domain when used alone")
    diff_p.add_argument("run_b", nargs="?", default=None, help="Current run id")

    verify_p = subparsers.add_parser(
        "verification-flags",
        help="Contradiction flags the verification agent raised for a run (no rescan)",
    )
    verify_p.add_argument("run_id", help="Run to query")
    verify_p.add_argument(
        "--status", choices=["CONFIRMED", "DISMISSED", "UNRESOLVED"], help="Filter by status"
    )

    assess_p = subparsers.add_parser(
        "assess-reportability",
        help=(
            "Assess persisted findings' bounty eligibility against a program's rules text "
            "via Claude and/or OpenAI — opt-in, spends real API credits, never run by 'run'"
        ),
    )
    assess_p.add_argument("run_id", help="Run whose findings to assess")
    assess_p.add_argument(
        "--program-rules",
        required=True,
        type=Path,
        help="Path to the program's rules text (plain text or Markdown)",
    )
    assess_p.add_argument("--severity", help="Comma-separated severities to include (default: all)")
    assess_p.add_argument("--host", help="Only assess findings for this host")
    assess_p.add_argument(
        "--limit",
        type=int,
        help="Override REPORTABILITY_MAX_FINDINGS_PER_BATCH for this run",
    )
    assess_p.add_argument(
        "--provider",
        choices=["anthropic", "openai"],
        help="Primary provider (default: REPORTABILITY_PROVIDER, itself defaulting to anthropic)",
    )
    assess_p.add_argument(
        "--adversarial-provider",
        choices=["anthropic", "openai"],
        help=(
            "Enable adversarial cross-validation: a second, different provider reviews the "
            "primary provider's structured verdicts. Any real disagreement is reported as "
            "UNCERTAIN rather than resolved in either provider's favor. "
            "(default: REPORTABILITY_ADVERSARIAL_PROVIDER, unset by default = disabled)"
        ),
    )
    assess_p.add_argument(
        "--allow-fuzzy-grounding",
        action="store_true",
        help=(
            "Allow a citation to be marked grounded via approximate text-similarity matching, "
            "not just exact/normalized substring matching. Off by default (design v2: this is "
            "the weakest, most conservative-by-default grounding tier)."
        ),
    )
    assess_p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation (required for non-interactive/automated use)",
    )

    hypotheses_p = subparsers.add_parser(
        "suggest-hypotheses",
        help=(
            "Propose investigation leads from a run's already-correlated relationships via "
            "Claude and/or OpenAI — opt-in, spends real API credits, never run by 'run'"
        ),
    )
    hypotheses_p.add_argument("run_id", help="Run whose relationships/entities to consider")
    hypotheses_p.add_argument(
        "--limit",
        type=int,
        help="Override HYPOTHESIS_MAX_RELATIONSHIPS_PER_BATCH for this run",
    )
    hypotheses_p.add_argument(
        "--provider",
        choices=["anthropic", "openai"],
        help="Primary provider (default: HYPOTHESIS_PROVIDER, itself defaulting to anthropic)",
    )
    hypotheses_p.add_argument(
        "--adversarial-provider",
        choices=["anthropic", "openai"],
        help=(
            "Enable reasoning-soundness review: a second, different provider audits whether "
            "each hypothesis's conclusion actually follows from the evidence it cited — never "
            "an independently-generated second hypothesis compared for disagreement. "
            "(default: HYPOTHESIS_ADVERSARIAL_PROVIDER, unset by default = disabled)"
        ),
    )
    hypotheses_p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation (required for non-interactive/automated use)",
    )

    client_report_p = subparsers.add_parser(
        "client-report",
        help=(
            "Generate a plain-language, tool-name-free draft report (Markdown or Word) from "
            "a run's persisted findings — a starting point to review and send to a client, "
            "never run by 'run', never sent automatically"
        ),
    )
    client_report_p.add_argument("run_id", help="Run to generate the client report for")
    client_report_p.add_argument(
        "--output",
        type=Path,
        help=(
            "Where to write the draft (default: <run_dir>/client_report.md or "
            "client_report.docx depending on --format)"
        ),
    )
    client_report_p.add_argument(
        "--format",
        dest="report_format",
        choices=["markdown", "docx"],
        default="markdown",
        help=(
            "Output format — 'markdown' (default, no extra dependency) or 'docx' "
            "(requires python-docx, requirements-optional.txt)"
        ),
    )
    client_report_p.add_argument(
        "--language",
        choices=["en", "es"],
        default="es",
        help=(
            "Language for the report's fixed text — headings, explanations, "
            "recommendations (default: es, unchanged from before this flag existed). "
            "Real findings/hosts/domains are never translated either way."
        ),
    )
    client_report_p.add_argument(
        "--company-name",
        dest="company_name",
        default=None,
        help=(
            "White-label the report with this name (an attribution line under the "
            "title/cover, both formats) instead of no branding at all. Omit for the "
            "default, unbranded report — unchanged from before this flag existed."
        ),
    )

    engagement_p = subparsers.add_parser(
        "engagement",
        help=(
            "Run recon, then walk through reportability assessment and a client-report "
            "draft in one guided flow — same confirmation gates as running each step by "
            "hand, never skips a money-spending confirmation, always headless (no dashboard)"
        ),
    )
    engagement_p.add_argument("-d", "--domain", help="Single target domain (e.g. example.com)")
    engagement_p.add_argument(
        "-f",
        "--file",
        type=Path,
        dest="targets_file",
        help="File with target domains (one per line)",
    )
    engagement_p.add_argument("--run-id", help="Custom run identifier for output directory")
    engagement_p.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the startup ASCII banner (also: HYDRA_NO_BANNER=1)",
    )
    engagement_p.add_argument(
        "--external",
        action="store_true",
        help=(
            "Force external-target-mode conservative defaults (lower rate limits; "
            "confirm before running active modules) regardless of OWNED_DOMAINS. "
            "Applied automatically when the target isn't in OWNED_DOMAINS."
        ),
    )
    engagement_p.add_argument(
        "--program-rules",
        type=Path,
        help=(
            "Path to the program's rules text — enables the reportability-assessment "
            "step below. Omit to skip that step automatically (same effect as "
            "--skip-reportability)."
        ),
    )
    engagement_p.add_argument(
        "--provider",
        choices=["anthropic", "openai"],
        help=(
            "Reportability primary provider, if that step runs "
            "(default: REPORTABILITY_PROVIDER, itself defaulting to anthropic)"
        ),
    )
    engagement_p.add_argument(
        "--adversarial-provider",
        choices=["anthropic", "openai"],
        help=(
            "Reportability adversarial provider, if that step runs "
            "(default: REPORTABILITY_ADVERSARIAL_PROVIDER, unset by default = disabled)"
        ),
    )
    engagement_p.add_argument(
        "--client-report-format",
        dest="client_report_format",
        choices=["markdown", "docx"],
        help=(
            "Client-report format to use if you accept that step " "(default: ask interactively)"
        ),
    )
    engagement_p.add_argument(
        "--client-report-language",
        dest="client_report_language",
        choices=["en", "es"],
        default="es",
        help=(
            "Language for the client-report draft's fixed text, if you accept that "
            "step (default: es, same as client-report's own default)"
        ),
    )
    engagement_p.add_argument(
        "--skip-reportability",
        action="store_true",
        help="Never offer the reportability-assessment step, interactive or not",
    )
    engagement_p.add_argument(
        "--skip-client-report",
        action="store_true",
        help="Never offer the client-report-draft step, interactive or not",
    )

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


def _external_mode_preflight(args: argparse.Namespace, settings: Settings) -> bool:
    """Classify this run against OWNED_DOMAINS, apply conservative defaults
    when it's targeting something outside that list, and require explicit
    confirmation before running active modules directly against it — even
    when they're already `true` in .env. Mutates `settings` in place.

    A decline (interactive "N", or no terminal attached at all) disables
    only the specific gated module(s) for this run rather than aborting the
    whole pipeline — discovery/observation stages still proceed. Always
    returns True today; the bool return keeps the call site ready for a
    future case that should refuse to proceed at all.
    """
    from core.external_mode import (
        EXTERNAL_MODE_GATED_FLAGS,
        classify_run,
        format_scope_summary,
    )
    from core.intel.scope import CollectionScope
    from utils.validators import load_targets

    if getattr(args, "external", False):
        settings.external_target_mode = True

    targets = load_targets(args.domain, args.targets_file, project_root=settings.project_root)
    domain_names = [t.domain for t in targets]
    if not classify_run(domain_names, settings):
        return True  # owned domain(s) — no behavior change

    changes = settings.apply_external_target_mode_defaults()
    scope = CollectionScope.from_seeds(
        domain_names,
        scope_file=settings.scope_file,
        cloud_collection_allowed=settings.cloud_bucket_enum_authorize_derived,
    )
    print(f"\n{'=' * 70}")
    print("EXTERNAL TARGET MODE — target(s) not in OWNED_DOMAINS")
    print("=" * 70)
    print(format_scope_summary(scope, settings))
    if changes:
        print("  Conservative overrides applied:")
        for change in changes:
            print(f"    {change}")
    active_gated = [name for name in EXTERNAL_MODE_GATED_FLAGS if getattr(settings, name)]
    if active_gated:
        print(
            "\nActive module(s) that would send traffic directly at this target: "
            + ", ".join(active_gated)
        )
        if not sys.stdin.isatty():
            print(
                "Non-interactive stdin — disabling these module(s) for this run "
                "(fail closed). Re-run with a terminal attached to confirm, or "
                "pass explicit flags in an automated context you control."
            )
            for name in active_gated:
                setattr(settings, name, False)
        else:
            answer = input(
                "Confirm running these active modules against this external " "target [y/N]: "
            )
            if answer.strip().lower() not in {"y", "yes"}:
                print("Declined — disabling these module(s) for this run.")
                for name in active_gated:
                    setattr(settings, name, False)
    print()
    return True


async def _run_headless_pipeline(
    settings: Settings,
    *,
    domain: str | None,
    targets_file: Path | None,
    run_id: str | None,
) -> tuple[int, PipelineContext]:
    """Run the reconnaissance pipeline without the terminal dashboard,
    printing the exact same dependency report / completion line /
    verification-flags summary line `run --no-ui` has always printed.
    Shared by `cmd_run` and the `engagement` orchestrator below, so the
    latter never reimplements pipeline execution — it only chains onto it.
    """
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
    context = await runner.run(domain=domain, targets_file=targets_file, run_id=run_id)
    if context.errors:
        for err in context.errors:
            app_logger.error(err)
    print(f"\nComplete. Output: {context.output_dir}")
    print(
        f"Subdomains: {len(context.subdomains)} | "
        f"Resolved: {len(context.resolved)} | "
        f"Alive: {len(context.alive_urls)}"
    )
    if context.run_id:
        from core.store import AssetStore
        from core.verification.grounding import summarize_verification_flags
        from ui.tables import verification_summary_line

        db_path = settings.project_root / settings.output_directory / "recon.db"
        if db_path.exists():
            flags = AssetStore(db_path).get_verification_flags(context.run_id)
            print(verification_summary_line(summarize_verification_flags(flags)))
    return (1 if context.errors else 0), context


async def cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    """Execute the reconnaissance pipeline."""
    if not args.domain and not args.targets_file:
        print("Error: Provide --domain or --file", file=sys.stderr)
        return 1

    _validate_cli_paths(args)

    if not _external_mode_preflight(args, settings):
        return 1

    if args.no_ui:
        rc, _context = await _run_headless_pipeline(
            settings, domain=args.domain, targets_file=args.targets_file, run_id=args.run_id
        )
        return rc

    context = await run_with_dashboard(
        settings,
        domain=args.domain,
        targets_file=args.targets_file,
        run_id=args.run_id,
    )
    return 1 if context.errors else 0


def _print_engagement_summary(generated: list[str]) -> None:
    print(f"\n{'=' * 70}")
    print("ENGAGEMENT SUMMARY")
    print("=" * 70)
    for line in generated:
        print(f"  - {line}")
    print(
        "\nNothing above was sent or published automatically — review each artifact "
        "yourself before sharing it."
    )


async def cmd_engagement(args: argparse.Namespace, settings: Settings) -> int:
    """`python app.py engagement` — the one-command version of the manual
    run -> investigate/verification-flags -> assess-reportability ->
    client-report sequence an operator otherwise has to remember and drive
    by hand. It chains those commands' own existing entry points, in that
    order, unchanged — every individual command still works exactly as it
    does today for anyone who wants to run a step by itself. Always runs
    the pipeline headless (no dashboard), since the guided prompts below
    need a normal top-to-bottom terminal flow.
    """
    if not args.domain and not args.targets_file:
        print("Error: Provide --domain or --file", file=sys.stderr)
        return 1

    _validate_cli_paths(args)

    if not _external_mode_preflight(args, settings):
        return 1

    rc, context = await _run_headless_pipeline(
        settings, domain=args.domain, targets_file=args.targets_file, run_id=args.run_id
    )
    if rc != 0 or not context.run_id:
        print(
            "\nReconnaissance run did not complete cleanly — stopping before the "
            "optional reportability/client-report steps.",
            file=sys.stderr,
        )
        return rc or 1

    run_id = context.run_id
    domain = args.domain or (context.targets[0].domain if context.targets else "")
    generated = [f"Reconnaissance run {run_id!r}: {context.output_dir}"]

    from core.intel.cli import cmd_investigate, cmd_verification_flags, default_db

    db_path = default_db(settings.project_root, settings.output_directory)
    print(f"\n{'=' * 70}")
    print("RUN SUMMARY")
    print("=" * 70)
    if db_path.exists() and domain:
        cmd_investigate(db_path, domain, run_id, None)
        cmd_verification_flags(db_path, run_id)

    # --- Reportability assessment: opt-in, spends real API credits. Reuses
    # assess-reportability's own cost-estimate + confirmation gate
    # unmodified — this step never asks a second, different question, it
    # just decides whether to invoke that exact same flow.
    if args.skip_reportability:
        print("\nSkipping reportability assessment (--skip-reportability).")
    elif not args.program_rules:
        print(
            "\nSkipping reportability assessment — no --program-rules file provided "
            "(same as --skip-reportability)."
        )
    else:
        from core.reportability.cli import (
            cmd_assess_reportability,
            provider_credentials,
            provider_env_var,
        )
        from core.reportability.provider import SUPPORTED_PROVIDERS

        provider_name = args.provider or settings.reportability_provider
        api_key = None
        if provider_name in SUPPORTED_PROVIDERS:
            api_key, _ = provider_credentials(settings, provider_name)
        if not api_key:
            env_var = (
                provider_env_var(provider_name)
                if provider_name in SUPPORTED_PROVIDERS
                else "ANTHROPIC_API_KEY/OPENAI_API_KEY"
            )
            print(
                f"\nSkipping reportability assessment — {env_var} is not configured. "
                "This step is opt-in and does nothing without it — see "
                "docs/REPORTABILITY_AGENT_DESIGN.md and config/.env.example."
            )
        else:
            print(f"\n{'=' * 70}")
            print("REPORTABILITY ASSESSMENT — optional, spends real API credits")
            print("=" * 70)
            if not sys.stdin.isatty():
                print(
                    "Non-interactive stdin — refusing to spend API credits without "
                    "confirmation (fail closed). Re-run with a terminal attached to "
                    "confirm, or pass --skip-reportability in an automated context "
                    "you control.",
                    file=sys.stderr,
                )
                return 1
            assess_rc = cmd_assess_reportability(
                settings,
                run_id,
                args.program_rules,
                provider=args.provider,
                adversarial_provider=args.adversarial_provider,
                yes=False,
            )
            if assess_rc != 0:
                # Declined, fail-closed, or a real error — assess-reportability
                # already printed the specific reason itself. Either way this
                # optional step didn't complete, so the chain stops here
                # without asking about a client report next.
                _print_engagement_summary(generated)
                return 0
            generated.append(f"Reportability assessment: persisted for run {run_id!r}")

    # --- Client report draft: never sent anywhere automatically. ---
    if args.skip_client_report:
        print("\nSkipping client report draft (--skip-client-report).")
    else:
        print(f"\n{'=' * 70}")
        print("CLIENT REPORT DRAFT — optional")
        print("=" * 70)
        if not sys.stdin.isatty():
            print(
                "Non-interactive stdin — skipping the client report draft (never "
                "assumes yes). Pass --skip-client-report to silence this, or run "
                "`client-report` directly once you can confirm interactively."
            )
        else:
            answer = input("Generate a client report draft? [y/N]: ")
            if answer.strip().lower() in {"y", "yes"}:
                report_format = args.client_report_format
                if report_format is None:
                    fmt_answer = input("Format — markdown or docx? [markdown]: ").strip().lower()
                    report_format = fmt_answer or "markdown"
                    if report_format not in {"markdown", "docx"}:
                        print(f"Unrecognized format {report_format!r} — using markdown.")
                        report_format = "markdown"
                from core.client_report.cli import cmd_client_report

                report_rc = cmd_client_report(
                    settings,
                    run_id,
                    output_format=report_format,
                    language=args.client_report_language,
                )
                if report_rc == 0:
                    generated.append(
                        f"Client report draft ({report_format}, " f"{args.client_report_language})"
                    )
            else:
                print("Declined — no client report generated.")

    _print_engagement_summary(generated)
    return 0


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
        cmd_verification_flags,
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
    if args.command == "verification-flags":
        return cmd_verification_flags(db_path, run_id, getattr(args, "status", None))
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
        if args.command == "engagement":
            settings.validate_or_raise()
            return asyncio.run(cmd_engagement(args, settings))
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
            "verification-flags",
        }:
            return cmd_intel(args, settings)
        if args.command == "assess-reportability":
            from core.reportability.cli import cmd_assess_reportability

            return cmd_assess_reportability(
                settings,
                args.run_id,
                args.program_rules,
                severity=args.severity,
                host=args.host,
                limit=args.limit,
                yes=args.yes,
                provider=args.provider,
                adversarial_provider=args.adversarial_provider,
                allow_fuzzy_grounding=args.allow_fuzzy_grounding,
            )
        if args.command == "suggest-hypotheses":
            from core.hypotheses.cli import cmd_suggest_hypotheses

            return cmd_suggest_hypotheses(
                settings,
                args.run_id,
                limit=args.limit,
                yes=args.yes,
                provider=args.provider,
                adversarial_provider=args.adversarial_provider,
            )
        if args.command == "client-report":
            from core.client_report.cli import cmd_client_report

            return cmd_client_report(
                settings,
                args.run_id,
                output_path=args.output,
                output_format=args.report_format,
                language=args.language,
                branding=args.company_name,
            )
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
