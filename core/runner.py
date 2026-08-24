"""Async pipeline orchestrator for reconnaissance workflows."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from core.assets import ScanRun
from core.collectors import (
    ACTIVE_COLLECTION_PLUGINS,
    POST_HTTP_PLUGINS,
    RESOLVE_DNS_PLUGINS,
    STRICT_OPSEC_ALLOWED_PLUGINS,
    SUBDOMAIN_PLUGINS,
    URL_DISCOVERY_PLUGINS,
)
from core.diff import diff_runs
from core.exceptions import (
    ConfigurationError,
    PipelineInterruptedError,
    ToolNotFoundError,
    ValidationError,
)
from core.logger import get_logger
from core.models import PipelineContext, PipelineStage, ToolStatus
from core.normalizer import load_httpx_results
from core.plugin_base import PluginResult
from core.registry import HostRegistry
from core.reporter import ReportGenerator
from core.store import AssetStore
from core.tool_manager import ToolManager
from utils.files import dedupe_file, read_lines, write_lines
from utils.subprocess import terminate_all_processes
from utils.validators import load_targets, sanitize_run_id

if TYPE_CHECKING:
    from config.settings import Settings
    from core.intel.engine import IntelRunConfig
    from core.plugin_base import ReconPlugin

    StageCallback = Callable[[PipelineContext, PipelineStage, str], None]

logger = get_logger("runner")


def _dns_record_identity(record: dict) -> str:
    """Deterministic identity for DNS JSONL records. First write wins."""
    host = str(record.get("host") or "").strip().rstrip(".").lower()
    payload = {key: record[key] for key in sorted(record) if key not in {"timestamp", "rtt"}}
    payload["host"] = host
    return json.dumps(payload, sort_keys=True, default=str)


def intel_config_for_pipeline(context: PipelineContext, settings: Settings) -> IntelRunConfig:
    """Build the IntelRunConfig used by finalize and follow-up collection."""
    from core.intel.bounds import DiscoveryBounds
    from core.intel.engine import IntelRunConfig
    from core.intel.scope import CollectionScope, allows_active_collection
    from core.scope import load_scope_patterns

    scope = context.collection_scope
    if scope is None:
        patterns: list[str] = []
        if settings.scope_file:
            patterns = load_scope_patterns(settings.scope_file)
        scope = CollectionScope.from_seeds(
            [t.domain for t in context.targets],
            patterns=patterns,
        )
        context.collection_scope = scope
    collected = {
        host.lower().rstrip(".")
        for host in context.resolved
        if allows_active_collection(host, scope)
    }
    return IntelRunConfig(
        run_id=context.run_id,
        seed_domains=list(scope.seed_domains) or [t.domain for t in context.targets],
        scope_patterns=list(scope.scope_patterns),
        bounds=DiscoveryBounds.from_settings(settings),
        collected_domains=collected,
        emissions=list(context.intel_emissions),
    )


class PipelineRunner:
    """Orchestrates the reconnaissance pipeline with async execution."""

    def __init__(
        self,
        settings: Settings,
        on_stage_change: StageCallback | None = None,
        on_log: Callable[[str, str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.tool_manager = ToolManager(settings)
        self.reporter = ReportGenerator(settings)
        self.on_stage_change = on_stage_change
        self.on_log = on_log
        self._cancelled = False
        self._context_lock = asyncio.Lock()
        self._store: AssetStore | None = None
        self._plugin_semaphore: asyncio.Semaphore | None = None

    def cancel(self) -> None:
        """Request pipeline cancellation and terminate child processes."""
        self._cancelled = True
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(terminate_all_processes())
        except RuntimeError:
            pass

    # Human-readable phase labels for each pipeline stage
    _PHASE_LABELS: dict[str, str] = {
        "validate": "Validation",
        "subfinder": "Discovery",
        "dedupe": "Deduplication",
        "dnsx": "DNS Resolution",
        "httpx": "HTTP Probing",
        "optional": "Enrichment",
        "metadata": "Intelligence",
        "output": "Reporting",
        "display": "Complete",
    }

    def _emit_stage(
        self, context: PipelineContext, stage: PipelineStage, message: str = ""
    ) -> None:
        context.current_stage = stage
        context.current_phase = self._PHASE_LABELS.get(stage.value, stage.value.title())
        if self.on_stage_change:
            self.on_stage_change(context, stage, message)
        logger.info("Stage: %s %s", stage.value, message)

    def _emit_log(self, level: str, message: str) -> None:
        if self.on_log:
            self.on_log(level, message)
        log_fn = getattr(logger, level.lower(), logger.info)
        log_fn(message)

    def _check_cancelled(self, context: PipelineContext) -> None:
        if self._cancelled:
            context.interrupted = True
            raise PipelineInterruptedError("Pipeline interrupted by user")

    def _enforce_scope(self, targets: list) -> None:
        """Fail closed when SCOPE_FILE is set and a target is outside it."""
        scope_path = self.settings.scope_file
        if not scope_path:
            return
        from core.scope import load_scope_patterns, out_of_scope_targets

        patterns = load_scope_patterns(scope_path)
        names = [t.domain for t in targets if getattr(t, "domain", None)]
        rejected = out_of_scope_targets(names, patterns)
        if rejected:
            raise ConfigurationError(
                "Target(s) outside SCOPE_FILE: " + ", ".join(rejected) + f" (file: {scope_path})"
            )

    def _collection_scope_for(self, context: PipelineContext):
        from core.intel.scope import CollectionScope
        from core.scope import load_scope_patterns

        if context.collection_scope is not None:
            return context.collection_scope
        patterns: list[str] = []
        if self.settings.scope_file:
            patterns = load_scope_patterns(self.settings.scope_file)
        return CollectionScope.from_seeds(
            [t.domain for t in context.targets],
            patterns=patterns,
        )

    def _authorized_names(self, context: PipelineContext, names: list[str]) -> list[str]:
        from core.intel.scope import filter_authorized_indicators

        scope = self._collection_scope_for(context)
        context.collection_scope = scope
        return filter_authorized_indicators(names, scope)

    def _gate_active_input(
        self, context: PipelineContext, plugin: ReconPlugin, input_path: Path
    ) -> Path:
        """Filter collector input immediately before cache lookup and invocation."""
        if plugin.name not in ACTIVE_COLLECTION_PLUGINS:
            return input_path
        from core.intel.scope import authorize_plugin_input

        context.collection_scope = self._collection_scope_for(context)
        return authorize_plugin_input(context, input_path, plugin.name)

    def _enabled_plugins(self, names: frozenset[str]) -> list[ReconPlugin]:
        return [
            p for p in self.tool_manager.get_all_plugins() if p.is_enabled() and p.name in names
        ]

    def _dns_plugins(self) -> list[ReconPlugin]:
        return self._enabled_plugins(RESOLVE_DNS_PLUGINS)

    def _optional_plugins(self) -> list[ReconPlugin]:
        return [
            p
            for p in self.tool_manager.get_all_plugins()
            if p.is_enabled() and (p.name in URL_DISCOVERY_PLUGINS or p.name in POST_HTTP_PLUGINS)
        ]

    async def run(
        self,
        domain: str | None = None,
        targets_file: Path | None = None,
        run_id: str | None = None,
    ) -> PipelineContext:
        """Execute the full reconnaissance pipeline."""
        self.settings.ensure_directories()
        context = PipelineContext(
            output_dir=self.settings.project_root / self.settings.output_directory / "_pending",
            started_at=datetime.utcnow(),
        )

        try:
            if self.settings.strict_opsec and not self.settings.outbound_proxy_url:
                raise ConfigurationError(
                    "STRICT_OPSEC requires OUTBOUND_PROXY_URL; direct probes are blocked"
                )
            validated_run_id = sanitize_run_id(run_id) or datetime.utcnow().strftime(
                "%Y%m%d_%H%M%S"
            )
            self._emit_stage(context, PipelineStage.VALIDATE, "Validating targets")
            context.targets = load_targets(
                domain,
                targets_file,
                project_root=self.settings.project_root,
            )
            self._enforce_scope(context.targets)
            context.collection_scope = self._collection_scope_for(context)

            output_dir = self.settings.get_run_output_dir(validated_run_id)
            context.output_dir = output_dir
            context.run_id = validated_run_id
            context.metadata["opsec_mode"] = (
                "strict_proxy" if self.settings.strict_opsec else "standard"
            )
            context.metadata["direct_network_allowed"] = not self.settings.strict_opsec
            context.registry = HostRegistry(validated_run_id, output_dir)
            self._emit_log("INFO", f"Loaded {len(context.targets)} target(s)")

            if self.settings.strict_opsec:
                from core.opsec_check import enforce_opsec_gate

                enforce_opsec_gate(self.settings, self.tool_manager)

            db_path = self.settings.project_root / self.settings.output_directory / "recon.db"
            store = AssetStore(db_path)
            self._store = store
            store.create_run(
                ScanRun(
                    run_id=validated_run_id,
                    started_at=context.started_at.isoformat() + "Z",
                    targets=[t.domain for t in context.targets],
                    program_name=self.settings.program_name,
                )
            )

            tools_ok = await self.tool_manager.validate_tools(context)
            if not tools_ok and not self.settings.strict_opsec:
                await self.tool_manager.ensure_mandatory_tools()
            if self.settings.strict_opsec and not self.tool_manager.is_runnable("httpx"):
                raise ToolNotFoundError(
                    "httpx",
                    "Install httpx for strict OPSEC proxy-routed probing.",
                )

            self._check_cancelled(context)

            targets_path = output_dir / "targets.txt"
            write_lines(
                targets_path,
                [t.domain for t in context.targets],
                base_dir=output_dir,
            )
            whois = self.tool_manager.get_plugin("whois")
            if whois and whois.is_enabled() and self.tool_manager.is_runnable("whois"):
                await self._run_single_plugin(context, whois, targets_path)

            # Stage 2: Subdomain enumeration only (subfinder, assetfinder)
            self._emit_stage(context, PipelineStage.SUBFINDER, "Enumerating subdomains")
            subdomain_plugins = self._enabled_plugins(SUBDOMAIN_PLUGINS)
            await self._run_plugin_chain(context, subdomain_plugins, targets_path)

            self._check_cancelled(context)

            # Stage 3: Deduplicate
            self._emit_stage(context, PipelineStage.DEDUPE, "Removing duplicates")
            subs_path = output_dir / "subdomains.txt"
            if subs_path.exists():
                _, count = dedupe_file(subs_path, base_dir=output_dir)
                context.subdomains = read_lines(subs_path)
                self._emit_log("INFO", f"Deduplicated to {count} subdomains")
            else:
                context.add_warning("No subdomains file produced")
                write_lines(subs_path, [t.domain for t in context.targets], base_dir=output_dir)
                context.subdomains = [t.domain for t in context.targets]

            anew = self.tool_manager.get_plugin("anew")
            if anew and anew.is_enabled():
                await self._run_single_plugin(context, anew, subs_path)

            self._check_cancelled(context)

            # Stage 4a: Wildcard DNS canary — before trusting any subdomain
            # enumeration result under a catch-all zone.
            wildcard_check = self.tool_manager.get_plugin("wildcard_check")
            if (
                wildcard_check
                and wildcard_check.is_enabled()
                and self.tool_manager.is_runnable("wildcard_check")
                and self.tool_manager.is_runnable("dnsx")
            ):
                await self._run_single_plugin(context, wildcard_check, targets_path)

            # Stage 4: DNS resolution (+ optional port scan)
            self._emit_stage(context, PipelineStage.DNSX, "Resolving DNS")
            await self._run_plugin_chain(context, self._dns_plugins(), subs_path)

            resolved_path = output_dir / "resolved.txt"
            if self.settings.strict_opsec:
                # Preserve hostnames for proxy-side resolution. Local DNS tools are
                # intentionally blocked because they would bypass the HTTP proxy.
                # Authorization still applies: out-of-scope names stay observations.
                authorized = self._authorized_names(context, context.subdomains)
                write_lines(
                    resolved_path,
                    authorized,
                    base_dir=output_dir,
                )
                context.resolved = authorized
                context.add_warning(
                    "Strict OPSEC: direct DNS, WHOIS, ASN, port, crawler, and scanner "
                    "plugins were blocked; HTTP hostnames resolve through the proxy."
                )
            elif not resolved_path.exists() or resolved_path.stat().st_size == 0:
                context.resolved = []
                context.add_warning(
                    "DNS resolution produced no results. Unresolved hosts will NOT be HTTP-probed."
                )
            else:
                context.resolved = self._authorized_names(context, read_lines(resolved_path))
                write_lines(resolved_path, context.resolved, base_dir=output_dir)
                unresolved = len(context.subdomains) - len(context.resolved)
                if unresolved > 0:
                    context.add_warning(
                        f"{unresolved} subdomains did not resolve — excluded from HTTP probing"
                    )

            asn_lookup = self.tool_manager.get_plugin("asn_lookup")
            if (
                asn_lookup
                and asn_lookup.is_enabled()
                and self.tool_manager.is_runnable("asn_lookup")
            ):
                if context.resolved:
                    await self._run_single_plugin(context, asn_lookup, resolved_path)
                else:
                    # Previously this gate left asn_lookup in tools_skipped with
                    # no warning at all (run 20260806_183325). Always explain.
                    reason = "skipped: no resolved IPs available"
                    asn_lookup.update_status(
                        context,
                        ToolStatus.SKIPPED,
                        error_message=reason,
                    )
                    context.add_warning(f"ASN Lookup: {reason}")
                    context.total_skipped += 1

            naabu = self.tool_manager.get_plugin("naabu")
            if (
                naabu
                and naabu.is_enabled()
                and self.tool_manager.is_runnable("naabu")
                and context.resolved
            ):
                naabu_result = await self._run_single_plugin(context, naabu, resolved_path)
                port_verify = self.tool_manager.get_plugin("port_verify")
                if (
                    naabu_result
                    and naabu_result.success
                    and port_verify
                    and port_verify.is_enabled()
                    and self.tool_manager.is_runnable("port_verify")
                ):
                    await self._run_single_plugin(
                        context,
                        port_verify,
                        naabu_result.output_path or resolved_path,
                    )

            self._check_cancelled(context)

            # Stage 5: HTTP probing (resolved hosts only)
            self._emit_stage(context, PipelineStage.HTTPX, "Probing HTTP services")
            httpx = self.tool_manager.get_plugin("httpx")
            if httpx and self.tool_manager.is_runnable("httpx") and context.resolved:
                await self._run_single_plugin(context, httpx, resolved_path)
            elif not context.resolved:
                context.add_warning("Skipping httpx — no resolved hosts")

            context.metadata.setdefault("dns_probes", len(context.subdomains))
            context.metadata.setdefault("http_probes", len(context.resolved))
            await self._maybe_collect_followups(context, resolved_path)

            soft404_check = self.tool_manager.get_plugin("soft404_check")
            alive_path = output_dir / "alive.txt"
            if (
                soft404_check
                and soft404_check.is_enabled()
                and self.tool_manager.is_runnable("soft404_check")
                and (
                    context.httpx_results
                    or context.alive_urls
                    or (alive_path.exists() and alive_path.stat().st_size > 0)
                )
            ):
                await self._run_single_plugin(context, soft404_check, alive_path)

            param_fuzz = self.tool_manager.get_plugin("param_fuzz")
            if (
                param_fuzz
                and param_fuzz.is_enabled()
                and self.tool_manager.is_runnable("param_fuzz")
                and (
                    context.httpx_results
                    or context.alive_urls
                    or (alive_path.exists() and alive_path.stat().st_size > 0)
                )
            ):
                await self._run_single_plugin(context, param_fuzz, alive_path)

            cloud_bucket_enum = self.tool_manager.get_plugin("cloud_bucket_enum")
            if (
                cloud_bucket_enum
                and cloud_bucket_enum.is_enabled()
                and self.tool_manager.is_runnable("cloud_bucket_enum")
            ):
                await self._run_single_plugin(
                    context, cloud_bucket_enum, output_dir / "targets.txt"
                )

            threat_intel = self.tool_manager.get_plugin("threat_intel")
            if (
                threat_intel
                and threat_intel.is_enabled()
                and self.tool_manager.is_runnable("threat_intel")
            ):
                await self._run_single_plugin(context, threat_intel, output_dir / "alive.txt")

            if not context.httpx_results:
                context.httpx_results = load_httpx_results(output_dir / "httpx.json")
                if context.httpx_results:
                    self._emit_log(
                        "INFO",
                        f"Loaded {len(context.httpx_results)} httpx record(s) from httpx.json",
                    )

            skip_no_httpx = "no httpx results available for technology correlation"
            await self._run_httpx_dependent_plugin(
                context, "vuln_match", alive_path, skip_reason=skip_no_httpx
            )
            await self._run_httpx_dependent_plugin(
                context, "security_headers", alive_path, skip_reason=skip_no_httpx
            )

            self._check_cancelled(context)

            # Stage 6: Optional tools (URL archives + crawlers/scanners) — concurrent
            optional = [
                p for p in self._optional_plugins() if self.tool_manager.is_runnable(p.name)
            ]
            if optional:
                names = ", ".join(p.display_name for p in optional)
                self._emit_stage(context, PipelineStage.OPTIONAL, f"Running: {names}")
                alive_path = output_dir / "alive.txt"
                input_for_optional = resolved_path
                if alive_path.exists() and alive_path.stat().st_size > 0:
                    input_for_optional = alive_path
                await self._run_plugins_concurrent(context, optional, input_for_optional)

            await self._maybe_collect_followups(context, resolved_path)

            browser_probe = self.tool_manager.get_plugin("browser_probe")
            if (
                browser_probe
                and browser_probe.is_enabled()
                and self.tool_manager.is_runnable("browser_probe")
            ):
                await self._run_single_plugin(
                    context,
                    browser_probe,
                    output_dir / "alive.txt",
                )

            self._emit_stage(context, PipelineStage.METADATA, "Normalizing and validating")
            self._finalize_to_store(context, store)

            self._emit_stage(context, PipelineStage.OUTPUT, "Generating reports")
            self.reporter.generate(context, store=store)
            context.finalized = True

            self._emit_stage(context, PipelineStage.DISPLAY, "Complete")
            context.current_tool = None
            self._emit_log("INFO", f"Pipeline complete in {context.duration_seconds:.1f}s")

        except PipelineInterruptedError:
            context.add_warning("Pipeline was interrupted")
            self._emit_log("WARNING", "Pipeline interrupted")
            await terminate_all_processes()
        except (ToolNotFoundError, ValidationError, ConfigurationError) as exc:
            context.add_error(str(exc))
            self._emit_log("ERROR", str(exc))
        except Exception as exc:
            context.add_error("An unexpected error occurred. Check logs for details.")
            self._emit_log("ERROR", "An unexpected error occurred. Check logs for details.")
            logger.exception("Pipeline failed: %s", type(exc).__name__)
        finally:
            context.current_tool = None
            context.finished_at = datetime.utcnow()
            await terminate_all_processes()
            try:
                if not context.finalized and context.run_id and context.subdomains:
                    db_path = (
                        self.settings.project_root / self.settings.output_directory / "recon.db"
                    )
                    store = AssetStore(db_path)
                    self._finalize_to_store(context, store)
                    self.reporter.generate(context, store=store)
                    context.finalized = True
            except Exception:
                logger.exception("Partial report generation failed")

        return context

    def schedule_followup_collection(self, context: PipelineContext, engine):
        """Claim, re-authorize, and write collector inputs. One bounded pass."""
        from core.intel.followup import load_wildcard_roots, plan_followup_collection
        from core.intel.model import IndicatorKind

        collected = {host.lower().rstrip(".") for host in context.resolved}
        claimed = engine.eligible_followups(IndicatorKind.DOMAIN)
        dns_left = self.settings.max_dns_probes - int(context.metadata.get("dns_probes") or 0)
        http_left = self.settings.max_http_probes - int(context.metadata.get("http_probes") or 0)
        plan = plan_followup_collection(
            candidates=claimed,
            scope=self._collection_scope_for(context),
            wildcard_roots=load_wildcard_roots(context.output_dir, context.metadata),
            already_collected=collected,
            dns_budget=dns_left,
            http_budget=http_left,
        )
        # Never trust the planner output either — re-check the hard gate.
        plan.dns_targets = self._authorized_names(context, plan.dns_targets)
        plan.http_targets = self._authorized_names(context, plan.http_targets)
        authorized = set(plan.dns_targets) | set(plan.http_targets)
        for decision in plan.decisions:
            if decision.allowed and decision.hostname not in authorized:
                decision.allowed = False
                decision.reason = "out_of_scope"
                decision.allow_dns = False
                decision.allow_http = False
        for decision in plan.rejected():
            engine.queue.mark_rejected(
                IndicatorKind.DOMAIN, decision.hostname, reason=decision.reason
            )
        write_lines(
            context.output_dir / "followup_domains.txt",
            plan.dns_targets,
            base_dir=context.output_dir,
        )
        write_lines(
            context.output_dir / "followup_http_targets.txt",
            plan.http_targets,
            base_dir=context.output_dir,
        )
        # Defense in depth: never schedule naabu against untrusted queue names.
        write_lines(
            context.output_dir / "followup_naabu_targets.txt",
            plan.dns_targets,
            base_dir=context.output_dir,
        )
        context.metadata["followup_dns_targets"] = list(plan.dns_targets)
        context.metadata["followup_http_targets"] = list(plan.http_targets)
        context.metadata["followup_rejected"] = [
            {"host": item.hostname, "reason": item.reason} for item in plan.rejected()
        ]
        return plan

    async def _maybe_collect_followups(self, context: PipelineContext, resolved_path: Path) -> None:
        """One bounded follow-up pass for in-scope indicators discovered from evidence."""
        settings = self.settings
        if not settings.enable_followup_collection or settings.max_discovery_depth < 1:
            return
        elapsed = context.duration_seconds
        if elapsed >= settings.max_runtime_seconds:
            context.add_warning("Follow-up collection skipped: MAX_RUNTIME reached")
            return

        from core.intel.engine import IntelEngine
        from core.intel.model import IndicatorKind

        collected = {host.lower().rstrip(".") for host in context.resolved}
        previously_claimed = [
            str(item).lower().rstrip(".")
            for item in (context.metadata.get("followup_claimed_indicators") or [])
            if item
        ]
        config = intel_config_for_pipeline(context, settings)
        engine = IntelEngine(config)
        for domain in collected:
            engine.queue.mark_collected(IndicatorKind.DOMAIN, domain)
        if context.registry:
            engine.ingest_hosts(context.registry.to_dict())
        engine.ingest_artifacts(context.output_dir)
        for domain in previously_claimed:
            engine.queue.mark_collected(IndicatorKind.DOMAIN, domain)
        engine.queue.followups_enqueued = max(
            engine.queue.followups_enqueued,
            int(context.metadata.get("followup_enqueued") or 0),
        )
        engine.queue.budget_used = max(
            engine.queue.budget_used,
            int(context.metadata.get("followup_budget_used") or 0),
        )
        plan = self.schedule_followup_collection(context, engine)
        claimed = list(dict.fromkeys([*previously_claimed, *plan.dns_targets, *plan.http_targets]))
        context.metadata["followup_claimed_indicators"] = claimed
        context.metadata["followup_enqueued"] = engine.queue.followups_enqueued
        context.metadata["followup_budget_used"] = engine.queue.budget_used
        if not plan.dns_targets and not plan.http_targets:
            return

        context.add_warning(
            f"Bounded follow-up: collecting {len(plan.dns_targets)} in-scope indicator(s) "
            f"(depth<={settings.max_discovery_depth})"
        )

        dnsx_plugins = self._dns_plugins()
        follow_path = context.output_dir / "followup_domains.txt"
        if (
            plan.dns_targets
            and dnsx_plugins
            and self.tool_manager.is_runnable("dnsx")
            and not settings.strict_opsec
        ):
            context.metadata["dnsx_output_suffix"] = "_followup"
            try:
                await self._run_plugin_chain(context, dnsx_plugins, follow_path)
            finally:
                context.metadata.pop("dnsx_output_suffix", None)
            self._merge_dnsx_followup(context)
            context.metadata["dns_probes"] = int(context.metadata.get("dns_probes") or 0) + len(
                plan.dns_targets
            )
            for host in plan.dns_targets:
                engine.queue.mark_collected(IndicatorKind.DOMAIN, host)
        elif settings.strict_opsec and plan.http_targets:
            merged = self._authorized_names(context, list(context.resolved) + plan.http_targets)
            write_lines(resolved_path, merged, base_dir=context.output_dir)
            context.resolved = merged

        http_targets = [name for name in plan.http_targets if name in set(context.resolved)]
        if settings.strict_opsec:
            http_targets = list(plan.http_targets)
        if not http_targets:
            return
        httpx = self.tool_manager.get_plugin("httpx")
        if not (httpx and self.tool_manager.is_runnable("httpx")):
            return
        probe_path = context.output_dir / "followup_http_targets.txt"
        write_lines(probe_path, http_targets, base_dir=context.output_dir)
        context.metadata["httpx_output_suffix"] = "_followup"
        try:
            await self._run_single_plugin(context, httpx, probe_path)
        finally:
            context.metadata.pop("httpx_output_suffix", None)
        self._merge_httpx_followup(context)
        context.metadata["http_probes"] = int(context.metadata.get("http_probes") or 0) + len(
            http_targets
        )
        for host in http_targets:
            engine.queue.mark_collected(IndicatorKind.DOMAIN, host)

    def _merge_dnsx_followup(self, context: PipelineContext) -> None:
        """Atomically union follow-up DNS into canonical artifacts without clobbering seed evidence."""
        from utils.files import read_jsonl, write_jsonl

        canonical_resolved = context.output_dir / "resolved.txt"
        follow_resolved = context.output_dir / "resolved_followup.txt"
        canonical_records = context.output_dir / "dnsx_records.jsonl"
        follow_records = context.output_dir / "dnsx_records_followup.jsonl"

        seed_hosts = read_lines(canonical_resolved) if canonical_resolved.exists() else []
        extra_hosts = read_lines(follow_resolved) if follow_resolved.exists() else []
        merged_hosts = self._authorized_names(
            context, list(context.resolved) + seed_hosts + extra_hosts
        )
        write_lines(canonical_resolved, merged_hosts, base_dir=context.output_dir)
        context.resolved = merged_hosts

        if follow_records.exists():
            merged_records: list[dict] = []
            seen: set[str] = set()
            for path in (canonical_records, follow_records):
                if not path.exists():
                    continue
                for record in read_jsonl(path):
                    key = _dns_record_identity(record)
                    if key in seen:
                        continue
                    seen.add(key)
                    merged_records.append(record)
            write_jsonl(canonical_records, merged_records, base_dir=context.output_dir)

    def _merge_httpx_followup(self, context: PipelineContext) -> None:
        from utils.files import read_jsonl, write_jsonl

        primary = context.output_dir / "httpx.json"
        extra = context.output_dir / "httpx_followup.json"
        if not extra.exists():
            return
        records = []
        if primary.exists():
            records.extend(read_jsonl(primary))
        records.extend(read_jsonl(extra))
        write_jsonl(primary, records, base_dir=context.output_dir)
        context.httpx_results = records
        extra_alive = context.output_dir / "alive_followup.txt"
        if extra_alive.exists():
            merged_alive = list(dict.fromkeys(context.alive_urls + read_lines(extra_alive)))
            from core.intel.scope import filter_authorized_indicators

            scope = getattr(context, "collection_scope", None)
            if scope is not None:
                merged_alive = filter_authorized_indicators(merged_alive, scope)
            write_lines(context.output_dir / "alive.txt", merged_alive, base_dir=context.output_dir)
            context.alive_urls = merged_alive

    def _finalize_to_store(self, context: PipelineContext, store: AssetStore) -> None:
        """Run intelligence engine and persist canonical hosts to SQLite."""
        httpx_path = context.output_dir / "httpx.json"
        context.httpx_results = load_httpx_results(httpx_path)

        registry = context.registry or HostRegistry(context.run_id, context.output_dir)
        registry.intel_config = intel_config_for_pipeline(context, self.settings)
        from core.parsers.registry import PARSER_REGISTRY

        for tool in PARSER_REGISTRY:
            registry.ingest(tool)

        hosts = registry.finalize()
        context.registry = registry

        context.alive_urls = []
        for host in hosts.values():
            for svc in host.http_services:
                if not svc.url or svc.url in context.alive_urls:
                    continue
                scope = getattr(context, "collection_scope", None)
                if scope is not None:
                    from core.intel.scope import allows_active_collection

                    if not allows_active_collection(svc.url, scope):
                        continue
                context.alive_urls.append(svc.url)

        context.store_warnings.extend(registry.warnings)
        for w in registry.warnings:
            context.add_warning(w)

        context.metadata["clusters"] = {c.cluster_id: len(c.members) for c in registry.clusters}
        context.metadata["graph_nodes"] = len(registry.graph.nodes)
        context.metadata["graph_edges"] = len(registry.graph.edges)

        store.persist_registry(
            context.run_id,
            hosts,
            clusters=registry.clusters,
            graph=registry.graph,
            intel=registry.intel,
        )

        store.finish_run(
            context.run_id,
            host_count=len(hosts),
            alive_count=len(context.alive_urls),
            warnings=context.warnings + context.store_warnings,
            errors=context.errors,
        )

        scan_diff = diff_runs(store, context.run_id)
        if scan_diff:
            from utils.files import write_json

            write_json(
                context.output_dir / "diff.json",
                scan_diff.to_dict(),
                base_dir=context.output_dir,
            )
            if scan_diff.new_hosts:
                context.add_warning(
                    f"Historical diff: {len(scan_diff.new_hosts)} new host(s) vs previous run"
                )
            from core.webhook import notify_scan_diff

            notify_scan_diff(self.settings.webhook_url, scan_diff.to_dict())

        self.reporter.collect_metadata(context, store=store)

    async def _run_httpx_dependent_plugin(
        self,
        context: PipelineContext,
        plugin_name: str,
        input_path: Path,
        *,
        skip_reason: str,
    ) -> PluginResult | None:
        """Run a plugin that needs structured httpx records, or skip with a reason.

        Previously vuln_match / security_headers were gated on a truthy
        ``context.httpx_results`` and vanished from tools_run / tools_skipped /
        tools_failed when the list was empty (cached httpx restored only
        alive.txt). A skip must always be visible in the report.
        """
        plugin = self.tool_manager.get_plugin(plugin_name)
        if plugin is None:
            return None
        if not plugin.is_enabled() or not self.tool_manager.is_runnable(plugin_name):
            return None
        if not context.httpx_results:
            plugin.update_status(context, ToolStatus.SKIPPED, error_message=skip_reason)
            warning = f"{plugin_name} skipped: {skip_reason}"
            context.add_warning(warning)
            context.total_skipped += 1
            self._emit_log("WARNING", warning)
            return PluginResult(success=False, skipped=True, message=warning)
        return await self._run_single_plugin(context, plugin, input_path)

    async def _run_single_plugin(
        self, context: PipelineContext, plugin: ReconPlugin, input_path: Path
    ):
        self._check_cancelled(context)
        if self.settings.strict_opsec and plugin.name not in STRICT_OPSEC_ALLOWED_PLUGINS:
            plugin.update_status(
                context,
                ToolStatus.SKIPPED,
                error_message="Blocked by strict OPSEC policy",
            )
            async with self._context_lock:
                context.total_skipped += 1
            return PluginResult(
                success=False,
                skipped=True,
                message="Blocked by strict OPSEC policy",
            )
        info = context.tool_states.get(plugin.name)
        if info and info.status in (ToolStatus.MISSING, ToolStatus.SKIPPED):
            async with self._context_lock:
                context.total_skipped += 1
            return None
        if not self.tool_manager.is_runnable(plugin.name):
            plugin.update_status(context, ToolStatus.SKIPPED)
            async with self._context_lock:
                context.total_skipped += 1
            return None

        context.current_tool = plugin.display_name
        plugin.update_status(context, ToolStatus.RUNNING)
        self._emit_log("INFO", f"Starting {plugin.display_name}...")
        logger.info("Starting plugin: %s", plugin.name)

        start = time.monotonic()
        try:
            input_path = self._gate_active_input(context, plugin, input_path)
            cached = self._load_cached_result(context, plugin, input_path)
            if cached:
                return cached
            result = await plugin.run(context, input_path)
            duration = time.monotonic() - start
            async with self._context_lock:
                if plugin.name in context.tool_states:
                    context.tool_states[plugin.name].duration_seconds = duration
            if result.skipped:
                plugin.update_status(context, ToolStatus.SKIPPED, duration_seconds=duration)
                async with self._context_lock:
                    context.total_skipped += 1
                self._emit_log("INFO", f"{plugin.display_name}: {result.message}")
                return result
            self._emit_log(
                "INFO" if result.success else "WARNING",
                f"{plugin.display_name}: {result.message or ('OK' if result.success else 'Failed')}",
            )
            if result and not result.skipped and context.registry:
                context.registry.ingest(plugin.name, artifact=result.output_path)
            if result and result.data and result.data.get("intel"):
                context.intel_emissions.append(result.data["intel"])
            if result and result.success and result.output_path:
                try:
                    result.output_path.chmod(0o600)
                except OSError:
                    pass
                self._store_cached_result(plugin, input_path, result)
            if result and not result.success and result.message and not result.skipped:
                async with self._context_lock:
                    context.add_error(f"{plugin.display_name}: {result.message}")
            return result
        except Exception as exc:
            duration = time.monotonic() - start
            async with self._context_lock:
                context.add_error(f"{plugin.display_name}: {exc}")
            plugin.update_status(
                context,
                ToolStatus.FAILED,
                duration_seconds=duration,
                error_message=str(exc),
            )
            logger.exception("Plugin %s failed", plugin.name)
            return None
        finally:
            if context.current_tool == plugin.display_name:
                context.current_tool = None

    async def _run_plugin_chain(
        self,
        context: PipelineContext,
        plugins: list[ReconPlugin],
        initial_input: Path,
    ) -> Path:
        current_input = initial_input
        for plugin in sorted(plugins, key=lambda p: p.stage_order):
            result = await self._run_single_plugin(context, plugin, current_input)
            if result and result.output_path and result.output_path.exists():
                current_input = result.output_path
        return current_input

    async def _run_plugins_concurrent(
        self,
        context: PipelineContext,
        plugins: list[ReconPlugin],
        input_path: Path,
    ) -> None:
        if not plugins:
            return
        results = await asyncio.gather(
            *[self._run_single_plugin_limited(context, p, input_path) for p in plugins],
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                async with self._context_lock:
                    context.add_error(f"Concurrent plugin error: {result}")

    async def _run_single_plugin_limited(
        self,
        context: PipelineContext,
        plugin: ReconPlugin,
        input_path: Path,
    ):
        limit = max(1, min(self.settings.threads, len(self.tool_manager.get_all_plugins())))
        if not hasattr(self, "_plugin_semaphore") or self._plugin_semaphore is None:
            self._plugin_semaphore = asyncio.Semaphore(limit)
        async with self._plugin_semaphore:
            return await self._run_single_plugin(context, plugin, input_path)

    def _cache_key(self, plugin: ReconPlugin, input_path: Path) -> tuple[str, str]:
        digest = hashlib.sha256()
        digest.update(plugin.name.encode("utf-8"))
        if input_path.exists():
            digest.update(input_path.read_bytes())
        digest.update(str(self.settings.timeout).encode("utf-8"))
        # Cache entries must never be shared between network modes: a result
        # fetched via direct (non-proxied) requests must not be replayed as a
        # "cache hit" for a later strict-OPSEC/proxied run of the same plugin
        # against the same input, or vice versa.
        digest.update(b"strict" if self.settings.strict_opsec else b"standard")
        digest.update((self.settings.outbound_proxy_url or "").encode("utf-8"))
        # Bust stale httpx caches that stored only alive.txt (no httpx.json /
        # response headers). Downstream vuln_match and security_headers need
        # the structured JSONL, not just the URL list.
        if plugin.name == "httpx":
            digest.update(b"httpx-json-v2-include-response-header")
        input_hash = digest.hexdigest()
        return f"{plugin.name}:{input_hash}", input_hash

    def _copy_cached_artifact(self, cached_path: Path, dest_dir: Path, plugin: ReconPlugin) -> Path:
        """Copy a cached file plus httpx siblings (json/alive/csv) into dest_dir."""
        names = {cached_path.name}
        if plugin.name == "httpx":
            names.update({"httpx.json", "alive.txt", "httpx.csv"})
        for name in names:
            src = cached_path.parent / name
            dest = dest_dir / name
            if src.exists() and src.is_file() and src.resolve() != dest.resolve():
                shutil.copy2(src, dest)
        return dest_dir / cached_path.name

    def _load_cached_result(
        self,
        context: PipelineContext,
        plugin: ReconPlugin,
        input_path: Path,
    ) -> PluginResult | None:
        if not self.settings.enable_cache or not self._store or not plugin.cacheable:
            return None
        cache_key, _input_hash = self._cache_key(plugin, input_path)
        entry = self._store.get_cache_entry(cache_key)
        if not entry:
            return None
        cached_path = Path(entry["artifact_path"])
        if not cached_path.exists() or not cached_path.is_file():
            return None
        output_path = self._copy_cached_artifact(cached_path, context.output_dir, plugin)
        apply_path = output_path
        httpx_json = context.output_dir / "httpx.json"
        if plugin.name == "httpx" and httpx_json.exists() and httpx_json.stat().st_size > 0:
            apply_path = httpx_json
        self._apply_cached_artifact(context, apply_path)
        if plugin.name == "httpx" and not context.httpx_results:
            self._emit_log(
                "WARNING",
                "httpx cache restored without httpx.json — structured probe data is empty",
            )
        plugin.update_status(
            context,
            ToolStatus.COMPLETED,
            output_lines=int(entry.get("lines_produced") or 0),
        )
        self._emit_log("INFO", f"{plugin.display_name}: reused cached artifact")
        if context.registry:
            context.registry.ingest(plugin.name, artifact=apply_path)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=int(entry.get("lines_produced") or 0),
            message="Reused cached artifact",
            data={"cached": True},
        )

    def _store_cached_result(
        self, plugin: ReconPlugin, input_path: Path, result: PluginResult
    ) -> None:
        if not self.settings.enable_cache or not self._store or not result.output_path:
            return
        if not plugin.cacheable:
            return
        if not result.output_path.exists() or result.skipped:
            return
        cache_key, input_hash = self._cache_key(plugin, input_path)
        self._store.set_cache_entry(
            cache_key,
            tool=plugin.name,
            input_hash=input_hash,
            artifact_path=str(result.output_path),
            lines_produced=result.lines_produced,
            ttl_seconds=self.settings.cache_ttl_seconds,
        )

    def _apply_cached_artifact(self, context: PipelineContext, output_path: Path) -> None:
        if output_path.name == "subdomains.txt":
            context.subdomains = read_lines(output_path)
        elif output_path.name == "resolved.txt":
            context.resolved = read_lines(output_path)
        elif output_path.name == "alive.txt":
            context.alive_urls = read_lines(output_path)
            httpx_json = context.output_dir / "httpx.json"
            if httpx_json.exists() and httpx_json.stat().st_size > 0:
                from utils.files import read_jsonl

                context.httpx_results = read_jsonl(httpx_json)
            self._restrict_alive_to_scope(context)
        elif output_path.name == "httpx.json":
            from utils.files import read_jsonl

            context.httpx_results = read_jsonl(output_path)
            alive_path = context.output_dir / "alive.txt"
            if alive_path.exists() and alive_path.stat().st_size > 0:
                context.alive_urls = read_lines(alive_path)
            elif context.httpx_results:
                from core.intel.scope import filter_authorized_indicators
                from modules.httpx import authorized_alive_url

                rebuilt: list[str] = []
                scope = getattr(context, "collection_scope", None)
                if scope is not None:
                    for rec in context.httpx_results:
                        url = authorized_alive_url(rec, scope)
                        if url:
                            rebuilt.append(url)
                    context.alive_urls = filter_authorized_indicators(rebuilt, scope)
                else:
                    context.alive_urls = [
                        str(rec.get("url") or rec.get("input") or "")
                        for rec in context.httpx_results
                        if rec.get("url") or rec.get("input")
                    ]
            self._restrict_alive_to_scope(context)

    def _restrict_alive_to_scope(self, context: PipelineContext) -> None:
        """alive.txt consumers must never inherit out-of-scope redirect landings."""
        scope = getattr(context, "collection_scope", None)
        if scope is None or not context.alive_urls:
            return
        from core.intel.scope import filter_authorized_indicators

        context.alive_urls = filter_authorized_indicators(context.alive_urls, scope)
