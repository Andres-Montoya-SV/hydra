"""Runs an actual scan for one account, reusing `app.py`'s own pipeline
orchestration verbatim — `_external_mode_preflight` (OWNED_DOMAINS
classification, conservative external-target defaults, fail-closed
gated-module handling on non-interactive stdin, which every API request
always is) and `_run_headless_pipeline` (the same function `cmd_run
--no-ui` and `engagement` already share). This module adds exactly one
new thing on top of those: recording status transitions in the control-
plane `scans` table so `GET /scans/{id}` has something durable to read.

Called only by `api/scan_worker.py`'s worker loop, AFTER
`ControlDB.claim_next_queued_scan` has already atomically transitioned
the row to `'running'` — this function never sets that status itself
(it would be redundant, and touching `updated_at` again right after the
claim already did is pointless churn). It only ever moves the row
forward from there, to `'completed'` or `'failed'`.

Durable execution (surviving a worker crash mid-scan, bounded automatic
retries) is `api/scan_worker.py`'s concern, not this module's — see that
module's own docstring for the full design (heartbeat liveness, the
retry ceiling, what "durable" does and does not mean here).

**Continuous monitoring's Speed 1** (`trigger_source == "scheduled_passive"`,
`api/monitoring_worker.py`) runs through this EXACT same function, not a
second execution path — the only difference is that the account's
`Settings` object has its active-tool `enable_*` flags narrowed to the
genuinely-passive-source subset
(`api/monitoring.py::passive_monitoring_settings_overrides`) before the
pipeline runs. `account_settings()` already constructs a fresh,
throwaway `Settings` instance per call (see `api/tenancy.py`), so
mutating it here never touches the account's own persisted
configuration — there is nothing to restore afterward. `"manual"` and
`"scheduled_active"` (Speed 2) both run the full pipeline unchanged.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import TYPE_CHECKING

from api.control_db import ControlDB
from api.tenancy import account_db_path, account_settings

if TYPE_CHECKING:
    from api.settings import APISettings
    from config.settings import Settings
    from core.models import PipelineContext

# Matches this codebase's own existing severity vocabulary
# (core/assets.py::RiskLevel; every parser in core/parsers/registry.py
# already writes Finding.severity as one of these lowercase strings) —
# never a second severity scale invented for the webhook path.
_HIGH_SEVERITY_LEVELS = frozenset({"critical", "high"})
# Capped for the same reason api/monitoring.py's own notification email
# caps the domain list — a scan with hundreds of high-severity findings
# (a plausible worst case, e.g. a leaked-secrets sweep) gets one bounded,
# readable webhook payload, never an unbounded one.
_MAX_FINDINGS_PER_WEBHOOK = 20


async def _enqueue_scan_events(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    account_id: str,
    domain: str,
    scan_id: str,
    organization_id: str | None,
) -> None:
    """Productization Phase 08: this completed scan's integration events —
    high-severity findings, and the exposures it opened or reopened."""
    await _enqueue_high_severity_findings_event(
        api_settings=api_settings,
        control_db=control_db,
        account_id=account_id,
        domain=domain,
        scan_id=scan_id,
    )
    if organization_id:
        control_db.enqueue_exposure_lifecycle_events(organization_id, scan_id)


async def _enqueue_high_severity_findings_event(
    *, api_settings: APISettings, control_db: ControlDB, account_id: str, domain: str, scan_id: str
) -> None:
    """`finding.high_severity` — the one webhook event type this task
    added that isn't already computed elsewhere (unlike the monitoring
    events, which reuse `api/monitoring_worker.py`'s own significance
    decision). The severity filter itself
    (`severity in _HIGH_SEVERITY_LEVELS`) is the ONLY place that answers
    "is this finding severe" for this event — `api/webhooks.py::
    event_for_high_severity_findings` only shapes the already-filtered
    list into a payload, it never re-derives severity itself."""
    from api.webhooks import event_for_high_severity_findings
    from core.store import AssetStore

    store = AssetStore(account_db_path(api_settings, account_id))
    hosts = store.get_hosts(scan_id)
    findings = [
        {
            "host": host.domain,
            "template_id": finding.template_id,
            "severity": finding.severity,
            "name": finding.name,
        }
        for host in hosts
        for finding in host.findings
        if finding.severity in _HIGH_SEVERITY_LEVELS
    ][:_MAX_FINDINGS_PER_WEBHOOK]

    if not findings:
        return
    event = event_for_high_severity_findings(domain=domain, scan_id=scan_id, findings=findings)
    # Productization Phase 08: onto the durable integration outbox (delivered
    # by api/integration_worker.py), once per scan.
    control_db.enqueue_integration_event(
        account_id=account_id,
        organization_id=None,  # account-level: the account's own webhooks
        event_type=event.event_type,
        data=event.payload,
        dedup_key=f"finding.high_severity:{scan_id}",
    )


def _apply_collection_capabilities(
    control_db: ControlDB, settings: Settings, *, account_id: str, scan_id: str
) -> None:
    """Replaces the runtime role of the per-process `ENABLE_*` flags for API
    scans: the scan's own override, else its organization's saved default,
    else the account settings' current flags — clipped to the tier ceiling
    as of execution time."""
    from api import subscriptions
    from api.collection_capabilities import (
        apply_to_settings,
        enabled_in_settings,
        resolve_scan_providers,
    )

    scan = control_db.get_owned_scan(scan_id, account_id)
    if scan is None:
        return
    tier = subscriptions.effective_limits(
        subscriptions.get_or_create_subscription(control_db, account_id)
    ).tier
    enabled = resolve_scan_providers(
        override=None if scan.capability_override is None else frozenset(scan.capability_override),
        org_default=(
            control_db.get_org_collection_settings(scan.organization_id)
            if scan.organization_id
            else None
        ),
        current=enabled_in_settings(settings),
        tier=tier,
    )
    apply_to_settings(settings, enabled)


def _scan_settings(
    api_settings: APISettings,
    control_db: ControlDB,
    *,
    account_id: str,
    scan_id: str,
    passive: bool,
) -> Settings:
    """The account's settings with this scan's collection capabilities
    applied, narrowed for passive scans, and the effective provider set
    recorded on the scan."""
    from api.collection_capabilities import enabled_in_settings

    settings = account_settings(api_settings, account_id)
    settings.validate_or_raise()
    # Per-account settings don't read .env, so the service-level offline
    # geo database is handed to each scan explicitly.
    settings.geoip_db_path = api_settings.geoip_db_path
    _apply_collection_capabilities(control_db, settings, account_id=account_id, scan_id=scan_id)
    scan = control_db.get_owned_scan(scan_id, account_id)
    if scan is not None and scan.organization_id:
        settings.scope_exclusions = control_db.active_exclusion_patterns(scan.organization_id)

    # Productization Phase 01: a client-chosen 'passive' profile on a
    # manually-triggered scan gets the EXACT SAME narrowing Speed 1
    # monitoring already applies — one definition of "passive" for
    # this whole service, not a second one invented here.
    if passive:
        from api.monitoring import passive_monitoring_settings_overrides

        enable_flags = {k: v for k, v in vars(settings).items() if k.startswith("enable_")}
        for attr, value in passive_monitoring_settings_overrides(enable_flags).items():
            setattr(settings, attr, value)

    # Recorded AFTER any passive narrowing, so the scan shows exactly
    # which optional providers were allowed to run.
    control_db.set_scan_effective_providers(scan_id, enabled_in_settings(settings))
    return settings


def _record_provider_outcomes(
    control_db: ControlDB,
    organization_id: str,
    account_id: str,
    scan_id: str,
    context: PipelineContext,
) -> None:
    """Every tool's end-of-run state as a terminal execution outcome, with
    its failure class. A tool the run never reached (no input for it) is
    SKIPPED; recording its raw `ready` state used to raise and flip a clean
    scan to failed."""
    from core.provider_contract import failure_class, recorded_outcome

    states = sorted(context.tool_states.items())
    control_db.record_provider_run_outcomes(
        organization_id=organization_id,
        account_id=account_id,
        run_id=scan_id,
        outcomes=[(name, recorded_outcome(info).value, info.output_lines) for name, info in states],
        failure_classes={
            name: cls for name, info in states if (cls := failure_class(info)) is not None
        },
    )


async def execute_scan(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    account_id: str,
    scan_id: str,
    domain: str,
    trigger_source: str = "manual",
    collection_profile: str = "standard",
) -> None:
    import app as hydra_app  # deferred: heavy import graph (ToolManager, plugins, …)

    try:
        settings = _scan_settings(
            api_settings,
            control_db,
            account_id=account_id,
            scan_id=scan_id,
            passive=trigger_source == "scheduled_passive" or collection_profile == "passive",
        )
        preflight_args = argparse.Namespace(domain=domain, targets_file=None, external=False)
        hydra_app._external_mode_preflight(preflight_args, settings)

        rc, context = await hydra_app._run_headless_pipeline(
            settings, domain=domain, targets_file=None, run_id=scan_id
        )
        if rc != 0 or context.errors:
            control_db.update_scan_status(
                scan_id, "failed", error_message="; ".join(context.errors) or "scan reported errors"
            )
        else:
            control_db.update_scan_status(scan_id, "completed")
            # Persist the Fase-09 execution outcome ledger before any
            # downstream notification/workflow logic consumes the run.
            # This is run-level operational evidence only; it deliberately
            # does NOT auto-resolve asset exposures because provider success
            # alone is not proof of exhaustive per-asset coverage.
            scan_record = control_db.get_owned_scan(scan_id, account_id)
            if scan_record is not None and scan_record.organization_id:
                _record_provider_outcomes(
                    control_db, scan_record.organization_id, account_id, scan_id, context
                )
                # Fase 18 (EASM roadmap): the missing wiring found while
                # building monitoring integration -- without this call,
                # `assets`/`observations`/`change_events`/`exposures`/
                # etc. are never populated by a real scan (only ever by
                # tests), which would make the new EASM-aware monitoring
                # trigger silently see nothing. Runs in a thread (this is
                # synchronous DB work, replaying full scan history per
                # organization -- see api/easm_backfill.py's own
                # docstring for the known scaling caveat) and in its own
                # try/except: a backfill bug must never retroactively
                # fail an already-completed scan.
                from api.easm_backfill import run_easm_backfill_for_organization_safely

                await asyncio.to_thread(
                    run_easm_backfill_for_organization_safely,
                    control_db=control_db,
                    api_settings=api_settings,
                    organization_id=scan_record.organization_id,
                )
            # Deliberately its OWN try/except, never inside the same
            # scope as the scan's own status transition above: a bug or
            # a slow/unreachable webhook receiver here must never
            # retroactively turn an already-successfully-completed scan
            # into a "failed" one from the client's point of view.
            try:
                await _enqueue_scan_events(
                    api_settings=api_settings,
                    control_db=control_db,
                    account_id=account_id,
                    domain=domain,
                    scan_id=scan_id,
                    organization_id=scan_record.organization_id if scan_record else None,
                )
            except Exception:
                logging.getLogger("hydra.api.integrations").exception(
                    "Error enqueueing integration events for account %s scan %s",
                    account_id,
                    scan_id,
                )
    except Exception as exc:
        # A background asyncio task's exception would otherwise vanish
        # silently (asyncio logs it to stderr at best) — recording it on
        # the scan row is what makes it visible to the client at all,
        # via GET /scans/{id}.
        control_db.update_scan_status(scan_id, "failed", error_message=str(exc))
