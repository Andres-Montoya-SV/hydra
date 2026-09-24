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
import logging
from typing import TYPE_CHECKING

from api.control_db import ControlDB
from api.tenancy import account_db_path, account_settings

if TYPE_CHECKING:
    from api.settings import APISettings

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


async def _deliver_high_severity_findings_webhook(
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
    from api.webhooks import deliver_event_to_subscribers, event_for_high_severity_findings
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
    await deliver_event_to_subscribers(control_db=control_db, account_id=account_id, event=event)


async def execute_scan(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    account_id: str,
    scan_id: str,
    domain: str,
    trigger_source: str = "manual",
) -> None:
    import app as hydra_app  # deferred: heavy import graph (ToolManager, plugins, …)

    try:
        settings = account_settings(api_settings, account_id)
        settings.validate_or_raise()

        if trigger_source == "scheduled_passive":
            from api.monitoring import passive_monitoring_settings_overrides

            enable_flags = {k: v for k, v in vars(settings).items() if k.startswith("enable_")}
            overrides = passive_monitoring_settings_overrides(enable_flags)
            for attr, value in overrides.items():
                setattr(settings, attr, value)

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
            # Deliberately its OWN try/except, never inside the same
            # scope as the scan's own status transition above: a bug or
            # a slow/unreachable webhook receiver here must never
            # retroactively turn an already-successfully-completed scan
            # into a "failed" one from the client's point of view.
            try:
                await _deliver_high_severity_findings_webhook(
                    api_settings=api_settings,
                    control_db=control_db,
                    account_id=account_id,
                    domain=domain,
                    scan_id=scan_id,
                )
            except Exception:
                logging.getLogger("hydra.api.webhooks").exception(
                    "Error delivering finding.high_severity webhook for account %s scan %s",
                    account_id,
                    scan_id,
                )
    except Exception as exc:
        # A background asyncio task's exception would otherwise vanish
        # silently (asyncio logs it to stderr at best) — recording it on
        # the scan row is what makes it visible to the client at all,
        # via GET /scans/{id}.
        control_db.update_scan_status(scan_id, "failed", error_message=str(exc))
