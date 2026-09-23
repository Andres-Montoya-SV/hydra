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
from typing import TYPE_CHECKING

from api.control_db import ControlDB
from api.tenancy import account_settings

if TYPE_CHECKING:
    from api.settings import APISettings


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
    except Exception as exc:
        # A background asyncio task's exception would otherwise vanish
        # silently (asyncio logs it to stderr at best) — recording it on
        # the scan row is what makes it visible to the client at all,
        # via GET /scans/{id}.
        control_db.update_scan_status(scan_id, "failed", error_message=str(exc))
