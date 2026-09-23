"""Scheduled reconciliation — the two jobs Part B/D.3
(docs/PAID_API_DESIGN.md) describe but no earlier round ever wired up
(the "Explicitly deferred beyond Round 3" list named both by name):
grace-period suspension enforcement and the tier-retention purge.

Started in `api/main.py`'s `lifespan` as its OWN periodic `asyncio`
loop — deliberately separate from `api/scan_worker.py`'s loop rather
than folded into it: that loop polls sub-second (claim latency matters
against a 25-minute scan), while billing and retention are
day-granularity concerns (`GRACE_PERIOD_DAYS = 3`; retention windows
measured in months). Forcing both through one shared interval would
mean either the scan queue claims work once a day, or this job
re-scans every account's subscription/retention state every half
second for no reason. Two independent lifespan-managed loops, sharing
the exact same "`asyncio.create_task` in `lifespan`, stopped via a
shared `stop_event` on shutdown" shape `scan_worker.py` already
established, is the honest generalization of that pattern — not a new
scheduler abstraction, and no new infrastructure (no system cron, no
external scheduler), per the task's own explicit instruction.

Runs both jobs once immediately at startup (recovers a grace period
that expired, or a purge that came due, while the process was down
across the actual deadline — the same "don't wait a full interval to
notice something already due" posture `scan_worker.py`'s own sweep
takes), then again every `api_settings.reconciliation_interval_seconds`
(default 24h, env-configurable).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from api.health import LoopHeartbeats
from api.subscriptions import get_or_create_subscription, grace_period_expired
from api.tiers import retention_days_for, tier_limits

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.email_sender import EmailSender
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.reconciliation")


def run_grace_period_job(*, control_db: ControlDB, email_sender: EmailSender) -> int:
    """Job 1: suspend every account whose grace period has expired.

    Reuses `grace_period_expired` (Part D.3's own 3-day math,
    `api/subscriptions.py`) unchanged — this job's only responsibility
    is to actually invoke it on a schedule, not to reimplement it. The
    candidate list (every currently `'past_due'` account) is gathered
    once, but each candidate is re-read FRESH (`get_subscription`)
    right before acting on it: a subscription that `restore_active_status`
    flipped back to `'active'` between the list query and this re-read
    is skipped here unconditionally. Even a fresh-and-still-`'past_due'`
    read is only ever turned into a write via
    `ControlDB.suspend_if_still_past_due` — a single atomic, conditional
    UPDATE (the same discipline `claim_next_queued_scan` uses for the
    scan-claim race) — which closes the remaining window a plain
    check-then-write pair would leave open if this loop and a payment
    webhook ever ran in different worker processes at nearly the same
    moment. `suspend_account` (the existing blind-write helper) is
    deliberately NOT used here for that reason; it remains correct and
    unchanged for its other caller (the admin manual-reconciliation
    path), where no concurrent-race concern exists.

    A newly-suspended account gets an email
    (`EmailSender.send_account_suspended_email`) — decided and built
    this round, not deferred: the API already returns 402 on
    `POST /scans` for a suspended account, but that's an error a client
    only sees the next time it tries to scan, not a proactive signal
    that anything changed. A customer whose card failed silently loses
    access with no explanation otherwise, which is a real self-service
    UX gap for a product with no human account manager. Sent via
    whichever `EmailSender` the app is already configured with
    (Postmark or console-log) — no new provider, no new configuration.
    If the account has no email on file (should not happen for a
    verified account, but not asserted away), the suspension itself
    still happens and is logged; only the notice is skipped.

    Returns how many accounts were actually suspended, for the caller's
    own summary log line."""
    suspended = 0
    for account_id in control_db.list_past_due_account_ids():
        subscription = control_db.get_subscription(account_id)
        if subscription is None or subscription.status != "past_due":
            continue
        if not grace_period_expired(subscription):
            continue
        if not control_db.suspend_if_still_past_due(account_id):
            # Lost a race against a payment landing between the read
            # above and this write — correctly NOT suspended.
            continue
        suspended += 1
        account = control_db.get_account(account_id)
        if account is not None and account.email is not None:
            email_sender.send_account_suspended_email(to=account.email, account_id=account_id)
        else:
            logger.warning(
                "Suspended account %s (grace period expired) but it has no email on "
                "file — no suspension notice sent.",
                account_id,
            )
    return suspended


def _retention_cutoff(retention_days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()


def run_retention_purge_job(*, api_settings: APISettings, control_db: ControlDB) -> int:
    """Job 2: delete `scans` rows and their `output/<scan_id>/`
    artifacts once they're older than the OWNING ACCOUNT's own
    effective retention window (`api/tiers.py::retention_days_for` —
    reused verbatim, tier logic never recomputed here).

    **Scope, stated explicitly**: only the control-plane `scans` row
    and the on-disk `output/<scan_id>/` directory are ever touched. The
    account's own `recon.db` (`api/tenancy.py`'s per-account
    `AssetStore`) is NEVER purged by this job — that database is the
    durable, structured findings/asset record an account's cross-scan
    analysis (reportability, hypotheses, historical comparison) depends
    on, a fundamentally different product than the raw per-tool JSONL
    artifacts Part B's retention language actually describes ("purges
    `output/<run_id>/` artifacts and rows" — the design doc's own
    words, unchanged here). Nothing in this task asked for the
    findings database itself to have a lifecycle, and treating "delete
    the raw scan artifacts" and "delete the account's accumulated
    knowledge" as the same operation would be a much bigger, much
    riskier change than what was asked for.

    **Terminal state only**: the query itself
    (`ControlDB.list_purgeable_scans_for_account`) only ever selects
    `status IN ('completed', 'failed')` — a `'running'` or `'queued'`
    scan is never a candidate, enforced structurally by the SQL WHERE
    clause, not by a runtime check elsewhere that could be forgotten.
    An unusually long scan on an old account is simply never selected,
    no matter how far past its nominal retention window its
    `created_at` already is.

    **Idempotent**: `shutil.rmtree(..., ignore_errors=True)` on an
    already-purged directory is a silent no-op, and deleting an
    already-deleted `scans` row (`ControlDB.delete_scan`) affects zero
    rows. Running this job twice in a row, or twice concurrently,
    purges nothing extra the second time.

    **Batched, not one giant transaction**: bounded to
    `api_settings.retention_purge_batch_size` scans per account per
    call (default 200). Each scan's row delete is its own short
    connection/transaction (the same per-row-connection shape every
    other single-row `ControlDB` writer already uses) — this never
    holds a lock that could stall `POST /scans` or any other route
    while a large backlog works through; a backlog bigger than one
    batch simply finishes across the next scheduled cycle(s) instead of
    in one pass.

    **Dry run**: when `api_settings.retention_purge_dry_run` is set,
    every candidate is logged (what WOULD be purged) and nothing is
    actually deleted or removed from disk. Defaults to OFF (real
    deletion) — an operator has to opt into a rehearsal, never opt into
    the destructive behavior by omission; this is exactly the kind of
    job worth verifying against real data before trusting it
    unattended.

    Returns how many scans were actually purged (always 0 in dry-run
    mode, even when candidates were found)."""
    purged = 0
    for account_id in control_db.list_account_ids():
        subscription = get_or_create_subscription(control_db, account_id)
        limits = tier_limits(subscription.tier)
        retention_days = retention_days_for(
            limits, retention_days_override=subscription.retention_days_override
        )
        cutoff = _retention_cutoff(retention_days)
        candidates = control_db.list_purgeable_scans_for_account(
            account_id, cutoff=cutoff, limit=api_settings.retention_purge_batch_size
        )
        for scan in candidates:
            if api_settings.retention_purge_dry_run:
                logger.info(
                    "[DRY RUN] would purge scan %s (account %s, tier %s, created_at %s, "
                    "retention_days=%d)",
                    scan.scan_id,
                    account_id,
                    subscription.tier,
                    scan.created_at,
                    retention_days,
                )
                continue
            output_dir = api_settings.account_root(account_id) / "output" / scan.scan_id
            shutil.rmtree(output_dir, ignore_errors=True)
            control_db.delete_scan(scan.scan_id, account_id)
            purged += 1
    return purged


async def run_reconciliation_loop(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    email_sender: EmailSender,
    stop_event: asyncio.Event,
    heartbeats: LoopHeartbeats,
) -> None:
    """Runs both jobs, logs one count-bearing summary line, then waits
    `api_settings.reconciliation_interval_seconds` (or until
    `stop_event` fires, whichever comes first) before repeating.

    Unlike `api/scan_worker.py`'s loop, this one is never cancelled
    mid-cycle on shutdown — each cycle's own work is bounded and fast
    (a handful of suspensions at most, a batched purge), so
    `api/main.py`'s `lifespan` simply awaits this task to the end of
    whatever it's currently doing rather than interrupting a delete
    loop partway through. There's no correctness reason this couldn't
    be cancelled too (every write here is already its own small atomic
    step, same as the scan worker's), it's just unnecessary: nothing
    here ever runs long enough for prompt-shutdown latency to matter
    the way an in-flight 25-minute scan does."""
    while not stop_event.is_set():
        heartbeats.mark_alive("reconciliation")  # GET /health's liveness signal, api/health.py
        suspended_count = run_grace_period_job(control_db=control_db, email_sender=email_sender)
        purged_count = run_retention_purge_job(api_settings=api_settings, control_db=control_db)
        logger.info(
            "Reconciliation cycle complete: %d account(s) suspended (grace period "
            "expired), %d scan(s) purged%s.",
            suspended_count,
            purged_count,
            " [DRY RUN — nothing actually deleted]" if api_settings.retention_purge_dry_run else "",
        )
        # `asyncio.TimeoutError`, never the bare builtin `TimeoutError` —
        # see api/scan_worker.py's identical fix for the full story: on
        # Python 3.10 these are different classes (unified only from
        # 3.11 on), so the builtin form silently failed to catch this
        # loop's own every-cycle timeout, crashing the task after its
        # first iteration on 3.10 specifically.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=api_settings.reconciliation_interval_seconds
            )
