"""Continuous monitoring's periodic loop ("Hydra API — Continuous
Monitoring for Verified Domains" task) — the two-speed model's actual
scheduler. Started in `api/main.py`'s `lifespan` as its OWN independent
`asyncio` loop, sharing only `stop_event`/`LoopHeartbeats` with the scan
worker and reconciliation loops, the same "one shared shape, independent
interval" pattern `api/reconciliation_worker.py`'s own module docstring
already established and justified — polling hourly (`monitoring_poll_
interval_seconds`) is the right granularity for daily/weekly cadences,
wrong for the scan queue's sub-second claim latency, and this task
invents no new scheduler abstraction to reconcile the two.

**Two phases per cycle, in this order — harvest before enqueue**:

1. **Harvest**: for every monitored domain with an in-flight scheduled
   scan (`pending_passive_scan_id`/`pending_active_scan_id` set), check
   whether that scan has reached a terminal state (`completed`/`failed`)
   and, if so, fold the result back into `monitored_domains` — compute
   the new asset digest/count, diff against the previous run's hostnames
   ONLY when the digest actually changed (the cheap-common-case
   optimization `api/monitoring.py`'s module docstring describes),
   check the asset-count ceiling, and queue a notification if there's
   anything worth telling the account. This phase runs first so a scan
   that finished between polls frees its row up for the SAME cycle's
   enqueue phase, rather than waiting a full extra poll interval.
2. **Enqueue**: for every monitored domain now due (keyset-paginated,
   `monitoring_batch_size` rows per page) with no scan already in
   flight, re-check domain-verification freshness and (for Speed 2)
   tier/quota, then queue a real scan through the EXACT SAME durable
   queue (`ControlDB.create_scan`) any manual `POST /scans` uses, tagged
   `trigger_source='scheduled_passive'`/`'scheduled_active'`.

**Per-account error isolation**: every per-domain operation in both
phases is wrapped in its own `try`/`except` — one account's malformed
data, one domain's missing recon.db, or one unexpected exception never
aborts the rest of the cycle; it's logged and that one row is simply
left for the next cycle to retry (harvest: still pending, tries again
next poll; enqueue: `next_*_due_at` untouched, so it's still "due" and
retried next poll too). Nothing about one account's failure is visible
to, or affects, any other account's processing this cycle.

**Time/work budget, and how resume actually works**: `monitoring_cycle_
time_budget_seconds` bounds a SINGLE call to `run_monitoring_cycle` — once
elapsed, the current page/batch already read finishes being processed and
written (never left half-flushed), then the function returns early rather
than claiming another page. This is safe to interrupt at any point
because of the schema decision in `api/control_db.py`'s own
`monitored_domains` docstring: `next_*_due_at` (the checkpoint) only ever
advances as the LAST step of successfully processing a row, batched via
`batch_record_monitoring_progress`. A row not yet reached when the budget
runs out, or a whole cycle killed outright (process crash, restart),
simply looks identical to "not due yet" or "still due" — the very next
cycle (this process or another) picks up exactly where the interrupted
one left off, with no separate checkpoint/offset table and no risk of
double-processing (harvesting is naturally idempotent — re-reading an
already-completed scan's already-unchanged recon.db and writing the same
digest back is a no-op in effect).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from api import subscriptions
from api.domain_verification import classify_scan_gate
from api.monitoring import (
    MonitoringRunOutcome,
    classify_asset_jump,
    compute_asset_digest,
    next_due_at,
    significance_rank,
)
from api.tenancy import account_db_path, account_settings

if TYPE_CHECKING:
    from api.control_db import ControlDB, MonitoredDomainRecord
    from api.email_sender import EmailSender
    from api.health import LoopHeartbeats
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.monitoring")

Speed = Literal["passive", "active"]
_SPEEDS: tuple[Speed, Speed] = ("passive", "active")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class _CycleBudget:
    deadline: float

    @classmethod
    def start(cls, seconds: float) -> _CycleBudget:
        return cls(deadline=time.monotonic() + seconds)

    def exhausted(self) -> bool:
        return time.monotonic() >= self.deadline


def _wildcard_detected_for_scan(api_settings: APISettings, account_id: str, scan_id: str) -> bool:
    """Reads the scan's own `wildcard_check.jsonl` artifact
    (`modules/wildcard_check.py`) rather than re-running any detection —
    the pipeline already did this real work once per scan; re-deriving it
    here would be a second, potentially-drifting implementation of the
    same check. Missing file (tool disabled/not installed for this
    account) or unparseable content is treated as "not detected," never
    as an error that would block the rest of harvesting this row."""
    settings = account_settings(api_settings, account_id)
    path = settings.project_root / settings.output_directory / scan_id / "wildcard_check.jsonl"
    if not path.is_file():
        return False
    try:
        import json

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("wildcard_dns_detected"):
                return True
    except (OSError, ValueError):
        return False
    return False


def _harvest_one(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    row: MonitoredDomainRecord,
    speed: Speed,
) -> tuple[dict | None, MonitoringRunOutcome | None]:
    """Returns `(batched_update, outcome_for_notification)` — either may
    be `None`: `batched_update` is `None` when the scan is still
    `queued`/`running` (nothing to harvest yet, row stays pending, try
    again next cycle); `outcome_for_notification` is `None` whenever
    there's genuinely nothing worth emailing about (scan failed, or
    succeeded with an unchanged asset digest)."""
    scan_id = row.pending_passive_scan_id if speed == "passive" else row.pending_active_scan_id
    if scan_id is None:
        # Caller (`run_monitoring_cycle`) only ever passes rows returned by
        # `list_pending_monitoring_harvest(speed=speed)`, which selects
        # exclusively on this column being non-NULL — reached only if that
        # invariant is ever violated, never in ordinary operation.
        raise ValueError(f"monitoring row {row.monitoring_id} has no pending {speed} scan_id")
    scan = control_db.get_owned_scan(scan_id, row.account_id)
    if scan is None or scan.status in ("queued", "running"):
        return None, None

    next_at = next_due_at(
        api_settings.monitoring_passive_interval_hours
        if speed == "passive"
        else api_settings.monitoring_active_interval_hours
    )

    if scan.status != "completed":
        logger.warning(
            "Scheduled %s monitoring scan %s for account %s domain %s did not complete "
            "(status=%s, error=%s) — rescheduling for the next cycle without changing the "
            "stored baseline.",
            speed,
            scan_id,
            row.account_id,
            row.domain,
            scan.status,
            scan.error_message,
        )
        update = {
            "monitoring_id": row.monitoring_id,
            "speed": speed,
            "scan_id": row.last_passive_scan_id if speed == "passive" else row.last_active_scan_id,
            "ran_at": _now_iso(),
            "next_due_at": next_at,
            "asset_digest": row.last_asset_digest,
            "asset_count": row.last_asset_count,
            "needs_review": row.needs_review,
            "status": row.status if row.status != "paused_verification_lapsed" else "active",
        }
        return update, None

    from core.store import AssetStore

    store = AssetStore(account_db_path(api_settings, row.account_id))
    hostnames = store.get_host_domains(scan_id)
    new_digest = compute_asset_digest(hostnames)
    new_count = len(hostnames)

    wildcard = _wildcard_detected_for_scan(api_settings, row.account_id, scan_id)
    jump = classify_asset_jump(
        previous_count=row.last_asset_count,
        new_count=new_count,
        ceiling=api_settings.monitoring_asset_count_ceiling,
        wildcard_dns_detected=wildcard,
    )

    # A domain's very first monitored run never itself triggers a
    # notification: `digest_changed` requires a prior digest to differ
    # from, and `classify_asset_jump` never flags `needs_review` when
    # `previous_count is None` — there is no "change" to report yet,
    # only a baseline being established.
    outcome: MonitoringRunOutcome | None = None
    digest_changed = row.last_asset_digest is not None and new_digest != row.last_asset_digest
    if jump.needs_review or digest_changed:
        hosts_added: list[str] = []
        hosts_removed: list[str] = []
        previous_scan_id = (
            row.last_passive_scan_id if speed == "passive" else row.last_active_scan_id
        )
        if digest_changed and previous_scan_id:
            previous_hostnames = set(store.get_host_domains(previous_scan_id))
            current_hostnames = set(hostnames)
            hosts_added = sorted(current_hostnames - previous_hostnames)
            hosts_removed = sorted(previous_hostnames - current_hostnames)
        if jump.needs_review or hosts_added or hosts_removed:
            outcome = MonitoringRunOutcome(
                monitoring_id=row.monitoring_id,
                account_id=row.account_id,
                domain=row.domain,
                speed=speed,
                scan_id=scan_id,
                hosts_added=hosts_added,
                hosts_removed=hosts_removed,
                asset_count=new_count,
                asset_digest=new_digest,
                needs_review=jump.needs_review,
                review_reason=jump.reason,
            )

    # Sticky by design, per the task's own explicit requirement: once a
    # domain is in `needs_review`, NOTHING harvested here ever clears it
    # again — not a smaller count next cycle, not the digest going back
    # to its old value, nothing short of the explicit human acknowledge
    # (`ControlDB.clear_needs_review`, `POST
    # /domains/{domain}/monitoring/acknowledge`). Without this, a count
    # that spikes past the ceiling and later happens to dip back under
    # it on an ordinary later cycle would silently self-heal
    # `classify_asset_jump`'s verdict (it only ever compares against the
    # IMMEDIATELY PRECEDING count, which this same function already
    # overwrites with `new_count` below) — exactly the "fully-automatic
    # resolution of a flagged domain" the ceiling exists to prevent.
    still_needs_review = row.status == "needs_review" or jump.needs_review
    update = {
        "monitoring_id": row.monitoring_id,
        "speed": speed,
        "scan_id": scan_id,
        "ran_at": _now_iso(),
        "next_due_at": next_at,
        "asset_digest": new_digest,
        "asset_count": new_count,
        "needs_review": still_needs_review,
        "status": "needs_review" if still_needs_review else "active",
    }
    return update, outcome


def _try_enqueue_one(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    row: MonitoredDomainRecord,
    speed: Speed,
) -> None:
    """Verification-freshness and (Speed 2 only) tier/quota gating,
    exactly as strict as a real client-facing `POST /scans` — a
    scheduled scan is never allowed to run against a domain the account
    could not itself legally scan right now. On any gate failure, the
    row's `next_*_due_at` is deliberately left untouched: it stays "due"
    and this same check simply runs again next poll cycle, so a lapsed
    verification that gets renewed an hour later resumes monitoring on
    the very next poll rather than waiting out a full daily/weekly
    cadence."""
    gate_status, _ = classify_scan_gate(
        row.domain,
        active_verifications=control_db.get_verified_domains_for_account(row.account_id),
        all_verifications=control_db.get_all_verifications_for_account(row.account_id),
    )
    if gate_status != "covered":
        if row.status != "paused_verification_lapsed":
            control_db.set_monitoring_status(row.monitoring_id, "paused_verification_lapsed")
            logger.warning(
                "Monitoring paused for account %s domain %s: verification is %s.",
                row.account_id,
                row.domain,
                gate_status,
            )
        return

    if row.status == "paused_verification_lapsed":
        control_db.set_monitoring_status(row.monitoring_id, "active")

    if speed == "active":
        subscription = subscriptions.get_or_create_subscription(control_db, row.account_id)
        limits = subscriptions.effective_limits(subscription)
        if not limits.monitoring_speed2:
            # The account's tier changed (downgrade) since opting in —
            # never silently keep running a feature the current tier no
            # longer includes; skip this cycle, leave speed2_enabled as
            # the account's own recorded preference (a later upgrade
            # resumes it with no action needed), and let a human notice
            # via GET /domains/{domain}/monitoring rather than emailing
            # every single skipped weekly cycle.
            logger.info(
                "Skipping Speed 2 scan for account %s domain %s: current tier no longer "
                "includes active monitoring.",
                row.account_id,
                row.domain,
            )
            return
        if subscriptions.access_blocked_by_billing(subscription):
            logger.info(
                "Skipping Speed 2 scan for account %s domain %s: account is suspended.",
                row.account_id,
                row.domain,
            )
            return
        ok, reason = subscriptions.check_scan_quota(control_db, row.account_id, limits)
        if not ok:
            logger.info(
                "Skipping Speed 2 scan for account %s domain %s: %s",
                row.account_id,
                row.domain,
                reason,
            )
            return

    import secrets

    scan_id = secrets.token_hex(16)
    db_path = str(account_settings(api_settings, row.account_id).project_root)
    trigger_source = "scheduled_passive" if speed == "passive" else "scheduled_active"
    control_db.create_scan(
        scan_id=scan_id,
        account_id=row.account_id,
        domain=row.domain,
        db_path=db_path,
        trigger_source=trigger_source,
    )
    if speed == "active":
        control_db.increment_scan_usage(row.account_id, subscriptions.current_period_key())
    control_db.mark_monitoring_scan_enqueued(row.monitoring_id, speed=speed, scan_id=scan_id)


def _flush_pending_notifications(
    *, control_db: ControlDB, email_sender: EmailSender, api_settings: APISettings
) -> int:
    """Reads the DURABLE outbox (`monitoring_pending_notifications`),
    never an in-memory dict scoped to this one call — a row written by
    an EARLIER cycle that crashed before reaching this same step is
    still `sent_at IS NULL` and gets flushed here exactly the same as
    one this very cycle's own harvest phase just wrote. This is the
    real fix for the lost-notification bug described in that table's own
    schema comment; see it for the full reasoning.

    Ordering per account is deliberately send-THEN-mark: if the process
    dies between the two, the next flush (this cycle's caller running
    again, or a fresh process entirely) finds the row still unsent and
    re-sends it — at most one duplicate, never a silent loss. Returns
    the number of accounts actually notified, for the caller's stats."""
    pending = control_db.list_unsent_notifications()
    if not pending:
        return 0

    by_account: dict[str, list[dict]] = {}
    for row in pending:
        by_account.setdefault(row["account_id"], []).append(row)

    notified_accounts = 0
    for account_id, rows in by_account.items():
_background_webhook_tasks: set[asyncio.Task] = set()


def _deliver_webhooks_for_outcome(control_db: ControlDB, outcome: MonitoringRunOutcome) -> None:
    """The exact same significance decision that just put `outcome` in
    `outcomes_by_account` (i.e. it was worth an email) is reused here,
    verbatim — `api/webhooks.py::event_for_monitoring_outcome` derives
    its event type from `outcome.needs_review`, never a second
    "is this worth alerting" computation.

    Bridges this module's own synchronous call shape (`run_monitoring_cycle`
    is a plain sync function, called both directly by tests and from
    inside `run_monitoring_loop`'s real `asyncio` loop) to webhook
    delivery's genuinely async HTTP calls: when a real event loop IS
    running (production), delivery is scheduled as a background task —
    never blocking the rest of this cycle's own per-account processing
    on a slow/unreachable webhook receiver, which is exactly the "one
    account's failing webhook never blocks another account's delivery"
    requirement. When no loop is running (every existing synchronous
    test), it runs to completion immediately via `asyncio.run` — the
    same deterministic, awaited-for-real behavior those tests already
    rely on for the email path."""
    from api.webhooks import deliver_event_to_subscribers, event_for_monitoring_outcome

    event = event_for_monitoring_outcome(outcome)
    coro = deliver_event_to_subscribers(
        control_db=control_db, account_id=outcome.account_id, event=event
    )
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(coro)
        return
    task = loop.create_task(coro)
    _background_webhook_tasks.add(task)
    task.add_done_callback(_background_webhook_tasks.discard)


def _send_notifications(
    *,
    control_db: ControlDB,
    email_sender: EmailSender,
    api_settings: APISettings,
    outcomes_by_account: dict[str, list[MonitoringRunOutcome]],
) -> None:
    for account_id, outcomes in outcomes_by_account.items():
        for outcome in outcomes:
            try:
                _deliver_webhooks_for_outcome(control_db, outcome)
            except Exception:
                # Per-account isolation extends to webhook delivery
                # scheduling itself — a bug here must never prevent this
                # same account's (or any other account's) email below.
                logger.exception(
                    "Error scheduling webhook delivery for account %s domain %s",
                    account_id,
                    outcome.domain,
                )

        account = control_db.get_account(account_id)
        if account is None or account.email is None:
            logger.warning(
                "Monitoring alert for account %s has no email on file — not sent (%d change(s)). "
                "Marked sent anyway: there is no email to retry delivery to on a later cycle.",
                account_id,
                len(rows),
            )
            control_db.mark_notifications_sent([r["notification_id"] for r in rows])
            continue

        pairs = [
            (
                MonitoringRunOutcome(
                    monitoring_id="",
                    account_id=r["account_id"],
                    domain=r["domain"],
                    speed=r["speed"],
                    scan_id=r["scan_id"],
                    hosts_added=r["hosts_added"],
                    hosts_removed=r["hosts_removed"],
                    asset_count=r["asset_count"],
                    asset_digest=r["asset_digest"],
                    needs_review=r["needs_review"],
                    review_reason=r["review_reason"],
                ),
                r["notification_id"],
            )
            for r in rows
        ]
        ordered_pairs = sorted(pairs, key=lambda pair: significance_rank(pair[0]))
        cap = api_settings.monitoring_max_domains_per_email
        shown_pairs, truncated_pairs = ordered_pairs[:cap], ordered_pairs[cap:]
        summary_lines = [_render_outcome_line(outcome) for outcome, _ in shown_pairs]

        email_sender.send_monitoring_alert(
            to=account.email,
            account_id=account_id,
            summary_lines=summary_lines,
            truncated_count=len(truncated_pairs),
        )
        # Only reached if the send above didn't raise — a raised
        # exception here (simulating a crash) leaves every row for this
        # account still unsent, to be retried by the next flush.
        control_db.mark_notifications_sent(
            [notification_id for _, notification_id in ordered_pairs]
        )
        notified_accounts += 1
    return notified_accounts


def _render_outcome_line(outcome: MonitoringRunOutcome) -> str:
    if outcome.needs_review:
        return f"- {outcome.domain} [NEEDS REVIEW]: {outcome.review_reason}"
    parts = []
    if outcome.hosts_added:
        parts.append(f"{len(outcome.hosts_added)} new host(s)")
    if outcome.hosts_removed:
        parts.append(f"{len(outcome.hosts_removed)} host(s) gone")
    return f"- {outcome.domain}: {', '.join(parts)} (now {outcome.asset_count} total)"


def run_monitoring_cycle(
    *, api_settings: APISettings, control_db: ControlDB, email_sender: EmailSender
) -> dict[str, int]:
    """One full harvest-then-enqueue pass, time-budgeted. Returns a
    small stats dict for the caller's own summary log line — never
    raises for an individual account/domain's failure (see the module
    docstring's error-isolation guarantee); a genuinely unexpected
    exception escaping this function entirely would mean a bug in the
    cycle's own control flow, not in any one account's data."""
    budget = _CycleBudget.start(api_settings.monitoring_cycle_time_budget_seconds)
    stats = {"harvested": 0, "enqueued": 0, "skipped_errors": 0, "notified_accounts": 0}

    for speed in _SPEEDS:
        pending_rows = control_db.list_pending_monitoring_harvest(speed=speed)
        updates: list[dict] = []
        notifications: list[dict] = []
        for row in pending_rows:
            if budget.exhausted():
                break
            try:
                update, outcome = _harvest_one(
                    api_settings=api_settings, control_db=control_db, row=row, speed=speed
                )
            except Exception:
                logger.exception(
                    "Error harvesting %s monitoring result for account %s domain %s — "
                    "left pending, will retry next cycle.",
                    speed,
                    row.account_id,
                    row.domain,
                )
                stats["skipped_errors"] += 1
                continue
            if update is not None:
                updates.append(update)
                stats["harvested"] += 1
            if outcome is not None:
                # Written to the durable outbox in the SAME transaction
                # as `update` below (both go into the same
                # `batch_record_monitoring_progress` call) — never held
                # only in memory. See `monitoring_pending_notifications`'s
                # own schema comment (api/control_db.py) for the real bug
                # this closes: a crash between the row update and a
                # deferred, in-memory-only send used to lose the
                # notification permanently.
                notifications.append(
                    {
                        "account_id": outcome.account_id,
                        "domain": outcome.domain,
                        "speed": outcome.speed,
                        "scan_id": outcome.scan_id,
                        "hosts_added": outcome.hosts_added,
                        "hosts_removed": outcome.hosts_removed,
                        "asset_count": outcome.asset_count,
                        "asset_digest": outcome.asset_digest,
                        "needs_review": outcome.needs_review,
                        "review_reason": outcome.review_reason,
                    }
                )
            if len(updates) >= api_settings.monitoring_batch_size:
                control_db.batch_record_monitoring_progress(updates, notifications=notifications)
                updates = []
                notifications = []
        if updates or notifications:
            control_db.batch_record_monitoring_progress(updates, notifications=notifications)

    now_iso = _now_iso()
    for speed in _SPEEDS:
        cursor: tuple[str, str] | None = None
        while not budget.exhausted():
            page = (
                control_db.list_due_passive_monitoring_page(
                    due_before=now_iso, cursor=cursor, limit=api_settings.monitoring_batch_size
                )
                if speed == "passive"
                else control_db.list_due_active_monitoring_page(
                    due_before=now_iso, cursor=cursor, limit=api_settings.monitoring_batch_size
                )
            )
            if not page:
                break
            for row in page:
                try:
                    _try_enqueue_one(
                        api_settings=api_settings, control_db=control_db, row=row, speed=speed
                    )
                    stats["enqueued"] += 1
                except Exception:
                    logger.exception(
                        "Error enqueuing %s monitoring scan for account %s domain %s — "
                        "will retry next cycle.",
                        speed,
                        row.account_id,
                        row.domain,
                    )
                    stats["skipped_errors"] += 1
            last = page[-1]
            cursor = (
                (last.next_passive_due_at, last.monitoring_id)
                if speed == "passive"
                else (last.next_active_due_at, last.monitoring_id)  # type: ignore[assignment]
            )
            if len(page) < api_settings.monitoring_batch_size:
                break

    stats["notified_accounts"] = _flush_pending_notifications(
        control_db=control_db, email_sender=email_sender, api_settings=api_settings
    )
    return stats


async def run_monitoring_loop(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    email_sender: EmailSender,
    stop_event: asyncio.Event,
    heartbeats: LoopHeartbeats,
) -> None:
    """The `asyncio.create_task` + `stop_event` periodic-loop shape every
    other background loop in this service already uses
    (`api/scan_worker.py`, `api/reconciliation_worker.py`,
    `api/backup_worker.py`) — no new scheduling infrastructure. Runs the
    cycle once immediately at startup (same "don't wait a full interval
    to notice something already due" posture the reconciliation loop
    takes), then every `monitoring_poll_interval_seconds`. If a single
    cycle's own time budget was exhausted with more due work still
    waiting, the NEXT iteration starts immediately rather than waiting
    out the rest of the poll interval — checked via `stats["enqueued"] +
    stats["harvested"] >= a full batch page`, a cheap proxy for "there is
    probably more work queued up" without a second query just to find
    out for certain."""
    while not stop_event.is_set():
        heartbeats.mark_alive("monitoring")
        stats = run_monitoring_cycle(
            api_settings=api_settings, control_db=control_db, email_sender=email_sender
        )
        logger.info(
            "Monitoring cycle complete: %d harvested, %d enqueued, %d skipped (errors), "
            "%d account(s) notified.",
            stats["harvested"],
            stats["enqueued"],
            stats["skipped_errors"],
            stats["notified_accounts"],
        )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=api_settings.monitoring_poll_interval_seconds
            )
