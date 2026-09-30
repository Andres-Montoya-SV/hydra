"""Productization Phase 08: delivers the canonical integration outbox.

Every integration event (monitoring, findings, exposure lifecycle,
remediation) is a row in `integration_events`, fanned out to one
`integration_deliveries` row per subscribed destination when it is
enqueued. This loop claims due deliveries under a lease, sends each one
once, and records the result durably:

- delivered -> done; the destination's failure streak resets;
- failed    -> rescheduled with backoff (RETRY_SCHEDULE_SECONDS), then
               dead after MAX_ATTEMPTS; a dead delivery counts toward the
               destination's automatic disable, and can be redelivered;
- a worker that dies mid-send leaves an in-flight lease that expires and
  is claimed again, so a restart never loses an event. The receiver may
  then see it twice, which is why every delivery carries the event id and
  delivery id headers: at-least-once, deduplicable by the receiver.

Every attempt re-validates the destination (SSRF / DNS rebinding) through
`api/webhooks.py::attempt_delivery`, the same path the old in-process
delivery used.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from api.webhooks import (
    DELIVERY_ID_HEADER,
    DISABLE_AFTER_CONSECUTIVE_FAILURES,
    EVENT_ID_HEADER,
    attempt_delivery,
)

if TYPE_CHECKING:
    from api.control_db import ControlDB, DeliveryWork, IntegrationEventRecord
    from api.health import LoopHeartbeats
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.integrations")

# Delay before each retry: 30s, 2m, 10m, 30m, 2h, 6h — about 9 hours of
# cover for a receiver that is down, then the delivery is dead.
RETRY_SCHEDULE_SECONDS: tuple[int, ...] = (30, 120, 600, 1800, 7200, 21600)
MAX_ATTEMPTS = len(RETRY_SCHEDULE_SECONDS) + 1
LEASE_SECONDS = 120
BATCH_SIZE = 50
CONCURRENCY = 10


def envelope(event: IntegrationEventRecord) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "created_at": event.created_at,
        "organization_id": event.organization_id,
        "data": event.payload,
    }


def summary_text(event_type: str, data: dict[str, object]) -> str:
    """One human-readable line for chat destinations."""
    subject = data.get("title") or data.get("domain") or data.get("exposure_id") or ""
    details = {
        "monitoring.changed": "attack surface changed",
        "monitoring.needs_review": f"needs review: {data.get('review_reason', '')}",
        "finding.high_severity": f"{data.get('finding_count', 0)} high/critical finding(s)",
        "exposure.opened": f"new {data.get('severity', '')} exposure",
        "exposure.reopened": f"{data.get('severity', '')} exposure reopened",
        "exposure.resolved": "exposure resolved",
        "remediation.state_changed": (
            f"remediation {data.get('from_state')} -> {data.get('to_state')}"
        ),
        "remediation.assigned": "remediation assigned",
    }
    return f"[Hydra] {event_type}: {subject} — {details.get(event_type, '')}".rstrip(" —")


def render_body(kind: str, event: IntegrationEventRecord) -> bytes:
    """The request body for a destination kind. `generic` gets the full
    signed envelope; Slack and Teams incoming webhooks get a chat message
    (they can't verify signatures, so they get a summary, not the data)."""
    if kind == "slack":
        body: dict[str, object] = {"text": summary_text(event.event_type, event.payload)}
    elif kind == "teams":
        body = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "wrap": True,
                                "text": summary_text(event.event_type, event.payload),
                            }
                        ],
                    },
                }
            ],
        }
    else:
        body = envelope(event)
    return json.dumps(body, sort_keys=True).encode("utf-8")


def next_attempt(attempts_before: int, now: datetime) -> datetime | None:
    """When to retry after a failed attempt, or None once it's dead.
    `attempts_before` = attempts made before this one."""
    if attempts_before + 1 >= MAX_ATTEMPTS:
        return None
    return now + timedelta(seconds=RETRY_SCHEDULE_SECONDS[attempts_before])


async def _deliver_one(control_db: ControlDB, work: DeliveryWork, *, verify: bool) -> str:
    ok, error, _retryable = await attempt_delivery(
        work.webhook,
        body=render_body(work.webhook.kind, work.event),
        event_type=work.event.event_type,
        verify=verify,
        extra_headers={EVENT_ID_HEADER: work.event.event_id, DELIVERY_ID_HEADER: work.delivery_id},
    )
    now = datetime.now(timezone.utc)
    if ok:
        control_db.record_delivery_attempt(work.delivery_id, error=None, now=now, retry_at=None)
        control_db.record_webhook_delivery_success(work.webhook.webhook_id)
        return "delivered"
    retry_at = next_attempt(work.attempts, now)
    control_db.record_delivery_attempt(work.delivery_id, error=error, now=now, retry_at=retry_at)
    if retry_at is not None:
        return "retrying"
    control_db.record_webhook_delivery_failure(
        work.webhook.webhook_id, error=error, disable_after=DISABLE_AFTER_CONSECUTIVE_FAILURES
    )
    logger.warning(
        "Delivery %s of %s to webhook %s is dead after %d attempts: %s",
        work.delivery_id,
        work.event.event_type,
        work.webhook.webhook_id,
        MAX_ATTEMPTS,
        error,
    )
    return "dead"


async def run_integration_delivery_cycle(
    control_db: ControlDB, *, verify: bool = True, batch_size: int = BATCH_SIZE
) -> dict[str, int]:
    """Claims and attempts one batch of due deliveries. Never raises for a
    single delivery's failure; returns counts per outcome."""
    work = control_db.claim_due_deliveries(
        now=datetime.now(timezone.utc), limit=batch_size, lease_seconds=LEASE_SECONDS
    )
    semaphore = asyncio.Semaphore(CONCURRENCY)
    stats = {"delivered": 0, "retrying": 0, "dead": 0, "errors": 0}

    async def run(item: DeliveryWork) -> None:
        async with semaphore:
            try:
                stats[await _deliver_one(control_db, item, verify=verify)] += 1
            except Exception:
                # The lease expires and the delivery is claimed again.
                stats["errors"] += 1
                logger.exception("Unexpected error delivering %s", item.delivery_id)

    await asyncio.gather(*(run(item) for item in work))
    return stats


async def run_integration_delivery_loop(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    stop_event: asyncio.Event,
    heartbeats: LoopHeartbeats,
) -> None:
    while not stop_event.is_set():
        heartbeats.mark_alive("integration_delivery")
        try:
            stats = await run_integration_delivery_cycle(control_db)
            if any(stats.values()):
                logger.info("Integration delivery cycle: %s", stats)
        except Exception:
            logger.exception("Integration delivery cycle failed; retrying next interval")
        # asyncio.TimeoutError, not the builtin: they differ on Python 3.10.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=api_settings.integration_delivery_interval_seconds
            )
