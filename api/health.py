"""Basic observability, Part 1: `GET /health`
(docs/PAID_API_DESIGN.md's "Basic observability" section). Deliberately
small — this is a liveness/readiness check for an uptime monitor, not a
metrics stack (explicitly out of scope for this task).

**Liveness for the background loops — a real signal, not "the asyncio
task object still exists"**: `asyncio.create_task`'s own return value
stays a valid, non-garbage-collected object even after the coroutine
inside it has crashed and stopped running — checking `task.done()` only
tells you whether it EVER finished, not whether it silently died on its
FIRST unhandled exception and never iterated again (exactly the kind of
bug the Python 3.10 `asyncio.TimeoutError` fix, `api/scan_worker.py`'s
own commit history, already found once in this exact class of loop).
`LoopHeartbeats` is the real signal instead: each loop calls
`mark_alive(name)` once per iteration, at the top of its `while` loop,
before doing any work — `/health` compares how long ago that happened
against a generous, per-loop threshold derived from that loop's own
configured interval, and calls it dead if the gap is too large.

**Threshold reasoning**: `max(interval_seconds * 2, 60.0)` — for the
scan worker (sub-second polling by default), the 60s floor avoids
false positives from ordinary GC pauses/CPU contention; for the daily
reconciliation/backup loops, `interval * 2` means a loop that's missed
two entire daily cycles in a row is treated as dead. This is
deliberately coarse for the daily loops (a real, stated tradeoff, not
an oversight) — this task explicitly excludes building any real
alerting/SLA system, and a same-day-precision liveness check for a
once-a-day job would need a second, faster heartbeat mechanism just for
monitoring, which is exactly the kind of complexity this task's own
"don't build a metrics stack" instruction rules out.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from api.control_db import ControlDB
    from api.settings import APISettings


class LoopHeartbeats:
    """One instance per process (`app.state.loop_heartbeats`), shared by
    every background loop and read by `GET /health`. `timestamps` is
    deliberately a plain public dict, not hidden behind an encapsulated
    setter — tests need to backdate an entry directly to simulate a
    stale/dead loop without waiting in real time for one to actually go
    stale."""

    def __init__(self) -> None:
        self.timestamps: dict[str, float] = {}

    def mark_alive(self, name: str) -> None:
        self.timestamps[name] = time.monotonic()

    def seconds_since_alive(self, name: str) -> float | None:
        """`None` means this loop has never once reported in — treated
        the same as "stale" by the caller, never as "healthy by
        default"."""
        last = self.timestamps.get(name)
        if last is None:
            return None
        return time.monotonic() - last


# (loop name, interval-seconds attribute on APISettings) — the set of
# background loops `/health` checks. Adding a new loop later means
# adding one entry here, not touching the route itself.
_MONITORED_LOOPS: tuple[tuple[str, str], ...] = (
    ("scan_worker", "scan_poll_interval_seconds"),
    ("reconciliation", "reconciliation_interval_seconds"),
    ("backup", "backup_interval_seconds"),
    ("monitoring", "monitoring_poll_interval_seconds"),
)


def check_health(
    *, control_db: ControlDB, heartbeats: LoopHeartbeats, api_settings: APISettings
) -> tuple[bool, dict[str, str]]:
    """Returns `(healthy, checks)` — `checks` maps each check name to a
    human-readable result, detailed enough to diagnose which piece is
    down without needing to also read the logs at 3am (the task's own
    explicit requirement)."""
    checks: dict[str, str] = {}
    healthy = True

    try:
        control_db.ping()
        checks["control_db"] = "ok"
    except (
        Exception
    ) as exc:  # noqa: BLE001 - any failure here means "unreachable", report it plainly
        checks["control_db"] = f"unreachable: {type(exc).__name__}: {exc}"
        healthy = False

    for name, interval_attr in _MONITORED_LOOPS:
        interval = getattr(api_settings, interval_attr)
        threshold = max(interval * 2, 60.0)
        elapsed = heartbeats.seconds_since_alive(name)
        if elapsed is None:
            checks[name] = "never reported alive"
            healthy = False
        elif elapsed > threshold:
            checks[name] = f"stale: last alive {elapsed:.0f}s ago (threshold {threshold:.0f}s)"
            healthy = False
        else:
            checks[name] = "ok"

    return healthy, checks
