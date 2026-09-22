"""The durable scan queue's worker loop (docs/PAID_API_DESIGN.md's
"Durable, multi-worker-safe scan execution" section) — replaces Round
1's `POST /scans` firing `asyncio.create_task(execute_scan(...))`
directly from the request handler. `create_scan`
(`api/routers/scans.py`) now only ever inserts a `'queued'` row; this
loop is what actually claims and runs it, on its own schedule.

**Worker model, decided and justified against how this service is
actually deployed today**: an in-process `asyncio` loop, started in
`api/main.py`'s `lifespan` alongside the HTTP server, not a separate
`python -m api.worker` process. `docker-compose.yml`'s only service
(`hydra`) is the CLI/recon-pipeline tool, not this API — confirmed by
reading it, not assumed: the API today runs as a bare `uvicorn
api.main:app` process directly (docs/PAID_API_DESIGN.md's "Running it
locally" section), with no Docker story of its own at all yet. There is
no second container this loop could run in without inventing both a
worker process AND an entire containerized-API deployment topology
nobody has built. The claim mechanism itself
(`ControlDB.claim_next_queued_scan`) is correct regardless: it's a
single atomic SQL statement keyed only on the `scans` table's own
`status`, so it works identically whether one `uvicorn` worker process
calls it or several do — the realistic next scaling step on one machine
(`uvicorn --workers N`) needs zero changes here, each process just runs
its own copy of this exact loop against the same `control.db`.

**What "durable" means here, stated as plainly as the task asked**:
this is status durability and automatic re-EXECUTION from scratch, not
true mid-scan resumption. A scan interrupted 80% of the way through
does not continue from 80% — it restarts the whole pipeline run against
the same `scan_id`/`run_id`, exactly like a client manually resubmitting
would, just automatic instead of requiring the client to notice and
retry. Real partial-progress resumption would mean checkpointing
`_run_headless_pipeline`'s internal state, a substantially bigger
project explicitly out of scope here.

**Liveness, not just a status flag**: `status='running'` alone can't
tell a genuinely-executing scan apart from one whose worker died
without updating it — once more than one worker process can exist,
there's no single process whose mere existence proves the scan is
still alive. Each claimed scan gets a concurrent heartbeat sub-task
(`_heartbeat_loop`) touching `heartbeat_at` every
`scan_heartbeat_interval_seconds` (default 30s) for as long as
`execute_scan` is actually running; `ControlDB.sweep_stale_running_scans`
(called every poll cycle, not just once at startup — this is what lets
an already-running OTHER worker pick up a scan whose worker just died,
without waiting for a restart at all) treats a `heartbeat_at` older
than `scan_stale_after_seconds` (default 120s — comfortably 4 heartbeat
intervals, so one slow/delayed write under load never false-triggers a
requeue of a scan that's actually fine) as proof that scan's worker is
gone.

**Retry ceiling, chosen and stated**: `scan_max_retries` (default 3) —
a scan interrupted this many times in a row is far more likely to be
one that reliably crashes the process itself (a genuine bug, a
domain that triggers a fatal pipeline error) than one that's just been
unlucky with restart timing. Requeuing it forever would occupy a
concurrency slot indefinitely and never surface the real problem;
giving up after a bounded number of attempts and marking it `failed`
with a diagnosable reason is what actually protects the rest of the
queue.

**What the client sees**: nothing new. A requeue-after-interruption
sets `status` back to `'queued'`, the exact same value it had before
ever being claimed — `GET /scans/{id}`'s existing poll loop sees it
resume naturally as `queued` → `running` → `completed`/`failed`, with
no new status value invented. The only client-visible difference from
before this task is that a scan interrupted mid-run eventually
completes instead of ending in an unresolvable `failed`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import uuid
from typing import TYPE_CHECKING

from api.scan_orchestrator import execute_scan

if TYPE_CHECKING:
    from api.control_db import ControlDB, ScanRecord
    from api.settings import APISettings

logger = logging.getLogger("hydra.api.scan_worker")


def generate_worker_id() -> str:
    """Unique per PROCESS (not per scan, not per loop iteration) —
    every scan this process claims is tagged with the same id for as
    long as the process lives, which is all `sweep_stale_running_scans`
    actually needs (it only cares whether a claim's heartbeat is still
    being updated, never which specific worker owns it)."""
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


async def _heartbeat_loop(control_db: ControlDB, scan_id: str, interval_seconds: float) -> None:
    """Runs concurrently with one claimed scan's real execution, for as
    long as that execution is in progress — cancelled from the outside
    (`_run_claimed_scan`'s `finally`) the moment it finishes, success or
    failure. Never the source of truth for the scan's own status, only
    proof-of-liveness for `sweep_stale_running_scans` elsewhere."""
    while True:
        await asyncio.sleep(interval_seconds)
        control_db.update_scan_heartbeat(scan_id)


async def _run_claimed_scan(
    *, api_settings: APISettings, control_db: ControlDB, scan: ScanRecord
) -> None:
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(control_db, scan.scan_id, api_settings.scan_heartbeat_interval_seconds)
    )
    try:
        await execute_scan(
            api_settings=api_settings,
            control_db=control_db,
            account_id=scan.account_id,
            scan_id=scan.scan_id,
            domain=scan.domain,
        )
    finally:
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task


async def run_worker_loop(
    *,
    api_settings: APISettings,
    control_db: ControlDB,
    worker_id: str,
    stop_event: asyncio.Event,
) -> None:
    """The loop itself: every `scan_poll_interval_seconds`, sweep for
    stale `running` scans (requeue-or-fail per the retry ceiling above),
    then claim and launch queued scans up to `max_concurrent_scans`.
    Runs until `stop_event` is set (`api/main.py`'s `lifespan` sets it
    on shutdown).

    On shutdown, any still-in-flight scans ARE cancelled — deliberately,
    so the process can actually exit promptly instead of blocking for up
    to ~25 minutes waiting out whatever happened to be running (this
    matters for tests too: `TestClient.__exit__` must not hang). This is
    not treated as a special "graceful shutdown" case distinct from a
    hard crash: a cancelled scan's row is simply left `'running'` with a
    heartbeat that stops advancing, and `sweep_stale_running_scans`
    reclaims it the exact same way it reclaims a scan whose process was
    killed outright — one mechanism handles both, not two."""
    active: set[asyncio.Task[None]] = set()
    try:
        while not stop_event.is_set():
            requeued, failed = control_db.sweep_stale_running_scans(
                stale_after_seconds=api_settings.scan_stale_after_seconds,
                max_retries=api_settings.scan_max_retries,
                reason_prefix="interrupted (worker heartbeat lost)",
            )
            if requeued:
                logger.warning(
                    "Requeued %d stale scan(s) for re-execution: %s",
                    len(requeued),
                    ", ".join(requeued),
                )
            if failed:
                logger.error(
                    "Gave up on %d scan(s) after %d interruptions each: %s",
                    len(failed),
                    api_settings.scan_max_retries,
                    ", ".join(failed),
                )

            while len(active) < api_settings.max_concurrent_scans:
                scan = control_db.claim_next_queued_scan(worker_id)
                if scan is None:
                    break
                task = asyncio.create_task(
                    _run_claimed_scan(api_settings=api_settings, control_db=control_db, scan=scan)
                )
                active.add(task)
                task.add_done_callback(active.discard)

            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    stop_event.wait(), timeout=api_settings.scan_poll_interval_seconds
                )
    finally:
        # Cancel every still-in-flight scan (see the docstring above for
        # why) and wait for each to actually finish unwinding before
        # this coroutine returns — `active` itself is mutated by each
        # task's `add_done_callback(active.discard)` as they complete,
        # so both loops below iterate a SNAPSHOT list, never the live
        # set (iterating the set directly here raised a real
        # "Set changed size during iteration" `RuntimeError` during this
        # task's own manual testing — caught before it ever reached the
        # test suite).
        pending = list(active)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task
