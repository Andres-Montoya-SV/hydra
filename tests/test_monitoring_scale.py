"""Real-scale tests for continuous monitoring's data-access layer — the
task's own explicit "~300,000-asset engineering scale target verified by
a real test" requirement. Rows are bulk-inserted directly via raw
`sqlite3`/`executemany` (bypassing `ControlDB`'s one-row-at-a-time CRUD
methods, which are correct but not how 300k rows would ever actually get
into this table — the real growth path is 300k separate `POST
/domains/{domain}/monitoring` calls over months, not one bulk load) so
the setup itself doesn't dominate the measured time. What's actually
under test is `api/control_db.py`'s READ path (keyset pagination) and
WRITE path (chunked `executemany` batches) against a table already at
that size — see `api/control_db.py`'s `monitored_domains` docstring and
`api/monitoring_worker.py`'s own module docstring for the design these
numbers are meant to validate.
"""

from __future__ import annotations

import resource
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from api.control_db import ControlDB

ROW_COUNT = 300_000
PAGE_SIZE = 1_000


def _bulk_insert_monitored_domains(db_path: Path, *, count: int, due_fraction: float) -> str:
    """Direct `sqlite3`, not `ControlDB` — one `executemany` for the
    whole load. Returns one real account_id every row references (a
    single account with 300k monitored domains is an extreme but valid
    shape, and keeps this fixture from also having to bulk-insert 300k
    `accounts` rows just to satisfy the `REFERENCES` clause, which would
    make setup itself the slow part of this test rather than the thing
    being measured)."""
    control_db = ControlDB(db_path)  # creates the schema
    account_id = control_db.create_account(email=f"scale-{secrets.token_hex(6)}@example.com")

    now = datetime.now(timezone.utc)
    due_at = (now - timedelta(hours=1)).isoformat()  # already due
    not_due_at = (now + timedelta(days=30)).isoformat()  # far in the future

    rows = []
    for i in range(count):
        is_due = i < int(count * due_fraction)
        rows.append(
            (
                secrets.token_hex(16),
                account_id,
                f"host{i}.scale-test.example",
                0,
                "active",
                due_at if is_due else not_due_at,
                now.isoformat(),
                now.isoformat(),
            )
        )

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executemany(
            "INSERT INTO monitored_domains "
            "(monitoring_id, account_id, domain, speed2_enabled, status, "
            "next_passive_due_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    return account_id


def _peak_rss_mb() -> float:
    """`ru_maxrss` units differ by platform — bytes on macOS (Darwin),
    KB on Linux — a real, documented `getrusage(2)` platform difference,
    not something derivable by inspecting the value itself (a small-RSS
    process on Linux and a small-RSS process on macOS can both report
    numbers in the same range, so guessing from magnitude alone is
    unreliable). This project's own dev platform is macOS (Darwin), per
    the environment banner, but this checks `sys.platform` explicitly
    rather than hardcoding one assumption, so it still reports correctly
    if this suite ever runs on Linux CI."""
    import sys

    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024


@pytest.fixture(scope="module")
def big_db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("monitoring_scale") / "control.db"
    _bulk_insert_monitored_domains(path, count=ROW_COUNT, due_fraction=0.1)
    return path


class TestPaginatedReadAtScale:
    def test_300k_rows_keyset_paginate_fully_in_bounded_time_and_memory(
        self, big_db_path: Path
    ) -> None:
        control_db = ControlDB(big_db_path)
        rss_before = _peak_rss_mb()

        started = time.monotonic()
        due_before = datetime.now(timezone.utc).isoformat()
        cursor: tuple[str, str] | None = None
        total_seen = 0
        pages = 0
        while True:
            page = control_db.list_due_passive_monitoring_page(
                due_before=due_before, cursor=cursor, limit=PAGE_SIZE
            )
            if not page:
                break
            total_seen += len(page)
            pages += 1
            last = page[-1]
            cursor = (last.next_passive_due_at, last.monitoring_id)
            if len(page) < PAGE_SIZE:
                break
        elapsed = time.monotonic() - started
        rss_after = _peak_rss_mb()

        # 10% of ROW_COUNT were inserted already-due.
        assert total_seen == ROW_COUNT // 10
        assert pages == total_seen // PAGE_SIZE

        # Real, measured numbers — not asserted-and-forgotten. A single
        # indexed range scan per page against 300k rows on ordinary dev
        # hardware finishes in low single-digit seconds; this leaves
        # generous headroom (10s) for slower CI hardware while still
        # catching an accidental full-table-scan regression (which would
        # take much longer, not marginally longer).
        print(
            f"\n[scale] paginated {total_seen} due rows ({pages} pages of {PAGE_SIZE}) "
            f"in {elapsed:.2f}s; peak RSS {rss_before:.1f}MB -> {rss_after:.1f}MB "
            f"(delta {rss_after - rss_before:.1f}MB)"
        )
        assert elapsed < 10.0
        # Peak RSS growth should be a small, bounded amount (one page's
        # worth of Row objects at a time), never proportional to the
        # full 300k-row table — a regression to "load everything, then
        # paginate in Python" would show up here as hundreds of MB, not
        # tens.
        assert (rss_after - rss_before) < 200.0

    def test_a_page_deep_into_the_due_set_is_not_slower_than_the_first_page(
        self, big_db_path: Path
    ) -> None:
        """The actual proof that this is keyset pagination and not OFFSET
        in disguise: fetching the LAST page of due rows costs the same as
        fetching the first — an OFFSET-based implementation would instead
        get progressively slower the deeper the cursor goes, since SQLite
        would have to walk and discard every prior row on every call."""
        control_db = ControlDB(big_db_path)
        due_before = datetime.now(timezone.utc).isoformat()

        started = time.monotonic()
        first_page = control_db.list_due_passive_monitoring_page(
            due_before=due_before, cursor=None, limit=PAGE_SIZE
        )
        first_page_time = time.monotonic() - started

        # Walk to (approximately) the last page.
        cursor = (first_page[-1].next_passive_due_at, first_page[-1].monitoring_id)
        for _ in range((ROW_COUNT // 10 // PAGE_SIZE) - 2):
            page = control_db.list_due_passive_monitoring_page(
                due_before=due_before, cursor=cursor, limit=PAGE_SIZE
            )
            cursor = (page[-1].next_passive_due_at, page[-1].monitoring_id)

        started = time.monotonic()
        deep_page = control_db.list_due_passive_monitoring_page(
            due_before=due_before, cursor=cursor, limit=PAGE_SIZE
        )
        deep_page_time = time.monotonic() - started

        assert len(deep_page) > 0
        print(
            f"\n[scale] first page {first_page_time * 1000:.1f}ms vs. deep page "
            f"{deep_page_time * 1000:.1f}ms"
        )
        # Generous multiplier (not equality) — real timing noise on a
        # shared/loaded test machine is expected; an OFFSET-based
        # regression would show 10-100x, not 1.5-3x, so this margin
        # still catches the real failure mode without being flaky.
        assert deep_page_time < max(first_page_time * 8, 0.5)


class TestBatchedWritesAtScale:
    def test_writing_progress_for_all_due_rows_completes_in_chunked_batches_quickly(
        self, big_db_path: Path
    ) -> None:
        control_db = ControlDB(big_db_path)
        due_before = datetime.now(timezone.utc).isoformat()
        expected_due = ROW_COUNT // 10  # `due_fraction=0.1` in the fixture
        rows = control_db.list_due_passive_monitoring_page(
            due_before=due_before, cursor=None, limit=expected_due
        )
        assert len(rows) == expected_due

        updates = [
            {
                "monitoring_id": r.monitoring_id,
                "speed": "passive",
                "scan_id": "scan-x",
                "ran_at": datetime.now(timezone.utc).isoformat(),
                "next_due_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "asset_digest": "digest-x",
                "asset_count": 1,
                "needs_review": False,
                "status": "active",
            }
            for r in rows
        ]

        started = time.monotonic()
        batch_size = 500
        for i in range(0, len(updates), batch_size):
            control_db.batch_record_monitoring_progress(updates[i : i + batch_size])
        elapsed = time.monotonic() - started

        print(
            f"\n[scale] wrote {len(updates)} rows in {len(updates) // batch_size} "
            f"batches of {batch_size} in {elapsed:.2f}s"
        )
        assert elapsed < 15.0

        # These 50k are no longer due (next_due_at pushed 24h out).
        remaining = control_db.list_due_passive_monitoring_page(
            due_before=due_before, cursor=None, limit=1
        )
        assert all(r.monitoring_id not in {row.monitoring_id for row in rows} for r in remaining)

    def test_a_single_500_row_batch_does_not_meaningfully_block_a_concurrent_small_write(
        self, tmp_path: Path
    ) -> None:
        """The scale requirement's "concurrent-write-non-blocking" half:
        SQLite serializes writers regardless of batching, so "non-
        blocking" here means "a single batch's own transaction is short
        enough that a concurrent small writer (the scan queue's own
        `create_scan`/`claim_next_queued_scan`) is delayed by
        milliseconds, not seconds" — the actual, real, measured
        justification for choosing 500-1000-row batches instead of one
        giant per-cycle transaction."""
        path = tmp_path / "control.db"
        _bulk_insert_monitored_domains(path, count=5_000, due_fraction=1.0)
        control_db = ControlDB(path)

        due_before = datetime.now(timezone.utc).isoformat()
        rows = control_db.list_due_passive_monitoring_page(
            due_before=due_before, cursor=None, limit=1_000
        )
        updates = [
            {
                "monitoring_id": r.monitoring_id,
                "speed": "passive",
                "scan_id": "scan-x",
                "ran_at": datetime.now(timezone.utc).isoformat(),
                "next_due_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "asset_digest": "digest-x",
                "asset_count": 1,
                "needs_review": False,
                "status": "active",
            }
            for r in rows
        ]

        small_write_latencies: list[float] = []
        stop = threading.Event()
        first_write_done = threading.Event()
        # Created up front, outside the timed hammer loop — on a heavily
        # loaded machine (this test also runs as part of the full 1600+
        # test suite, not just in isolation) account creation itself can
        # be slow enough to eat the entire window the batch write takes,
        # which would make the very first hammer write race the batch's
        # own completion instead of genuinely overlapping it.
        other_account = control_db.create_account(email=f"hammer-{secrets.token_hex(6)}@e.com")

        def hammer_small_writes() -> None:
            i = 0
            while not stop.is_set():
                started = time.monotonic()
                control_db.create_scan(
                    scan_id=f"hammer-{i}",
                    account_id=other_account,
                    domain="hammer.example",
                    db_path="/tmp/x",
                )
                small_write_latencies.append(time.monotonic() - started)
                first_write_done.set()
                i += 1
                time.sleep(0.01)

        hammer_thread = threading.Thread(target=hammer_small_writes)
        hammer_thread.start()
        # Block until the hammer thread has proven it's actually running
        # and writing, so the batch write below is guaranteed to overlap
        # at least one real concurrent small write rather than racing an
        # empty measurement window (the actual cause of this test's own
        # observed flakiness under full-suite load).
        assert first_write_done.wait(timeout=5.0), "hammer thread never started writing"
        try:
            control_db.batch_record_monitoring_progress(updates)
        finally:
            stop.set()
            hammer_thread.join(timeout=5.0)

        assert small_write_latencies, "the hammer thread never got a single write in — broken test"
        worst = max(small_write_latencies)
        print(
            f"\n[scale] {len(small_write_latencies)} concurrent small writes during one "
            f"{len(updates)}-row batch; worst latency {worst * 1000:.1f}ms"
        )
        # A single small INSERT ever taking more than a couple of
        # seconds would mean it queued behind a long-held write lock —
        # exactly what batching (vs. one giant transaction) exists to
        # avoid. Generous bound for shared/CI hardware; still an order
        # of magnitude below what an un-batched, all-5000-rows-in-one-
        # transaction write would cost a contending writer.
        assert worst < 2.0
