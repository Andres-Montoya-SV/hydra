"""Security audit (hardening round 1, Task 6): transactional safety of
multi-table persistence writes.

Real finding, fixed in this round: `AssetStore.persist_registry` used to
call `clear_run_data(run_id)` — its own, separately-committed transaction —
and only *afterward* open a second connection/transaction for the actual
inserts (hosts, clusters, graph, intel entities/observations/evidence/
relationships/indicators/hypotheses/attempts). A crash between those two
transactions (process killed, OOM, disk full, power loss — not a
hypothetical, this is exactly the kind of failure a long-running recon
process can hit) left the run with ALL prior data deleted and NO new data
written: total data loss for that run, not a merely-partial write.

Fixed by moving `clear_run_data` onto the same connection/transaction
`persist_registry` already holds open (`core/store.py`). This file proves
the fix with a real simulated crash — not by re-reading the code and
assuming the fix works.
"""

from __future__ import annotations

import pytest

from core.assets import Host, HttpService, ScanRun
from core.store import AssetStore


def _seed_first_good_run(store: AssetStore, run_id: str) -> None:
    store.create_run(
        ScanRun(run_id=run_id, started_at="2026-01-01T00:00:00Z", targets=["example.com"])
    )
    host = Host(domain="good.example.com")
    host.http_services.append(
        HttpService(url="https://good.example.com", host="good.example.com", status_code=200)
    )
    store.persist_registry(run_id, {host.domain: host})


class TestPersistRegistryIsAtomic:
    def test_a_crash_mid_write_never_leaves_the_run_with_prior_data_deleted_and_nothing_written(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_path = tmp_path / "recon.db"
        store = AssetStore(db_path)
        run_id = "run1"
        _seed_first_good_run(store, run_id)

        # Confirm the "before" state is real, not assumed.
        rows_before = store.get_findings(run_id)  # empty is fine; we care about hosts below
        assert rows_before == []
        with store._connect() as conn:  # noqa: SLF001
            hosts_before = conn.execute(
                "SELECT domain FROM hosts WHERE run_id=?", (run_id,)
            ).fetchall()
        assert [r["domain"] for r in hosts_before] == ["good.example.com"]

        # Simulate a crash partway through re-finalizing the SAME run —
        # after clear_run_data's DELETEs have run (inside the same
        # transaction now), but before the transaction commits.
        real_insert_host = AssetStore._insert_host

        def _crash_after_first_host(self, conn, run_id, host):  # noqa: ANN001
            raise RuntimeError("simulated crash mid-persist_registry")

        monkeypatch.setattr(AssetStore, "_insert_host", _crash_after_first_host)

        new_host = Host(domain="new-but-never-fully-written.example.com")
        with pytest.raises(RuntimeError, match="simulated crash"):
            store.persist_registry(run_id, {new_host.domain: new_host})

        monkeypatch.setattr(AssetStore, "_insert_host", real_insert_host)

        # The crash must not have left the run empty — the ORIGINAL data
        # (from before this failed call) must still be there, because the
        # DELETE and the (failed) INSERT were one transaction that rolled
        # back together.
        with store._connect() as conn:  # noqa: SLF001
            hosts_after = conn.execute(
                "SELECT domain FROM hosts WHERE run_id=?", (run_id,)
            ).fetchall()
        assert [r["domain"] for r in hosts_after] == [
            "good.example.com"
        ], "a crash mid-write must never leave the run with its prior data deleted and nothing replacing it"

    def test_successful_reruns_still_fully_replace_prior_data_not_accumulate(
        self, tmp_path
    ) -> None:
        """The atomicity fix must not turn clear-then-rebuild into
        rebuild-without-clearing — re-finalizing a run with a different
        host set must still fully replace the old one."""
        db_path = tmp_path / "recon.db"
        store = AssetStore(db_path)
        run_id = "run1"
        _seed_first_good_run(store, run_id)

        replacement_host = Host(domain="replacement.example.com")
        store.persist_registry(run_id, {replacement_host.domain: replacement_host})

        with store._connect() as conn:  # noqa: SLF001
            domains = {
                row["domain"]
                for row in conn.execute(
                    "SELECT domain FROM hosts WHERE run_id=?", (run_id,)
                ).fetchall()
            }
        assert domains == {"replacement.example.com"}

    def test_clear_run_data_standalone_call_still_commits_its_own_transaction(
        self, tmp_path
    ) -> None:
        """Backward-compatible standalone usage (conn=None, the default)
        must be unchanged: still its own immediately-committed
        transaction, for any caller that isn't doing clear-then-rebuild."""
        db_path = tmp_path / "recon.db"
        store = AssetStore(db_path)
        run_id = "run1"
        _seed_first_good_run(store, run_id)

        store.clear_run_data(run_id)

        with store._connect() as conn:  # noqa: SLF001
            hosts = conn.execute("SELECT domain FROM hosts WHERE run_id=?", (run_id,)).fetchall()
        assert hosts == []
