"""Productization Phase 10b: SQLite -> PostgreSQL control-plane migration."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from _pg_mode import POSTGRES_URL

import api.migrate_control_db as migrate
import api.pg_transfer as pg_transfer
from api.asset_identity import ReconciliationDecision
from api.control_db import ControlDB
from api.db import SqliteBackend
from api.migrate_control_db import (
    MigrationError,
    MigrationReport,
    TableReport,
    copy_control_db,
    verify_control_db,
)

on_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="needs HYDRA_TEST_DATABASE_URL")


def _sqlite_control_db(path: Path) -> ControlDB:
    # Always a SQLite file, also in the Postgres test mode (the source).
    return ControlDB(path, backend=SqliteBackend(path))


def _seed(db: ControlDB) -> dict[str, str]:
    """A small but real control plane: accounts, organization, scan,
    webhook, monitoring, scope exclusion, assets with identifiers
    (AUTOINCREMENT) and account-creation attempts (AUTOINCREMENT)."""
    owner = db.create_account(email="owner@example.com")
    db.create_account(email="second@example.com")
    org, _ = db.list_organizations_for_account(owner)[0]
    db.create_default_subscription(owner)
    db.create_scan(
        scan_id="scan-1", account_id=owner, domain="example.com", db_path="/x", organization_id=org
    )
    db.create_webhook(
        account_id=owner,
        url="https://hooks.example.com/x",
        secret="s3cret-value",  # noqa: S106 - fixture value
        event_types=("monitoring.changed",),
        organization_id=org,
    )
    db.create_or_update_monitored_domain(
        account_id=owner,
        domain="example.com",
        speed2_enabled=True,
        passive_interval_hours=24,
        active_interval_hours=168,
    )
    db.add_scope_exclusion(
        organization_id=org, account_id=owner, pattern="mta*.example.com", reason="mail"
    )
    db.apply_asset_reconciliation(
        organization_id=org,
        run_id="scan-1",
        decisions=[
            ReconciliationDecision(
                asset_id=f"asset-{i}",
                asset_type="domain",
                identity_key=f"domain:h{i}.example.com",
                is_new=True,
                identifiers=(("ip", f"203.0.113.{i}"),),
            )
            for i in range(1, 6)
        ],
    )
    for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
        db.record_account_creation_attempt(ip)
    db.increment_scan_usage(owner, "2026-09")
    return {"owner": owner, "org": org}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sqlite_tables(path: Path) -> dict[str, set[str]]:
    """table -> the tables it references."""
    with closing(sqlite3.connect(path)) as conn:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
        ]
        return {
            name: {
                row[0]
                for row in conn.execute('SELECT "table" FROM pragma_foreign_key_list(?)', (name,))
            }
            for name in names
        }


class TestTableCatalog:
    def test_covers_exactly_the_current_schema(self, tmp_path: Path) -> None:
        _sqlite_control_db(tmp_path / "control.db")
        assert set(pg_transfer.SQLITE_TABLE_READS) == set(_sqlite_tables(tmp_path / "control.db"))

    def test_parents_come_before_children(self, tmp_path: Path) -> None:
        _sqlite_control_db(tmp_path / "control.db")
        order = list(pg_transfer.SQLITE_TABLE_READS)
        for table, parents in _sqlite_tables(tmp_path / "control.db").items():
            for parent in parents:
                assert order.index(parent) < order.index(table), (parent, table)

    def test_every_statement_is_a_plain_literal_read_of_its_own_table(self) -> None:
        for table, statement in pg_transfer.SQLITE_TABLE_READS.items():
            assert re.fullmatch(r"[a-z_]+", table)
            assert statement.split() == ["SELECT", "*", "FROM", table]


class TestDigest:
    def test_is_order_independent_and_content_sensitive(self) -> None:
        rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        forward, backward, changed = (
            pg_transfer.Digest(),
            pg_transfer.Digest(),
            pg_transfer.Digest(),
        )
        for row in rows:
            forward.add(row)
        for row in reversed(rows):
            backward.add(row)
        for row in [{"a": 1, "b": "x"}, {"a": 2, "b": "z"}]:
            changed.add(row)
        assert forward.hexdigest == backward.hexdigest and forward.rows == 2
        assert changed.hexdigest != forward.hexdigest

    def test_integral_floats_equal_ints(self) -> None:
        a, b = pg_transfer.Digest(), pg_transfer.Digest()
        a.add({"score": 5.0})
        b.add({"score": 5})
        assert a.hexdigest == b.hexdigest

    def test_nan_is_refused_not_hashed(self) -> None:
        with pytest.raises(ValueError):
            pg_transfer.Digest().add({"score": float("nan")})


class TestReport:
    def test_render_and_matches(self) -> None:
        good = TableReport("accounts", 2, 2, "d1", "d1")
        bad = TableReport("scans", 1, 2, "d2", "d3")
        report = MigrationReport(tables=(good, bad))
        assert good.matches and not bad.matches and not report.matches
        text = report.render()
        assert "accounts" in text and "DIFFERS" in text and "TOTAL" in text


class TestRefusals:
    def test_target_must_be_postgres(self, tmp_path: Path) -> None:
        _sqlite_control_db(tmp_path / "source.db")
        target = _sqlite_control_db(tmp_path / "target.db")
        with pytest.raises(MigrationError, match="PostgreSQL"):
            copy_control_db(tmp_path / "source.db", target)

    def test_a_missing_source_is_refused(self, tmp_path: Path) -> None:
        target = _sqlite_control_db(tmp_path / "target.db")
        with pytest.raises(MigrationError, match="not found"):
            copy_control_db(tmp_path / "absent.db", target)

    def test_main_needs_the_url_from_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("HYDRA_API_DATABASE_URL", raising=False)
        assert migrate.main(["copy", str(tmp_path / "control.db")]) == 2


@on_postgres
class TestCopyOnPostgres:
    def test_copies_every_row_and_never_touches_the_source(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        seeded = _seed(_sqlite_control_db(source_path))
        before = _sha256(source_path)
        target = ControlDB(tmp_path / "target.db")

        report = copy_control_db(source_path, target)

        assert report.matches
        counts = {t.table: t.target_rows for t in report.tables}
        assert counts["accounts"] == 2 and counts["asset_identifiers"] == 5
        assert counts["account_creation_attempts"] == 3 and counts["webhooks"] == 1
        assert _sha256(source_path) == before
        # The application reads the migrated data through its normal API.
        account = target.get_account(seeded["owner"])
        assert account is not None and account.email == "owner@example.com"
        assert [s.scan_id for s in target.list_scans_for_organization(seeded["org"])] == ["scan-1"]
        assert verify_control_db(source_path, target).matches

    def test_identity_sequences_continue_after_the_copied_ids(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        target = ControlDB(tmp_path / "target.db")
        copy_control_db(source_path, target)

        target.record_account_creation_attempt("192.0.2.77")

        with target._connect() as conn:
            ids = [row[0] for row in conn.execute("SELECT id FROM account_creation_attempts")]
        assert len(ids) == len(set(ids)) == 4 and max(ids) == 4

    def test_a_non_empty_target_is_refused_and_left_as_it_was(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        target = ControlDB(tmp_path / "target.db")
        existing = target.create_account(email="already@example.com")

        with pytest.raises(MigrationError, match="already has data"):
            copy_control_db(source_path, target)
        assert target.get_account(existing) is not None
        rows = {t.table: t.target_rows for t in verify_control_db(source_path, target).tables}
        assert rows["accounts"] == 1  # only the pre-existing one

    def test_a_failure_mid_copy_leaves_the_target_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        target = ControlDB(tmp_path / "target.db")
        real_compare = migrate._compare

        def tampered(copy: Path, conn: object) -> MigrationReport:
            report = real_compare(copy, conn)
            first = report.tables[0]
            broken = TableReport(first.table, first.source_rows, first.target_rows + 1, "a", "b")
            return MigrationReport(tables=(broken, *report.tables[1:]))

        monkeypatch.setattr(migrate, "_compare", tampered)
        with pytest.raises(MigrationError, match="verification failed"):
            copy_control_db(source_path, target)

        monkeypatch.setattr(migrate, "_compare", real_compare)
        report = verify_control_db(source_path, target)
        assert all(t.target_rows == 0 for t in report.tables)

    def test_a_row_postgres_rejects_rolls_everything_back(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        # SQLite accepts text in an INTEGER column; Postgres does not.
        with closing(sqlite3.connect(source_path)) as conn, conn:  # commits, then closes
            conn.execute("UPDATE monthly_usage SET scans_used = 'lots'")
        target = ControlDB(tmp_path / "target.db")

        with pytest.raises(MigrationError, match="monthly_usage: .*invalid input syntax"):
            copy_control_db(source_path, target)
        assert all(t.target_rows == 0 for t in verify_control_db(source_path, target).tables)

    def test_an_unknown_source_table_is_refused(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        with closing(sqlite3.connect(source_path)) as conn, conn:  # commits, then closes
            conn.execute("CREATE TABLE legacy_things (id TEXT)")
        with pytest.raises(MigrationError, match="legacy_things"):
            copy_control_db(source_path, ControlDB(tmp_path / "target.db"))

    def test_a_source_column_postgres_lacks_is_refused(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        with closing(sqlite3.connect(source_path)) as conn, conn:  # commits, then closes
            conn.execute("ALTER TABLE accounts ADD COLUMN legacy_flag TEXT")
        with pytest.raises(MigrationError, match="accounts.legacy_flag"):
            copy_control_db(source_path, ControlDB(tmp_path / "target.db"))


@on_postgres
class TestVerifyForRollback:
    def test_writes_after_the_copy_show_up_per_table(self, tmp_path: Path) -> None:
        source_path = tmp_path / "source.db"
        _seed(_sqlite_control_db(source_path))
        target = ControlDB(tmp_path / "target.db")
        copy_control_db(source_path, target)

        target.create_account(email="after-cutover@example.com")

        report = verify_control_db(source_path, target)
        differing = {
            t.table: (t.source_rows, t.target_rows) for t in report.tables if not t.matches
        }
        assert differing["accounts"] == (2, 3)
        assert not report.matches

    def test_main_copy_then_verify(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        source_path = tmp_path / "control.db"
        _seed(_sqlite_control_db(source_path))
        monkeypatch.setenv("HYDRA_API_DATABASE_URL", str(POSTGRES_URL))

        assert migrate.main(["copy", str(source_path)]) == 0
        assert migrate.main(["verify", str(source_path)]) == 0
        assert migrate.main(["copy", str(source_path)]) == 1  # target no longer empty

        out = capsys.readouterr()
        assert "every table matches" in out.out and "TOTAL" in out.out
        assert "already has data" in out.err
        assert (
            "hydra-dev-only" not in out.out + out.err and "hydra-ci-only" not in out.out + out.err
        )
