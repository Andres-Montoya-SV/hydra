"""Productization Phase 10d: backup and restore of the PostgreSQL control
plane — the restore rehearsal, automated."""

from __future__ import annotations

import gzip
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from _pg_mode import POSTGRES_URL
from test_migrate_control_db import _seed

import api.control_export as control_export
import api.restore_backup as restore_backup_module
from api.backup_worker import run_backup_job
from api.control_db import ControlDB
from api.control_export import (
    FORMAT,
    MANIFEST,
    ExportedTable,
    Manifest,
    Sequence,
    export_control_plane,
    inspect_control_plane,
    read_manifest,
    restore_control_plane,
)
from api.db import SqliteBackend
from api.pg_transfer import TransferError
from api.restore_backup import restore_postgres_backup
from api.settings import APISettings

on_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="needs HYDRA_TEST_DATABASE_URL")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _rows(control_dir: Path, table: str) -> list[dict[str, Any]]:
    with gzip.open(control_dir / f"{table}.jsonl.gz", "rt", encoding="utf-8") as lines:
        return [json.loads(line) for line in lines]


def _counts(report: Any) -> dict[str, int]:
    return {t.table: t.target_rows for t in report.tables}


class TestManifest:
    def test_round_trips(self) -> None:
        manifest = Manifest(
            format=FORMAT,
            created_at="2026-10-01T00:00:00+00:00",
            tables=(ExportedTable("accounts", 2, "ab" * 32, ("account_id", "email")),),
            sequences=(Sequence("account_creation_attempts", "id", 3),),
        )
        assert Manifest.from_json(manifest.to_json()) == manifest

    def test_an_unknown_format_is_refused(self) -> None:
        with pytest.raises(TransferError, match="unsupported export format"):
            Manifest.from_json(json.dumps({"format": "something-else/9"}))

    def test_a_directory_without_a_manifest_is_incomplete(self, tmp_path: Path) -> None:
        with pytest.raises(TransferError, match="incomplete"):
            read_manifest(tmp_path)

    def test_the_sqlite_control_plane_is_not_exported_this_way(self, tmp_path: Path) -> None:
        db = ControlDB(tmp_path / "c.db", backend=SqliteBackend(tmp_path / "c.db"))
        with pytest.raises(TransferError, match="not on PostgreSQL"):
            export_control_plane(db, tmp_path / "out")


@on_postgres
class TestRestoreRehearsal:
    def test_backup_then_restore_into_a_fresh_database(self, tmp_path: Path) -> None:
        """The rehearsal: a real backup cycle, a restore into an empty
        database, and the application reading the restored data."""
        settings = APISettings(data_dir=tmp_path / "live")
        live = ControlDB(settings.control_db_path)
        seeded = _seed(live)

        snapshot = run_backup_job(api_settings=settings, control_db=live)

        control_dir = snapshot / "control"
        assert _mode(control_dir) == 0o700
        assert all(_mode(f) == 0o600 for f in control_dir.iterdir())
        assert not (snapshot / "control.db").exists()

        restored = ControlDB(tmp_path / "restored" / "control.db")
        report = restore_postgres_backup(snapshot, tmp_path / "restored", restored)

        assert report.matches
        counts = _counts(report)
        assert counts["accounts"] == 2 and counts["asset_identifiers"] == 5
        account = restored.get_account(seeded["owner"])
        assert account is not None and account.email == "owner@example.com"
        assert [s.scan_id for s in restored.list_scans_for_organization(seeded["org"])] == [
            "scan-1"
        ]
        # Identity sequences continue after the restored ids.
        restored.record_account_creation_attempt("192.0.2.9")
        with restored._connect() as conn:
            ids = [row[0] for row in conn.execute("SELECT id FROM account_creation_attempts")]
        assert sorted(ids) == [1, 2, 3, 4]

    def test_the_export_is_one_consistent_instant(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A write that commits while the export runs is not in it."""
        live = ControlDB(tmp_path / "live.db")
        _seed(live)
        real_export_table = control_export._export_table
        written: list[str] = []

        def export_then_write(conn: Any, db: ControlDB, dest: Path, table: str) -> Any:
            result = real_export_table(conn, db, dest, table)
            if not written:  # after the first table, from another connection
                with live._connect() as other:
                    other.execute(
                        "INSERT INTO rate_limit_buckets (key_id, tokens, last_refill_at) "
                        "VALUES ('mid-export', 1, '2026-10-01T00:00:00+00:00')"
                    )
                written.append(table)
            return result

        monkeypatch.setattr(control_export, "_export_table", export_then_write)
        manifest = export_control_plane(live, tmp_path / "export")

        rows = {t.name: t.rows for t in manifest.tables}
        assert written and rows["rate_limit_buckets"] == 0
        with live._connect() as conn:  # it did commit, just after the instant
            assert conn.execute("SELECT count(*) FROM rate_limit_buckets").fetchone()[0] == 1

    def test_a_corrupted_file_is_refused_before_anything_is_written(self, tmp_path: Path) -> None:
        live = ControlDB(tmp_path / "live.db")
        _seed(live)
        export_control_plane(live, tmp_path / "export")
        accounts = _rows(tmp_path / "export", "accounts")
        accounts[0]["email"] = "tampered@example.com"
        (tmp_path / "export" / "accounts.jsonl.gz").unlink()
        with gzip.open(tmp_path / "export" / "accounts.jsonl.gz", "wt", encoding="utf-8") as out:
            out.writelines(json.dumps(row) + "\n" for row in accounts)

        target = ControlDB(tmp_path / "target.db")
        with pytest.raises(TransferError, match="accounts: the export file does not match"):
            restore_control_plane(tmp_path / "export", target)
        assert all(state.rows == 0 for state in inspect_control_plane(target))

    def test_a_truncated_file_is_refused(self, tmp_path: Path) -> None:
        live = ControlDB(tmp_path / "live.db")
        _seed(live)
        export_control_plane(live, tmp_path / "export")
        path = tmp_path / "export" / "asset_identifiers.jsonl.gz"
        path.write_bytes(path.read_bytes()[:20])

        with pytest.raises(TransferError, match="asset_identifiers"):
            restore_control_plane(tmp_path / "export", ControlDB(tmp_path / "target.db"))

    def test_a_non_empty_target_is_refused(self, tmp_path: Path) -> None:
        live = ControlDB(tmp_path / "live.db")
        _seed(live)
        export_control_plane(live, tmp_path / "export")
        target = ControlDB(tmp_path / "target.db")
        target.create_account(email="already@example.com")

        with pytest.raises(TransferError, match="already has data"):
            restore_control_plane(tmp_path / "export", target)
        assert {s.table: s.rows for s in inspect_control_plane(target)}["accounts"] == 1

    def test_inspect_reports_rows_and_the_newest_timestamp(self, tmp_path: Path) -> None:
        live = ControlDB(tmp_path / "live.db")
        _seed(live)
        states = {s.table: s for s in inspect_control_plane(live)}
        assert states["accounts"].rows == 2 and states["accounts"].newest
        assert states["ticketing_links"].rows == 0 and states["ticketing_links"].newest is None

    def test_restore_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        settings = APISettings(data_dir=tmp_path / "live")
        live = ControlDB(settings.control_db_path)
        _seed(live)
        snapshot = run_backup_job(api_settings=settings, control_db=live)
        target_dir = tmp_path / "restored"

        monkeypatch.delenv("HYDRA_API_DATABASE_URL", raising=False)
        assert restore_backup_module.main([str(snapshot), str(target_dir)]) == 2

        monkeypatch.setenv("HYDRA_API_DATABASE_URL", str(POSTGRES_URL))
        assert restore_backup_module.main([str(snapshot), str(target_dir)]) == 0
        assert restore_backup_module.main([str(snapshot), str(target_dir)]) == 1  # not empty

        out = capsys.readouterr()
        assert "TOTAL" in out.out and "already has data" in out.err
        assert "PostgreSQL control plane" in out.err

    def test_export_and_inspect_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _seed(ControlDB(Path("control.db")))  # the CLI's own (test-mode) database
        monkeypatch.setenv("HYDRA_API_DATABASE_URL", str(POSTGRES_URL))

        assert control_export.main(["inspect"]) == 0
        assert control_export.main(["export", str(tmp_path / "cli-export")]) == 0
        assert control_export.main(["export", str(tmp_path / "cli-export")]) == 1  # exists

        assert (tmp_path / "cli-export" / MANIFEST).is_file()
        out = capsys.readouterr().out
        assert "accounts" in out and "Exported" in out
