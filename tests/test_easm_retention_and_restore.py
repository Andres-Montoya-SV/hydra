"""Fase 20 (EASM roadmap) — retention, backup/restore coverage, and
referential integrity for the domain model Fases 02-19 built.

Four required proofs, each its own test class:
1. Backup/restore covers every EASM table, verified with real row
   comparisons after a real backup + restore, not just "the file exists."
2. Idempotency: running the full EASM backfill twice over the same
   fixture produces zero duplicates (extends what Fases 03-18 already
   proved individually with one full-chain, end-to-end confirmation).
3. Referential integrity after restoring a corrupted/mixed snapshot is
   detected and reported, never silently discarded, never blocking the
   restore itself.
4. The observation-retention purge job never deletes the single
   remaining observation an asset's current evidence depends on, and
   never touches `assets`/`evidence`/`exposures` themselves.
"""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

import pytest

from api.asset_backfill import backfill_assets_for_organization
from api.backup_worker import backup_sqlite_file
from api.control_db import ControlDB
from api.easm_backfill import run_easm_backfill_for_organization
from api.exposure_identity import exposure_from_finding
from api.reconciliation_worker import run_observation_retention_purge_job
from api.restore_backup import restore_backup
from api.restore_integrity import check_referential_integrity
from api.settings import APISettings
from api.tenancy import account_db_path
from core.assets import Host, TechnologyFinding, TlsCertificate
from core.store import AssetStore, ScanRun


@pytest.fixture
def api_settings(tmp_path: Path) -> APISettings:
    return APISettings(data_dir=tmp_path / "api_data")


@pytest.fixture
def control_db(api_settings: APISettings) -> ControlDB:
    return ControlDB(api_settings.control_db_path)


def _seed_full_easm_state(
    control_db: ControlDB, api_settings: APISettings, *, account_id: str, organization_id: str
) -> str:
    """One real, rich scan that, once backfilled, populates every EASM
    table this phase needs to prove backup/restore coverage for."""
    scan_id = secrets.token_hex(16)
    control_db.create_scan(
        scan_id=scan_id,
        account_id=account_id,
        domain="example.com",
        db_path=str(api_settings.data_dir),
        organization_id=organization_id,
    )
    store = AssetStore(account_db_path(api_settings, account_id))
    store.create_run(ScanRun(run_id=scan_id, started_at="2026-01-01T00:00:00+00:00"))
    from core.assets import HttpService

    host = Host(
        domain="example.com",
        discovery_sources=["dnsx"],
        tls=TlsCertificate(
            host="example.com",
            issuer="Let's Encrypt",
            subject="CN=example.com",
            sans=["example.com"],
            not_before="2026-01-01",
            not_after="2026-04-01",
            fingerprint_sha256="a" * 64,
        ),
        http_services=[
            HttpService(
                url="https://example.com",
                host="example.com",
                status_code=200,
                source="httpx",
                technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=95)],
            )
        ],
    )
    store.upsert_host(scan_id, host)
    control_db.update_scan_status(scan_id, "completed")
    run_easm_backfill_for_organization(
        control_db=control_db, api_settings=api_settings, organization_id=organization_id
    )
    return scan_id


class TestBackupRestoreCoversEveryEasmTable:
    def test_a_real_backup_and_restore_round_trips_every_easm_row(
        self, control_db: ControlDB, api_settings: APISettings, tmp_path: Path
    ) -> None:
        account_id = control_db.create_account(email="owner@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_full_easm_state(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )

        def _snapshot(db: ControlDB) -> dict[str, int]:
            asset = db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type="domain",
                identity_key="domain:example.com",
            )
            return {
                "assets": len(db.list_assets_for_organization(organization_id)),
                "observations": len(db.list_observations_for_asset(asset.asset_id)),
                "change_events": len(db.list_change_events_for_asset(asset.asset_id)),
                "certificate_events": len(db.list_certificate_events_for_asset(asset.asset_id)),
                "technology_events": len(db.list_technology_events_for_asset(asset.asset_id)),
            }

        before = _snapshot(control_db)
        assert before["assets"] >= 1
        assert before["observations"] >= 1
        assert before["certificate_events"] >= 1
        assert before["technology_events"] >= 1

        backup_dest = tmp_path / "backup" / "control.db"
        backup_sqlite_file(api_settings.control_db_path, backup_dest)

        # Simulate real data loss: destroy the original.
        api_settings.control_db_path.unlink()

        restored_dir = tmp_path / "restored"
        report = restore_backup(tmp_path / "backup", restored_dir, force=False)
        assert report.is_clean

        restored_db = ControlDB(restored_dir / "control.db")
        after = _snapshot(restored_db)
        assert after == before


class TestFullBackfillIdempotency:
    def test_running_the_full_easm_backfill_twice_produces_zero_duplicates(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner2@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_full_easm_state(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )

        def _counts() -> dict[str, int]:
            asset = control_db.get_asset_by_identity(
                organization_id=organization_id,
                asset_type="domain",
                identity_key="domain:example.com",
            )
            return {
                "assets": len(control_db.list_assets_for_organization(organization_id)),
                "observations": len(control_db.list_observations_for_asset(asset.asset_id)),
                "certificate_events": len(
                    control_db.list_certificate_events_for_asset(asset.asset_id)
                ),
                "technology_events": len(
                    control_db.list_technology_events_for_asset(asset.asset_id)
                ),
            }

        first_pass = _counts()

        # Run the full backfill chain twice more over the exact same
        # underlying scan data.
        run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        run_easm_backfill_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )

        second_pass = _counts()
        assert second_pass == first_pass


class TestRestoreReferentialIntegrityCheck:
    def test_a_corrupted_snapshot_missing_an_asset_is_detected_never_silently_fixed(
        self, control_db: ControlDB, api_settings: APISettings, tmp_path: Path
    ) -> None:
        account_id = control_db.create_account(email="owner3@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_full_easm_state(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )

        backup_dest = tmp_path / "backup" / "control.db"
        backup_sqlite_file(api_settings.control_db_path, backup_dest)

        # Simulate a hand-edited/corrupted snapshot: delete the asset row
        # directly (bypassing ControlDB entirely), leaving its
        # certificate_events/technology_events/observations dangling.
        conn = sqlite3.connect(backup_dest)
        conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset.asset_id,))
        conn.commit()
        # backup_sqlite_file's destination inherits WAL mode from the
        # source (core.store.connect_sqlite's own default) -- without an
        # explicit checkpoint, this DELETE lands in backup_dest-wal,
        # invisible to restore_backup's plain shutil.copy2 of control.db
        # alone.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()

        restored_dir = tmp_path / "restored"
        report = restore_backup(tmp_path / "backup", restored_dir, force=False)

        assert not report.is_clean
        orphan_tables = {row.table for row in report.orphaned_rows}
        assert "certificate_events" in orphan_tables
        assert "technology_events" in orphan_tables
        assert "observations" in orphan_tables

        # Report-only: nothing was deleted or "fixed" by the check itself.
        restored_db = ControlDB(restored_dir / "control.db")
        after_asset = restored_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        assert after_asset is None  # still missing -- untouched, exactly as restored
        # And the direct integrity check function itself is read-only too:
        report_again = check_referential_integrity(restored_dir / "control.db")
        assert report_again.orphaned_rows == report.orphaned_rows

    def test_a_clean_restore_reports_no_orphans(
        self, control_db: ControlDB, api_settings: APISettings, tmp_path: Path
    ) -> None:
        account_id = control_db.create_account(email="owner4@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        _seed_full_easm_state(
            control_db, api_settings, account_id=account_id, organization_id=organization_id
        )
        backup_dest = tmp_path / "backup" / "control.db"
        backup_sqlite_file(api_settings.control_db_path, backup_dest)

        report = restore_backup(tmp_path / "backup", tmp_path / "restored", force=False)
        assert report.is_clean
        assert report.orphaned_rows == ()


class TestObservationRetentionNeverBreaksAssetOrExposureTraceability:
    def test_purge_never_deletes_the_last_observation_of_the_current_fact(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        account_id = control_db.create_account(email="owner5@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        store = AssetStore(account_db_path(api_settings, account_id))

        def run_scan(historical_time: str) -> None:
            scan_id = secrets.token_hex(16)
            control_db.create_scan(
                scan_id=scan_id,
                account_id=account_id,
                domain="example.com",
                db_path=str(api_settings.data_dir),
                organization_id=organization_id,
            )
            store.create_run(ScanRun(run_id=scan_id, started_at=historical_time))
            store.upsert_host(scan_id, Host(domain="example.com", discovery_sources=["dnsx"]))
            control_db.update_scan_status(scan_id, "completed")
            with sqlite3.connect(api_settings.control_db_path) as conn:
                conn.execute(
                    "UPDATE scans SET created_at = ?, updated_at = ? WHERE scan_id = ?",
                    (historical_time, historical_time, scan_id),
                )
            backfill_assets_for_organization(
                control_db=control_db, api_settings=api_settings, organization_id=organization_id
            )

        run_scan("2020-01-01T00:00:00+00:00")
        run_scan("2020-01-02T00:00:00+00:00")
        run_scan("2026-01-01T00:00:00+00:00")  # recent -- must survive

        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        before = control_db.list_observations_for_asset(asset.asset_id)
        assert len(before) == 3

        observations_purged, evidence_purged = control_db.purge_stale_observations_for_organization(
            organization_id, cutoff="2025-01-01T00:00:00+00:00"
        )
        assert observations_purged == 2
        assert evidence_purged == 0  # the fact is still current -- its evidence survives

        after = control_db.list_observations_for_asset(asset.asset_id)
        assert len(after) == 1
        assert after[0].observation.observed_at == "2026-01-01T00:00:00+00:00"

        # The asset itself is never touched by this job, under any
        # circumstance.
        assert control_db.get_asset(organization_id, asset.asset_id) is not None

    def test_dry_run_purges_nothing(self, control_db: ControlDB, api_settings: APISettings) -> None:
        account_id = control_db.create_account(email="owner6@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        store = AssetStore(account_db_path(api_settings, account_id))
        scan_id = secrets.token_hex(16)
        control_db.create_scan(
            scan_id=scan_id,
            account_id=account_id,
            domain="example.com",
            db_path=str(api_settings.data_dir),
            organization_id=organization_id,
        )
        store.create_run(ScanRun(run_id=scan_id, started_at="2020-01-01T00:00:00+00:00"))
        store.upsert_host(scan_id, Host(domain="example.com", discovery_sources=["dnsx"]))
        control_db.update_scan_status(scan_id, "completed")
        with sqlite3.connect(api_settings.control_db_path) as conn:
            conn.execute(
                "UPDATE scans SET created_at = ?, updated_at = ? WHERE scan_id = ?",
                ("2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00", scan_id),
            )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        before_count = len(control_db.list_observations_for_asset(asset.asset_id))

        api_settings.retention_purge_dry_run = True
        observations_purged, evidence_purged = run_observation_retention_purge_job(
            api_settings=api_settings, control_db=control_db
        )
        assert observations_purged == 0
        assert evidence_purged == 0
        assert len(control_db.list_observations_for_asset(asset.asset_id)) == before_count

    def test_exposure_and_its_evidence_are_never_touched_by_the_purge(
        self, control_db: ControlDB, api_settings: APISettings
    ) -> None:
        """Exposures trace back to raw per-run Findings
        (`exposure_evidence.finding_id`, in the account's own recon.db),
        never to `control_db.py`'s own `observations`/`evidence` tables
        -- a structurally different lineage this purge job never touches
        at all. This test proves that isolation holds end-to-end: an
        open exposure's own evidence/history survive a purge cycle
        untouched, regardless of how old the unrelated observations are."""
        account_id = control_db.create_account(email="owner7@example.com")
        organization_id, _ = control_db.list_organizations_for_account(account_id)[0]
        store = AssetStore(account_db_path(api_settings, account_id))
        scan_id = secrets.token_hex(16)
        control_db.create_scan(
            scan_id=scan_id,
            account_id=account_id,
            domain="example.com",
            db_path=str(api_settings.data_dir),
            organization_id=organization_id,
        )
        store.create_run(ScanRun(run_id=scan_id, started_at="2020-01-01T00:00:00+00:00"))
        store.upsert_host(scan_id, Host(domain="example.com", discovery_sources=["dnsx"]))
        control_db.update_scan_status(scan_id, "completed")
        with sqlite3.connect(api_settings.control_db_path) as conn:
            conn.execute(
                "UPDATE scans SET created_at = ?, updated_at = ? WHERE scan_id = ?",
                ("2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00", scan_id),
            )
        backfill_assets_for_organization(
            control_db=control_db, api_settings=api_settings, organization_id=organization_id
        )
        asset = control_db.get_asset_by_identity(
            organization_id=organization_id, asset_type="domain", identity_key="domain:example.com"
        )
        draft = exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "admin-exposed",
                "severity": "high",
                "source": "nuclei",
                "url": "https://example.com/admin",
                "name": "Admin exposed",
            },
            asset_id=asset.asset_id,
        )
        assert draft is not None
        exposure_id, _, _ = control_db.upsert_exposure(
            organization_id=organization_id,
            account_id=account_id,
            run_id=scan_id,
            finding_id=1,
            draft=draft,
            observed_at="2020-01-01T00:01:00+00:00",
        )

        control_db.purge_stale_observations_for_organization(
            organization_id, cutoff="2025-01-01T00:00:00+00:00"
        )

        exposure_after = control_db.get_exposure_for_organization(organization_id, exposure_id)
        assert exposure_after is not None
        assert exposure_after.status == "open"
        assert len(control_db.list_exposure_evidence(organization_id, exposure_id)) == 1
