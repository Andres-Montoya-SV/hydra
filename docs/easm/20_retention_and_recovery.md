# EASM Fase 20 — Retention, Backup/Restore, Idempotency

## Purpose

Extends the existing, already-tested backup/restore infrastructure
(`api/backup_worker.py`, `api/restore_backup.py`) to cover the EASM
domain model, adds a referential-integrity check for restores, and adds
the one genuinely missing retention job: bounding the unbounded growth
of raw `observations` from continuous monitoring, without ever touching
`assets`/`evidence`/`exposures` themselves.

## 1. Backup/restore already covers every EASM table — verified, not assumed

`backup_sqlite_file()` uses `sqlite3.Connection.backup()` — a whole-
database, page-level copy, not a table-by-table export. Every EASM
table (`assets`, `observations`, `evidence`, `change_events`,
`candidate_assets`, `relationships`, `exposures`,
`certificate_events`, `technology_events`, `observation_batches`, ...)
already lives inside `control.db`, so it was already covered before
this phase touched anything. Proven with a real test
(`tests/test_easm_retention_and_restore.py::
TestBackupRestoreCoversEveryEasmTable`): seed a rich EASM state, back
up, destroy the original, restore, compare exact row counts across
assets/observations/change events/certificate events/technology events
before and after — not "the file exists," a real data comparison.

## 2. Idempotency

Already established per-phase (Fases 03-18 each proved their own
backfill/import function idempotent). This phase adds one full-chain,
end-to-end confirmation:
`tests/test_easm_retention_and_restore.py::TestFullBackfillIdempotency`
runs `api/easm_backfill.py::run_easm_backfill_for_organization()` three
times total over the same fixture and asserts zero duplicates across
every table it touches — plus Fase 11's own existing import-idempotency
tests (`tests/test_nmap_masscan_import.py`) already cover the
"importación corrida dos veces" half of this requirement.

## 3. Referential integrity after restore

**New**: `api/restore_integrity.py::check_referential_integrity()`.
**Correction (Fase 21 cleanup)**: this section originally claimed no
connection anywhere enables SQLite's FK enforcement — wrong.
`core/store.py::configure_sqlite()` (used by every `connect_sqlite()`
connection, including `ControlDB`'s own) DOES set `PRAGMA
foreign_keys=ON`, so an ordinary write through Hydra's own code already
gets real, enforced referential integrity — SQLite itself would reject a
`DELETE` that left a dangling reference. This check exists for cases
OUTSIDE that protection: a snapshot hand-edited with a bare `sqlite3`
connection or external tool that never enables the pragma (SQLite's own
default, regardless of what other connections do), byte-level file
corruption, or a partial/mixed restore assembled by hand from different
snapshots. An *ordinary* backup/restore cycle can never produce a
dangling reference on its own (the whole database is copied atomically).
`restore_backup()` now runs this check against the just-restored file
and prints every dangling reference found, specifically (table, row,
missing reference).

**The explicit decision this phase required**: neither silently discard
an orphaned row nor block the restore outright. Both would be worse
than the alternative — silent discard destroys evidence/history an
operator never gets to see; blocking turns an often-emergency recovery
action into a hard failure over a data-quality issue unrelated to the
restore mechanism itself. `check_referential_integrity()` only ever
reads; nothing in this module deletes or modifies a row. Verified with
a real corrupted-snapshot test
(`TestRestoreReferentialIntegrityCheck`): manually delete an asset from
a backup snapshot (with an explicit `PRAGMA wal_checkpoint(TRUNCATE)` —
a real subtlety found while writing this test: `backup_sqlite_file`'s
destination inherits WAL mode from the source, so a later direct edit to
a snapshot file needs an explicit checkpoint before a plain file copy
will see it), restore it, and confirm the dangling
`certificate_events`/`technology_events`/`observations` rows are
reported — and that the restored database is left exactly as restored,
untouched by the check itself.

## 4. Retention policy for raw observations

**New**: `ControlDB.purge_stale_observations_for_organization()` +
`api/reconciliation_worker.py::run_observation_retention_purge_job()`
(Job 3, alongside the existing grace-period and scan-artifact purge
jobs — a third, separate job, never folded into the existing
`run_retention_purge_job`, which purges whole `scans` rows and their
on-disk artifacts on an entirely different unit and schedule).

**The rule**: for each distinct (asset, fact) pair, the single most
recent `observations` row is never purged, no matter how old — deleting
it would make the asset look like it has zero observations of a fact it
currently holds. Any OTHER, superseded observation row for that same
pair, older than `api_settings.observation_retention_days` (180 days
default, `HYDRA_API_OBSERVATION_RETENTION_DAYS`-configurable), is what
actually gets purged — pure "this run also saw the same thing again"
redundancy from repeated monitoring cycles. `evidence` rows are purged
only as a defensive follow-on (zero remaining observations AND past the
cutoff — a data anomaly this schema doesn't normally produce, since
`find_or_create_evidence`/`record_observation` are always called
together). `assets`/`exposures` are never touched by this job under any
circumstance — they persist for as long as the asset exists, per the
phase's own explicit requirement.

Reuses the exact same dry-run contract (`api_settings.
retention_purge_dry_run`) `run_retention_purge_job` already established.

**"Never deletes the only evidence of an open exposure"**: verified
directly against the real schema, not assumed. `exposure_evidence`
references raw per-run Findings (`finding_id`, in the account's own
`recon.db`), never `control_db.py`'s own `observations`/`evidence`
tables — the two are structurally separate lineages. The retention job
this phase adds therefore cannot touch exposure evidence at all, by
construction; proven with a direct test
(`TestObservationRetentionNeverBreaksAssetOrExposureTraceability::
test_exposure_and_its_evidence_are_never_touched_by_the_purge`).

## Not rewritten

- `backup_sqlite_file`, `rotate_backups`, `restore_backup`'s `--force`
  requirement — all unchanged. `restore_backup()`'s signature gained a
  return value (`IntegrityReport`, previously `None`) since nothing
  outside its own tests called it and none of them asserted on the
  previous `None` return.
- `run_retention_purge_job` (scan/artifact retention) — unchanged,
  untouched; the new observation-retention job is a genuinely separate
  concern with a separate unit and separate "what survives" guarantee.

## Tests

`tests/test_easm_retention_and_restore.py` — the four required proofs
above, plus a dry-run test confirming zero deletions. All pre-existing
`tests/test_backup_and_restore.py` (16 tests) and
`tests/test_reconciliation_worker.py` (14 tests) pass unchanged.
