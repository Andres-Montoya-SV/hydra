# Product Phase 10d — Backup and Restore on PostgreSQL

Branch: `productization/10d-pg-backup-restore`. Base: `main` @ `c2cc4ed`
(after PR #112, Phase 10c).

The roadmap asks to rewrite backup and restore for Postgres and redo the
restore rehearsal afterwards. This phase covers both.

## Three layers

| Layer | What it protects against | Where |
|---|---|---|
| DigitalOcean managed backups (daily) and point-in-time recovery | a bad deploy, accidental deletes, a lost node | inside DigitalOcean; restores into a **new** cluster |
| **Logical export** of the control plane, in every backup snapshot (new) | losing the DigitalOcean account or region; any provider-level failure | the snapshot directory, uploaded to S3-compatible storage when configured |
| Per-account `recon.db` files | as before | the same snapshot directory |

## The export (`api/control_export.py`)

On Postgres, every backup cycle writes `<snapshot>/control/`:

- `manifest.json`: the format, the creation time and, for each table, its
  rows, content digest and columns, plus the positions of the identity
  sequences;
- `<table>.jsonl.gz`: one JSON object per row.

- **Consistent:** all tables are read in one `REPEATABLE READ`
  transaction, so the export shows a single instant while the API keeps
  writing. A test commits a write in the middle of an export and checks
  that it is absent; without snapshot isolation that test fails.
- **Complete or obviously not:** the manifest is written last. A
  directory without one is refused as incomplete.
- **Private:** files are created 0600 and the directory 0700. They hold
  what the database holds: API-key hashes, emails and sealed secrets.
- **Size:** the local rehearsal's 2,028 rows took about 200 KB on disk, most of it the minimum block size of 46 small files.

## Restore (`python -m api.restore_backup <snapshot> <target-data-dir>`)

The same command as before. A snapshot with `control/manifest.json` is
restored into the database at `HYDRA_API_DATABASE_URL`, which must be
empty. The restore:

1. re-hashes every file against the manifest before writing anything, so
   a corrupted or truncated file is refused;
2. checks that the target schema has every exported column;
3. loads every table in one transaction, parents first, and continues
   the identity sequences;
4. commits only if every table's rows and digest match the manifest.
   Otherwise the transaction rolls back and the target stays empty;
5. copies the account `recon.db` files. Existing ones are refused unless
   `--force` is given.

SQLite snapshots (`control.db`) restore exactly as before.

`python -m api.control_export export <dir>` takes an ad-hoc export (for
example from a point-in-time fork). `python -m api.control_export
inspect` prints the rows and newest timestamp of each table.

## Rehearsals

**Automated, in CI** (`tests/test_control_export.py`, `postgres` job):

1. A real backup cycle (`run_backup_job`) runs against a seeded Postgres
   control plane.
2. The snapshot is restored into a fresh database.
3. The application reads the restored data through its normal API.
4. A new id continues after the restored ones.

The same file also covers a corrupted file, a truncated file, a non-empty
target, the consistency check above, and the CLIs.

**Manual, 2026-10-01, local `postgres:18`**, two scratch databases,
through the real CLIs:

```
backup cycle                → snapshot …/backups/20261001T062531Z (control/ 0700, files 0600)
python -m api.restore_backup → 45 tables "ok", TOTAL 2028 / 2028
python -m api.control_export inspect (live vs restored):
  account_creation_attempts  2003  2026-10-01T06:25:30.950495+00:00   (identical)
  accounts                      3  2026-10-01T06:25:30.952175+00:00   (identical)
  asset_identifiers             5  2026-10-01T06:25:30.943112+00:00   (identical)
```

### Point-in-time recovery on DigitalOcean (operator procedure)

This one can only be rehearsed on the real cluster. The development
environment never connects to it.

1. In the control panel, restore the cluster from a backup to the chosen
   point in time. DigitalOcean creates a **new** cluster; the current one
   is untouched. Check DigitalOcean's documentation for the current
   retention window.
2. Create the application role on the new cluster, as in 10c: not
   `doadmin`.
3. Check what was recovered:

   ```
   HYDRA_API_DATABASE_URL=<new cluster> python -m api.control_export inspect
   ```

   The newest timestamps must be at or just before the chosen point, and
   the row counts plausible.
4. Point a staging API at the new cluster and smoke-test it (`/health`,
   listings, one scan).
5. To cut over, stop the API, switch `HYDRA_API_DATABASE_URL`, and start
   it. Keep the old cluster until the new one is confirmed.
6. Record the date, the chosen point, the inspect output and the smoke
   result here.

Restoring from a logical export instead (provider-independent): create
an empty database, then:

```
HYDRA_API_DATABASE_URL=<empty db> python -m api.restore_backup <snapshot> <data-dir>
```
