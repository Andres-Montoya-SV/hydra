# Product Phase 10b — Control-Plane Migration to PostgreSQL: Runbook

Branch: `productization/10b-postgres-migration`. Base: `main` @ `5b654b7`
(after PR #110, Phase 10a).

This runbook moves an existing deployment's control plane (`control.db`,
SQLite) to PostgreSQL (DigitalOcean managed Postgres 18). Phase 10a made
the API able to run on either backend; this phase moves the data. The
per-account `recon.db` files are not part of this move and stay on disk.

## The tool: `python -m api.migrate_control_db`

| Command | What it does | Writes |
|---|---|---|
| `copy <control.db>` | Copies every table into an **empty** Postgres database, verifies, and commits only when every table matches | Postgres only |
| `verify <control.db>` | Compares every table (row count and content digest) between the file and Postgres | nothing |

The target URL is read only from `HYDRA_API_DATABASE_URL`. It is never a
command-line argument (shell history, process listings) and the tool
never prints it.

How `copy` works:

1. **The source is never modified.** The tool takes an online backup of
   `control.db` (opened read-only) into a temporary copy, and runs the
   schema upgrade on the copy, not on the source.
2. **Guards.** It refuses to continue when:
   - the source has a table the tool doesn't know;
   - a source column has no counterpart in Postgres (data would be dropped);
   - the Postgres target already holds any rows.
3. **One transaction.** Tables are copied parents first (foreign-key
   order), in batches of 1,000 rows. The two AUTOINCREMENT tables'
   identity sequences continue after the highest id SQLite ever issued,
   so no id is ever reused.
4. **Verified or nothing.** Before committing, each table's row count and
   content digest are compared: an order-independent SHA-256 over every
   row's values. Any difference, or any row Postgres rejects (for example
   text that SQLite allowed in an INTEGER column), rolls the whole
   transaction back, leaving the target empty. The error names the table.

It prints one line per table (SQLite rows, Postgres rows, result) and a
total. Exit code 0 means every table matches.

No SQL is built at runtime:

- **SQLite reads:** literal statements (`_SOURCE_SELECTS`). A test fails
  if that catalog drifts from the schema or breaks foreign-key order.
- **Postgres writes:** table names are bound parameters, quoted by the
  server (`format('%I')`) inside session-temporary functions.

Measured locally, copying and verifying 60,000 rows took 2.3 s.

## Before the cutover

1. **Provision** the managed database:
   - Postgres 18;
   - trusted sources limited to the API host;
   - `sslmode=require`.

   Put the URL in the deployment's secret store.
2. **Carry over secrets.** Keep `HYDRA_API_SECRETS_KEYS` identical on the
   Postgres deployment. Sealed webhook and ticketing secrets are copied
   byte-for-byte and must still decrypt.
3. **Rehearse** on a throwaway database (a second managed database, or a
   local `postgres:18`) with the latest backup snapshot's `control.db`:
   - run `copy`;
   - start an API against it;
   - check `/health`;
   - list organizations, scans and exposures with a known API key.

   Record the table report.

## Cutover

1. **Announce** a maintenance window.
2. **Stop the API**, including its workers (scan, monitoring, integration
   delivery, backup), so that `control.db` stops changing. Scans that were
   running are requeued by the orphaned-scan recovery on the next start.
3. **Keep the rollback point.** Record `sha256sum control.db` and make the
   file read-only (`chmod 400`). The tool never writes to it; this guards
   against everything else.
4. **Copy:**

   ```
   HYDRA_API_DATABASE_URL=... python -m api.migrate_control_db copy /data/control.db
   ```

   Continue only on exit code 0 ("every table matches").
5. **Switch** the deployment's `HYDRA_API_DATABASE_URL` to the database,
   then start the API.
6. **Smoke-test:**
   - `/health` is 200;
   - the same listings as in the rehearsal;
   - one scan end to end.

## Rollback

The SQLite file is the rollback point for as long as it is kept (keep it
at least 7 days). Deciding whether a rollback loses data takes one
command:

```
HYDRA_API_DATABASE_URL=... python -m api.migrate_control_db verify /data/control.db
```

- **Every table matches (exit 0).** Postgres has taken no writes since
  the copy, so the rollback is lossless:
  1. Stop the API.
  2. Unset `HYDRA_API_DATABASE_URL`.
  3. Start the API. It is back on `control.db` exactly as it was.
- **Some tables differ (exit 1).** Postgres has accepted writes since the
  cutover, and the report shows which tables and how many rows. A rollback
  loses those rows (for example, accounts or webhooks created since),
  and there is no automatic reverse sync. Prefer fixing forward. If rolling
  back anyway:
  1. Record the report.
  2. Tell the affected users.
  3. Follow the lossless steps above.

**Retrying after a rollback.** `copy` only writes into an empty target.
Drop and recreate the database (or restore its empty-at-creation
snapshot) before running it again.

## Out of scope here

- **Per-account data:** the `recon.db` files stay on SQLite and are still
  backed up by the backup loop.
- **Phase 10c:**
  - row-level security;
  - pool sizing;
  - backup and point-in-time-recovery restore rehearsal on the managed
    database.

## Verification

- **`tests/test_migrate_control_db.py`**, in CI's `postgres` job:
  - every row is copied and the source file's SHA-256 is unchanged;
  - the app reads the migrated data through its normal API;
  - identity sequences continue after the copied ids;
  - a non-empty target is refused and left untouched;
  - a failed verification or a row Postgres rejects leaves the target
    empty;
  - an unknown table and an unknown column are refused;
  - `verify` reports writes made after the copy, per table;
  - the CLI's exit codes, and the URL never appears in its output.
- **Without Postgres:** the catalog, foreign-key order, digest and refusal
  tests run in the SQLite suite too.
