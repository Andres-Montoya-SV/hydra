# Product Phase 10a — PostgreSQL Control Plane

Branch: `productization/10a-postgres-backend`. Base: `main` @ `871d2c9`
(after PR #109).

## Scope and decisions

Phase 10 moves the API's control plane (`ControlDB`, `api/control_db.py`:
accounts, organizations, exposures, remediation, integrations, outbox …)
to PostgreSQL. It is split in three PRs:

| Part | What |
|---|---|
| **10a** (this) | backend abstraction, portable SQL, Postgres schema, dual-backend CI |
| 10b | SQLite → Postgres migration tool (per-table row counts) and rollback plan |
| 10c | row-level security, pool sizing, backup / PITR restore rehearsal on the managed database |

Decisions:

- **Control plane first.** Per-account asset stores (`core/store.py`,
  `recon.db`) stay SQLite; they are single-writer per account and are
  still backed up by `api/backup_worker.py`.
- **Both backends stay.** SQLite remains the CLI, local-development and
  single-node mode; `HYDRA_API_DATABASE_URL` switches the API to Postgres.
- **Target:** DigitalOcean managed PostgreSQL 18, `sslmode=require`. The
  URL is read only from the environment (`api/settings.py`); nothing in
  the repository holds a credential, and no test or CI job ever connects
  to it.

## How one codebase runs on both (`api/db.py`)

The SQL is written once:

- `?` and `:name` placeholders, translated for psycopg (`%s`,
  `%(name)s`) outside quoted text; `::` casts and literal `%` are kept
  intact;
- `INSERT … ON CONFLICT DO NOTHING / DO UPDATE` in place of SQLite's
  `INSERT OR IGNORE / OR REPLACE`;
- `julianday()` and `instr()` are defined in the Postgres schema with
  SQLite's semantics, so the time arithmetic in the shared SQL is
  unchanged;
- booleans are bound as `0/1` (as SQLite stores them) and compared
  explicitly (`? = 1`), never used bare as a condition;
- parameters are bound client-side (`ClientCursor`), so `? IS NULL` with
  `None` behaves as in SQLite;
- rows read like `sqlite3.Row` (`row["col"]`, `row[0]`, `dict(row)`).

The few statements that genuinely differ exist as **two complete literal
variants** keyed by dialect, never assembled from fragments:

| Statement | SQLite | Postgres |
|---|---|---|
| JSON id lists (`_CRITICAL_NEIGHBOR_SQL`, `_NEIGHBORHOOD_SQL`, `_EXPOSURES_IN_SQL`) | `json_each(?)` | `jsonb_array_elements_text(?::jsonb)` |
| Remediation worklist default due date (`_WORKLIST_SQL`) | `strftime(… '+7 days')` | `to_char(… + interval)` |

The dialect object owns the rest:

| | SQLite | Postgres |
|---|---|---|
| read-then-write exclusivity (`begin_write`) | `BEGIN IMMEDIATE` (whole file) | `pg_advisory_xact_lock` per resource key (e.g. `remediation:{org}`) |
| DDL | as written | identity columns, `DOUBLE PRECISION` for `REAL` |
| column introspection | `pragma_table_info` | `information_schema.columns` (current schema) |
| health ping | `sqlite_master` | `information_schema.tables` |

Other portability fixes: remediation events order by
`created_at, event_id` (not `rowid`); an unbounded `LIMIT` is a large
integer (not `-1`); the scan rate limiter uses named parameters and
`CASE` instead of two-argument `MIN`.

Connections come from one `psycopg_pool.ConnectionPool` per URL
(`min_size=1`, `max_size=10`; sizing is 10c's job). Each checkout sets the
`search_path` to the instance's schema — `public` in production.

## Operations

- **Backups.** On Postgres the control plane is backed up by the managed
  database (daily snapshots, point-in-time recovery). The backup loop then
  copies only the per-account `recon.db` files. `api/restore_backup.py`
  and `api/restore_integrity.py` restore SQLite snapshots and are
  unchanged; the Postgres restore path is rehearsed in 10c.
- **Configuration:** `HYDRA_API_DATABASE_URL` (see `api/.env.example`).
  Unset keeps `control.db` under the API data directory.

## Verification

- The whole suite runs twice in CI: as before (SQLite), and in the new
  `postgres` job against a `postgres:18.6` service with
  `HYDRA_TEST_DATABASE_URL`. In that mode `tests/_pg_mode.py` maps every
  `ControlDB` path to its own schema (all dropped at session end).
- Test helpers that backdated rows or read raw columns through a bare
  `sqlite3.connect(control_db.db_path)` now use the instance's own
  connection, so they run on both backends. Only tests that are about the
  SQLite file itself are marked `sqlite_only` and skipped on Postgres:
  file backup/restore, upgrading a hand-built legacy file, a corrupted
  file, SQLite write timing at scale, and the kill-and-relaunch test
  whose API runs in a separate process.
- `tests/test_db_backends.py`: placeholder translation, `Row` parity with
  `sqlite3.Row`, DDL translation, identifier safety, schema isolation.
- Locally: `docker run -d --name hydra-pg -p 127.0.0.1:55432:5432
  -e POSTGRES_USER=hydra -e POSTGRES_PASSWORD=hydra-dev-only
  -e POSTGRES_DB=hydra postgres:18`, then
  `HYDRA_TEST_DATABASE_URL=postgresql://hydra:hydra-dev-only@127.0.0.1:55432/hydra pytest tests/`.
