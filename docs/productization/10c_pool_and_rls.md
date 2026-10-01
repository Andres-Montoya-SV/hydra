# Product Phase 10c — Connection Pool and Row-Level Security

Branch: `productization/10c-pool-rls`. Base: `main` @ `ae5b87b` (after
PR #111, Phase 10b).

The roadmap asks for "pooling under concurrent writers" and "RLS layered on
app checks". Backup and point-in-time-recovery restore rehearsal for
Postgres follows in 10d.

## Row-level security

The application's organization checks (`api/routers/org_access.py`:
non-member → 404, non-owner change → 403) stay the first line of
defense. Postgres now enforces a second one.

**The policy.** Every table with an `organization_id` column (about 30,
including `organizations`, `assets`, `exposures`, `scans`, `webhooks` and
`integration_events`) has `hydra_organization_isolation`, which applies
to both reads (`USING`) and writes (`WITH CHECK`):

```
hydra_org_visible(organization_id)
  = no organization context  OR  organization_id = the request's organization
```

The tables also have `FORCE ROW LEVEL SECURITY`, so the policy applies to
the tables' owner as well.

**The context.** `require_member`, which every organization-scoped
endpoint calls, records the verified organization for the rest of that
request (`api.db.set_request_organization`, a context variable). Each
database transaction then sets `hydra.organization_id` from it. Within
such a request, a query that forgets its `WHERE organization_id = ?`
still sees only that organization's rows, and cannot insert or move rows
into another organization. `tests/test_row_level_security.py` simulates
exactly that bug through the API and shows the database containing it;
the test fails if the scoping is removed.

**Without a context the policy allows everything**, as before. That
covers:

- the workers (scan, monitoring, integration delivery, backup,
  reconciliation);
- account-level endpoints such as `/accounts` and `/scans`;
- migrations.

Those paths keep relying on the application's checks alone. A stricter
split (a separate restricted role for request traffic) is possible later
and would not change these policies.

**Installation is idempotent.** The policies are created with the schema,
server-side (`format('%I')`). A table that's already protected is not
altered, so restarting the API takes no table locks.

### The database role must not bypass it

Superusers and roles with `BYPASSRLS` ignore every policy. Run the API as
a dedicated ordinary role. On DigitalOcean that means a user created
under the cluster's *Users & Databases*, not `doadmin`. With `FORCE`, the
role may own the tables it creates. At startup, `ControlDB` logs a
warning if the connected role bypasses row-level security. In that case,
isolation rests on the application's checks alone.

The Postgres test mode follows the same rule. It provisions an ordinary
`hydra_test_app` role, with a fresh random password each session, and
runs the whole suite as that role. Every API and IDOR test therefore
also runs with the policies enforced.

## Connection pool

One `psycopg_pool` pool per API process.

| Setting | Default | Meaning |
|---|---|---|
| `HYDRA_API_DATABASE_POOL_MIN` | 1 | connections kept open |
| `HYDRA_API_DATABASE_POOL_MAX` | 10 | upper bound per process |
| `HYDRA_API_DATABASE_POOL_TIMEOUT` | 30 | seconds a request waits for a free connection, then fails |

- **Sizing.** `MAX × API processes`, plus the migration and admin tools,
  must stay below the cluster's connection limit (shown in the
  DigitalOcean control panel), leaving headroom for maintenance
  connections. Inconsistent values (`MIN > MAX`, zero, a non-positive
  timeout) stop the API at startup.
- **Stale connections.** Each connection is checked before it is handed
  out, so one dropped by a failover or maintenance is replaced instead of
  failing a request.
- **Concurrent writers.** Writers that read before writing take a
  per-resource advisory lock (Phase 10a). More writers than connections
  queue for a connection; they don't fail. The tests run 16 writers
  through a 2-connection pool, and check that an exhausted pool raises
  after its timeout instead of hanging.
- **PgBouncer compatible.** DigitalOcean's connection pools run PgBouncer.
  This works with a transaction-mode pool because:
  - every setting (`search_path`, `hydra.organization_id`) is
    transaction-local;
  - each `ControlDB` operation is one transaction;
  - parameters are bound client-side (no server-side prepared statements);
  - the advisory locks are transaction-scoped.

  Run the migration tool (10b) against the direct connection, not through
  a pool.

## Verification

- **`tests/test_row_level_security.py`:**
  - the policy is present and forced on every organization table;
  - re-initialization is idempotent;
  - reads are limited to the request's organization, and writes into
    another organization are refused;
  - the scope never outlives its transaction on a reused pooled
    connection;
  - the end-to-end "forgotten filter" API test;
  - pool settings (defaults, environment, refusals), concurrent writers,
    and the exhausted-pool timeout.
- **The whole suite** runs on Postgres as the non-superuser role, so the
  policies are enforced throughout.
