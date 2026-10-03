# Hydra Operator Runbook

For whoever runs a Hydra API deployment: day-to-day checks, routine tasks
and what to do when something goes wrong.

Standing a deployment up (host, domain, TLS, data, first start) is
[DEPLOYMENT.md](../DEPLOYMENT.md). Every setting is documented inline in
`api/.env.example`; a test keeps that file complete.

Every command below runs on the host, inside the API container, for
example `docker compose run --rm api python -m api.operators list`. The
commands use the same database as the API (`HYDRA_API_DATA_DIR` or
`HYDRA_API_DATABASE_URL`).

## Daily checks

| Check | How | Healthy |
|---|---|---|
| Liveness | `GET /health` | `200`; a `503` names the failing database or loop |
| Readiness (route traffic on this) | `GET /ready` | `200` |
| Version deployed | `GET /version` | the release you expect |
| Metrics | `GET /metrics` with an operator key | queue depth, scan outcomes, deliveries |
| Logs | `docker compose logs api` | no repeated `ERROR`; each loop logged its start |
| Backups | the backup directory, or the S3 bucket | a new snapshot per interval |

**Logs and the request id.**
- Every log line carries the request id.
- Every response returns it as `X-Request-ID`, and every error body has
  it as `error.request_id`.
- When a customer quotes one, search the logs for it: a 500 logs the
  exception under that id, and the customer never sees it.

## Operators

Admin endpoints accept only an operator account's own API key; everyone
else gets 404.

```sh
python -m api.operators list
python -m api.operators grant  <account_id | email>
python -m api.operators revoke <account_id | email>
```

- Grants and revocations can only be made on the host, and each one is
  recorded in the security audit log.
- Operators rotate their keys with the normal key endpoints.

| Endpoint | For |
|---|---|
| `GET /admin/security-events` | the security audit log: sign-ins, keys, members, integrations, admin actions |
| `GET /admin/feedback` | beta feedback, newest first (Phase 13b) |
| `GET /admin/wompi/unmatched`, `POST /admin/wompi/reconcile` | payments that couldn't be matched to an account |
| `GET /metrics` | Prometheus metrics |

Reading the audit log or the feedback is itself audited.

## Routine tasks

### Helping a customer

1. **Ask for their diagnostics.** They run `GET /account/diagnostics`, or
   `python -m hydra_client diagnostics`. It shows:
   - email verification and the subscription status;
   - quota use;
   - verified domains, including ones beyond the tier's limit;
   - paused monitoring;
   - the last 10 scans, with their errors;
   - plain-language `hints`.

   Most questions are answered by the hints.
2. **Match the request id** from their error or diagnostics against the
   logs.
3. **Look at the error `code`.** The table in
   [13a](../productization/13a_errors_and_diagnostics.md#codes) says what
   each code means and what the customer should do.

### Feedback

Read `GET /admin/feedback`. Each item carries the account, the category,
the request id and the release it came from.

### Tenant export and deletion

Customers can do all of this themselves through the API. On the host, for
legal requests or support:

```sh
python -m api.tenants pending
python -m api.tenants export-organization <organization_id> <file.zip>
python -m api.tenants delete-organization <organization_id> [--now]
python -m api.tenants delete-account <account_id | email> [--now]
python -m api.tenants cancel-organization <organization_id>
python -m api.tenants cancel-account <account_id | email>
```

Without `--now`, a deletion gets the same 30-day grace as the API. With
`--now`, it purges at once.

### Rotating the secrets key

Stored webhook secrets and ticketing credentials are encrypted with
`HYDRA_API_SECRETS_KEYS`. To rotate:
1. Put a new Fernet key first in the list, and keep the old ones after it.
2. Restart the API.

New writes use the first key, and every key decrypts.

### Operator scan settings

API scans take only the operator's infrastructure and safety settings
from `config/.env`: proxy, rate limits, tool paths, timeouts. An operator
can switch a tool off for API scans, never on. Third-party data-source
keys are never used by API scans. See
[11f](../productization/11f_operator_scan_settings.md).

## When something goes wrong

| Symptom | Likely cause | What to do |
|---|---|---|
| `/health` 503, `control_db` failing | database unreachable | check the database, its credentials (`HYDRA_API_DATABASE_URL`) and pool limits; `/ready` fails too, so the load balancer stops routing |
| `/health` 503, a loop `stale` | a background loop died or is stuck | the logs show its last error; restart the API. Scans interrupted by a restart are requeued automatically, up to `HYDRA_API_SCAN_MAX_RETRIES` |
| Scans stay `queued` | no worker capacity, or the worker loop is stale | `/health`; `HYDRA_API_MAX_CONCURRENT_SCANS`; queue depth in `/metrics`. Pro/Ultra scans are claimed first by design |
| Scans `failed` | tool, network or scope problem | the scan's `error_message` (in diagnostics); the logs under the scan id |
| A customer gets `account_suspended` (402) | payment past the grace period | read-only until billing is resolved; `/admin/wompi/unmatched` if they say they paid |
| A customer gets `rate_limited` (429) | too many requests | expected; `Retry-After` says when to retry. Per-key limit: `HYDRA_API_RATE_LIMIT_PER_MINUTE` |
| Webhook or ticket deliveries failing | destination down or misconfigured | the organization's delivery log; deliveries retry with backoff and are marked dead after the last attempt; redeliver through the API |
| Monitoring stopped for a domain | its verification lapsed, the account is suspended, or the domain is beyond the tier's limit | diagnostics shows which. Monitoring resumes on its own once the cause is fixed |
| Disk filling up | scan artifacts, backups | retention purges scans past each tier's window; `HYDRA_API_BACKUP_RETENTION_COUNT` bounds local backups |

## Backups and restore

- **What's backed up.** The backup loop snapshots the control plane and
  every account's results, locally, and to S3-compatible storage when
  configured.
- **Restoring:** see [10d](../productization/10d_backup_restore.md):

  ```sh
  python -m api.restore_backup <snapshot-dir> <target-data-dir>
  ```

  Restore re-verifies every file against the snapshot's manifest before
  writing anything.
- **Point-in-time recovery.** On managed PostgreSQL, the provider's PITR
  is the first line; see 10d's DigitalOcean procedure.
- **Rehearse restores.** An untested backup is not a backup: rehearse a
  restore into a throwaway directory after any change to storage.

## Releases, migrations and rollback

See [13d](../productization/13d_release_migration_rollback.md):
- the release checklist;
- how the schema migrates (additive, on start);
- moving from SQLite to PostgreSQL
  ([10b](../productization/10b_migration_runbook.md));
- rolling back to the previous image.

## Dated items

- **2026-11-15:** the one reviewed exception in
  `security/vulnerability-allowlist.json` expires (CPython 3.12,
  CVE-2026-82049). After that date the image vulnerability gate fails
  until the base image is updated or the exception is reviewed again.
