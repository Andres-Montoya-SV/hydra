# Product Phase 11c — Tenant Export and Deletion

Branch: `productization/11c-tenant-export-deletion`. Base: `main` @
`682149f` (after PR #115, Phase 11b).

Decisions (2026-10-01):

| Question | Decision |
|---|---|
| Who deletes, and when | **Self-service with a 30-day grace period**, cancellable until due. Operators can purge at once from the host. |
| What survives a deletion | **Audit and billing records are kept, pseudonymized.** Emails, raw payment payloads and client addresses are removed; ids stay as opaque ids. Everything else of the tenant is deleted. |
| Export format | **Everything, as one archive.** |

## Endpoints

| Endpoint | Who | Does |
|---|---|---|
| `GET /organizations/{id}/export` | owners | ZIP of every dataset plus a manifest |
| `DELETE /organizations/{id}` | owners | schedules the deletion; **202** `{deletion_due_at}`. Idempotent: a repeat keeps the original date. |
| `POST /organizations/{id}/deletion/cancel` | owners | 204, or 404 when nothing is pending |
| `GET /account/export` | the account | what is held about the account itself: account, subscription, key metadata, memberships, its security events |
| `DELETE /account` | the account | schedules its deletion. The audit event lists the organizations that go with it. |
| `POST /account/deletion/cancel` | the account | 204, or 404 |

On the organization endpoints, members get 403 and outsiders get 404.
Every call is in the security audit log.

From the host (operators):

```
python -m api.tenants pending
python -m api.tenants export-organization <org> <file.zip>   # no size limit
python -m api.tenants delete-organization <org> [--now]
python -m api.tenants delete-account <account_id | email> [--now]
python -m api.tenants cancel-organization <org>
python -m api.tenants cancel-account <account_id | email>
```

The daily reconciliation loop purges what is due. In a deployment set to
`HYDRA_API_RETENTION_PURGE_DRY_RUN`, it only logs what it would purge.

## Export (`api/tenant_export.py`)

The archive holds `manifest.json` (format, organization, time, and each
dataset's row count and SHA-256) plus one `<dataset>.json` per
control-plane table holding the organization's rows:

- inventory and observations;
- exposures and remediation;
- integrations and their deliveries;
- scans, settings and members;
- its security audit log.

Each dataset is a literal per-table read, and a test pins the list to
the schema.

- **Never exported:** webhook signing secrets, integration credentials and
  API-key hashes (their columns are dropped). Any sealed `enc:v1:` value
  that reaches a row anyway is masked.
- **Size:** archives over `HYDRA_API_EXPORT_MAX_BYTES` (default 100 MB)
  get a 413 over HTTP; the host CLI has no limit.
- **Raw scan results** stay in each account's `recon.db` and are available
  as scan reports.

## Purge

**An organization** (`purge_organization_now`):
1. Take the list of its scans.
2. Delete every row of the organization in **one transaction**, children
   before parents (literal statements, pinned to the schema by a test).
   Its kept security audit events lose their client addresses.
3. For each scan, delete the run's data from the member's `recon.db`
   (`AssetStore.purge_run`: 27 literal per-table deletes, also pinned to
   the schema) and its artifact directory. A file that can't be removed
   is logged with its scan id. The database purge has already happened.

**An account** (`purge_account_now`):
1. Purge the organizations it owns alone. Organizations with another owner
   stay, without the account.
2. Delete its own rows: keys and their rate-limit buckets, memberships,
   webhooks and their deliveries, monitoring, domain verifications, usage,
   cost estimates, pending enrollments.
3. Pseudonymize what is kept:
   - the account row becomes a **tombstone** (no email, no tokens,
     `deleted_at` set);
   - the subscription loses its billing email and white-label name;
   - payments and Wompi webhook events lose the payer email and raw
     payload;
   - security events about the account lose their client address.
4. Remove its data directory, including `recon.db`.

Its scans in organizations that survive are kept as those organizations'
history and point at the tombstone. Lookups treat a tombstone as
nonexistent: its keys no longer authenticate, and it can't be re-added as
a member.

**Every control table has a defined fate**, enforced by a test:

| Fate | Tables |
|---|---|
| Purged | the organization statements, the account statements |
| Kept as tombstone, billing or audit record, pseudonymized | `accounts`, `subscriptions`, `wompi_unmatched_payments`, `wompi_webhook_events`, `security_audit_log` |
| Kept, belongs to no tenant | `account_creation_attempts` and `rate_limit_buckets` (IP-keyed abuse counters) |

## Tests (`tests/test_tenant_lifecycle.py`, both backends)

- **Catalogs:** the run purge, the organization purge and the export
  datasets match the schemas exactly and run children first. Every
  control table has a fate.
- **Organization purge:** all of A's datasets end empty except its kept
  audit log; B is unchanged; A's runs are gone from `recon.db`. The kept
  events have no client address.
- **Scheduling:**
  - 202 with a date 30 days out, idempotent;
  - the job waits for the due date, then purges;
  - cancel, and a second cancel is 404;
  - dry run purges nothing;
  - viewers 403, outsiders 404.
- **Account purge:**
  - its sole-owned organization goes, a shared one stays with its other
    owner;
  - tombstone; its key gets 401; its directory is removed;
  - billing and audit records are pseudonymized;
  - self-service cancel works.
- **Export:**
  - the manifest matches the files;
  - every dataset is present;
  - no webhook secret or sealed value appears;
  - 413 above the limit;
  - the account export has no key hashes.
- **Host CLI:** schedule, pending, cancel, export (refuses to overwrite),
  purge at once by email, unknown target.
