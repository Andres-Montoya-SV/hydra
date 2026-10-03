# Product Phase 13d — Documentation, Releases, Migrations and Rollback

Branch: `productization/13d-docs-and-runbooks`. Base: `main` @ `7959c16`
(after PR #130, Phase 13c). This is the last part of Phase 13 (Private
Beta Readiness): see [13a](13a_errors_and_diagnostics.md) for the split.

## What this part adds

| Roadmap item | Where |
|---|---|
| Real API-reference docs | [`docs/API_REFERENCE.md`](../API_REFERENCE.md) and [`docs/api/openapi.json`](../api/openapi.json), generated from the code |
| Operator runbook | [`docs/runbooks/OPERATOR_RUNBOOK.md`](../runbooks/OPERATOR_RUNBOOK.md) |
| Customer runbook | [`docs/runbooks/CUSTOMER_GUIDE.md`](../runbooks/CUSTOMER_GUIDE.md) |
| Migration strategy, rollback plan | this document |
| Feature flags, if needed | not needed; see below |

## The API reference: generated, never hand-written

`python -m api.openapi_docs` writes the reference from the running app's
OpenAPI document.

**What was improved in the served document** (`/openapi.json`, `/docs`):
- **Authentication** is the `ApiKeyAuth` security scheme. Before, the key
  appeared as an optional `X-API-Key` header parameter on 103 operations.
- **Errors:** every operation declares `4XX` and `5XX` with the shared
  `ErrorResponse` shape.
- **Version:** the contract version is `info.x-api-version`.
- **Description:** the stale one (it still described the old SQLite-only
  queue) is replaced by a short guide pointer.

**What the tests check** (`tests/test_api_reference.py`):
- the committed files equal what the code generates, so a route change
  without regenerating fails CI;
- the served document equals the committed one;
- every operation declares the error responses;
- the public operations are exactly six: `/health`, `/ready`,
  `/version`, `POST /accounts`, `POST /accounts/verify-email` and the
  signature-authenticated `POST /webhooks/wompi`.

**Configuration docs.** `tests/test_api_config_documentation.py` now
keeps `api/.env.example` complete, both ways. It found three variables
that were read but undocumented:
- `GEOIP_DB_PATH`;
- `HYDRA_API_OBSERVATION_RETENTION_DAYS`;
- `HYDRA_BUILD_COMMIT`.

It also found the retired `HYDRA_API_ADMIN_TOKEN` unmentioned. All four
are documented now.

## A flaky failure on `main`, fixed

`main`'s postgres job failed once after the 13c merge (`7959c16`). The
same code had passed on the branch twice.

**What it was.** Repeating the beta acceptance test reproduced a failure
about once in 20 runs: `verify-email` rejected the token as missing.

**The cause was a real customer bug.** Email verification tokens were
URL-safe base64, which starts with `-` about once in 64 tokens. A command
line reads such a value as an option, so about 1.6% of new customers
couldn't paste their token into the CLI.

**The fix:**
- Tokens are now 256 random bits as hex, which never start with a dash.
  Outstanding tokens stay valid, since they're matched by value.
- The CLI documents `--` for any value that starts with `-`.
- Regression tests cover both.
- Forcing a dash token reproduces the original failure every time. With
  the fix, the acceptance test passed every repeated run on PostgreSQL.

**One caveat.** The CI job reported "Event loop is closed". Locally, on
Python 3.13, the same failure shows as the argparse `SystemExit` escaping
the test app's shutdown. CI's logs need admin access, so the exact CI
message wasn't confirmed against this cause.

## Versioning

- **The release** (`HYDRA_VERSION`, `pyproject.toml`, the CLI's
  `--version`) follows semantic versioning. A test keeps the three
  equal.
- **The contract** (`API_VERSION`) changes only for a breaking change to
  an existing endpoint. Additions keep it: new endpoints, new optional
  request fields, new response fields, new error codes. Clients should
  ignore unknown fields.
- **The build commit** is in the authenticated diagnostics.

## Release checklist

1. Review the change to `docs/api/openapi.json` in the PR: it is the
   contract diff. A removed or renamed field, or a newly required request
   field, is a breaking change: bump `API_VERSION` and announce it.
2. CI is green: lint, types, bandit, the full suite on Python
   3.10/3.11/3.12 and on PostgreSQL, and the image with its vulnerability
   gate.
3. Build the image with
   `--build-arg HYDRA_BUILD_COMMIT=$(git rev-parse HEAD)`.
4. Take a backup, or confirm the latest snapshot and PITR window, before
   deploying.
5. Deploy. Watch `/health` and `/ready`, the logs, and `/metrics`. Check
   `GET /version`.
6. Smoke-test with the CLI: `version`, `diagnostics` with a test
   account, then `demo`.

## Migration strategy

- **Additive, applied on start.** `ControlDB` creates missing tables and
  indexes (`CREATE … IF NOT EXISTS`) and adds missing columns
  (`_COLUMN_MIGRATIONS`, with defaults) every time the API starts. The
  same code applies on SQLite and PostgreSQL, and each step is idempotent.
- **Nothing destructive.** No migration drops or rewrites a column. A new
  `NOT NULL` column always has a default.
- **Data moves are tools, not startup steps.** SQLite to PostgreSQL uses
  `python -m api.migrate_control_db copy|verify`
  ([10b](10b_migration_runbook.md)). It runs offline, verifies row
  counts and content digests in one transaction, and leaves the source
  untouched as the rollback path.
- **Coverage is tested.** Every table has a defined fate in the Postgres
  transfer, tenant export and purge; the existing tests enforce it.

## Rollback plan

1. **Redeploy the previous image.** This is the normal rollback. Because
   migrations are additive, the previous release runs on the newer
   schema: it ignores tables and columns it doesn't know, and new columns
   have defaults.
2. **If data was damaged,** restore the last good snapshot
   ([10d](10d_backup_restore.md)), or use point-in-time recovery on
   managed PostgreSQL. Then deploy the release that matches it.
3. **A SQLite-to-Postgres cutover rolls back** to the untouched SQLite
   file ([10b](10b_migration_runbook.md#rollback)).

### Rehearsed (2026-10-02)

- **Setup.** On a database written by the current code (13c: a demo
  organization, feedback and a queued scan), the previous release
  (`aaefc67`, 13a, which predates both) started without error.
- **The previous release then:**
  - listed both organizations;
  - served the demo's assets and its three exposures;
  - served the subscription view and diagnostics;
  - claimed and started the queued scan;
  - created a new account.
- **Rolling forward again** to the current code worked as well.

**What a rollback loses, by design:**
- Features newer than the release are absent while it runs.
- **Rolling back past 13b** (`814013e`) leaves demo organizations behind
  as ordinary organizations: writable, and counted against the
  organization limit until they're deleted. Delete them first
  (`python -m api.tenants delete-organization <id> --now`) if that
  matters.
- **Feedback** stays stored, but is unreadable until roll-forward.

## Feature flags: not needed now

The beta doesn't need a runtime feature-flag system.

**Every capability that varies already has a controlled switch:**
- per tier, as data (`api/tiers.py`);
- per organization, the collection settings;
- per scan, the provider override;
- per deployment, the operator's tool switches, which can only switch a
  tool off.

**A flag system would add** a second, untested path through every
guarded route.

**Revisit** if a beta needs a feature on for some customers before it's
ready for a tier.

## Phase 13 status

| Roadmap item | Where |
|---|---|
| First-run onboarding via API/CLI | 13c CLI; [customer guide](../runbooks/CUSTOMER_GUIDE.md) |
| Structured errors for every failure mode | [13a](13a_errors_and_diagnostics.md) |
| Documented retry semantics | 13a; enforced by the 13c client |
| Real API-reference docs | 13d (this) |
| Operator runbook, customer runbook | 13d (this) |
| Demo org from safe fixtures | [13b](13b_demo_and_feedback.md) |
| Feedback mechanism | 13b |
| Support diagnostics | 13a |
| Release/version endpoint | 13a |
| Feature flags if needed | not needed (above) |
| Migration strategy, rollback plan | 13d (this) |
| Beta acceptance test, entirely via API/CLI | [13c](13c_client_cli.md) |

**Next:** Phase 14, the final productization audit.

## Tests

- `tests/test_api_reference.py`: the reference matches the code and the
  served document; auth and errors are declared on every operation; the
  public set is exact.
- `tests/test_api_config_documentation.py`: `api/.env.example` is
  complete, both ways.
- `tests/test_api_account_verification.py`: verification tokens never
  start with a dash.
- `tests/test_hydra_client.py`: a value starting with a dash goes after
  `--`.
