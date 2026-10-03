# Product Phase 13b — Demo Organization and Feedback

Branch: `productization/13b-demo-and-feedback`. Base: `main` @ `aaefc67`
(after PR #123, Phase 13a). Part of Phase 13 (Private Beta Readiness):
see [13a](13a_errors_and_diagnostics.md) for the split.

## The demo organization (decision 2026-10-02: self-serve)

`POST /demo/organization` gives the caller a labelled organization full of
sample data. A beta customer can then explore assets, evidence, exposures
and changes before verifying a real domain.

- **201** creates it; **200** returns the account's existing one. Each
  account has at most one, even under concurrent requests: the check and
  the insert share the organization entitlement's lock.
- Every listing marks it with `"is_demo": true`, and its name says it's
  sample data.

### Safe fixtures, real engine

- **Reserved names and addresses only:**
  - names reserved for documentation: `example.com` and its subdomains
    (RFC 2606), and `.test` (RFC 6761);
  - addresses in the documentation ranges `192.0.2.0/24`,
    `198.51.100.0/24` and `203.0.113.0/24` (RFC 5737).

  Nothing refers to anyone's real infrastructure. A test checks every
  name, URL and address in the fixture.
- **Nothing is scanned or contacted.** The fixtures (`api/demo.py`) are
  written as one completed scan with `trigger_source = 'demo'` in the
  owner's results database. The ordinary EASM backfill then builds the
  assets, observations, evidence, exposures and events
  from it. The demo shows exactly what a real scan would, produced by the
  same deterministic engine, with real evidence chains.
- **What's in it:** six hosts with DNS records, open ports, web services
  and technologies, and two certificates with different expiry dates.
  There are three exposures: an exposed admin panel (high), an outdated
  CMS (medium) and a directory listing (low).

### Read-only, never scanned, not counted

- **Read-only.** Every write naming a demo organization in its path is
  refused with 403 `demo_organization_read_only`, except deleting it and
  cancelling that deletion. One guard in `require_api_key` applies this,
  so no route can forget it. A test enumerates every organization write
  route.
- **Never disclosed to non-members.** The guard refuses only members.
  Anyone else gets the route's ordinary 404, so the guard never reveals
  that an organization exists, let alone that it is a demo.
- **Never scanned.** Scans always target the account's default
  organization (its oldest owned one), which a demo organization never
  is. No write names an organization in its body. The demo domains can't
  be verified by anyone: `example.com` belongs to IANA, and `.test` never
  resolves.
- **Not counted.** The demo doesn't count against the organization
  entitlement or `organizations_owned`. Its scan doesn't count against
  the scan quota.
- **Not purged by retention.** Retention skips the demo scan, so its
  evidence stays readable. Deleting the organization purges everything,
  the scan included, and then the account can create a new demo.

## Feedback (decision 2026-10-02: stored in Hydra)

- **`POST /feedback`** takes `{"category": "bug" | "idea" | "question" |
  "other", "message": "..."}`, a message of 1 to 4000 characters, and
  returns 201.
  - **Rate-limited.** An account can send 20 messages per 24 hours.
    After that it gets 429 with `Retry-After: 3600`.
  - **Matched to the log.** Each message is stored with the request id
    and the release, so it can be matched to the server log.
  - **Open to suspended accounts.** It stays a way to reach us.
- **`GET /admin/feedback`** is for operators only; anyone else gets 404.
  It lists newest first, paged with `limit` and `offset`. Reading it is
  recorded in the security audit log.
- **The audit log** records `feedback.submitted` with the category,
  never the text.
- **It's the account's data.** `GET /account/export` includes it, and
  purging the account deletes it.

## Schema

These changes are additive, and an existing database gains them on start:

| Change | Details |
|---|---|
| `organizations.is_demo` | `INTEGER NOT NULL DEFAULT 0` |
| `feedback` table | indexed by account and time |
| Postgres transfer | includes `feedback` |
| account purge | deletes `feedback` |

## Tests (`tests/test_demo_and_feedback.py`, both backends)

- **Fixtures:** every name, URL and address is reserved for
  documentation.
- **Demo:**
  - created once, then 200;
  - labelled in the list;
  - assets, three exposures and evidence from the real engine;
  - one demo from six concurrent `ControlDB`s.
- **Read-only:**
  - all 17 organization writes outside the allow-list are refused;
  - a non-member gets 404;
  - delete, purge and create again works.
- **Not counted:** a Free account keeps its one organization and its scan
  quota. Scans never target the demo, and retention skips it.
- **Feedback:**
  - stored with the request id and included in the export;
  - validated and bounded;
  - rate-limited per account, with `Retry-After`;
  - allowed while suspended;
  - operator-only listing;
  - the text never reaches the audit log;
  - deleted with the account.

### Mutation checks

| Mutation | Result |
|---|---|
| guard off | 17 tests fail |
| demo counted against organizations | 1 fails |
| retention purges the demo | 1 fails |
| guard without the membership check | the non-member test fails |
| a public IP in the fixture | the fixture test fails |
