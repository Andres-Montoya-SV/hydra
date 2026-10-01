# Product Phase 11b — Security Audit Log and Operator Accounts

Branch: `productization/11b-audit-operators`. Base: `main` @ `976619a`
(after PR #114, Phase 11a).

Decisions (2026-10-01):

- Admin access moves to **operator accounts**, replacing the static
  `HYDRA_API_ADMIN_TOKEN`.
- The audit log records **keys and authentication, members and roles,
  integrations, and admin actions**.

## The security audit log

There is one append-only table, `security_audit_log`. The application has
no code path that updates or deletes its rows. Each event records:

- **what happened:** the action, the time, and the target (type, id);
- **who did it:** the actor type (`account`, `operator`, `host` or
  `anonymous`) and the actor's account;
- **whose security it concerns:** the subject account (a key's owner, a
  member);
- **where:** the organization, when there is one;
- **request context:** the request id (Phase 11a, so an event can be
  matched to its log lines) and the client address;
- **details** (JSON).

| Action | Recorded when |
|---|---|
| `account.created`, `key.created` | an account and its first key are created |
| `key.rotated`, `key.revoked` | a key is rotated (with the new key id and the old key's grace end) or revoked |
| `auth.failed` | a request is refused for a missing, invalid, or revoked/expired key: **at most one event per client address per minute** |
| `organization.created` | a new organization |
| `member.added`, `member.role_changed`, `member.removed` | membership changes (with the role before and after); re-granting the same role records nothing |
| `webhook.created`, `webhook.deleted`, `webhook.redelivered` | webhook changes |
| `integration.created`, `integration.removed` | ticketing integration changes |
| `admin.payments_listed`, `admin.payment_reconciled`, `admin.security_events_listed` | every admin endpoint call, with the acting operator |
| `operator.granted`, `operator.revoked` | the host CLI, with the host user who ran it |

**Never recorded:** API keys (not even a guessed one), webhook signing
secrets, and integration credentials or configuration. For webhooks only
the destination **host** is kept, because Slack and Teams URLs carry a
secret in their path. Tests assert each of these is absent from the
recorded events.

**Failed sign-ins** are throttled through the persisted rate-limit
buckets, keyed by client address. A credential-stuffing burst therefore
leaves a trace without flooding the table.

**Isolation.** The table has an `organization_id` column, so on Postgres
the Phase 10c row-level security policy covers it: an organization-scoped
request can't read another organization's events.

**Recording happens in the routers**, right after the change succeeds,
not inside the same database transaction. A failure between the two
would lose an event, never invent one. Moving the writes into the changes'
own transactions is possible later.

### Reading it

| Endpoint | Who | What |
|---|---|---|
| `GET /organizations/{id}/security-events` | owners (viewers 403, non-members 404) | the organization's events |
| `GET /account/security-events` | any account | events about the caller's own keys and memberships |
| `GET /admin/security-events` | operators (everyone else 404) | everything, including failed sign-ins; the read itself is recorded |

All three list newest first and take `limit` (1–500) and `offset`.

## Operator accounts

The admin endpoints (`/admin/wompi/unmatched`, `/admin/wompi/reconcile`,
`/admin/security-events`) now require the **API key of an operator
account**:

- **Accountability:** each action is attributed to a person.
- **Key hygiene:** rotation and revocation are the normal key endpoints.
- **Hidden surface:** the old token compared with a plain `!=`; that
  check is gone. A non-operator gets **404**, so the admin surface is not
  discoverable.

The operator flag (`accounts.is_operator`) can only be changed on the
host, and every change is audited:

```
python -m api.operators list
python -m api.operators grant <account_id | email>
python -m api.operators revoke <account_id | email>
```

No API endpoint sets the flag, so a compromised account cannot promote
itself.

**Migration from the static token:**

1. Grant one or more operators.
2. Switch the admin tooling to their API keys.
3. Remove `HYDRA_API_ADMIN_TOKEN`.

If the variable is still set, the API logs a warning at startup that it
is ignored.

## Data

- `accounts.is_operator` is a new column. Existing SQLite files gain it
  through the column migrations, defaulting to 0.
- The SQLite→Postgres migration and the Postgres backup/restore (10b, 10d)
  include `security_audit_log`. The catalog test enforces this.

## Tests (`tests/test_security_audit.py`, plus the updated subscription tests)

- **Key lifecycle:** recorded in order, and no key appears in any event.
- **Request context:** the request id and client address are recorded.
- **Failed sign-ins:** recorded once per client per minute, without the
  guessed key.
- **Members:** added, role changed and removed, with no event for an
  unchanged role. Owners can read the log, viewers get 403, outsiders 404.
- **Organizations:** creation is recorded in the new organization.
- **Webhooks:** only the host is recorded (no path secret, no signing
  secret).
- **Ticketing integrations:** the credential is never recorded.
- **Admin endpoints:**
  - no key → 401;
  - the old token header → 401;
  - a non-operator key → 404;
  - an operator → allowed and recorded.
- **Operators CLI:** grant (by email, case-insensitive), list, revoke, an
  unknown account (exit 1), and the audit events with the host user.
