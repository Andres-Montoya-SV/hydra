# Product Phase 08 — Integrations

Branch: `productization/08-integrations-outbox`. Base: `main` @ `8120cf3`
(after PR #105).

Phase 08 is split into two PRs. **Part A (this branch)** adds one durable
event/outbox model with its delivery worker. It feeds generic signed
webhooks, Slack and Microsoft Teams, plus the documented CSV/NDJSON export
and REST API that already existed. **Part B** adds native ticketing (Jira,
Linear, a ServiceNow interface) with encrypted credential storage. It
builds on this outbox and needs its own security review, because it
stores third-party API tokens.

## What existed, and the problem

Hydra already had generic outbound webhooks, and parts of them were
strong:

- HMAC-signed bodies;
- an SSRF gate that re-validates the destination's IPs on every attempt
  and connects to the pinned IP (a DNS-rebinding defense);
- automatic disable after repeated failures;
- a registration cap.

**Delivery was not durable.** Scan and monitoring code called the
delivery function directly. It retried in-process for about 6 seconds and
then gave up for good. Monitoring fired it as a fire-and-forget background
task *after* marking the email notification sent. So a restart, a crash,
or a receiver outage longer than a few seconds lost the event silently.
Phase 00 had recorded this as "webhook delivery is less durable than the
monitoring-email path; no persisted queue."

Events also had no identity, so a receiver couldn't tell a retry from a
new event.

## The model

**`integration_events`** holds one row per logical event: its type, its
payload, and a unique `dedup_key` (for example `monitoring:<notification
id>` or `exposure.resolved:<history id>`). Enqueueing the same key twice
does nothing.

- **Organization events** (exposure lifecycle, remediation) are fanned out
  to the organization's active webhooks.
- **Account events** (monitoring, high-severity findings) go to the
  account's own webhooks, exactly as before.

**`integration_deliveries`** holds one row per event × subscribed
destination, created at enqueue time. Its states are `pending`,
`in_flight`, `delivered` and `dead`.

**Events are written with the change that causes them.** Remediation
transitions and assignments, and exposure resolves, enqueue on the same
connection and in the same transaction as the change. A rejected change
therefore enqueues nothing, and a test checks this.

Two producers enqueue at defined points instead:

- **Monitoring** enqueues *before* the email is attempted and before the
  notification is marked sent. A crash in between leaves both on disk;
  the retry sends the email, and the dedup key keeps the event single.
  Both are tested.
- **Scan completion** enqueues `finding.high_severity`,
  `exposure.opened` and `exposure.reopened` after the EASM backfill, keyed
  per scan, exposure or history row.

## Delivery (`api/integration_worker.py`)

A background loop (the `integration_delivery` entry in `/health`,
interval `HYDRA_API_INTEGRATION_DELIVERY_INTERVAL_SECONDS`, default 15s)
works in cycles:

1. **Claim.** It takes due deliveries under a 120-second lease, inside a
   write-locked transaction, so two workers never take the same delivery.
   A delivery whose destination was removed or disabled is marked `dead`
   instead of being sent.
2. **Attempt once**, through the same SSRF-safe, pinned-IP send as before.
   The destination is re-validated on every attempt.
3. **Record the result:**
   - delivered → the destination's failure streak resets;
   - failed → retried after 30s, 2m, 10m, 30m, 2h and 6h, about 9 hours
     of cover in total;
   - after 7 attempts → `dead`. A dead delivery counts toward the
     destination's automatic disable (after 5 consecutive dead
     deliveries).
4. **Crash recovery.** If a worker dies mid-send, its lease expires and
   the delivery is claimed again. Nothing is lost.

Delivery is therefore **at-least-once**, which is why every request
carries identifiers.

## What a receiver gets

Every request carries these headers:

| Header | Meaning |
|---|---|
| `X-Hydra-Event` | event type |
| `X-Hydra-Event-Id` | the same for every retry and redelivery of this event; use it to drop duplicates |
| `X-Hydra-Delivery-Id` | this event to this destination |
| `X-Hydra-Signature` | `sha256=<HMAC-SHA256 of the raw body with the webhook's secret>` |

The body depends on the destination kind:

- **`generic`** gets the envelope:
  `{"event_id", "event_type", "created_at", "organization_id", "data": {...}}`.
- **`slack`** gets `{"text": "[Hydra] <event_type>: <subject> — <summary>"}`.
- **`teams`** gets an Adaptive Card message with the same line.

Chat destinations can't verify signatures, so they get a summary, never
the event data. A test checks that no data leaks into them.

## Event types

- **Existing:** `monitoring.changed`, `monitoring.needs_review`,
  `finding.high_severity`.
- **New:** `exposure.opened`, `exposure.reopened`, `exposure.resolved`,
  `remediation.state_changed`, `remediation.assigned`. The last two are
  the notifications Phase 07 deferred to this phase.

## API

| Endpoint | Change |
|---|---|
| `POST /webhooks` | new optional `kind`: `generic` (default), `slack` or `teams` |
| `GET /webhooks` | responses include `kind` |
| `GET /webhooks/{id}/deliveries` | new: this webhook's delivery log (status, attempts, next attempt, last error) |
| `POST /webhooks/{id}/deliveries/{delivery_id}/redeliver` | new: re-queue a dead or delivered delivery, due now, with the same event id |

These stay account-scoped, like the rest of `/webhooks`. Another
account's webhook or delivery returns 404.

## Compatibility

- `deliver_event` (in-process, with its short retry loop) is unchanged in
  behavior, and all of its real-HTTPS tests pass. It is now a loop over
  the single-attempt `attempt_delivery` that the worker also uses. No
  production path calls it any more.
- Monitoring's three wiring tests were rewritten against the outbox,
  because monitoring now enqueues instead of calling delivery.

## Not done here

- **Jira, Linear, ServiceNow:** part B.
- **Encrypting webhook secrets at rest:** part B does this together with
  the ticketing API tokens. Both need a server-side key and the same
  review.
- **Assignment reminders and overdue alerts:** these need a scheduled
  producer, which is a small addition on this outbox.


---

# Part B — ticketing and secrets at rest

Branch: `productization/08b-ticketing`. Base: `main` @ `920dab7` (after
PRs #106 and #107).

## Secrets at rest (`api/secrets_box.py`)

**Before:** webhook signing secrets were stored in plaintext, and there was
nowhere safe to keep a third-party API token.

**Now:**

- **Encryption:** secrets are sealed with Fernet (authenticated encryption)
  under `HYDRA_API_SECRETS_KEYS`.
- **Rotation:** the setting holds comma-separated keys. The first key
  encrypts and every key can decrypt, so a key is rotated by putting the
  new one first.
- **Format:** sealed values carry an `enc:v1:` prefix. Legacy plaintext is
  still read correctly. A sealed value that no configured key can decrypt
  fails closed. A malformed key fails startup.
- **Webhook secrets** are sealed on write inside ControlDB and revealed
  only when a record is built for signing, so the signing path is
  unchanged. With a key configured, startup seals any plaintext secret left
  from before; this is idempotent.
- **Ticketing credentials require a key.** Without one, connecting an
  integration returns `503 secrets_key_not_configured`. Hydra never stores
  a third-party token in plaintext.
- **Dependency:** `cryptography` moved into `requirements-api`, with the
  same audited pin as before.

## Ticketing (`api/ticketing/`)

| Provider | Request | Auth | Config / credential |
|---|---|---|---|
| Jira Cloud | `POST {site_url}/rest/api/3/issue`, description in Atlassian Document Format | Basic (email + API token) | `site_url`, `project_key`, optional `issue_type` / `email`, `api_token` |
| Linear | GraphQL `issueCreate` at `https://api.linear.app/graphql` | API key | `team_id` / `api_key` |
| ServiceNow | Table API `POST {instance_url}/api/now/table/incident`, urgency from severity | Basic | `instance_url` / `username`, `password` |

### Behavior

- **Events.** An integration subscribes to `exposure.opened` (the default)
  and optionally `exposure.reopened`, delivered through the Part A outbox.
- **Retries and failures** follow the same schedule as webhooks: retry
  with backoff, dead after 7 attempts. Five consecutive dead deliveries
  disable the integration automatically.
- **One ticket per exposure.** `ticketing_links` records the ticket created
  for each (integration, exposure). A later event for the same exposure (a
  retry, or a reopen) sends nothing.
  - Remaining risk: a request that times out after the provider created the
    issue can't be told apart from a failure. None of these APIs offers an
    idempotency key, so that one case may produce a duplicate issue.
- **Link back.** The created ticket fills the exposure's remediation
  `ticket_url` if it's empty, recorded as a remediation event by
  `integration:<id>`. A link someone set by hand is never overwritten.
- **SSRF protection.** A customer-supplied Jira or ServiceNow host goes
  through the same SSRF / DNS-rebinding gate as a webhook URL, both when
  the integration is created and on every attempt. Linear's API host is
  fixed.
- **Rate limits.** A provider's HTTP 429 is honored: a numeric
  `Retry-After` delays the next attempt, capped at the longest backoff
  step (6h). The HTTP-date form falls back to the normal schedule.
- **Wire formats** are pure functions, one module per provider
  (`api/ticketing/jira.py`, `linear.py`, `servicenow.py`) behind a common
  interface (`api/ticketing/base.py::Provider`), tested against each provider's
  documented request and response shapes. End-to-end tests point a Jira
  integration at a real local HTTPS server. No real service is called.

### Ticketing API

| Endpoint | Who |
|---|---|
| `GET /organizations/{org}/integrations` | member (credentials never returned) |
| `POST /organizations/{org}/integrations` | owner |
| `DELETE /organizations/{org}/integrations/{id}` | owner: disables the integration and erases its credential; its ticket links stay |
| `GET /organizations/{org}/integrations/{id}/deliveries` | member |

- **Limit:** at most 10 active integrations per organization.
- **Errors:** invalid config returns 422; a refused host returns 422;
  another organization returns 404.
- **Credential safety:** tests check that the credential never appears in
  any response, delivery log or error.

## Not done

- **Comments on an existing ticket for reopen or resolve events.** For now
  a reopen reuses the linked ticket silently.
- **Two-way sync** (closing an exposure when its ticket closes). That
  needs inbound provider webhooks, a separate authenticated surface.
- **Microsoft Teams bot or Slack app** (as opposed to incoming webhooks).
