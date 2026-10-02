# Product Phase 12b — Account State

Branch: `productization/12b-account-state`. Base: `main` @ `1cfa822`
(after PR #121, Phase 12a).

This part covers the three findings that
[12a](12a_entitlements.md) left for later:
- what a suspended account may still do;
- what happens to verified domains after a downgrade;
- the advertised `priority_queue`, which was a no-op.

The rule from 12a still holds: a tier or a billing state may **deny**
product access but never **grants** authorization to scan.

## Read-only suspension (decision 2026-10-02)

Before this phase, a suspended account was blocked only from new manual
scans and weekly active monitoring. Passive monitoring, imports, new
organizations and integrations kept working.

Now a `"suspended"` account is **read-only**. One guard in
`require_api_key` (`api/auth.py`) applies it to every authenticated
route.

| Still allowed | Refused with 402 `account_suspended` |
|---|---|
| every read (`GET`, `HEAD`, `OPTIONS`), exports included | every other write: scans, imports, organizations, members, integrations, webhooks, exclusions, monitoring opt-ins… |
| rotating and revoking API keys | |
| resolving billing (`POST /account/subscription`) | |
| deleting the account or an organization, and cancelling either deletion | |

- The allowed writes are a short, explicit list matched on the route
  **template** (`/keys/{key_id}/rotate`), so a path parameter can't
  spoof it. A test checks that every entry names a real route.
- A new write route is refused by default; nobody has to remember to
  add a check.
- `/admin/*` is out of scope: operators are not customer accounts.
- **Monitoring stops entirely**, passive included. The domains stay
  opted in and resume when the account is restored.
- `"past_due"` (inside the grace period) is unchanged and behaves like
  `"active"`.

```json
{"detail": {"error": "account_suspended",
            "message": "This account is suspended for non-payment and is read-only. Resolve billing via POST /account/subscription to resume."}}
```

## After a downgrade: the oldest N domains stay scannable (decision 2026-10-02)

Before, verified domains beyond the new tier's
`max_concurrent_verified_domains` kept working until their verification
expired.

Now:
- **The N oldest verifications stay scannable**, where N is the new
  tier's limit. Age is `verified_at`, with the domain name as a
  tie-break.
- **The rest stay verified** but can't be scanned or opted into
  monitoring. Trying gives a 403 `entitlement_exceeded` with
  `"entitlement": "verified_domains"`, the same structured error as 12a.
- **Scheduled monitoring skips them** quietly, and they stay opted in.
- **An upgrade restores them** immediately, with no re-verification.
- `GET /account/subscription` lists them in
  `unscannable_verified_domains`.

There's one rule, `subscriptions.domain_scan_gate`, used by
`POST /scans`, the monitoring opt-in and the monitoring worker. It first
requires the domain's own verification, exactly as before. The tier can
only narrow access afterwards.

## Scan priority queue (decision 2026-10-02)

`priority_queue` is now real. For tiers with it (Pro and Ultra), queued
scans are claimed first, then oldest first. Within each group the order
stays first in, first out.

- The order is part of the single atomic claim statement
  (`ControlDB.claim_next_queued_scan`). Several workers still never
  claim the same scan.
- The priority tiers come from the tier table (`PRIORITY_TIERS` in
  `api/scan_worker.py`), not a hard-coded list.
- `GET /account/subscription` reports `priority_queue`.
- **Trade-off:** a steady stream of priority scans can delay others.
  The concurrency limit and the monthly quotas bound this. There's no
  aging yet; revisit if queues grow in the beta.

## Tests (`tests/test_account_state.py`, both backends)

- **Suspension**, enumerated over every route from the adversarial
  suite's route table:
  - every write outside the allow-list is 402 `account_suspended`;
  - every allowed write is not 402;
  - reads and both exports stay 200;
  - a due monitoring cycle creates no scan.
- **Downgrade, in the worker:** with two monitored domains, after a
  downgrade to Free only the oldest is scanned. The other stays opted in.
- **Downgrade, through the API:** Medium with three domains, then Free:
  - the oldest domain scans;
  - the third gets the structured 403;
  - the second can't be opted into monitoring;
  - the subscription view lists both;
  - upgrading restores scanning.
- **Priority:** Pro and Ultra are claimed before Free and Medium, oldest
  first within each group. Without priority tiers, order is plain
  oldest first.

### Mutation checks

| Mutation | Result |
|---|---|
| the suspension guard disabled | 33 tests fail |
| the worker's suspension skip disabled | the suspended-monitoring test fails |
| the worker's over-limit skip disabled | the worker downgrade test fails |
| the downgrade rule disabled (`domain_scan_gate` always covered) | the downgrade test fails |
| the priority `CASE` made constant | the priority test fails |

## Review follow-up

- **Fewer database reads.** `domain_scan_gate` now reads the account's
  verifications once, and the monitoring worker runs the gate once per
  domain. Opening a passive monitoring row takes 6 connections: 9 in the
  first version of this PR, 5 on `main`. The extra one is the
  subscription read that suspension needs.
- **No per-account cache across a monitoring cycle.** A suspension, a
  downgrade or a lapsed verification takes effect on the very next
  domain, which matters more than saving one read per domain.
