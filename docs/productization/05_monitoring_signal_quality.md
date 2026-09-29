# Product Phase 05 — Continuous Monitoring & Signal Quality

Branch: `productization/05-monitoring-signals`. Base: `main` @ `eb4f507`
(includes the merged Phase 04 exposure-operations PR #98). Post-merge CI on
that commit was verified green before this phase's branch was created.

## Re-reading main fresh (Roadmap Rule 1)

Phase 00 found most of this phase already built, and re-reading confirmed it:

- **Scheduled monitoring** — two speeds (passive daily; active weekly on
  Pro/Ultra), durable email outbox plus signed webhooks, needs-review with a
  sticky human acknowledge, an asset-count ceiling, a wildcard-DNS check.
- **Change signals** — certificate, technology, exposure, and change events,
  cited into each notification (Fase 18).
- **Noise control in the EASM layer** — `api/change_detection.py` needs
  **two consecutive** missed runs before calling an asset `DISAPPEARED`, so
  one bad run can never hide an asset.

Phase 00 had left "failed/partial provider visibility" as UNVERIFIED.
Verifying it found one real bug and two gaps.

### The bug: a collector failure was reported as hosts being removed

The monitoring hostname diff (`api/monitoring_worker.py::_harvest_one`) did
**not** have the tolerance the EASM layer has. If a scan *completed* but one
discovery collector failed (for example CT logs timing out), the hostnames
only that collector finds were missing from the run. Monitoring then:

1. alerted that those hosts were **removed**, although nothing had changed
   and a collector had simply failed; and
2. saved that degraded result as the new baseline, so the next healthy run
   alerted that the same hosts had been **added**.

A single collector failure produced two false alerts. That breaks both of
the roadmap's non-negotiables for this area: *provider failure must never
become a clean result* and *reduce noise*.

### Gap: no way to see how collectors did

`provider_run_outcomes` has recorded every collector's outcome per scan
since Fase 09 (`success_with_results`, `success_no_results`, `partial`,
`blocked_by_scope`, `skipped`, `unavailable`, `failed`), but no endpoint
exposed it. A scan's own status only says the pipeline finished, so a scan
where a collector failed looked identical to a clean one.

### Gap: alerts couldn't be read back

Every notification is stored with its reasons (hosts added/removed, the
review reason, the EASM citations), but only the email/webhook delivery
read that table. Once an alert went out, a client couldn't ask "what fired,
and why?"

## What shipped

### 1. A collector failure is no longer a host removal

New pure function `api/monitoring.py::regressed_providers`: the collectors
that returned results in the baseline run (`success_with_results`) and are
`failed`, `unavailable`, or `partial` in this one. It is deterministic, and
its output is sorted.

In `_harvest_one`, when any collector regressed:

- no hostname diff is reported, neither removals nor additions;
- the previous baseline (digest, count, and baseline scan id) is kept, so
  the next healthy run is compared against the last *trustworthy* result;
- a warning is logged naming the collectors.

Everything else still works as before on a degraded run: EASM citations
(which are positive evidence and already have their own two-run tolerance)
and the needs-review ceiling.

Two deliberate boundaries:

- **A collector that was already failing doesn't count.** If a tool was
  `unavailable` in the baseline run too (for example not installed), it
  wasn't contributing hostnames, so its absence can't make any disappear.
  Without this rule, one permanently missing tool would silence removal
  alerts forever.
- **A collector that found nothing last time doesn't count**, for the same
  reason (`success_no_results` → `failed` removes nothing).

A real removal, with every collector healthy, still alerts as before
(tested).

### 2. `GET /scans/{scan_id}/collection`

Returns `{scan_id, degraded, outcomes[]}`. Each outcome has the collector
(`provider`), its product-facing `capability` (from the provider inventory,
so API consumers can use product language), the `outcome`, `output_lines`,
and `recorded_at`. `degraded` is true if any collector failed, was
unavailable, or ran partially. It is gated by the same scan-ownership check
as every other `/scans/{id}` route (404 for someone else's scan).

### 3. `GET /domains/{domain}/monitoring/notifications`

A monitored domain's alert history, newest first, with SQL-level pagination
(1–500): hosts added and removed, asset count, needs-review and its reason,
the `citations` explaining why, and `created_at`/`sent_at`. It is scoped to
the calling account; an unmonitored or someone else's domain is a 404. It
reads the same rows the email/webhook outbox delivers, so what a client
sees is exactly what was sent.

## What was deliberately not built

1. **Degraded-run alerts.** A degraded run doesn't send a notification of
   its own. Alerting on every transient collector failure would add noise,
   which is what this phase exists to remove. The information is available
   through `/collection` instead.
2. **Visual-change monitoring.** The roadmap lists "meaningful visual
   changes"; visual intelligence still has no wiring into the EASM model
   (confirmed in Phases 00 and 02), so there is nothing to diff yet.
3. **Candidate-review and risk-change alerts.** Neither event type exists in
   the notification pipeline today. Adding them means new event types and
   significance rules for the webhook contract, which is better designed
   together with Phase 08's single canonical event model than bolted on here.
4. **A second tolerance model.** The monitoring digest path now reacts to
   explicit collector failures, while the EASM change-detection layer keeps
   its own two-missed-runs rule. I didn't merge them: they answer different
   questions (did the whole scan's host set change, versus did one asset
   disappear).

## Security review (Roadmap Rule 9, for this phase's changes)

1. **Can this grant authorization?** No. Nothing here touches scope,
   verification, or collection.
2. **Can it leak across tenants?** `/collection` goes through
   `_owned_scan_or_404` (account + scan). The notification history requires
   the domain to be monitored by the *calling* account and filters rows by
   that `account_id`. Foreign accounts get 404 on both (tested).
3. **Can a failure become a clean state?** This is the bug fixed above: a
   failed collector can no longer be read as "hosts disappeared", and
   `/collection` makes a degraded run visible instead of indistinguishable
   from a clean one.
4. **Can stale data override stronger current evidence?** The baseline is
   now kept on a degraded run, so a weaker result never replaces a stronger
   one. It is replaced as soon as a healthy run arrives (tested).
5. **Is it bounded?** The notification history is paginated at the SQL
   level. `/collection` returns one row per collector for a single scan.

## Tests

`tests/test_monitoring_signal_quality.py` (new, 10 tests):

- `regressed_providers`: contributing collector now failing (listed);
  already-failing collector (not listed); nothing-found-last-time (not
  listed); `partial`/`unavailable` count and output is sorted.
- A failed-collector run sends no alert and keeps the baseline count and
  scan id; the next healthy run doesn't report everything as added; a
  genuine removal with healthy collectors still alerts once and is recorded
  as removing exactly that host.
- `/collection` flags a degraded scan and maps collectors to capabilities;
  a clean scan isn't degraded; a foreign account gets 404.
- The notification history returns the alert with its citations; a foreign
  account gets 404.

**The two bug tests were confirmed to fail with the fix disabled**, so they
test the bug itself, not just the new code path. All 56 pre-existing
monitoring tests pass unchanged; their scans record no collector outcomes,
so the new check is a no-op for them.

## Deferred (explicit)

1. Candidate-review and risk-change alert types, which belong with Phase
   08's canonical event model.
2. Visual-change monitoring, blocked on visual intelligence having no EASM
   wiring.
3. All earlier deferred items (organization-scoped domain verification and
   scanning, invite-by-email, `core/intelligence/`/`core/diff.py`
   deprecation, provider-version qualification, the `account_settings()`
   `.env` bug, static admin-token auth, empty branch-protection required
   checks, webhook durability, candidate-asset pagination, the rare
   misleading 409 on resolve) remain open and out of scope.
