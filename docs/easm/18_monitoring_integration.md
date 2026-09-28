# EASM Fase 18 — Monitoring Integration

## Purpose

Connect `api/monitoring_worker.py`'s existing Speed 1/Speed 2
notification pipeline to the EASM model (Fases 03-16), so notifications
cite the exact `change_event`/`exposure`/`certificate_event`/
`technology_event` that motivated them, instead of only a raw hostname
digest diff. The outbox, webhooks, and scheduler are not rewritten — see
"Not rewritten" below.

## A blocker found before this phase could be built safely

Verified directly: **every EASM backfill function
(`backfill_assets_for_organization`, `detect_and_record_changes_for_organization`,
`backfill_candidate_assets_for_organization`,
`backfill_relationships_for_organization`,
`backfill_exposures_for_organization`,
`detect_certificate_events_for_organization`,
`detect_technology_events_for_organization`) had zero callers anywhere
in the live pipeline** — every one of them was only ever invoked from
tests. That meant `assets`/`observations`/`change_events`/`exposures`/
`certificate_events`/`technology_events` were never actually populated
by a real scan. Wiring the monitoring trigger to read from those tables
as literally specified would have made real notifications silently stop
firing — those tables would always be empty in production.

This was surfaced to Andrés as a stop-and-report per the roadmap's own
rule ("si cambiar la forma de `MonitoringRunOutcome` rompe algo que ya
depende de ella → alto-y-reportar"), rather than silently deciding
either to wire against empty tables or to unilaterally expand scope.
Andrés confirmed: wire the backfill into scan completion first, as
necessary groundwork for this phase.

## Part 1: `api/easm_backfill.py` (the missing wiring)

`run_easm_backfill_for_organization()` calls all seven backfill
functions in real dependency order (assets before anything reading
them; observations before the two per-observation-type classifiers).
Called from `api/scan_orchestrator.py::execute_scan()` — the ONE
function every scan trigger source already runs through (manual, Speed
1 passive, Speed 2 active; confirmed by that module's own docstring) —
right after the scan's status becomes `"completed"` and provider
outcomes are recorded.

**Isolation, matching the existing pattern**: runs via
`run_easm_backfill_for_organization_safely()`, in `asyncio.to_thread`
(synchronous DB work must not block the event loop), inside its own
`try`/`except` — a backfill bug can never retroactively turn an
already-successfully-completed scan into a "failed" one, the exact same
guarantee `_deliver_high_severity_findings_webhook` already gets in that
same function.

**Known, accepted scaling characteristic, not introduced by this
phase**: every one of the seven backfill functions replays ALL of an
organization's completed scans from scratch on every call (how each was
independently built in its own phase) — not incrementally, just the
latest scan. Calling them after every scan completion means backfill
cost grows with an organization's total scan history. This is a real,
pre-existing limitation inherited from Fases 03-14, now exercised live
for the first time. **Flagged here explicitly as a risk for a future
phase** (likely Fase 20's retention/performance scope) to make these
incremental — not silently absorbed, not fixed in this phase (that would
mean rewriting seven already-tested modules, well beyond this phase's
own scope).

## Part 2: EASM-aware monitoring trigger

`api/monitoring_worker.py::_easm_citations_for_run()` — new. Queries,
for one scan's `run_id`: `change_events` (Fase 05, generic — covers DNS
posture, visual, and cloud changes, none of which built their own
dedicated event table), `certificate_events` (Fase 12),
`technology_events` (Fase 14), and `exposure_history` (Fase 08, via two
new by-run-id query methods added to `ControlDB`:
`list_certificate_events_for_run`, `list_technology_events_for_run`,
`list_exposure_history_for_run`, plus `get_exposure` — `exposure_history.run_id`
already existed, this is simply its first by-run query). Each becomes
one human-readable citation string.

`_harvest_one()` now triggers a `MonitoringRunOutcome` when
`jump.needs_review OR digest_changed OR easm_citations` — previously
only the first two. **This is the real behavioral improvement**: a
certificate renewal, a new exposure, or a technology change with the
EXACT SAME hostname set (something the old digest-only trigger could
never see) now correctly generates a notification.

`MonitoringRunOutcome` gained one new field, `easm_citations: tuple[str,
...] = ()` — additive, defaults to empty for every existing/pre-Fase-18
code path. `monitoring_pending_notifications` gained one new column
(`easm_citations_json`, migrated the same way every prior phase's schema
additions were) so the durable outbox carries citations through a crash-
and-retry cycle exactly like every other field already does. Both the
email summary line (`_render_outcome_line`) and the webhook payload
(`api/webhooks.py::event_for_monitoring_outcome`) now include the
citation when present.

**`needs_review` is unchanged** — still governed by
`classify_asset_jump`'s existing raw asset-count-ceiling logic, per the
phase's own "si ahora debe evaluarse sobre conteos de assets, decirlo
explícitamente" — it was not changed, so nothing new to document there.

## Not rewritten

- The outbox mechanism itself (`monitoring_pending_notifications`,
  `list_unsent_notifications`, `mark_notifications_sent`, the durable
  send-then-mark ordering) — only a new column was added, following the
  exact same additive-migration pattern every prior phase used.
- `_deliver_webhooks_for_outcome`'s delivery/scheduling logic.
- `_flush_pending_notifications`'s per-account batching, capping, and
  ordering (`significance_rank` gained one new rank tier for
  "citations only, no hostname change," never a rewrite of its existing
  ordering).
- The scheduler (`run_monitoring_cycle`, `run_monitoring_loop`,
  cadence/enqueue logic) — completely untouched.
- No second notification path was created — one outbox, one flush, now
  carrying richer content.

## Tests

- All pre-existing tests in `tests/test_monitoring_worker.py`,
  `tests/test_monitoring_logic.py`, `tests/test_monitoring_scale.py`,
  `tests/test_api_monitoring_endpoints.py`, and the webhook test suite
  pass unchanged (109 tests total across these + the new files) — proving
  `easm_citations` defaulting to empty never alters existing behavior for
  any scenario that doesn't exercise the new EASM path.
- `tests/test_easm_backfill.py` — the new orchestration function
  populates every EASM table from one real scan; idempotent; a failure
  in one step never propagates.
- `tests/test_scan_orchestrator_easm_wiring.py` — `execute_scan` actually
  triggers the backfill; a backfill failure never fails the scan.
- `tests/test_monitoring_easm_integration.py` — the phase's own required
  adversarial: a certificate renewal alone (no hostname change) produces
  exactly one notification, citing the real evidence, in both the email
  and the webhook payload; an unchanged scan with no EASM events still
  sends nothing (no fabricated notifications).
