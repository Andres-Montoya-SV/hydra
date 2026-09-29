# Product Phase 04 — Exposure Operations (API)

Branch: `productization/04-exposure-operations`. Base: `main` @ `2080fe9`
(includes the merged Phase 03 evidence-explainability PR #97). Post-merge
CI on that commit was verified green before this phase's branch was created.

## Re-reading main fresh (Roadmap Rule 1)

Phase 00 classified exposure inventory, detail, history, and resolution as
ALREADY_DONE, and remediation notes / assignee / bulk triage as MISSING
(sequenced to Phase 07). Re-reading `api/routers/exposures.py` and
`api/control_db.py` confirmed most of that:

- **Already done, verified:** list with `status`/`severity`/`asset_id`
  filters and real SQL-level pagination; detail; history; per-exposure risk
  with reasons (Fase 21); the history-backed exposure report; owner-only
  resolve with a required reason, recorded as a `resolved` history event.
- **The lifecycle invariant already holds**, and is the most important
  thing this phase had to check rather than build.
  `ControlDB.upsert_exposure` reopens a *resolved* exposure only when a
  later run actually re-observes it (recorded as a `reopened` history
  event), and its docstring states explicitly that absence from a later
  run never resolves anything, because Hydra doesn't persist enough
  per-provider execution outcome to prove "missing finding" means "fixed".
  `resolve_exposure` is only ever called from the explicit API endpoint.
  This matches the roadmap's "do not auto-resolve purely because a
  subsequent scan lacks a Finding" requirement exactly — nothing to change.

Three real gaps were found:

1. **Exposure evidence could not explain itself.** `GET .../evidence`
   returned `run_id` and an integer `finding_id` — a row id in the
   *per-account* `recon.db`, which no API endpoint could dereference. The
   only human-readable "why" was the history event's
   `"nuclei:admin-exposed; finding=1"` string. So "why does this exposure
   exist" had no real answer through the API.
2. **A resolution could not be undone.** An exposure resolved by mistake
   stayed resolved until some later scan happened to re-observe it — there
   was no way for a person to say "this isn't actually fixed."
3. **A pre-existing bug:** `ResolveExposureRequest.reason` used
   `min_length=1`, which accepts `"   "`. The router strips it to `""`,
   `ControlDB.resolve_exposure` rejects that with a `ValueError`, and the
   client got a **500** instead of a 422.

## What shipped

### 1. Evidence that explains itself

`GET /organizations/{id}/exposures/{exposure_id}/evidence` now returns, for
each evidence row, a `finding` object with the actual detector result:
`host`, `url`, `name`, `severity`, `description`, `confidence_score`,
`discovered_at`.

- Resolved via a new `AssetStore.get_finding(run_id, finding_id)` that
  matches on **both** `id` and `run_id` — the same pairing the `findings`
  table's own `UNIQUE(id, run_id)` constraint exists for, so a finding id
  can't be dereferenced under a different run.
- Each evidence row already records which `account_id`'s scan produced it
  (enforced at write time by `upsert_exposure`), so the lookup opens *that*
  account's `recon.db` — at most once per account per request.
- `finding` is `null`, never fabricated, when the row can't be read. The
  endpoint checks that the account's `recon.db` exists before opening it:
  `AssetStore(...)` creates a schema on construction, and a read endpoint
  must never create an empty database as a side effect (tested directly).
- The endpoint is now paginated (`limit` 1–500, default 100; `offset`),
  applied *before* any finding lookups, so one request's cost is bounded
  regardless of how many runs have observed the exposure.
- No raw payloads are exposed: the `findings` table stores metadata only
  (and `github_secrets` redacts at the source — the raw secret is never
  stored anywhere).

### 2. Audited manual reopen

`POST /organizations/{id}/exposures/{exposure_id}/reopen` with a required
`reason`.

- Same gate as resolve (now shared in one `_require_owner_and_exposure`
  helper): non-member or unknown exposure → 404, viewer → 403.
- Only a `resolved` exposure can be reopened; anything else is a 409, so a
  replayed reopen can't write a second history event (tested).
- `ControlDB.reopen_exposure` sets `status='reopened'` and clears
  `resolved_at` / `resolved_run_id` / `resolution_reason` on the row, which
  always describes the *current* state. The earlier resolution is not
  erased: it stays in `exposure_history`, which is append-only, followed
  by the new `reopened` event with its reason and `run_id = NULL` (a
  person did this, not a scan).
- A reopened exposure can be resolved again; the lifecycle stays a plain,
  auditable sequence of history events.

### 3. Blank reasons are a 422

Both `ResolveExposureRequest` and the new `ReopenExposureRequest` reject
whitespace-only reasons in a validator, so the client gets a 422 instead
of the previous 500.

## What was deliberately not built

1. **Bulk triage.** The roadmap allows it "only if authorization semantics
   are unambiguous and tested". Deferred to Phase 07, where assignment,
   suppression and accepted-risk will define what bulk actions even mean;
   building bulk-resolve alone now would likely need reworking then.
2. **Remediation notes, owner/assignee, due dates.** Phase 07's job, as
   Phase 00 already sequenced it. The resolve/reopen reasons are the only
   free text for now.
3. **Risk level in the list response.** Risk is per-exposure
   (`.../risk`). Computing it for every row of a 500-row page would mean
   500 extra factor queries per request; left as a separate endpoint.
4. **More list filters or sorting** (by detector, first/last-seen range).
   Not needed for any flow in this phase; status/severity/asset already
   cover triage.
5. **`resolve` returning a misleading 409.** `resolve_exposure` also
   requires `last_seen_at <= resolved_at`. If an exposure's `last_seen_at`
   is somehow in the future (clock skew, a future-dated import), resolve
   fails and the API says "already resolved". Rare, pre-existing, and
   unrelated to this phase's changes — noted, not fixed.

## Security review (Roadmap Rule 9, for this phase's changes)

1. **Can this grant authorization?** No. Resolve/reopen change an
   exposure's triage state only; they never touch scope, domain
   verification, or collection.
2. **Can this leak data across tenants?** The evidence lookup opens a
   `recon.db` chosen by the evidence row's own `account_id`, and that row
   is reached only through `list_exposure_evidence(organization_id, ...)`
   after `_require_member` — so a caller can only ever reach findings for
   runs that belong to their own organization. Foreign accounts get 404 on
   reopen (tested) and on evidence (existing test).
3. **Can replay create duplicate state?** No — reopen only matches
   `status = 'resolved'`; a second call is a 409 and writes nothing (tested).
4. **Can a failure become a clean state?** A missing or unreadable finding
   is reported as `null`, never as an empty-but-valid finding.
5. **Can a user bypass the UI and mutate through the API?** Viewers get
   403 on both resolve and reopen, and the test confirms their attempts
   leave the exposure unchanged.
6. **Malformed input?** Blank reasons → 422; evidence pagination is
   bounded (1–500); `finding_id` is always a bound parameter matched
   together with `run_id`.
7. **Can this erase provenance?** No. Reopen clears the row's current
   resolution fields, but every resolution stays in the append-only history.

## Tests

`tests/test_api_exposure_operations.py` (new, 10 tests):
- evidence includes the real detector result from a genuine `findings` row;
- an unreadable finding is `null`, and the GET creates no `recon.db`;
- evidence pagination across two runs;
- reopen after resolve: status, cleared resolution fields, and history
  order `observed → resolved → reopened` with both reasons;
- reopening a non-resolved exposure is 409;
- a replayed reopen is 409 and adds no second `reopened` event;
- a reopened exposure can be resolved again;
- a viewer gets 403 on resolve and reopen, and the state is unchanged;
- a foreign account gets 404 on reopen;
- blank reasons are 422 on both resolve and reopen.

`tests/test_api_exposures.py` (existing, 4 tests) passes unchanged — its
seed uses `finding_id=1` with no `recon.db`, which now exercises the
`finding: null` path.

## Deferred (explicit)

1. Bulk triage, remediation notes, assignee/owner, SLA, suppression and
   accepted-risk — Phase 07.
2. The misleading 409 on resolve when `last_seen_at` is in the future.
3. `list_candidate_assets_for_organization`'s Python-side pagination (from
   Phase 02) — still open.
4. Visual intelligence wiring — still the one fully missing capability.
5. All earlier deferred items (organization-scoped domain verification and
   scanning, invite-by-email, `core/intelligence/`/`core/diff.py`
   deprecation, provider-version qualification, the `account_settings()`
   `.env` bug, static admin-token auth, empty branch-protection required
   checks, webhook durability) remain open and out of scope.
