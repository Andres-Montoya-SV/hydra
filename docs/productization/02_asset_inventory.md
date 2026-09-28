# Product Phase 02 — Attack Surface Inventory API

Branch: `productization/02-asset-inventory`. Base: `main` @ `f51c5f7`
(includes the merged Phase 01 onboarding PR #94). Post-merge CI on that
commit was verified green before this phase started.

## Re-reading main fresh (Roadmap Rule 1) — several corrections to Phase
00's own classifications

Phase 00's baseline doc classified DNS/ports/cloud as **MISSING**
(explicitly deferred per Fase 19) and the `asset_identifiers` table's
write path as unverified. Re-reading the actual code for this phase
found the real picture is considerably better than that, and one
genuinely worse:

- **DNS records and open ports are NOT missing** — they were wrong to
  classify as such. `api/observation_identity.py::observations_for_host`
  (called from `api/asset_backfill.py:128` on every real scan, Fase 04)
  derives `OBSERVATION_TYPE_DNS_RECORD_PRESENT`/`_DNS_POSTURE_TAG` from
  `host.dns_records` and `OBSERVATION_TYPE_PORT_OPEN` from `host.ports`.
  More importantly: DNS records and ports are each their own **first-
  class `Asset` row** (`ASSET_TYPE_DNS_RECORD`/`ASSET_TYPE_PORT`,
  `api/asset_identity.py:67-68`), exactly the same architectural pattern
  as cloud storage (`ASSET_TYPE_CLOUD_STORAGE`, already confirmed
  ALREADY_DONE in Phase 00). They were already fully listable/gettable
  through the existing generic `GET /organizations/{id}/assets` and
  `GET .../assets/{asset_id}` endpoints, filtered by `asset_type`, before
  this phase touched anything. Nothing needed building for these three;
  they needed recognizing and documenting, which this document now does.
- **`asset_identifiers` is NOT dead** — a grep for `identifier_type=` as
  a Python keyword argument (my first check) missed the real write path,
  which uses raw parameterized SQL (`api/control_db.py`'s asset-upsert
  method, `INSERT OR IGNORE INTO asset_identifiers ...`). It's populated
  today from `host.ips` on every real scan. The genuine gap was narrower
  than "nothing writes this" — it was "nothing reads this over HTTP yet."
- **A real, newly-found bug**: `api/routers/easm.py`'s own module
  docstring claimed "Assets and candidate assets paginate at the SQL
  level, matching exposures." This was false for both.
  `list_assets_for_organization` had no `LIMIT`/`OFFSET` at all — the
  router's `_paginate` helper was Python-slicing an already-fully-
  fetched, unbounded result set on every single request. An organization
  with 50,000 assets would have every single one fetched and constructed
  into an `AssetRecord` on every paginated page request, just to return
  100 of them. Fixed for assets in this phase (see below);
  `list_candidate_assets_for_organization` has the exact same bug and is
  explicitly left unfixed here — a real, named, deferred item, not
  silently carried forward as if it didn't exist.
- **Visual intelligence is confirmed the one genuine total gap**: no
  observation type, no asset type, no table, nothing in `api/` at all
  connects `modules/browser_probe.py`'s screenshots to the EASM domain
  model. This one matches Phase 00's MISSING classification exactly.

## What shipped

### 1. Real SQL-level pagination, search, and sort for asset listing

`ControlDB.list_assets_for_organization` gained `q`, `sort`, `order`,
`limit`, `offset` — all new, additive, keyword-only. Critically,
`limit=None` (the default) means **no SQL `LIMIT` clause at all**, so
every pre-existing internal caller (certificate/technology/change
backfills, `list_assets_running_technology`) keeps getting the complete,
unbounded set it always has — only `GET /organizations/{id}/assets`
passes an explicit `limit`, and now gets real SQL-level pagination
matching `list_exposures_for_organization`'s established pattern exactly.

- `q`: case-insensitive substring match on `identity_key`, with `%`/`_`
  correctly escaped so a domain literally containing those characters
  can't be used to widen the match into an unintended wildcard pattern.
- `sort`/`order`: allowlisted to `first_seen_at`/`last_seen_at` and
  `asc`/`desc` — never a caller-supplied column name interpolated
  directly into `ORDER BY` (the same identifier-allowlist discipline
  this codebase already applies everywhere user input could reach raw
  SQL, most recently in the Snyk path-traversal remediation).

### 2. Current certificate per asset

`ControlDB.get_current_certificate_for_asset` + `GET
/organizations/{id}/assets/{asset_id}/certificate`. Reuses
`OBSERVATION_TYPE_CERTIFICATE_PRESENT` (already recorded from real
`Host.tls` captures) and the exact same "latest run wins" derivation
`list_current_technologies_for_asset` established — that shared logic
was extracted into one module-level helper (`_latest_run_id_among`) so
a third future "current state" view doesn't have to re-derive it a third
time. Returns `null` (HTTP 200), never 404, for an asset that exists but
has never had a parseable certificate observation — a domain with no
HTTPS presence is a normal state, not an error.

### 3. Asset identifiers endpoint

`GET /organizations/{id}/assets/{asset_id}/identifiers` — the first API
surface over `ControlDB.list_identifiers_for_asset`, which was already
fully written and populated (resolved IPs, from Fase 03) but had no
endpoint before this phase.

### 4. Documentation-only: DNS, ports, cloud are already asset types

No code changed for these — `api/routers/easm.py`'s own asset-listing
docstring and this document now state plainly that `asset_type` in `GET
/organizations/{id}/assets?asset_type=dns_record` (or `port`, or
`cloud_storage`) is how a client reaches these today, alongside
`domain`. Every asset, regardless of type, already has its own evidence
trail reachable via the existing `.../assets/{asset_id}/observations`
endpoint — so the roadmap's "why is this asset here" requirement is
already satisfied generically, for every asset type, not just domains.

## What was deliberately not built

1. **`list_candidate_assets_for_organization`'s identical pagination
   bug** — same fix, same file area, left alone this phase to keep the
   change focused on the asset-inventory endpoint this phase is actually
   about. A clean, small follow-up for whoever picks it up (candidate-
   asset review workflow is Fase 06/Phase 04's territory, not this one).
2. **Visual intelligence wiring** — confirmed a genuine, complete gap
   (no observation type, no asset type, nothing). Wiring
   `browser_probe`'s screenshots into the durable asset model is a real
   design task (where does a screenshot reference live — a new
   observation type analogous to `CERTIFICATE_PRESENT`? A dedicated
   table? An external object-storage reference?) that deserves its own
   reconnaissance, not a decision made as a side effect of this phase's
   pagination fix.
3. **A materialized "current DNS records" / "current open ports" view
   analogous to `.../technologies`** — not needed. DNS records and
   ports are already independently listable/gettable assets in their own
   right (see above), each with its own full evidence trail; there is no
   separate "current state, as opposed to the asset itself" question to
   answer for them the way there was for certificates (a domain asset
   doesn't stop being a DNS-record-having domain the way it can stop
   presenting a given TLS certificate — the record's own asset row IS
   the current state, tracked via ordinary `last_seen_at`/change-event
   semantics already built in earlier phases).
4. **Asset "state" as an explicit field** — the roadmap's Phase 02 list
   names "asset state." No new field was added: an asset's presence/
   absence in the most recent run is already exactly what
   `change_events`' `DISAPPEARED`/`REAPPEARED` transitions track,
   reachable via the existing `.../change-events` endpoint. Adding a
   redundant `state` enum to `AssetResponse` that just restates the same
   fact a different way was judged not worth the schema churn.

## Security review (Roadmap Rule 9, abbreviated to what this phase's
changes could plausibly affect)

1. **Can the new `q`/`sort` parameters enable SQL injection?** No —
   `sort` and `order` are checked against fixed allowlists before ever
   reaching the query string (`ValueError` on anything else, surfaced as
   `422` at the router via FastAPI's own `Literal` validation, so an
   invalid value never even reaches `ControlDB`); `q` is always bound as
   a parameterized value, never string-formatted into the query, with
   its own `LIKE` wildcard characters explicitly escaped.
2. **Can the new pagination change leak data across tenants?** No — the
   `WHERE organization_id = ?` clause is unconditional and unchanged;
   every new parameter only narrows or orders results already scoped to
   the caller's own organization, verified by `_require_member` before
   the query ever runs, unchanged.
3. **Can the certificate/identifiers endpoints leak another org's data?**
   No — both route through the same `_require_member`/`_require_asset`
   gate every other asset sub-resource endpoint already uses, and both
   were added to the file's existing foreign-account IDOR probe test.
4. **Can `limit=None`'s backward-compatibility default silently break an
   existing security-relevant invariant?** No — it restores the exact
   pre-existing behavior (fetch everything) for every caller that
   doesn't explicitly ask for a bounded page; nothing about who can see
   what changed, only how much of it one HTTP response returns at once.

## Tests

- `tests/test_asset_inventory.py` (new, 10 tests): real SQL-level
  pagination across page boundaries with no gaps/duplicates; `limit=None`
  preserves the unbounded internal-caller behavior; `q` substring search
  (including a wildcard-escaping adversarial case —
  `test_q_treats_percent_and_underscore_as_literal_characters`); sort/
  order correctness; rejected sort column and rejected order value;
  current-certificate returns `None` when never observed and returns the
  most recent run's certificate (not an older one) when two runs
  presented different certificates; identifiers lists a real resolved IP.
- `tests/test_api_easm.py` (12 new tests across two new classes): HTTP-
  level `q`/`sort`/`order` including the `422` on an unsupported sort
  value; the certificate endpoint against a real seeded TLS snapshot and
  against an asset that never had one (`200` + `null`, not `404`); the
  identifiers endpoint against a real seeded IP; both new endpoints added
  to the existing foreign-account IDOR probe.
- All pre-existing tests in `tests/test_technology_backfill.py`,
  `tests/test_certificate_events.py`, `tests/test_certificate_backfill.py`
  re-run and pass unchanged after the `_latest_run_id_among` extraction
  refactor.

Full-suite and CI results recorded in the PR description, not duplicated
here.

## Deferred (explicit)

1. `list_candidate_assets_for_organization`'s identical pagination bug.
2. Visual intelligence wiring into the EASM asset model — the one
   genuine complete gap remaining from Phase 00's original MISSING list,
   confirmed still accurate.
3. Every deferred item from Phases 00–01 that this phase's own asset-
   inventory work didn't touch (organization-scoped domain verification/
   scanning, invite-by-email, `core/intelligence/`/`core/diff.py`
   deprecation, provider-version qualification, the `account_settings()`
   `.env`-override bug, static admin-token auth, empty branch-protection
   required checks, webhook-durability asymmetry) remains open,
   unchanged, and out of scope here per Roadmap Rule 4.
