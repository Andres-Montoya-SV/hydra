# Product Phase 01 — Onboarding & Organization Setup

Branch: `productization/01-onboarding`. Base: `main` @ `0b496f8` (includes
the merged Phase 00 baseline, PR #93). Post-merge CI on that commit was
verified green before this phase started (Roadmap 01's own "never open
N+1 before N is merged and green" rule).

## Goal, as actually scoped

`docs/productization/00_product_baseline.md` §12 already found that most
of Roadmap Phase 01's generic description (accounts, keys, email
verification, domain verification, first-scan trigger, status/retry) is
**already built** — this phase's real job was narrower: verify that
finding by writing tests against the real API first, then close the
three genuine gaps Phase 00 identified. Re-reading `main` fresh for this
phase (Roadmap Rule 1) turned up one correction to Phase 00's own
classification, described below.

## What Phase 00 got right, and one thing it understated

Phase 00 classified organization creation as **PARTIALLY_DONE** — correct
as far as it went, but a fresh read of `api/control_db.py` found more
than the baseline doc implied: `ControlDB.create_organization()`,
`add_account_organization_role()`, `role_can_modify_scope()`, and
**`role_can_manage_members()`** were all already built and fully unit-
tested in Fase 02 of the EASM roadmap — `role_can_manage_members` in
particular had **zero production callers** anywhere in `api/` before
this phase. The real gap was never "design a data model for multi-org
membership" — it was purely "these tested functions have no HTTP surface
yet." This is a cleaner, smaller gap than Phase 00's own PARTIALLY_DONE
label suggested, and a direct illustration of Roadmap Rule 1 in practice:
verify a prior phase's own claims against real code before building on
them, even when that prior phase was this same roadmap's own baseline.

## What shipped

### 1. Organization creation and membership (`api/routers/easm.py`)

- `POST /organizations` — creates a second (or later) organization for
  the calling account and grants it the `owner` role. Pure HTTP wrapper
  over `ControlDB.create_organization`/`add_account_organization_role` —
  no new persistence.
- `GET /organizations/{organization_id}/members` — any member (owner or
  viewer) can list who has access. New `ControlDB.list_members_for_organization`.
- `POST /organizations/{organization_id}/members` — owner-only (via
  `role_can_manage_members`, its first real caller), grants a role by
  `account_id`. Returns `404` if the target account doesn't exist.
- `DELETE /organizations/{organization_id}/members/{account_id}` —
  owner-only, refuses (`409`) to remove an organization's last owner.
  New `ControlDB.remove_account_organization_role` + `LastOwnerError`.

**Deliberately not built**: invite-by-email. There is no invite-by-token
flow anywhere in this system yet; a caller must already know the target
account's `account_id`. Building a real invite flow is a reasonable
future addition, not done here — it would be a new onboarding concept
(email-based invite tokens), not a thin wrapper over existing logic, and
the roadmap's own Rule 4 asks for small, reviewable steps over expanding
a phase because an adjacent improvement looks attractive.

**A real, load-bearing limitation, stated plainly**: `POST /domains` and
`POST /scans` still operate only on the calling account's own default
organization — neither endpoint accepts an `organization_id` parameter.
A consultant can create a second organization and add a client as a
viewer on it today, but **cannot yet verify a domain into that second
organization or scan on its behalf** — the "consultant with two clients"
scenario `ControlDB.create_organization`'s own docstring names is real
at the data-and-membership layer but not yet reachable end-to-end
through the product API. Wiring `organization_id` through domain
verification and scan creation (and deciding whether quota/billing
checks, which are account-scoped today, need to become organization-
scoped too) is real, separate work — flagged here rather than silently
taken on, since it touches the billing/quota code path this phase's
"small additive change" mandate should not expand into.

### 2. Collection profile on `POST /scans`

- `CreateScanRequest.profile: "standard" | "passive" = "standard"`.
- `"passive"` applies the **exact same** narrowing
  `api/monitoring.py::passive_monitoring_settings_overrides` already
  applies to Speed 1 continuous monitoring — one definition of "passive"
  for the whole service, reused rather than reinvented. It forces off
  every `enable_<plugin>` flag whose plugin has `active_collection=True`
  that the account currently has on; it never turns anything on.
- New `scans.collection_profile` column (additive migration, default
  `'standard'`, same `_migrate_table_columns` pattern already used for
  `trigger_source`/`retry_count`/etc.) — echoed back on `GET /scans/{id}`.
- Monitoring-triggered scans (`trigger_source in ("scheduled_passive",
  "scheduled_active")`) ignore this field entirely; their own
  `trigger_source` already decides passive vs. active, unchanged.

**Deliberately not built**: a third profile, or per-plugin selection.
The roadmap's own Phase 01 description asks for "collection profile/
intensity/capability selection," plural — this phase ships the one
binary distinction (`standard`/`passive`) the codebase already has a
real, tested definition for (`ReconPlugin.active_collection`). A finer-
grained selection (e.g., choosing individual `Capability` enum values
per scan) would need new plumbing this phase's "small, additive" mandate
argues against building speculatively, with no client asking for it yet.

### 3. Acceptance test

`tests/test_api_domain_verification_endpoints.py::TestDnsTxtEndToEndThroughTheRealApi::test_onboarding_acceptance_journey_account_to_first_scan`
— create account → list its automatic 1:1 organization → register and
verify a domain (real DNS TXT check against a real local test server,
same fixture the file's pre-existing full-flow test uses) → create a
scan with `profile: "passive"` → confirm it's accepted and the profile
is echoed correctly. Deliberately does not poll to completion or create
a second organization — see the test's own docstring for why (this
file's `_stub_pipeline` helper is weaker than `test_api_scans.py`'s, and
full completion + `profile: "passive"` end-to-end is already proven
there; exercising a second org here would misleadingly imply domain
verification/scanning already compose with it, which §"real, load-
bearing limitation" above says they don't).

## Data model / security review (Roadmap Rule 9, abbreviated to the
questions actually relevant to this phase's changes)

1. **Can this grant authorization?** No — organization membership
   controls who can *see*/*manage* an organization's product data; it
   never touches `CollectionScope`/domain verification/scan
   authorization, which remain entirely separate systems, unchanged.
2. **Can this leak data across tenants?** No new leak surface: every new
   endpoint routes through `require_api_key` + `_require_member`/
   `_require_member_manager`, matching this router's existing
   anti-enumeration convention exactly (a non-member gets `404`, never
   `403`, so "wrong org" and "org doesn't exist" stay indistinguishable).
   Covered by `TestForeignAccountCannotProbeAnyEndpoint`'s extended probe
   list.
3. **Can a role escalate itself?** No — `role_can_manage_members` gates
   `POST`/`DELETE .../members` at owner-only; a viewer calling either
   gets `403` (tested).
4. **Can an organization end up with zero owners?**  No —
   `remove_account_organization_role` refuses with `LastOwnerError`
   (→ `409`) when the target is the organization's last owner (tested,
   including the "one of two owners" and "no-op on an outsider" edge
   cases).
5. **Can the new `collection_profile` field expand what a scan does
   beyond the account's own configuration?** No — `passive_monitoring_
   settings_overrides` only ever turns flags off, never on (a documented
   invariant of the function this phase reused verbatim, not modified).

## Tests

- `tests/test_organizations.py` — 5 new tests (`TestMemberListingAndRemoval`)
  covering listing, viewer removal, last-owner refusal, two-owner removal,
  and no-op-on-outsider; plus one new assertion in the existing pre-Fase-02
  migration test confirming `collection_profile` migrates in with the
  `'standard'` default for a `scans` row that predates the column entirely.
- `tests/test_api_easm.py` — 7 new tests (`TestOrganizationCreationAndMembers`)
  covering creation, add+list, viewer-cannot-add (403), nonexistent-account
  (404), owner-can-remove, last-owner-refused (409), viewer-cannot-remove
  (403); plus the new endpoints added to the existing foreign-account IDOR
  probe list.
- `tests/test_scan_orchestrator_easm_wiring.py` — 2 new tests
  (`TestExecuteScanCollectionProfile`) proving `passive` forces off an
  active-collection plugin the account had on, and `standard` leaves it
  untouched, at the `execute_scan` level (below the HTTP layer).
- `tests/test_api_scans.py` — 3 new tests: default profile is `standard`
  and echoed; `passive` is accepted, echoed, and completes through the
  full stubbed pipeline (`_install_pipeline_stubs`, which — unlike the
  domain-verification file's weaker stub — does mock `ToolManager` and so
  can poll all the way to `"completed"`); an unknown profile value is a
  clean `422`.
- `tests/test_api_domain_verification_endpoints.py` — 1 new end-to-end
  acceptance test (above).

All new and pre-existing tests pass; full suite results and CI status
recorded in the PR description, not duplicated here (this document
describes behavior, not a point-in-time test run).

## Deferred (explicit, not silently dropped)

1. **`organization_id` on `POST /domains`/`POST /scans`** — the real
   remaining piece of the "consultant with two clients" journey. Needs
   its own reconnaissance into whether quota/billing checks
   (`api/subscriptions.py`, currently account-scoped) should become
   organization-scoped, or whether an account's tier limits should simply
   apply across all its organizations combined. Proposed for a future
   phase, not decided here.
2. **Invite-by-email** — member management today requires already
   knowing the target `account_id`. A token-based invite flow (mirroring
   the existing email-verification-token pattern) is a reasonable, small
   future addition.
3. **Finer-grained collection profiles** — only the binary `standard`/
   `passive` distinction shipped, matching the one real, tested
   definition (`active_collection`) already in the codebase. Per-
   `Capability` selection would need new plumbing not built here.
4. Every other deferred risk from Phase 00 (`core/intelligence/`/
   `core/diff.py` deprecation, provider-version qualification, the
   `account_settings()` `.env`-override bug, static admin-token auth,
   empty branch-protection required checks, webhook-durability asymmetry)
   remains open and unchanged by this phase — none of them were this
   phase's job, per Roadmap Rule 4 ("avoid unrelated cleanup").
