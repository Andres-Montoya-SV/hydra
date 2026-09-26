# EASM roadmap — `main` state review and hardening — 2026-09-26

This is NOT a new roadmap phase. Between the Fase 00 baseline (2026-09-25,
`docs/easm/00_baseline.md`) and this review, `main` advanced far beyond
Fase 06 without this session's involvement — Fases 06 through (parts of)
16 were merged via PRs #64, #65, #67, #69, #70, #79, #80, several of them
bundling more than one roadmap phase's work into a single PR (confirmed:
e.g. `feat/easm-relationships` (#64) also contains the actual Fase 06
Candidate Assets commits; `docs/easm/` has two different "08" documents
and two different "06"/"09" documents as a direct symptom of this). This
document records a full state review of what actually landed, plus the
concrete bugs found and fixed. It is deliberately not a claim that Fases
06-16 are "done" — see the open items section.

## 1. What is actually merged into `main` (verified via `git merge-base
--is-ancestor`, not assumed from branch names)

Merged: Fase 06 (Candidate Assets, incomplete — see below), Fase 07
(Relationships), Fase 08 (Exposures) + a hardening follow-up, Fase 09
(Provider Contract), Fase 13 (DNS Posture Intelligence), Fase 15 (Visual
Asset Intelligence v2), Fase 16 (Cloud Asset Discovery), plus a
production-validation fix and routine dependency-security patches
(python-dotenv, sslyze stack quarantine).

Not merged, confirmed abandoned with nothing of value lost: the original,
separate `feat/easm-candidate-assets` branch (superseded by the copy that
landed inside #64 — same code, same gaps) and `feat/easm-visual-
intelligence` (v1, superseded by v2; its one unique commit is already
present on `main` verbatim).

Never started: Fase 10 (external observations), Fase 11 (importers),
Fase 12 (certificate intelligence/RDAP), Fase 14 (Technology Intelligence
as its own phase — though `WhatWebParser`/technology-observation plumbing
already exists, folded into other merges), Fase 17 (capability
architecture), Fase 18 (monitoring integration), Fase 19 (API surface —
except `api/routers/exposures.py`, built early, see below), Fase 20
(retention/backup coverage for the new tables), Fase 21 (final audit/
cleanup).

**Two open, routine dependency-bump PRs** (`dependabot/pip/mypy-2.3.1`,
`dependabot/pip/ruff-0.16.8`) are sitting unmerged — not evaluated as
part of this review (out of scope: not EASM roadmap work), left for
Andrés's own call.

## 2. Real bugs found and fixed in this review

Three parallel deep-audit passes (one per merged phase cluster) plus
direct verification of the highest-risk items (organization isolation,
authorization-boundary code, merge-splice-style damage in shared files)
found the following CONFIRMED, reproducible issues — each verified by
tracing real code, not assumed from comments or docs:

### 2.1 Crash bug: `cloud_storage` assets abort change detection for the whole organization

`api/change_detection.py::host_for_asset` only has branches for
`domain`/`port`/`dns_record`/`url` and raises `ValueError` for anything
else — which is correct in isolation, but `api/change_backfill.py`'s
per-asset loop let that exception propagate uncaught. The moment any
organization has even one `cloud_storage` asset (Fase 16's own asset
type), `detect_and_record_changes_for_organization()` would raise and
abort — silently preventing change detection (including legitimate
`DISAPPEARED` detection) for every OTHER asset in that same organization,
not just the cloud one. **Not yet exploitable in production** — this
whole backfill family (`api/asset_backfill.py`, `api/change_backfill.py`,
`api/exposure_backfill.py`, `api/relationship_backfill.py`) has zero
callers outside its own tests; nothing wires it into a live router or
worker yet. Fixed in `api/change_backfill.py`: unsupported asset types
are now skipped and counted (`assets_skipped_unsupported_type`), never
allowed to abort the rest of the organization's pass. Regression test:
`tests/test_change_backfill.py::
TestUnsupportedAssetTypesNeverAbortTheWholeOrganizationsDetection` —
seeds a real `cloud_storage` asset via the real backfill path, confirms
the call no longer raises, and confirms a real domain asset in the same
organization still gets correct change-detection history.

### 2.2 Spurious-notification bug: `browser_probe`'s rendered-DOM hash silently overwrote httpx's real body hash

`docs/easm/VISUAL_ASSET_INTELLIGENCE.md` explicitly promises visual hashes
are "neutral per-run observations" that deliberately do NOT feed into
Fase 05's change digest, specifically because dynamic timestamps/nonces/
rotating banners/ads can change a rendered-page hash on every single run
even when nothing real changed. The actual merged code did the opposite:
`Host._merge_http` (`core/assets.py`) unconditionally overwrote an
existing `HttpService.body_hash` (httpx's raw-response hash — exactly
what `core/diff.py`'s `BODY_HASH_CHANGED` reads to decide whether to fire
a real change event, which `core/runner.py` turns into a real outbound
webhook via `notify_scan_diff` on every scan finalization) with
`browser_probe`'s own rendered-DOM hash whenever browser_probe ran.
Net effect: any page with a timestamp, session id, or rotating ad in its
rendered DOM (nearly all real pages) would produce `BODY_HASH_CHANGED` —
and a real webhook notification — on almost every scan. This directly
contradicted the phase's own design doc, and had shipped without a test
catching it (the existing enrichment test only proved the overwrite
happened, never checked the downstream diff consequence). Fixed in
`core/assets.py::_merge_http`: an incoming `body_hash` is now only
applied when the canonical service doesn't already have one — an
already-anchored httpx hash can never be clobbered by a later enrichment
pass. Regression test:
`tests/test_visual_intelligence.py::
test_visual_enrichment_never_overwrites_an_already_established_httpx_body_hash`.

### 2.3 Three latent cross-tenant IDOR footguns (signature inconsistencies, not live vulnerabilities)

`api/control_db.py::get_asset(asset_id)`, `get_candidate_asset
(candidate_asset_id)`, and `list_relationship_evidence(relationship_id)`
all took a bare row id with no `organization_id` filter — unlike every
other single-record accessor for the new EASM tables (compare
`get_exposure_for_organization(organization_id, exposure_id)`,
`list_exposure_evidence(organization_id, exposure_id)`, which are
correctly tenant-scoped and are what `api/routers/exposures.py` — the
one EASM router that actually exists and is live — correctly calls).
Confirmed via repo-wide grep that all three have **zero callers outside
their own definitions** (or, for `list_relationship_evidence`, one test
call site) — not exploitable today, since no Relationships/Assets/
Candidate-Assets router exists yet. Fixed to require and filter by
`organization_id`, matching the established, already-proven-safe
`get_exposure_for_organization` pattern exactly — this closes the
footgun before Fase 19 (API surface) has the chance to wire an endpoint
to the unsafe version.

## 3. Real gaps found, NOT fixed in this review — flagged for a dedicated follow-up, per this roadmap's own one-phase-at-a-time discipline

These are missing features / architecture-decision drift, not
vulnerabilities or crash bugs — fixing them properly deserves its own
branch/PR/review cycle rather than being bundled into a "find and fix
real bugs" pass:

1. **Fase 06's actual core deliverable — the human confirm/discard
   promotion flow with an audit trail — was never built**, in either the
   merged attempt or the abandoned duplicate branch. Both explicitly,
   silently descoped it (`docs/easm/06_candidate_assets.md`: "No
   promotion policy from Candidate Asset to Asset in this phase") without
   surfacing that as a stop-and-report decision. What exists today is
   only the read/backfill half: `candidate_assets` table,
   normalization, backfill from `intel_indicators`, and a list query. No
   `promote_candidate`/`discard_candidate` methods, no audit trail (who/
   when/why), no "discarded doesn't reappear without a new signal" logic,
   and none of the phase's three required tests exist. This is fail-safe
   by omission (nothing can be promoted, so no accidental scope
   expansion is currently possible) — not a live risk — but it is a real
   compliance gap against the phase's own explicit spec.
2. **`core/registry.py` was never migrated off the legacy
   `core/intelligence/graph.py` engine**, contradicting
   `docs/easm/00_consolidation_plan.md`'s own explicit decision ("stop
   populating [`graph_nodes`/`graph_edges`] once the migration lands...
   `core/registry.py:46-61` is the only call site that needs to change").
   The new `relationships`/`relationship_evidence` tables correctly read
   from `intel_relationships` (the right absorption target) rather than
   duplicating the legacy graph logic, but the legacy engine still runs
   on every single scan, unretired.
3. **Exposure's required three-nature distinction (informational
   posture / security exposure / configuration change) was never
   implemented** — only a single flat `severity` enum
   (`low/medium/high/critical`) exists. The only nature-like behavior
   present is binary and implicit: an informational-severity finding is
   silently never promoted to an Exposure at all, rather than being
   classified into its own first-class category.
4. **Provider Contract's timeout path has no real test** — the code
   (`modules/_base.py`) looks correct by inspection (any exception,
   including a subprocess timeout, maps to `FAILED`, never a clean
   state), but `docs/easm/09_provider_contract.md`'s claim that
   "subprocess timeout handling in BaseToolPlugin" has reused regression
   coverage is not substantiated — no test anywhere actually forces a
   timeout and asserts the resulting state.
5. **Numbering/naming collisions in `docs/easm/`** (two different "08"
   documents, two different "06"/duplicate "09"/duplicate technology-
   intelligence docs) are a direct, visible symptom of multiple PRs
   bundling more than one phase's work — Fase 21's own "nombres
   consistentes entre fases" cleanup checklist item is real, necessary
   work, not a formality.

## 4. Pipeline result after the fixes in section 2

`compileall`/`ruff`/`black`/`isort`/`mypy`/`bandit` all clean (bandit: 0
real findings). Full suite green 3x — see the PR for this review's exact
captured counts (this document does not restate them to avoid drifting
out of sync with the actual run).
