# EASM Fase 06 — Candidate Assets

## Purpose

A **Candidate Asset** is something Hydra discovered that may deserve future
investigation, but that has not become an owned EASM Asset merely because it
was observed.

This phase absorbs the existing per-run `core.intel.model.Indicator` lifecycle
into an organization-scoped, cross-run registry:

```text
run-scoped intel_indicators
          ↓
pure normalization
          ↓
organization-scoped candidate_assets
```

The existing Indicator model remains the source of truth for one run. Fase 06
adds durable identity across runs; it does not replace the queue.

## Identity

Candidate reconciliation is exact and deterministic:

```text
(organization_id, candidate_type, normalized_value)
```

No shared IP, certificate, ASN, branding signal, fuzzy URL comparison, or LLM
decision can merge candidates.

Supported kinds inherit the existing `IndicatorKind` vocabulary:

- DOMAIN
- IP
- CERTIFICATE
- URL

## Security boundary

These are intentionally different statements:

```text
candidate discovered != asset owned
candidate discovered != authorized for collection
candidate persisted != eligible for collection
```

An OUT_OF_SCOPE, UNKNOWN, NOT_ALLOWED, FAILED, or REJECTED candidate is still
useful intelligence and remains in history. Persisting it never changes
`CollectionScope`, never calls `authorize_active_indicator`, and never creates
an `assets` row.

## Lineage

The source `intel_indicators.evidence_id` field is a documented legacy
overload: depending on the producer, it can contain an `intel_evidence` ID or
an `intel_observations` ID. Candidate Assets therefore store it as
`lineage_reference`, opaque text with no foreign key.

This is deliberate. Fase 06 preserves what the source can prove rather than
inventing referential certainty.

## Cross-run state

The first observation fixes:

- `first_seen_at`
- `first_seen_run_id`
- stable `candidate_asset_id`

Later observations of the exact same candidate update:

- `last_seen_at`
- `last_seen_run_id`
- latest scope/authorization status
- latest collection lifecycle status
- reason/depth/priority/collector/source lineage

Replaying the same history is idempotent because the database UNIQUE constraint
is the reconciliation rule itself.

## Promotion and discard — 2026-09-26

**This was silently descoped when this document was first written**
("No promotion policy from Candidate Asset to Asset in this phase") even
though the phase's own original spec explicitly required it as a core
deliverable, not an optional extra. Closed in a follow-up review, on top
of everything above — nothing in the identity/backfill design changed.

Two new `ControlDB` methods, and one new audit table
(`candidate_asset_reviews`, one row per action, never mutated):

- `promote_candidate_asset(*, organization_id, candidate_asset_id,
  account_id, justification)` — requires `account_id` to hold the
  `owner` role on this organization (`role_can_modify_scope`, the SAME
  check `resolve_exposure`'s router already uses — no second
  authorization mechanism). Creates exactly one `assets` row via the
  identical reconciliation path Fase 03 already uses for scan-derived
  assets (`ReconciliationDecision` + `apply_asset_reconciliation`) —
  promotion and a real scan converge on the same table through the same
  code, never a separate "promoted assets" concept. Only `DOMAIN` and
  `URL` candidates can be promoted today (Fase 03 has no `ip`/
  `certificate` asset type yet); promoting either raises `ValueError`
  rather than inventing a new, undesigned asset type.
- `discard_candidate_asset(*, organization_id, candidate_asset_id,
  account_id, justification)` — same role check. Records the exact
  signal (`candidate_signal_hash`: candidate_type + normalized_value +
  reason + scope/collection/authorization status) that was discarded.

**Why promotion is not a second authorization system, stated plainly**:
an `assets` row has never carried scanning authorization by itself —
that has always been `domain_verifications`' job
(`POST /domains/{domain}/verify`, `_require_verified_domain_or_403`),
completely unaffected by any of this. Promoting a candidate makes Hydra
*track* it as a known asset; it grants zero new ability to actively scan
it. Proven directly: `tests/test_candidate_assets.py::
TestCandidateNeverFeedsActiveScanningWithoutPromotion` promotes a real
candidate and confirms it still doesn't appear in
`get_verified_domains_for_account` (the real scan gate) or
`list_due_active_monitoring_page` (Speed 2's real due-list).

**"Un candidato descartado no se vuelve a proponer sin una señal
nueva," made real, not just documented**: `upsert_candidate_asset` (the
automated backfill path) compares each re-observation's own signal hash
against the one recorded at discard time. An identical hash means
nothing new happened — the discard stands, silently, exactly as
intended. A different hash means a materially different observation
arrived that no human has judged yet — the candidate reopens to
`pending` automatically, recorded as its own audited `reopened` row
(`account_id = NULL`, since the system made this call, not a human).
Proven directly:
`tests/test_candidate_assets.py::TestDiscardedCandidateDoesNotReappearWithoutANewSignal`.

## Non-goals

- No new authorization rules (promotion reuses the existing owner-role
  check; scanning authorization stays exclusively `domain_verifications`').
- No network collection.
- No Exposure/risk judgment (Fase 08).
- No Candidate Assets API router yet (Fase 19) — the two write methods
  above are ready for one, including the role check, but nothing calls
  them outside tests today.
- No fuzzy ownership attribution.
- No promotion path for `IP`/`CERTIFICATE` candidates — Fase 03's asset
  model doesn't have a matching asset type for either yet; a future
  phase that adds one should extend `promote_candidate_asset`'s
  `candidate_type` branch, not invent a parallel promotion mechanism.

## Migration compatibility

The run-scoped `intel_indicators` table is unchanged and remains available for
per-run forensic reconstruction. Candidate Assets are an additive control-plane
projection, matching the Fase 01 boundary: per-run raw/intel data remains in
`AssetStore`; cross-run EASM identity lives in `control.db`.
