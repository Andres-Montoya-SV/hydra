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

## Non-goals

- No promotion policy from Candidate Asset to Asset in this phase.
- No new authorization rules.
- No network collection.
- No Exposure/risk judgment (Fase 08).
- No Candidate Assets API router (Fase 19).
- No fuzzy ownership attribution.

## Migration compatibility

The run-scoped `intel_indicators` table is unchanged and remains available for
per-run forensic reconstruction. Candidate Assets are an additive control-plane
projection, matching the Fase 01 boundary: per-run raw/intel data remains in
`AssetStore`; cross-run EASM identity lives in `control.db`.
