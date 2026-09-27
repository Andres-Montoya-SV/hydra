# EASM Fase 10 — External Observations

## Purpose

Not every fact about an organization's footprint comes from Hydra's own
scans. RDAP lookups, an Nmap report a customer hands over, a certificate
transparency feed, a third-party intelligence export — all of these can
produce facts worth recording. This phase gives those facts one narrow,
audited door into the existing Fase 04 Observation/Evidence model, without
creating a second observation pipeline and without ever letting an import
stand in for authorization.

**The rule this phase exists to enforce:** `Imported != Authorized`,
`Third-party != Direct observation`.

## What is new

- `api/external_observation.py` (pure module): `ObservationSource`,
  `ObservationConfidenceClass`, `CONFIDENCE_CLASS_RANK`,
  `reconcile_precedence()`, `ExternalObservationDraft`.
- `EvidenceContent.confidence_class` (`api/observation_identity.py`) — a new
  field, default `"DIRECT_CURRENT"`, so every existing real-scan caller is
  unaffected.
- `evidence.confidence_class` column (migration, default
  `'DIRECT_CURRENT'`).
- `observation_batches` table — one row per ingest call, recording who
  imported it, from which source, at what confidence class, and an optional
  pointer to the raw artifact (a file path, an S3 URI) for later audit.
- `api/external_observation_ingest.py::ingest_external_observation_batch()` —
  the only place external facts enter the system.

## Confidence class vocabulary and precedence

```text
DIRECT_CURRENT        100   — Hydra's own current scan
CUSTOMER_SUPPLIED       80   — the organization's own inventory/records
THIRD_PARTY_CURRENT     60   — a live third-party source (RDAP, Nmap import)
INFERRED_RELATIONSHIP   40   — derived, not directly observed
HISTORICAL              20   — known to have been true, not current
```

`reconcile_precedence()` picks the "current" fact for an asset/observation
type purely by this rank, then by recency, then by `evidence_id` as a final
deterministic tiebreak. Recency alone never lets a stale third-party import
outrank a newer... nor a newer one outrank an older DIRECT_CURRENT scan —
rank always dominates. This is the same "reuse before build" and "no
black-box scoring" discipline the roadmap's shared rules require: the
ranking is a fixed table, not a learned or heuristic score.

`ControlDB.current_evidence_for_asset_and_type()` is the query surface that
applies this rule against real stored evidence.

## Imported != Authorized

`ingest_external_observation_batch()` does exactly one identity check per
draft: does an `assets` row already exist for this organization at this
identity? (Reuses `api/asset_identity.py`'s own `domain_identity_key`/
`url_identity_key` — no new identity scheme.)

- **Yes** → this is a fact about something Hydra (or a human, via Fase 06
  promotion) already knows and owns. It becomes ordinary corroborating
  Evidence + Observation, through the exact same
  `find_or_create_evidence`/`record_observation` calls a real scan uses.
- **No** → the fact can only ever produce a `candidate_assets` row (Fase 06),
  with `authorization_status="DENY"`, `scope_status=UNKNOWN`,
  `collection_status=NOT_COLLECTED` — fail closed, reviewable, promotable,
  discardable through the exact same human workflow every other candidate
  goes through. There is no "trusted import" shortcut that skips review.

A candidate created this way is, by construction, invisible to every
scan-authorization surface (`get_verified_domains_for_account`,
`list_due_active_monitoring_page`) — proven directly in
`tests/test_external_observation_ingest.py::TestImportedAssetIsNeverAuthorized`.

## Organization isolation

Every batch, candidate, and evidence row created here carries
`organization_id` through the same required-parameter path Fases 02-06
already established. No cross-organization query exists in this module.

## Non-goals

- No new asset types. Only `DOMAIN`/`URL` candidate types resolve to a known
  asset today (the same limitation Fase 06's promotion carries) — `IP`/
  `CERTIFICATE` imports always become candidates.
- No automatic promotion of an imported candidate, ever — that is Fase 06's
  owner-gated action, unaffected by import volume or apparent source
  trustworthiness.
- No relationship or exposure is created directly from an external
  observation. An import can at most produce Evidence/Observation or a
  Candidate — never a Relationship or Exposure, which must be derived
  through their own phases' evidence-backed pipelines.
