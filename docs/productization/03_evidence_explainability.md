# Product Phase 03 — Evidence Explainability API

Branch: `productization/03-evidence-explainability`. Base: `main` @
`3f216a7` (includes the merged Phase 02 asset-inventory PR #95 and the
standalone domain-verification-test-flake fix PR #96). Post-merge CI on
that commit was verified green before this phase started.

## Re-reading main fresh (Roadmap Rule 1)

Phase 00's baseline doc classified Relationships as **MISSING**
(explicitly deferred per Fase 19: "populated data with no API surface at
all") and change/tech/cert-event "why did this change" as
PARTIALLY_DONE. Re-reading the actual code for this phase confirmed and
sharpened both:

- **Change/certificate/technology events already fully answer "why did
  this change"** — `ChangeEventResponse`/`CertificateEventResponse`/
  `TechnologyEventResponse` (`api/schemas.py`) all already carry a real
  `reason: str` field, populated by the deterministic classifiers built
  in earlier EASM phases. **No work needed here** — this requirement was
  already ALREADY_DONE, more completely than Phase 00's PARTIALLY_DONE
  label suggested.
- **Relationships were exactly as missing as Phase 00 said — but the
  underlying data layer is far more complete than "populated data,
  no API surface" implied.** `ControlDB` already had, fully built and
  unit-tested since Fase 07: `list_relationships_for_organization`,
  `list_relationship_evidence` (with a docstring explicitly noting it
  was "originally... a latent cross-tenant IDOR unreachable only because
  no Relationships API router exists yet" — i.e., this exact gap was
  anticipated and pre-hardened), and `relationship_neighborhood` — a
  bounded, depth-limited, tenant-safe breadth-first graph traversal.
  Nothing needed building at the data layer; everything needed was a
  thin HTTP wrapper.

This phase is therefore almost entirely about **exposing** already-solid
data, not building new data-layer logic — consistent with this
roadmap's emerging pattern (Phase 02 found the same for DNS/ports/
cloud/identifiers).

## What shipped

### 1. Real SQL-level pagination for relationships, from the start

`ControlDB.list_relationships_for_organization` gained `limit`/`offset`
(default `100`/`0`, capped at 500, matching `list_exposures_for_organization`'s
established pattern exactly). Unlike `list_assets_for_organization`
before Phase 02, this method had **zero pre-existing internal callers**
(confirmed by grep) — there was no unbounded-fetch backward-compatibility
case to preserve, so no `limit=None` escape hatch was needed here.

### 2. Three new endpoints (`api/routers/easm.py`)

```
GET /organizations/{id}/relationships
GET /organizations/{id}/relationships/{relationship_id}/evidence
GET /organizations/{id}/assets/{asset_id}/relationships
```

- **List**: paginated, filterable by `relationship_type`, returns
  `RelationshipResponse` — including `data`, the relationship's
  structured supporting detail (e.g. the shared IP/certificate a
  `SHARES_IPV4`/`PRESENTS_CERTIFICATE` relationship cites), **parsed
  from the stored JSON string into a real object**, never returned as a
  raw JSON-string blob or a raw database row (the roadmap's own explicit
  requirement).
- **Evidence**: the actual "why are these two entities related" answer
  — every piece of mechanically-resolved evidence behind one
  relationship, each with a human-readable `reason` and parsed
  `metadata`. `404` (not an empty list) for a relationship_id that
  doesn't belong to the caller's organization — added a new
  `ControlDB.get_relationship(organization_id, relationship_id)`
  tenant-scoped lookup for this, mirroring `get_asset`/`get_candidate_asset`'s
  existing shape exactly.
- **Asset-centric neighborhood**: every relationship reachable from one
  specific asset within `depth` hops (default 1, capped at 8 — the
  existing method's own ceiling). This reuses
  `relationship_neighborhood` verbatim; its own pre-existing `max_edges`
  bound (already tested) means a densely-connected asset returns a
  large-but-bounded page, never an unbounded one — no new capping logic
  needed.

### 3. JSON parsing discipline

A small `_parse_json_object` helper in `api/routers/easm.py`: returns
`{}` for `None`/empty/malformed JSON rather than ever raising a `500`
for a product-facing read endpoint — the same "defensive against
malformed stored data" discipline `parse_certificate_snapshot`
(Phase 02's certificate work) already established for this codebase.

## What was deliberately not built

1. **A single, unified "explanation" resource shape reused across every
   assertion type.** The roadmap's Phase 03 description asks for one
   reusable shape "any future client can render without needing bespoke
   logic per assertion type." Investigated this directly: exposure risk
   already uses `reasons: list[str]`; change/cert/tech events already use
   `reason: str` (singular); the new relationship evidence endpoint uses
   `reason: str` + structured `metadata`. Unifying these into one literal
   shared Pydantic model would mean either (a) changing three already-
   shipped, already-tested response schemas with no functional
   improvement (pure churn), or (b) inventing a new wrapper type nothing
   would actually use yet. Judged not worth doing speculatively — every
   existing "why" answer is already structured and explainable in its
   own right; the roadmap's real ask (don't return raw DB rows, always
   cite concrete reasons) is already satisfied everywhere it applies.
   Revisit if a future phase's own client integration work finds the
   inconsistency genuinely costly, rather than fixing it pre-emptively
   here.
2. **A generic per-asset "why does this asset exist" synthesis endpoint.**
   The existing `.../assets/{asset_id}/observations` endpoint already
   answers this with real evidence (source, detail, confidence) for
   every asset type — domains, DNS records, ports, and cloud storage
   alike (Phase 02 confirmed these are all real, peer asset types). A
   separate "explain" endpoint over the same data would be a pure
   reshaping exercise with no new information, and none was requested
   by name in this phase's own task list.
3. **A raw-provenance/analyst-debug endpoint distinct from the product
   endpoint**, per the roadmap's optional callout. Not built — no
   concrete analyst consumer exists yet needing it; the existing
   evidence/observation endpoints already avoid provider-tool-name
   leakage (Phase 00 confirmed the `Capability` enum discipline already
   holds), so there's no raw-vs-product distinction currently missing.

## Security review (Roadmap Rule 9, abbreviated to this phase's changes)

1. **Can these new endpoints leak another organization's relationship
   data?** No — `list_relationships_for_organization`/
   `list_relationship_evidence`/`relationship_neighborhood`/
   `get_relationship` are all `organization_id`-scoped at the SQL level,
   unconditionally, and every router endpoint calls `_require_member`
   before touching them, matching the router's existing convention.
   `get_relationship`'s addition specifically closes the exact latent
   IDOR its own docstring already flagged as anticipated-but-unreachable
   — now reachable, and now closed, in the same commit.
2. **Can a caller enumerate relationships or asset existence across
   organizations via a crafted `relationship_id`/`asset_id`?** No —
   `404`, never `403`, for a relationship or asset that exists but
   belongs to a different organization, matching this router's
   established anti-enumeration convention; verified via the foreign-
   account probe tests (both the dedicated new test file and the
   existing router-wide IDOR probe in `tests/test_api_easm.py`).
3. **Can the new pagination/filter parameters reach raw SQL unsafely?**
   No — `limit`/`offset` are always bound parameters; `relationship_type`
   is always bound, never interpolated; no new `ORDER BY`/column-name
   allowlisting concern exists here since sort order is fixed
   (`first_seen_at, relationship_id`), unlike Phase 02's asset `sort`
   parameter.
4. **Can the parsed `data`/`metadata` JSON leak something unintended?**
   No new risk — this is the exact same structured content
   `core.intel.model.Relationship.data`/`Evidence.metadata` already
   persisted for the organization's own use; parsing it for display
   doesn't expose anything the raw row wouldn't already have, and
   `_parse_json_object`'s defensive `{}` fallback means malformed stored
   data degrades to an empty object rather than ever raising.

## Tests

- `tests/test_api_relationships.py` (new, 7 tests): list with real
  structured `data`; `relationship_type` filter; real SQL-level
  pagination across page boundaries with no duplicates; evidence with a
  real `reason`/`metadata`; a nonexistent relationship_id is a clean
  `404`; the asset-centric neighborhood view against a real seeded
  domain-to-domain relationship; the foreign-account 404 probe for both
  the list and evidence endpoints.
- `tests/test_api_easm.py`: the three new endpoints added to the file's
  existing, canonical foreign-account IDOR probe list
  (`/relationships`, `/assets/{id}/relationships` — the evidence
  sub-resource's IDOR case needs a real `relationship_id` and is covered
  in the dedicated new test file instead).
- `tests/test_easm_relationships.py` (pre-existing, Fase 07): re-run
  unchanged and passing after `list_relationships_for_organization`'s
  signature gained `limit`/`offset` — confirmed no regression from the
  new keyword-only parameters.

Full-suite and CI results recorded in the PR description, not duplicated
here.

## Deferred (explicit)

1. A single unified cross-assertion-type "explanation" shape — judged
   premature; every existing "why" answer is already real and
   structured in its own right (see "What was deliberately not built"
   above).
2. `list_candidate_assets_for_organization`'s pagination bug — still
   unfixed since Phase 02 flagged it; still not this phase's job.
3. Visual intelligence wiring — still the one genuine, complete gap,
   unchanged since Phase 00/02.
4. Every other deferred item from Phases 00–02 (organization-scoped
   domain verification/scanning, invite-by-email, `core/intelligence/`/
   `core/diff.py` deprecation, provider-version qualification, the
   `account_settings()` `.env`-override bug, static admin-token auth,
   empty branch-protection required checks, webhook-durability
   asymmetry) remains open, unchanged, and out of scope here per
   Roadmap Rule 4.
