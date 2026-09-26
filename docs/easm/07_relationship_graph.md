# EASM Fase 07 — Relationship Graph

Fase 07 promotes Hydra's existing run-scoped, typed
`core.intel.model.Relationship` observations into a durable,
organization-scoped relationship graph.

## Boundary

The run-scoped `intel_relationships` / `intel_evidence` tables remain the
source facts. Fase 07 does not invent new relationship types and does not use
the legacy `graph_nodes` / `graph_edges` representation as its canonical
source.

The durable identity is exactly:

```text
organization
+ source_entity
+ relationship_type
+ target_entity
```

Seeing the same edge in a later run updates `last_seen_at` and
`last_seen_run_id`; it does not create a second relationship.

## Evidence-first rule

A relationship without mechanically resolvable evidence from the same source
run is not promoted into the durable graph.

```text
relationship without evidence => skipped
```

Each accepted run contributes an immutable `relationship_evidence` row so an
analyst can answer why Hydra believes the edge exists and which run produced
that support.

## Asset links are optional

A relationship endpoint is an Intel entity id such as:

```text
domain:app.example.com
certificate:<sha256>
ip:203.0.113.10
```

If a matching durable Asset already exists, Fase 07 links it through
`source_asset_id` / `target_asset_id`. A missing Asset does not cause Hydra
to fabricate one merely to satisfy the graph.

Those Asset foreign keys are descriptive links only and never participate in
relationship identity, attribution, ownership, scope, or authorization.

Cross-organization Asset links are rejected.

## Security semantics

These statements remain distinct:

```text
related != owned
related != attributed
related != authorized
relationship evidence != authorization
shared infrastructure != same organization
```

Nothing in the Fase 07 tables feeds `CollectionScope` or
`authorize_active_indicator`.

## Data model

`relationships` stores one durable typed edge per organization.

`relationship_evidence` stores the per-run supporting evidence:

- source evidence id
- source
- collector
- reason
- normalized metadata
- observed time
- originating run

## Intentionally not done here

- no AI-generated edges
- no fuzzy identity matching
- no automatic ownership inference
- no graph traversal that expands active scan scope
- no migration of legacy `graph_nodes` / `graph_edges` yet
- no API router yet; that belongs to the API-surface phase
