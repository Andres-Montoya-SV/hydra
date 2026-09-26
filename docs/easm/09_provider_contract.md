# EASM Fase 09 — Minimal Provider Contract

Fase 09 introduces the smallest product-level provider contract needed by the
remaining EASM roadmap. It deliberately **does not** replace Hydra's existing
`ReconPlugin`, dependency registry, parsers, provenance, or authorization
machinery.

## Why

Before this phase, `ToolStatus.COMPLETED` could mean either "the provider ran
and found facts" or "the provider ran cleanly and found nothing". An
enabled-but-missing optional tool was also reported as `SKIPPED`. Those
ambiguities are unsafe for Exposure reconciliation: failure or unavailable
coverage must never become "clean".

The normalized terminal execution outcomes are now:

```text
SUCCESS_WITH_RESULTS
SUCCESS_NO_RESULTS
PARTIAL
BLOCKED_BY_SCOPE
SKIPPED
UNAVAILABLE
FAILED
```

`COMPLETED` remains as a compatibility state for direct plugin callers and old
fixtures; `PipelineRunner` normalizes real pipeline runs to the new states.

## Reused architecture

The contract is a projection of existing sources of truth:

- `ReconPlugin`: provider name, product capability, active/passive behavior,
  outputs and network properties.
- `core/dependencies/registry.py`: external-binary capabilities, discovery,
  version probes and installation policy.
- `PROXY_VERIFIED_TOOLS`: confinement evidence.
- parsers + `HostRegistry`: normalized observations.
- `core.provenance`: source and artifact reference.
- existing Observation / Evidence / Relationship / Exposure persistence.

There is no second provider registry.

## Provider inventory

`core.provider_contract.provider_inventory()` returns machine-readable
descriptors with:

- provider / display name
- provider kind: discovery, intelligence, exposure or import
- product capability
- active/passive classification
- authorization requirement
- confinement level
- external dependency flag
- required/optional
- declared outputs
- supported asset types when explicitly known
- dependency-registry capabilities
- provenance source

Fase 09 intentionally derives safe defaults for legacy plugins. Fase 17 is the
incremental migration of every remaining provider to explicit product
capabilities/policies.

## Execution semantics

The runner, not individual tools, is the final authority for execution outcome.

```text
provider success + facts       -> SUCCESS_WITH_RESULTS
provider success + no facts    -> SUCCESS_NO_RESULTS
bounded incomplete result      -> PARTIAL
all active input denied        -> BLOCKED_BY_SCOPE
operator/policy skip           -> SKIPPED
enabled dependency unavailable -> UNAVAILABLE
execution/parser failure       -> FAILED
```

A full scope denial is classified only *after* the existing
`authorize_plugin_input()` has made the authorization decision and written the
authorized sidecar. The provider contract therefore observes the outcome; it
does not introduce another scope system.

Cached artifacts retain the same distinction using their persisted line count.

## Evidence pipeline

Hydra keeps one evidence pipeline:

```text
raw provider artifact
        ↓
provider parser
        ↓
normalized Host / observation
        ↓
Provenance / Evidence
        ↓
Asset / Relationship / Exposure
```

Raw artifact paths remain provenance metadata and are reduced to shareable
filenames/relative paths where the existing code already requires that. Raw
output is not a public domain object.

## Required test coverage

Fase 09 adds direct tests for:

- machine-readable inventory derived from the existing registries
- supported/incompatible version policy remains in the dependency registry
- missing dependency
- `SUCCESS_WITH_RESULTS` vs `SUCCESS_NO_RESULTS`
- `PARTIAL`
- provider exception -> `FAILED`
- full scope denial -> `BLOCKED_BY_SCOPE`
- raw artifact/provenance separation

Existing regression coverage is reused rather than duplicated for:

- subprocess timeout handling in `BaseToolPlugin`
- malformed WhatWeb/provider output failing closed
- parser provenance and local-path redaction
- live confinement / scope enforcement

## Invariants

```text
Provider != authorization authority
Capability policy != authorization
Collection failed != no findings
Unavailable != skipped
Partial != clean
Blocked by scope != failed
Raw artifact != normalized fact
```

This phase does not resolve exposures automatically and does not change
CollectionScope.
