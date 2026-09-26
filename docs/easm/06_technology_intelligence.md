# EASM Fase 06 — Technology Intelligence

Status: implementation branch `feat/easm-technology-intelligence`.

## Decision

Technology is a **neutral observation about an asset**, not an Asset type and not
an Exposure. This phase therefore extends the existing Fase-04 path instead of
creating a parallel `asset_technologies` table:

```text
httpx / WhatWeb
      ↓
TechnologyFinding
      ↓
technology_detected Observation
      ↓
Evidence
      ↓
cross-run Asset history
```

`httpx` remains the primary provider. WhatWeb is optional enrichment.

## WhatWeb provider

The integration targets WhatWeb 0.6.4's documented CLI/JSON interface:

- `--log-json=FILE`
- `--follow-redirect=never`
- `--proxy <hostname:port>`
- `--max-threads`
- `--open-timeout` / `--read-timeout`

Hydra deliberately keeps WhatWeb at its default aggression level 1. Levels 3/4
may generate additional requests and do not belong in the default EASM
fingerprinting path.

Only already-alive URLs that independently pass
`AuthorizedCollectionTarget.authorize()` are handed to WhatWeb. Redirect
following is disabled so the target cannot expand collection through a
`Location` header.

Traffic is configured through `ScopeEnforcingProxy`, but WhatWeb is
**not** added to `PROXY_VERIFIED_TOOLS` in this phase: a dedicated real-binary
confinement test has not yet proven that this exact build routes every outbound
connection through the proxy. Hydra therefore emits its existing
`UNTRUSTED_NETWORK_TOOL` warning for the provider, and the provider is not
allowed under `STRICT_OPSEC`.

That is an intentional honest boundary, not a missing documentation claim.

## Normalization

WhatWeb plugin names become `TechnologyFinding.name`; a reported version is
preserved when present. Metadata-only plugins such as Title/IP/Country are
discarded so Technology Intelligence does not become a bag of unrelated page
metadata.

A normalized record retains:

- host
- URL
- technology
- optional version
- source=`whatweb`
- confidence score

The canonical parser attaches these to the existing `HttpService.technologies`
list. Fase 04 then creates durable `technology_detected` observations/evidence
without schema duplication.

## Product semantics

The important product capability is **Technology Intelligence**, not "having
WhatWeb". A future provider can replace or complement WhatWeb without changing
the EASM data model.

Hard invariants remain:

```text
technology observation != exposure
technology observation != ownership
technology observation != authorization
provider result != authorization authority
```

## Deferred

- A real installed-WhatWeb proxy-confinement test before it can be considered
  `PROXY_VERIFIED_TOOLS` / STRICT_OPSEC-safe.
- Capability-level multi-provider confidence composition (later provider
  architecture phase).
- API filtering/query UX for technologies (Fase 19/API surface).
