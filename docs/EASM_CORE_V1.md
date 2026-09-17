# Hydra EASM Core v1

## Goal

Turn Hydra from a run-centric reconnaissance system into a persistent external
attack-surface management platform without discarding the parts that are already
strong: scope enforcement, evidence/provenance, correlation, deterministic
verification, and grounded hypothesis generation.

This migration is intentionally additive. `runs`, `hosts`, `findings`, and the
`intel_*` graph remain authoritative for existing behavior until each EASM
projection is proven equivalent and explicitly adopted.

## Core invariant

A scan is an observation event, not the identity of an asset.

Old mental model:

```text
run -> hosts/findings
```

Target mental model:

```text
organization -> persistent asset -> observations -> events -> exposures
                                      ^
                                      |
                                     runs
```

An asset must keep the same `asset_id` across runs as long as its canonical
identity is the same inside the same organization.

## v1 domain model

### Organization

The tenant/security boundary for asset ownership and policy. An organization
may later contain subsidiaries/business units, but v1 deliberately avoids a
hierarchy until real product requirements demand one.

### Persistent asset

Stable identity keyed by:

```text
(organization_id, asset_type, canonical_key)
```

The first supported asset vocabulary is intentionally broader than hosts so the
same model can later represent cloud resources, repositories, certificates,
CIDRs, and ASNs.

Persistent mutable state includes:

- first/last seen
- active/inactive/retired status
- ownership state and confidence
- criticality
- environment
- business unit and owner team
- whether internet exposure is expected
- arbitrary metadata for additive enrichment

### Asset observation

Append-only statement that a collector observed something about an asset at a
point in time. It may reference a Hydra `run_id`, but does not require one so
future passive feeds/cloud inventory syncs can contribute observations without
pretending they are reconnaissance runs.

An observation stores:

- source and collector
- timestamp
- confidence
- deterministic content fingerprint
- structured data payload

Observations are facts about what Hydra saw, not conclusions about ownership or
risk.

### Asset event

A material state transition derived from observations. Events are the
operational interface for alerting and dashboards.

Initial vocabulary includes:

- new/reappeared/inactive/retired asset
- DNS/IP change
- port opened/closed
- HTTP/technology change
- certificate change/expiry
- finding opened/resolved/reopened
- ownership, risk, and business-context change

Events store previous/current state rather than forcing consumers to reconstruct
every change by diffing raw run tables.

### Ownership evidence

Ownership is not a raw correlation edge and must not be calculated as a naive
sum of independent-looking signals that come from the same underlying cause.

Each evidence row belongs to a signal family, for example:

- certificate identity
- DNS relationship
- registrant/business identity
- application identity
- network proximity
- cloud identity
- historical relationship
- internal inventory confirmation

The future ownership engine must combine *families*, not blindly add every
signal. Shared IP + shared ASN + same cloud provider may all be one weak network
family, not three independent votes.

Ownership states:

```text
confirmed
likely
possible
unlikely
rejected
unknown
```

No ownership assessment is allowed to expand active collection scope. Scope and
authorization remain governed exclusively by Hydra's existing collection
controls.

### Exposure

An exposure is persistent across runs. Findings are evidence emitted by tools;
an exposure is the lifecycle object security teams manage.

Lifecycle target:

```text
open -> acknowledged -> remediating -> resolved
                                ^          |
                                |          v
                              reopened <---+
```

v1 schema establishes stable exposure identity, first/last seen, status,
confidence, source, resolution timestamp, and reopen count. Workflow APIs come
later.

## Migration phases

### Phase 1 — foundation (this branch)

- additive `core/easm` package
- persistent organization identity
- persistent asset identity
- append-only observations
- material events
- ownership-evidence and exposure tables
- unit tests proving asset identity survives multiple runs

No existing run path changes yet.

### Phase 2 — projection from Hydra runs

Add a deterministic projector after `HostRegistry.finalize()` / persistence:

```text
run-scoped Host + intel entities + findings
              |
              v
        EASM projector
              |
              +-> asset upserts
              +-> observations
              +-> events
              +-> exposure lifecycle updates
```

The projector must be idempotent for a given run. Replaying a run must not create
duplicate events/exposures.

### Phase 3 — change engine

Build typed state snapshots and event derivation for:

- IP/DNS sets
- ports/services
- HTTP fingerprints/technology
- certificate identity and validity
- findings/exposures

Rules must distinguish meaningful change from collector noise.

### Phase 4 — ownership engine

Consume existing `intel_relationships` plus optional internal inventory signals.
Output an ownership assessment with:

- state
- confidence
- supporting evidence families
- contradictory evidence
- explanation

Do not permit LLM output to set ownership. A model may explain an already
computed assessment, but the assessment itself must remain deterministic and
auditable.

### Phase 5 — business context and risk v2

Risk becomes an exposure-level prioritization model rather than host heuristics
alone. Inputs should include:

- technical severity
- exploitability
- internet reachability
- ownership confidence
- evidence confidence
- asset criticality
- production/non-production environment
- data classification
- exposure age/reopen history

Business context may come from users, cloud accounts, CMDB, tags, or inferred
signals, but inferred context must be visibly distinguishable from asserted
context.

### Phase 6 — continuous monitoring

Add policies + scheduler + queue + workers. Do not split into microservices
prematurely; a modular monolith with separate worker processes is the preferred
first deployment shape.

Suggested boundaries:

```text
hydra API/process
scheduler
worker pool
PostgreSQL (when SQLite becomes the operational bottleneck)
queue/cache
object/artifact storage
```

## What we deliberately do not build yet

- more scanners simply to increase tool count
- graph database without a proven query need
- attack-path generation before persistent asset/exposure state is reliable
- autonomous LLM-driven collection
- microservices for components that do not yet need independent scaling
- enterprise RBAC/UI before the continuous EASM core works

## Quality gates

Every EASM phase should keep the properties Hydra already treats as non-
negotiable:

1. scope enforcement is not weakened by correlation or ownership
2. observations retain provenance
3. conclusions are separable from facts
4. persistent IDs are deterministic where identity is deterministic
5. replaying stored data is idempotent
6. false-positive reduction is preferred over scanner-count growth
7. all state transitions are testable without live third-party scanning
8. LLMs may synthesize/explain, never invent authorization or evidence

## Immediate next implementation step

Build the run-to-EASM projector and test it against two synthetic runs of the
same organization:

1. run 1 discovers `api.example.com` at IP A with ports 443/8443
2. run 2 sees the same persistent asset at IP B with ports 443/6379
3. projector must retain one asset ID and emit typed IP/port change events
4. exposures must be opened/resolved/reopened idempotently from verified findings

That is the first point where Hydra stops merely storing historical scans and
starts maintaining a living attack-surface state.
