# EASM consolidation plan — Fase 01 (reconocimiento, solo lectura)

**Status of the prerequisite read**: this phase's prompt says "Lee
`00_READ_FIRST.md` primero." That file does not exist anywhere in this
repository (`find . -iname "00_READ_FIRST.md"` returns nothing, checked
at the start of this phase). Per the shared rule "si un prompt cita algo
que ya no es cierto, parar, decir exactamente qué difiere, y adaptar,"
this is stated here rather than silently skipped or invented. Nothing
in the rest of this phase depended on that file's contents, so the work
below proceeded anyway; if `00_READ_FIRST.md` was supposed to exist and
carries context not captured here, that needs to come back to this
phase before phase 02 starts.

Every factual claim below cites a real `file:line` from a file read in
full for this phase (`core/assets.py` 732 lines, `core/store.py` 2654
lines, all 16 files of `core/intel/` totaling 4,489 lines, and all 6
files of `core/intelligence/` — all read completely, not skimmed).
`core/registry.py` and `api/control_db.py` were also read where cited,
since they turned out to be load-bearing for the actual answer.

---

## 1. What each candidate module actually is

### `core/assets.py` (732 lines) — the canonical per-run Host model

Defines the data every collection tool ultimately writes into: `Host`
(`core/assets.py:266-268`, "canonical host object — single source of
truth per domain") with attached `Port`, `HttpService`, `DnsRecord`,
`TlsCertificate`, `URL`, `Finding`, `TechnologyFinding` sub-entities,
each carrying its own `source`/`confidence`/`confidence_score`
(observation-shaped fields). `Host.provenance: list[ProvenanceRecord]`
(`core/assets.py:328`, `core/provenance.py:15-25`) is a full
tool/field/value/confidence/discovered_at audit record — this is
already an Observation/Evidence-shaped type, just not named that.

It also already contains a **relationship graph model**:
`InfrastructureCluster`, `GraphNode`, `GraphEdge`, `InfrastructureGraph`
(`core/assets.py:611-696`), with `GraphEdge.evidence_id`/`first_seen`/
`last_seen` fields present in the schema — and a **risk model**:
`Host.risk_level`/`risk_score`/`risk_reasons`
(`core/assets.py:329-333`).

**Lifecycle**: `AssetCollection` (`core/assets.py:699-732`) holds
`Host` objects in a plain `dict[str, Host]`, in memory, for exactly one
pipeline run. Nothing in this file persists anything — persistence is
entirely `core/store.py`'s job (below). No identity survives a process
exit except via `core/store.py`'s SQLite rows, which are run-scoped
(see §2).

**Callers**: imported everywhere in `core/`, `modules/`, and `api/`
(via `core/store.py`/`core/registry.py`) — this is the actively-used,
central data model of the whole codebase, not a legacy file.

### `core/store.py` (2654 lines) — the SQLite persistence layer, and the real fact that changes everything

`SCHEMA` (`core/store.py:29-695`) defines two **parallel** families of
tables, both scoped `UNIQUE(run_id, ...)` and FK'd to `runs(run_id)`:

1. **The `Host`-shaped tables**: `hosts`, `http_services`, `ports`,
   `dns_records`, `tls_certificates`, `urls`, `findings`, `provenance`,
   `clusters`, `graph_nodes`, `graph_edges` (`core/store.py:46-374`) —
   one row set per run, mirroring `core/assets.py`'s dataclasses
   directly.
2. **The `intel_*` tables**: `intel_entities`, `intel_observations`,
   `intel_evidence`, `intel_relationships`, `intel_indicators`,
   `intel_hypotheses`, `intel_llm_hypotheses`,
   `intel_llm_hypothesis_evidence`, `intel_collection_attempts`,
   `intel_network_requests` (`core/store.py:376-644`) — mirroring
   `core/intel/model.py`'s dataclasses, **using the exact words this
   roadmap uses**: Entity, Observation, Evidence, Relationship.

**The fact that changes everything**: every single `UNIQUE` constraint
in this entire schema — across *both* families, no exception — is
scoped to `run_id`. `hosts`: `UNIQUE(run_id, domain)`
(`core/store.py:88`). `intel_entities`: `UNIQUE(run_id, entity_id)`
(`core/store.py:388`), even though `entity_id()`
(`core/intel/model.py:100-102`) is a deterministic, value-based key
(`f"domain:{name}"`) that would be *identical* across two different
runs of the same domain. **Nothing anywhere in `core/` merges or links
those two runs' rows into one persistent identity.** The same real
domain scanned twice gets two completely independent row sets, related
only by an application-level, on-demand string match — never a stored
foreign key, never a shared surrogate ID.

The one place that *reconstructs* a cross-run view is `core/diff.py`
(476 lines, read in full): `diff_runs()`
(`core/diff.py:78-105`) takes two `run_id`s, loads each run's `Host`
dict independently (`store.get_hosts(...)`, `core/diff.py:87-88`), and
computes set differences (`new_hosts`, `removed_hosts`, `field_changes`
via plain-Python `Host` field comparison, `core/diff.py:122-160`) plus
`_intel_history_diff` (relationship/entity/evidence deltas over the
`intel_*` tables). Its output (`ScanDiff`, `core/diff.py:33-73`) is
**never persisted** — `core/runner.py:1159-1174` writes it straight to
a JSON file (`context.output_dir / "diff.json"`) and fires an existing,
separate webhook notifier (`core/webhook.py::notify_scan_diff`,
`core/runner.py:1173`) — there is no `change_events` table, no
`intel_change_events` table, nothing durable. Confirmed by grep: no
match anywhere in the tree for `change_event`/`ChangeEvent` outside
this plan.

`core/store.py:2424-2460` (`find_previous_run`) and
`core/store.py:2462-2508` (`find_latest_finished_run`) are the only
cross-run lookups that exist, and they operate purely on the `runs`
table's `targets_json`/`intel_entities.key`, matched by string — again,
no stored identity link.

### `core/intel/` (16 files, 4,489 lines) — the mature, actively-enforced model

This is **not a legacy or parallel system to be cautious of** — it is
the single most safety-critical module in the codebase. `core/intel/
scope.py`'s `CollectionScope`/`allows_active_collection`
(`core/intel/scope.py:22-63,139`) and `core/intel/authorize.py`'s
`authorize_active_indicator` (`core/intel/authorize.py:98-215`) are the
actual SSRF/scope-authorization gate imported by essentially every
active-collection module in `modules/` (confirmed: `sslyze.py`,
`dnsx.py`, `httpx.py`, `wafw00f.py`, `cloud_bucket_enum.py`, `ffuf.py`,
`asn_lookup.py`, `vuln_match.py`, `browser_probe.py`, `soft404_check.py`,
`passive_dns.py`, `sub_takeover.py`, `gau.py`, `param_fuzz.py`,
`waybackurls.py`, `whois.py`, `wildcard_check.py`, `threat_intel.py`,
plus `core/collection/gateway.py:46`, `core/collection/target.py:51`,
`core/collection/crawler_proxy.py:36`, `app.py:450`) and by ~40 test
files. **Per shared rule #4/#7, this gate must never be weakened,
wrapped loosely, or bypassed by any later phase** — any EASM identity
model that wants to attach itself to collection must call through this
gate exactly as-is, never re-derive scope logic.

`core/intel/model.py` (347 lines, read in full) is the actual data
model, and it is a **direct, already-correct match** for four of the
nine roadmap concepts:

- `Observation` (`core/intel/model.py:140-161`): `observation_id,
  entity_id, source, collector, run_id, observed_at, data,
  scope_status` — exactly the EASM "Observation" concept.
- `Evidence` (`core/intel/model.py:164-183`): `evidence_id, source,
  collector, observation_id, reason, metadata, observed_at` — exactly
  the EASM "Evidence" concept.
- `Relationship` (`core/intel/model.py:186-211`) with `RelationshipType`
  (`core/intel/model.py:57-74`, 17 values: `RESOLVES_TO`,
  `SHARES_CERTIFICATE`, `SHARES_IPV4`, `SAN_CONTAINS`, `IN_ASN`, etc.)
  and `ConfidenceBand` (`core/intel/model.py:49-54`) — exactly the EASM
  "Relationship" concept, already typed and confidence-scored.
- `IntelEntity` (`core/intel/model.py:114-137`) with `EntityType`
  (`core/intel/model.py:12-20`: `DOMAIN, IP_ADDRESS, CERTIFICATE, ASN,
  NAMESERVER, URL, HTTP_SERVICE, TECHNOLOGY`) — the closest match for
  "Asset," but see the run-scoping problem above: this is an
  infrastructure-entity model, not a persistent cross-scan asset
  registry.

`Indicator` (`core/intel/model.py:214-257`, queue-managed by
`core/intel/queue.py`'s `IndicatorQueue`, 272 lines read in full) is a
**candidate asset awaiting collection** — `DISCOVERED → ELIGIBLE →
IN_FLIGHT → COLLECTED/FAILED/REJECTED` (`CollectionStatus`,
`core/intel/model.py:36-46`) — this is a strong existing match for
roadmap phase 06's "assets candidatos."

`IntelSnapshot` (`core/intel/engine.py:86-103`) bundles one run's
entities/observations/evidence/relationships/indicators/hypotheses —
the closest existing "Snapshot," but it is a **transient in-memory
dataclass**, discarded once written to SQLite; nothing queries "the
snapshot as of time T" as a first-class stored object, only "all rows
WHERE run_id = X" via `core/intel/query.py`'s `IntelQuery`
(403 lines, read in full).

`Organization` and `Exposure` are **absent from every one of the 16
files** — confirmed, no class/table/enum resembles either concept
anywhere in `core/intel/`.

One real, already-documented schema wart worth carrying forward:
`intel_indicators.evidence_id` is overloaded — sometimes a genuine
`intel_evidence.evidence_id`, sometimes actually an
`intel_observations.observation_id`, per `core/store.py:464-481`'s own
comment (a composite FK was tried and reverted because
`core/intel/engine.py`'s DNS-resolution ingestion legitimately stores
an observation_id there). Any new EASM identifier/evidence-lineage
model should fix this rather than copy it forward.

### `core/intelligence/` (6 files) — the legacy first pass, already superseded in the wired-up path

- `clustering.py`: `compute_clusters()` groups hosts by shared
  infrastructure signal, **delegates its own confidence scoring to
  `core.intel.correlate.band_score`** (`core/intelligence/
  clustering.py:8`) — i.e. this module already depends on `core/intel/`
  for its core semantics, not the reverse.
- `graph.py`: `build_infrastructure_graph()` builds `GraphNode`/
  `GraphEdge` objects (the `core/assets.py` graph types, not its own),
  using string relation labels (`"resolves_to"`, `"hosted_on"`,
  `"PRESENTS_CERTIFICATE"` — inconsistent casing, a real smell) rather
  than `core/intel/model.py`'s typed `RelationshipType` enum. Its
  `GraphEdge.evidence_id`/`first_seen`/`last_seen` fields are **defined
  but never set** by any construction site in the file — dead schema
  slots.
- `profile.py`/`risk.py`: host categorization and a single aggregate
  `risk_score`/`risk_reasons`, collapsing `Host.findings` into one
  number rather than tracking individual findings with their own
  identity/status.

**The two systems are not parallel alternatives — they are wired
together, and `core/intel/` wins**: `core/registry.py:46-61`
(`HostRegistry.finalize()`, read directly) runs
`core.intelligence.engine.IntelligenceEngine().process(hosts)` first
(line 51), then — only `if self.intel_config is not None` (line 55) —
builds a second, richer `core.intel.engine.IntelEngine` (`build_intel`,
line 58) and **overwrites** `self.graph` with
`engine.to_infrastructure_graph(host_graph=result.graph)` (line 60).
`to_infrastructure_graph()` (`core/intel/engine.py:725-737`, read
directly) even strips certificate nodes out of the `core/intelligence/`
graph before layering its own richer entity/relationship graph on top.
**Both graphs get persisted, separately**: `AssetStore.persist_registry`
(`core/store.py:945-...`) writes the final (`core/intel/`-wrapped)
`graph`/`clusters` into `graph_nodes`/`graph_edges`/`clusters`, while
`core/intel/`'s own native `intel_relationships`/`intel_entities` are
written separately by `_insert_intel` — **two different persisted
relationship-graph representations exist side by side today**, one
loosely-typed and one richly-typed, and phase 07 must decide which one
the new consolidated graph is built from (see decision below).

Also confirmed: `core/intel/cloud.py:8`'s own comment ("Keep in sync
with core.intelligence.engine ranges") is a live, hand-maintained
duplication of the same AWS/Cloudflare/GCP/Azure CIDR list in both
`core/intel/cloud.py:9-21` and `core/intelligence/engine.py`'s
`_CLOUD_IP_RANGES` — a real, small, already-acknowledged drift risk.

### A fourth place, not named in the prompt but directly relevant: `api/control_db.py`

`api/control_db.py:1-9`'s own module docstring states the existing
boundary explicitly: *"This is deliberately a SEPARATE, small SQLite
database from any account's own `recon.db`
(`core.store.AssetStore`'s schema is the recon/findings domain; this is
the account/auth/scan-registry domain)."* Confirmed by
`api/scan_orchestrator.py:73`/`api/monitoring_worker.py:192`: each
account gets its own `AssetStore` file (`account_db_path(...)`),
completely separate from the shared `control.db`.

The **one existing place with real, persistent, cross-run identity in
the whole codebase** lives here, not in `core/`:
`monitored_domains` (`api/control_db.py:213-233`) has
`UNIQUE(account_id, domain)` — no `run_id` in that constraint at all —
one row per domain that survives forever, with `last_asset_digest`/
`last_asset_count` (a SHA-256 of the sorted hostname set,
`api/monitoring.py:109-121`) as its only change-detection signal. This
is extremely coarse (a single hash, no field-level history) but it is
the only durable, cross-scan asset-identity precedent in this codebase
today, and phases 02/03/05/09 will sit directly on top of or next to
it. Phase 02 ("Organization") should also note `accounts`
(`api/control_db.py:43-52`) is today's closest "Organization" analog —
one row per tenant, single email, no multi-user/organization concept.

---

## 2. Overlap table — roadmap concept → existing equivalent

| Roadmap concept | Closest existing equivalent | File:line | Cross-run identity? |
|---|---|---|---|
| Organization | `accounts` table | `api/control_db.py:43-52` | Yes (persistent), but single-user, no multi-member org |
| Asset | `IntelEntity` / `Host` | `core/intel/model.py:114-137`, `core/assets.py:266-268` | **No** — run-scoped only |
| Identifier | `entity_id()` | `core/intel/model.py:100-102` | Deterministic by value, but never linked across runs |
| Observation | `Observation` | `core/intel/model.py:140-161` | No — run-scoped |
| Evidence | `Evidence` | `core/intel/model.py:164-183` | No — run-scoped |
| Relationship | `Relationship`/`RelationshipType` (rich) **and** `GraphEdge` (loose) | `core/intel/model.py:186-211`, `core/assets.py:644-656` | No — run-scoped, and two competing representations |
| Exposure | `findings` table (aggregate `risk_score` only in `core/intelligence/risk.py`) | `core/store.py:187-209` | No — run-scoped, no per-finding lifecycle |
| Snapshot | `IntelSnapshot` (transient) / "all rows WHERE run_id=X" | `core/intel/engine.py:86-103` | No — not a stored object at all |
| Change Event | `ScanDiff` (computed on demand, written to a JSON file, never persisted) | `core/diff.py:33-105` | No — ephemeral, no table |

The one **partial** exception to "no cross-run identity anywhere": `api/control_db.py`'s `monitored_domains` (account_id, domain) row and its `last_asset_digest`, which is real but coarse.

---

## 3. Decisions — absorb / wrap / coexist

1. **Relationship / Entity / Observation / Evidence / Indicator
   (`core/intel/model.py`) → ABSORB, don't reinvent.** These four types
   are already correctly shaped, already have `.to_dict()`
   serialization, already have a real persistence layer
   (`core/store.py`'s `intel_*` tables), and are exercised by the
   heaviest test coverage in the package (`test_intel_engine.py`,
   `test_intel_integrity.py`, `test_correlation_correctness.py`, and
   ~40 files for the scope/authorization gate alone). Phase 03/04/06/07
   should extend these types with a cross-run identity layer (a new
   table linking `entity_id` values across `run_id`s, or promoting
   `entity_id` itself out of the run-scoped table into an
   account-scoped one) rather than defining new Entity/Observation/
   Evidence/Relationship classes from scratch. The scope/authorization
   gate (`core/intel/scope.py`, `core/intel/authorize.py`) must be
   called through exactly as-is (shared rule #4/#7) — it is out of
   scope for any phase to touch its logic.

2. **`core/intelligence/` (clustering.py, engine.py, graph.py,
   profile.py, risk.py) → ABSORB, with a documented migration.** It is
   real production code (wired through `core/registry.py`), but it is
   the *simpler* first pass that `core/intel/`'s richer engine already
   wraps and partially overwrites in the one path where both are
   enabled (`intel_config is not None`). Migration plan: `profile.py`'s
   `HostCategory` classification and `risk.py`'s scoring heuristics are
   genuinely useful input signal and should be preserved, but re-expressed
   as producers of `core/intel/model.py` `Observation`/`Evidence`
   records instead of mutating `Host.profile`/`Host.risk_score`
   in place. `clustering.py`/`graph.py`'s loosely-typed `GraphEdge`
   output should be retired in favor of `core/intel/`'s typed
   `Relationship`/`RelationshipType` — phase 07 should build the
   consolidated relationship graph from `intel_relationships`, not from
   `graph_nodes`/`graph_edges`, and stop populating the latter once the
   migration lands (a concrete "what calls the old one today and how it
   moves" migration note, per this phase's own required format:
   `core/registry.py:46-61` is the only call site that needs to change).
   The duplicated cloud-IP-range list (`core/intel/cloud.py` vs
   `core/intelligence/engine.py`) should be deleted from one side as
   part of this absorption, not fixed by adding a third "keep in sync"
   comment.

3. **`core/assets.py`'s `Host` and its sub-entities → COEXIST, with an
   explicit boundary.** `Host` is the correct shape for "what a single
   scan observed about a domain" and is deeply embedded in the
   collection/parsing/reporting pipeline (every `modules/*.py` parser
   produces partial `Host` objects). Rewriting it is out of scope and
   unjustified — the actual gap is entirely about **identity across
   scans**, which `Host` was never meant to carry. Boundary: `Host`
   remains the per-run collection result; the new EASM Asset model
   (phase 03) is a separate, account-scoped, cross-run entity that a
   `Host` gets reconciled into after each run — never the other way
   around, and never by adding cross-run fields onto `Host` itself.

4. **`monitored_domains` (`api/control_db.py`) → WRAP, don't replace
   silently.** It is the one real, tested, production cross-run
   identity precedent (used by the entire continuous-monitoring
   feature — `api/monitoring_worker.py`, `api/routers/monitoring.py`).
   Phase 03's new Asset table should be designed so `monitored_domains`
   can eventually reference or be superseded by it, but phase 09
   ("Monitoreo... sobre el nuevo modelo") is the phase that actually
   makes that migration — phases 02-08 must not silently change
   `monitored_domains`'s meaning or columns.

5. **`ScanDiff`/`core/diff.py` → ABSORB into a persisted Change Event
   model, don't keep as a JSON-file side effect.** The diffing *logic*
   (`_field_changes`, `_intel_history_diff`) is sound and already
   tested; phase 05's job is to make its output a first-class, queryable,
   persisted row set instead of a discarded dataclass written to
   `diff.json`. `core/webhook.py::notify_scan_diff` (the CLI-level
   webhook notifier fired from `core/runner.py:1173`) is a **separate,
   older system** from the multi-tenant `api/webhooks.py` built for the
   paid API — flagged here as a discovered overlap outside this
   phase's core scope, for whoever picks up notification consolidation
   later to reconcile rather than have two independent
   "monitoring.changed"-shaped notifiers.

---

## 4. Glossary — binding on phases 02-12

| Roadmap term | Real name today | File | Status |
|---|---|---|---|
| Organization | `accounts` | `api/control_db.py:43` | coexists with; phase 02 extends |
| Asset | `IntelEntity` (infra) / `Host` (per-run) / `monitored_domains` (durable, narrow) | `core/intel/model.py:114`, `core/assets.py:266`, `api/control_db.py:213` | absorbs `IntelEntity`; new cross-run table needed |
| Identifier | `entity_id()` | `core/intel/model.py:100` | absorb; add cross-run linkage |
| Observation | `Observation` | `core/intel/model.py:140` | absorb as-is |
| Evidence | `Evidence` | `core/intel/model.py:164` | absorb as-is |
| Relationship | `Relationship`/`RelationshipType` | `core/intel/model.py:186`, `57` | absorb; retire `GraphEdge` path |
| Exposure | `findings` (no lifecycle) | `core/store.py:187` | new model needed, findings feed it |
| Snapshot | `IntelSnapshot` (transient) | `core/intel/engine.py:86` | new persisted model needed |
| Change Event | `ScanDiff` (ephemeral, JSON only) | `core/diff.py:33` | absorb logic into new persisted model |

No later phase may introduce a different name for any row in this
table. If a phase's own prompt uses different terminology than this
glossary, the glossary wins (per this phase's own instructions) and the
discrepancy must be written down in that phase's PR, not silently
reconciled.

---

## 5. Where the roadmap/prompt's own assumptions were checked against real code

- The roadmap overview's premise — "`core/store.py` scopes every
  `UNIQUE` constraint to `run_id`, so no asset identity survives across
  runs" — is **fully confirmed**, including for the newer `intel_*`
  tables that weren't explicitly named in that premise.
- Phase 01's prompt names exactly three modules to reconcile
  (`core/assets.py`, `core/intel/`, `core/intelligence/`). Real code
  shows a **fourth**, unnamed but directly relevant place
  (`api/control_db.py`'s `monitored_domains`/`accounts`) that already
  holds the only genuine cross-run identity in the codebase. Phases
  02/03/09 need this in scope even though phase 01's own prompt didn't
  name it — flagged here rather than silently expanding phase 01's own
  work beyond "read `core/assets.py`, `core/intel/`, `core/intelligence/`,
  `core/store.py`."
- **Not yet checked**: the individual prompts for phases 02-12 have not
  been written/received yet as of this phase — only the roadmap
  overview table and shared rules file were available. This document
  can only confirm it does not contradict *those*, not each phase's own
  future prompt text. Whoever writes each phase's prompt must re-check
  it against this glossary before opening that phase's branch, per the
  roadmap's own rule; this phase cannot certify prompts that don't
  exist yet.

## 6. What was intentionally NOT done in this phase

No production code was touched. No tables, migrations, or modules were
created. `docs/easm/` was created only to hold this one document.
