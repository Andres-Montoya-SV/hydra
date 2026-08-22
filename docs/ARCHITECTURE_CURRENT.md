# Hydra — current architecture (as implemented)

This document describes the **runtime as of 2026-08-22**. Source, tests, the
SQLite schema, and CLI behavior are authoritative. The README is kept in
sync with this file; if they diverge, trust the tests.

The 2026-08-21 pre-intelligence audit that previously lived here is
superseded. Historical review notes remain in `docs/ARCHITECTURE_REVIEW.md`.

---

## Control flow

```
COLLECT (subprocess-isolated plugins, capability groups)
  → NORMALIZE (parsers + IntelEngine ingest)
  → OBSERVE (entities / observations, including OOS SANs)
  → CORRELATE (named-band, evidence-backed relationships)
  → EVALUATE (Host risk/profile — separate from correlation)
  → BOUNDED FOLLOW-UP (one pass, depth ≤ MAX_DISCOVERY_DEPTH, re-authorized)
  → PERSIST (SQLite: host tables + intel_* tables)
  → QUERY (investigate / graph / relationships / evidence / diff — no rescan)
  → REPORT (HTML / Markdown / JSON reading the same store)
```

`PipelineRunner` still owns the linear seed collect (whois → enumerate →
wildcard → dnsx → optional ports → httpx → optional HTTP tools). Stage
*groups* are derived from plugin `capability` / `active_collection` /
`strict_opsec_allowed` in `core/collectors.py`. Unique steps (httpx, naabu,
wildcard_check) remain named because they have unique I/O contracts.

There is **one** bounded follow-up pass. There is no recursive crawler and
no Neo4j.

---

## What is collected vs observed

| Kind | Active collection | Observation |
|---|---|---|
| CLI seeds | Yes | Yes |
| Names in `SCOPE_FILE` | Yes (still bounded) | Yes |
| Names under a seed eTLD+1 when no scope file | Yes | Yes |
| Certificate SANs on other eTLD+1s | **No** | Yes (`OUT_OF_SCOPE` / `NOT_ALLOWED`) |
| Shared IPs without a resolution artifact | Never invented | N/A |

Discovery ≠ authorization. `allows_active_collection` is the hard gate.
`authorize_plugin_input` rewrites collector input immediately before use.

---

## Plugin contract

`ReconPlugin` class attributes:

- `produces` — domains, IPs, certificates, URLs, technologies, …
- `followup_kinds` — optional declared follow-up kinds
- `capability` — used by the runner to group work
- `active_collection` — whether the plugin may touch the network
- `strict_opsec_allowed` — whether it may run under `STRICT_OPSEC`

Plugins still write artifacts. They **may** attach
`PluginResult.data["intel"]` (`StructuredEmission`). The engine ingests
emissions, including `followups`, through the same queue/scope rules.
Artifact parsers remain the production ingest path.

Subprocess isolation is unchanged: no `shell=True`, output caps, path
confinement.

---

## SQLite is the source of truth

`output/recon.db`:

- Host reporting: `runs`, `hosts`, `http_services`, `ports`, `dns_records`,
  `tls_certificates`, `urls`, `findings`, `provenance`, `clusters`
- Reporting graph view: `graph_nodes`, `graph_edges` (not a graph database)
- Intelligence: `intel_entities`, `intel_observations`, `intel_evidence`,
  `intel_relationships`, `intel_indicators`

Query CLI reads `intel_*` only. Composite foreign keys apply on newly
created databases. Existing files get additive `runs.intel_truncated` /
`intel_truncation_reason`.

---

## Bounds (defaults)

| Setting | Default |
|---|---|
| `MAX_DISCOVERY_DEPTH` | 1 (0 = seeds only) |
| `MAX_FOLLOWUP_INDICATORS` | 50 |
| `MAX_HTTP_PROBES` / `MAX_DNS_PROBES` | 200 |
| `MAX_ENTITIES` | 5000 |
| `MAX_RELATIONSHIPS` | 20000 |
| Pairwise `SHARES_*` clique | 16 members; larger sets stay hub-only |

Caps fail closed: no dummy entities, no orphan observations/relationships.

---

## Confidence vocabulary

Correlation bands (shared by SQLite, CLI, HTML, Markdown, JSON):

`VERY_HIGH` (98) · `HIGH` (88) · `MEDIUM` (65) · `LOW` (40)

Host observation confidence (`core/confidence.py`) is a **separate**
scale for “do we believe this host/service exists?”. It is not a
correlation band and is not mixed into relationship strength.

Risk (`core/intelligence/risk.py`) is a **third** concept: surface
interestingness. Correlation must not mutate `host.risk_score`.

Hydra never emits “same owner”, “same actor”, or “same threat group”.

---

## STRICT_OPSEC

When `STRICT_OPSEC=true`, plugins whose `strict_opsec_allowed` is false
are skipped. Proxy is mandatory. Raw DNS/TCP tools (dnsx, naabu, whois,
wildcard, …) are blocked. httpx and crt.sh are allowed when proxied.
This is exposure reduction, not anonymity.

---

## Query CLI (no rescan)

```
python app.py investigate DOMAIN
python app.py graph DOMAIN
python app.py relationships DOMAIN
python app.py evidence DOMAIN|RELATIONSHIP_ID
python app.py certificates DOMAIN
python app.py indicators DOMAIN
python app.py diff DOMAIN
python app.py diff RUN_A RUN_B
```

Default run is the latest **finished** run that observed/targeted the
domain. Unfinished runs are never selected.

---

## Known dualism (honest)

`core/intel/` is the intelligence engine. `core/intelligence/` is the
Host-view profiler/risk/cluster layer used by reports. Both persist to
the same SQLite file. Do not treat `graph_*` as query truth.
