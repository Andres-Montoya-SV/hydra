# EASM Fase 21 — Risk/Reports, Cleanup, and Final Audit

**This is the closing phase of the 21-phase EASM roadmap.** Any future
EASM work starts its own reconnaissance cycle (the way Fase 01 did for
this set) — nothing here assumes the terrain stays as documented below
forever.

## 1. Risk/criticality classification — deterministic, explainable

`core/risk_scoring.py::classify_exposure_risk()`. Combines the exposure's
own severity, whether its asset's domain is currently under confirmed
(verified) scope, how long it has been open, and whether it is related
(Fase 07's relationship graph) to another asset with its own open high/
critical exposure. Every classification cites the concrete reasons that
produced it — never a bare label. No ML, no tuned weights: a fixed
severity table plus two deterministic one-level escalation rules
(≥30 days open; related to a critical neighbor). `ControlDB.
risk_factors_for_exposure()` gathers the real signals; `GET
/organizations/{id}/exposures/{exposure_id}/risk` serves it.

## 2. Reports connected to exposures with history

**Verified before building anything** (never assumed): neither
`api/reportability_orchestrator.py` (`store.get_findings(run_id)`, one
run at a time) nor `api/hypotheses_orchestrator.py`
(`core/hypotheses/evidence.py::gather_run_evidence`, the legacy
`intel_relationships` table, also one run at a time) nor
`core/client_report/collect.py` (raw per-run `Finding` objects) ever
queried the `exposures`/`exposure_history` tables. New
`core/client_report/exposure_report.py::exposure_history_report_data()`
is the missing connection — additive, alongside the existing per-run
report pipeline, never a rewrite of `collect.py`/`render.py`'s own
already-tested rendering logic. Served via `GET
/organizations/{id}/reports/exposures`. Proven with a real test: 5 scans
confirming the same exposure produce one report entry with all 5 history
events, not a fresh-looking finding each time; a resolve-then-reappear
sequence shows `observed → resolved → reopened` in order.

## 3. Cleanup checklist

- [x] **Fase 01's "absorb" decisions, status checked against real code**
  (`docs/easm/00_consolidation_plan.md:269-344`):
  - `core/intel/model.py` (Relationship/Entity/Observation/Evidence/
    Indicator) — ABSORB, **done**. Actively imported across `core/store.py`,
    `core/runner.py`, `api/control_db.py`, `api/candidate_assets.py`,
    `api/asset_identity.py`, `api/external_observation_ingest.py`,
    `api/relationship_identity.py`, `modules/httpx.py`, and ~25 test files.
  - `core/intelligence/` (legacy clustering/graph engine) — ABSORB WITH
    MIGRATION, **not done**. `core/registry.py::HostRegistry.finalize()`
    still runs it unconditionally on every scan; its `clusters`/`graph`
    output is silently discarded whenever the newer `core.intel.engine`
    also runs. **Marked deprecated with a date** (`core/registry.py`'s own
    module docstring, 2026-09-28) rather than removed — real code still
    calls it and `core/store.py` still persists its output into
    `clusters`/`graph_nodes`/`graph_edges` every run; removing it requires
    its own reconnaissance pass to confirm nothing still reads those
    tables, out of this closing phase's own safe scope.
  - `core/assets.py::Host` — COEXIST, unchanged, correct.
  - `monitored_domains` — WRAP, unchanged, correct.
  - `core/diff.py::ScanDiff` — ABSORB into the persisted Change Event
    model (Fase 05) — **still not done**, verified directly: `core/diff.py`
    carries no deprecation notice, and is still actively imported by
    `core/runner.py`, `core/intel/cli.py`, and `core/verification/grounding.py`.
    Fase 05's `api/change_detection.py`/`api/change_backfill.py` provide
    the durable, cross-run Change Event model this was meant to absorb
    into, but `core/diff.py` itself was neither migrated nor marked
    deprecated by any prior phase. Marked here, now, with today's date —
    the same "eliminado o marcado como deprecado con fecha" checklist
    item `core/intelligence/` above already satisfies — since determining
    whether its 3 real callers can be safely repointed at the EASM model
    is its own reconnaissance task, out of this closing phase's safe
    scope to attempt blind.
- [x] **Naming consistency across phases**:
  - `docs/easm/08_dns_posture_intelligence.md` was mislabeled (really
    Fase 13) — renamed to `13_dns_posture_intelligence.md`, redirect stub
    left at the old path (matching the existing `06_technology_intelligence.md`
    → `technology_intelligence.md` precedent).
  - `docs/easm/09_cloud_asset_identity.md` was mislabeled (really Fase 16)
    — renamed to `16_cloud_asset_identity.md`, redirect stub left.
  - `docs/easm/technology_intelligence.md` (unnumbered, pre-Fase-14) and
    `docs/easm/14_technology_intelligence.md` (Fase 14's own additions) —
    kept as two documents (genuinely different content, not a duplicate),
    cross-referenced explicitly so neither reads as the sole authority.
  - A real, unrelated factual error found and fixed during this pass:
    `api/restore_integrity.py`'s own docstring (Fase 20) claimed no
    connection anywhere enables SQLite's FK enforcement. Verified
    directly (`core/store.py::configure_sqlite` sets `PRAGMA
    foreign_keys=ON` for every `connect_sqlite()` connection, including
    `ControlDB`'s own — confirmed with a real `IntegrityError` on a
    direct violating `DELETE`) and corrected in the docstring, the Fase 20
    doc, `docs/PAID_API_DESIGN.md`, and the test that exercises it.
- [x] **`git grep -n '<<<<<<<\|=======\|>>>>>>>' -- '*.py'`**: zero real
  hits (one false positive inside a test's own docstring describing what
  a conflict marker looks like).
- [x] **`python -m compileall -q -f .`**: zero errors, full repo.
- [x] **`docs/PAID_API_DESIGN.md`, README, provider matrix**: see below.

## 4. Provider capability matrix (generated from `provider_inventory()`, not hand-maintained)

| Capability | Provider | Active by default | Required | Purpose |
|---|---|---|---|---|
| cloud | cloud_bucket_enum | no | no | cloud_enum |
| dns | dnsx | yes | yes | resolve_dns |
| dns | passive_dns | no | no | passive_dns |
| dns | wildcard_check | yes | no | wildcard_dns |
| domain_discovery | amass | no | no | enumerate_domains |
| domain_discovery | assetfinder | no | no | enumerate_domains |
| domain_discovery | ctlogs | yes | no | enumerate_domains |
| domain_discovery | subfinder | yes | yes | enumerate_domains |
| exposure_detection | github_secrets | no | no | leaked_secrets_scanning |
| exposure_detection | sub_takeover | no | no | sub_takeover |
| exposure_detection | vuln_match | yes | no | vuln_match |
| external_intelligence | dnstwist | no | no | typosquat_detection |
| external_intelligence | theharvester | no | no | email_personnel_osint |
| external_intelligence | threat_intel | no | no | reputation |
| external_intelligence | whois | yes | no | registration |
| http | ffuf | no | no | content_discovery |
| http | gau | no | no | url_archive |
| http | hakrawler | no | no | post_http |
| http | httpx | yes | yes | http_probe |
| http | katana | no | no | post_http |
| http | nuclei | no | no | post_http |
| http | param_fuzz | no | no | param_fuzz |
| http | security_headers | yes | no | http_headers |
| http | soft404_check | yes | no | http_verify |
| http | unfurl | no | no | post_http |
| http | waybackurls | no | no | url_archive |
| network_discovery | asn_lookup | yes | no | asn |
| network_discovery | naabu | no | no | port_scan |
| network_discovery | port_verify | no | no | port_verify |
| technology | wafw00f | no | no | waf_detection |
| technology | whatweb | no | no | technology_intelligence |
| tls | sslyze | no | no | tls_posture |
| visual | browser_probe | no | no | browser |

(`anew`, capability `uncategorized`, is a dedup utility, not a product
capability — see `core/capabilities.py`'s own documented exception.)
Reproduce with: `core.provider_contract.provider_inventory()` joined
against `ToolManager.get_all_plugins()`'s own `is_enabled()`.

## 5. Adversarial self-audit — every phase against real merged code

Answered with direct evidence (own work: Fases 06/09/10/11/12/14/17/18/
19/20; Fases 07/08/13/15/16 verified fresh in this pass, not assumed from
the 2026-09-26 audit):

1. **¿Algún resultado de provider, importación, RDAP, SAN, DNS o cloud se
   volvió autorización?** No. Proven directly with adversarial tests at
   each phase: `TestImportedAssetIsNeverAuthorized` (Fase 10),
   `TestImportedIpIsNeverAuthorized` (Fase 11),
   `TestRdapEnrichesOnlyAlreadyKnownAssets` (Fase 12), Fase 06's own
   `TestCandidateNeverFeedsActiveScanningWithoutPromotion` (which a CT-SAN
   candidate goes through unchanged). Cloud (`modules/cloud_bucket_enum.py`)
   requires both an explicit settings opt-in AND per-URL
   `CollectionGateway.authorize()` before any request — an unauthorized
   candidate is recorded `"not_authorized"` and never requested.
2. **¿Un hostname cloud generado puede sondearse fuera de scope?** No —
   same gate as above; no bypass path found in `core/parsers/registry.py`.
3. **¿WhatWeb o la navegación del navegador pueden escapar del scope?**
   No. `modules/whatweb.py` authorizes every URL via
   `AuthorizedCollectionTarget`/`require_collection_scope` before
   requesting. `modules/browser_probe.py` routes all traffic through its
   own `ScopeEnforcingProxy` confinement plus a per-page in-browser
   navigation guard that aborts any request to an unauthorized host.
4. **¿Los screenshots pueden filtrar secretos a logs?** No — on capture
   failure only the hostname and exception text are logged; raw
   HTML/screenshot bytes go to disk artifacts, never to a log line.
5. **¿Un collector o provider fallido produce estado "limpio"?** No.
   `core/models.py`'s `ToolStatus` vocabulary distinguishes `FAILED`/
   `UNAVAILABLE`/`BLOCKED_BY_SCOPE`/`SUCCESS_NO_RESULTS` explicitly;
   `modules/whatweb.py` maps subprocess failure/malformed output to
   `FAILED` with a message, never silent "no findings." DNS posture tags
   derive only from records dnsx actually returned — a dnsx failure
   yields zero records, and the tool's own `FAILED` status is recorded
   separately, never conflated with a clean DNS posture verdict.
6. **¿Scans o importaciones repetidas duplican algo?** No — proven
   exhaustively: `TestFullBackfillIdempotency` (Fase 21, full chain, 3x),
   every individual backfill's own idempotency test (Fases 03-14),
   `TestImportingTheSameArtifactTwiceNeverDuplicates` (Fase 11).
7. **¿Una organización puede ver o importar datos de otra?** No — every
   phase's own IDOR/BOLA test suite, most recently Fase 19's `
   TestForeignAccountCannotProbeAnyEndpoint` (11 GET paths + 2 POST
   actions, checked individually) and this phase's own
   `TestExposureReportShowsHistoryAcrossRuns::
   test_report_never_leaks_across_organizations`.
8. **¿Datos viejos pueden pisar observaciones directas más nuevas?** No
   — Fase 10's `reconcile_precedence()` ranks by confidence class first,
   recency only as a same-class tiebreaker; a stale third-party import
   can never outrank a fresher `DIRECT_CURRENT` Hydra observation,
   proven directly.
9. **¿Puede perderse la procedencia durante la normalización?** No —
   Fase 14's technology name canonicalization normalizes the NAME only;
   `source`/`confidence_class`/`detail` pass through unchanged, proven
   in `tests/test_technology_backfill.py`.
10. **¿Fuentes duplicadas inflan la confianza?** Addressed, not
    universally wired: Fase 17's `core/confidence_composition.py`
    explicitly caps correlated sources (httpx/WhatWeb/security-headers
    reading the same HTTP response) at the best single confidence rather
    than compounding them, and combines genuinely independent sources via
    documented noisy-OR. Deliberately not wired into every existing
    confidence computation in this pass (`core/confidence.py`'s own
    `max()`-based aggregation is untouched) — a new, additive capability
    for future callers, not yet the aggregation path every consumer uses.
11. **¿Una actualización de provider puede cambiar la semántica en
    silencio?** Partially addressed: `core/dependencies/registry.py`'s
    `KNOWN_INCOMPATIBLE_VERSIONS` blocks specific known-bad versions, and
    `core/provider_contract.py` records each provider's declared
    metadata — but there is no general semantic-versioning contract
    verifying a NEW provider version still means the same thing. Not
    fixed in this pass; a real, open risk worth a future phase's
    attention, not silently claimed as solved.
12. **¿El fallo de una herramienta aborta una capacidad entera?** No —
    `core/runner.py::_run_single_plugin` wraps every plugin call in its
    own try/except, recording only that plugin's own `FAILED` status;
    confirmed a WhatWeb crash cannot abort httpx's own contribution to
    Technology Intelligence or any other plugin in the same category.

**Net result**: no credible security regression found across the
adversarial checklist. Two real findings were NOT security bugs but
process/documentation debt, both addressed in this phase: the
`core/intelligence/` migration gap (marked deprecated, not silently
left undocumented) and the doc-numbering collisions (renamed). One real
open risk is named explicitly rather than claimed solved: provider
version updates can silently change semantics (#11) — flagged for a
future phase, consistent with this roadmap's own discipline that no
phase claims more than it actually verified.

## 6. This is the roadmap's close

Every phase from Fase 00 through this one has been built, tested (3x
green pipeline per phase), and documented under `docs/easm/`. Any EASM
work beyond this 21-phase set is new scope — it starts its own
reconnaissance cycle, the way Fase 01 did, rather than assuming any of
the above stays true unexamined.
