# Hydra current-state architecture audit

**Date:** 2026-08-24  
**Method:** runtime code, not README / prior reports. Entry: `python app.py run -d <target>` → `PipelineRunner.run()`.  
**Rule:** observation is not authorization. Tests and comments were treated as untrusted.

This document is the Phase 1 map. Implementation follows it; it is not a marketing recap of the previous refactor.

---

## Runtime map

```
app.py:main
  load_settings → cmd_run
    ToolManager + PipelineRunner.run
      CollectionScope.from_seeds (always attached if runner runs)
      plugins (whois → enum → CT → seed dnsx → httpx → optional → follow-up)
      IntelEngine ingest/correlate (follow-up + finalize)
      AssetStore SQLite
      ReportGenerator + CLI query
```

Network sinks (actual I/O):

| Sink | Module | Hostname source | Gate today |
|---|---|---|---|
| subprocess argv | `utils/subprocess.py` (no `shell=True`) | plugin argv | plugin-specific |
| dnsx | `modules/dnsx.py` | authorized input file | `_authorized_input`; **output filter skipped if scope is None** |
| httpx `-follow-redirects` | `modules/httpx.py` | authorized input | input gated; **binary still fetches OOS Location once** |
| naabu / nmap | naabu, port_verify | authorized resolved / naabu list | `_authorized_input` |
| katana | `modules/katana.py` | `authorized_alive.txt` | input gated; **tool-internal crawl ungated** |
| hakrawler `-depth 2` | `modules/hakrawler.py` | `_alive_urls()` | input gated; **in-page crawl ungated** |
| nuclei | `modules/nuclei.py` | authorized alive | input gated; **templates may hit derived URLs** |
| Playwright | `modules/browser_probe.py` | httpx URLs | **FAIL OPEN if scope is None**; subresources not aborted |
| urllib HTTPS | ctlogs, threat_intel, vuln_match, cloud, param_fuzz, soft404 | seeds / hosts / derived | mixed |
| sockets | `modules/asn_lookup.py` | resolved IPs | Team Cymru; IPs not hostname-gated |
| whois binary | `modules/whois.py` | target roots | `authorize_active_indicator` per root |
| gau / waybackurls | archive APIs | seeds | per-seed authorize |
| cloud_bucket_enum | derived FQDNs | brand permute | policy flag + require scope |

No `os.system`, no `shell=True` execution, no `requests`/`aiohttp` in-tree.

---

## Invariant vs implementation

| Invariant | Current | Violation | Sev | Files | Correction |
|---|---|---|---|---|---|
| A Observation ≠ authorization | CT SANs observed; OOS kept out of canonical alive/resolved when scope exists | none for canonical artifacts when runner attached scope | — | engine, httpx, artifacts | keep |
| B Fail closed without CollectionScope | `require_collection_scope` on `_output_path` for `active_collection=True` | **browser_probe `allow_browser_navigation` returns True if scope is None**; `_install_scope_navigation_guard` no-ops; `_httpx_targets` probes all records; threat_intel `_alive_hosts` queries all; vuln_match `_collect_techs` uses all; dnsx output unfiltered | **P0** | `browser_probe.py`, `threat_intel.py`, `vuln_match.py`, `dnsx.py`, `runner.py` `_restrict_alive_to_scope` | require scope; DENY |
| C One authorization API | `authorize_active_indicator` + `allows_active_collection` wrapper | OPSEC is a separate runner skip list, not in the same primitive; plugins still mix `allows_*` vs `authorize_*` vs ad-hoc `if scope is not None` | P1 | `authorize.py`, plugins, `runner.py` | `authorize_collection(indicator, scope, capability, opsec)` used everywhere |
| D Redirects never expand auth | httpx withholds OOS landing from alive | tool still follows; stored `httpx.json` may contain OOS URL as observation (intentional) | P2 residual | `httpx.py` | keep observation; do not add to alive; document fetch-once |
| E alive/resolved derived | seed snapshots + follow-up sidecars + union | runner still mutates `context.alive_urls`; union uses files (good) | P2 | `runner.py`, `artifacts.py` | keep files authoritative |
| F COLLECTED only on success | queue + sidecar presence | no per-capability attempt row; DNS success + HTTP fail still one indicator status | P1 | `queue.py`, `runner.py` | `CollectionAttempt` + `PARTIAL` |
| G Collection attempts first-class | **missing** | overloaded `indicator.collection_status` | P1 | model, store | new table |
| Hypothesis type | **missing** | planner consumes indicators; correlation can enqueue without an explicit hypothesis object | P1 | model, engine, followup | `Hypothesis` → plan |
| Intel is correlation truth | intel_relationships + serialize | Host graph still built independently (CDN/ASN LOW) | P2 | `intelligence/graph.py` | keep as projection only |
| Certificate identity | fingerprint → serial+issuer → unidentified | CT can be unidentified; SHARES_CERTIFICATE skipped without identity | ok | `engine.py` | keep; tests |
| Wildcard | seed DNS policy + follow-up | — | ok | followup.py, runner `_seed_dns_input` | keep |
| Cloud endpoints | policy required | cloud plugin still HTTP-gets canary `*.s3.amazonaws.com` when policy on | ok if policy | cloud_bucket_enum.py | keep fail-closed default |
| STRICT_OPSEC vs scope | runner skips plugins | not composed in authorize() | P1 | authorize, runner | compose |
| Hypothesis/attempts in SQLite | **missing tables** | cannot reconstruct DNS SUCCESS / HTTP FAILED | P1 | store.py | migrate |
| RelationshipView | `serialize_relationship()` | missing `evidence_ids`, `rationale`, `scope_status`, `collection_status` on the view | P2 | serialize.py | extend, do not fork |
| CI format | ruff format locally | **black --check fails on 8 files** | P0 CI | listed below | run `black` |

Black-unformatted (CI):

- `core/intel/followup.py`
- `core/intel/queue.py`
- `modules/katana.py`
- `modules/nuclei.py`
- `modules/waybackurls.py`
- `core/store.py`
- `core/runner.py`
- `tests/test_asi_loop_e2e.py`

---

## Follow-up / intelligence loop (as coded)

Pass 0: seed collect (enum files → `authorized_dns_targets.txt`, not full CT merge) → httpx → snapshot seed DNS/HTTP.

Pass 1+: `IntelEngine.ingest_artifacts` → `correlate` → `plan_followup_collection` (authorize + evidence + wildcard) → sidecar collect → authorized union → persist indicators.

Stop: `MAX_DISCOVERY_DEPTH`, probe budgets, `MAX_RUNTIME`. Second `_maybe_collect_followups` exists after optional plugins.

**Gap:** there is no `Hypothesis` object. A SAN_CONTAINS relationship plus an ELIGIBLE indicator is the implicit hypothesis. That is correlation adjacent to collection, not a typed plan.

**Gap:** `COLLECTED` is hostname-level, not capability-level.

---

## SQLite

WAL + `foreign_keys=ON` on connect. Intel tables: entities, observations, evidence, relationships, indicators (+ lifecycle columns). No `intel_hypotheses`, no `intel_collection_attempts`. Truncation flags on `runs`.

---

## Reporting

CLI/HTML/MD/JSON use `serialize_relationship`. Host clusters/graph remain a reporting projection.

---

## What is already true (do not regress)

- No `shell=True` / `os.system`
- Structured subprocess argv, path confinement, output caps
- SQLite not Neo4j
- Fingerprint-first certificates; SAN equality does not merge
- Follow-up sidecars; seed snapshots survive empty/crash
- Planner rejects spoofed `CERTIFICATE_SAN` without evidence
- `UNKNOWN` authorization fails closed in `authorize_active_indicator`
- Presence of a CollectionScope object is not authorization of a hostname

---

## Implementation order after this audit

1. Fail-closed every `if scope is None: allow` path.
2. `authorize_collection` = scope + capability + OPSEC composition.
3. `Hypothesis` + `CollectionAttempt` types, SQLite, planner/runner wiring.
4. Extend `RelationshipView` fields; one serializer.
5. Black format + adversarial tests for the new fail-closed paths and attempts/hypotheses.
6. Honest claims only.
