# Architecture Review — Reconnaissance Framework

**Review date:** 2026-06-29  
**Scope:** 35 Python source files (`app.py`, `config/`, `core/`, `modules/`, `ui/`, `utils/`, `tests/`)  
**Reviewers (roles):** Security Engineer, DevSecOps, Bug Bounty Hunter, Infrastructure Engineer, Python Architect

---

> ## ⚠️ Status update (2026-08-04)
>
> This document is preserved as the **historical record of the review that
> motivated the Phase 2/3 refactor** (now branded **Hydra**). Most of the
> Critical/High findings below and most rows marked "❌ Missing" in the Gap
> Analysis have since been addressed. It is **no longer an accurate picture
> of the current codebase** — treat `docs/PHASE2_STATUS.md`, `README.md`,
> and `SECURITY.md` as the current source of truth. Notably now resolved:
>
> - **C1–C4, C6, C7, C9** (tool skip logic, exit-code/empty-output failure
>   semantics, 50MB stdout cap, DNS-failure fallback, non-zero exit codes) —
>   see "Critical Fixes Applied" in `docs/PHASE2_STATUS.md`.
> - **No unified asset model / no SQLite** — `core/assets.py` (canonical
>   `Host`), `core/store.py` (`output/recon.db`).
> - **No confidence layer** — `core/confidence.py`, `Confidence` enum on `Host`.
> - **No infrastructure graph** — `core/intelligence/graph.py`.
> - **ASN intelligence** — `modules/asn_lookup.py` (Team Cymru).
> - **Priority scoring** — `core/intelligence/risk.py`, `HostProfile.priority`.
> - **Persistent storage + historical diff** — `core/store.py`, `core/diff.py`
>   (automatic, per-target, against the most recent prior run).
> - **TCP re-validation of naabu ports** — `modules/port_verify.py` (`nmap -sV`).
> - **DNS intelligence breadth** — `dnsx` now collects A/AAAA/CNAME/MX/TXT/NS/
>   SOA/CAA/SRV/PTR, not just A/AAAA/CNAME.
> - **H4/H5/H6** (gau/waybackurls/nuclei never merged downstream, anew not
>   merged back) — all now ingested into the canonical `Host` registry via
>   `core/parsers/registry.py`, and `anew.py` merges back into `subdomains.txt`.
> - **H16** (`PluginResult(success=False)` not surfaced) — `runner.py` now
>   calls `context.add_error()` on plugin failure.
>
> Items **not yet addressed**: resume/checkpoint (M6), config profiles,
> per-tool configurable timeouts beyond the handful that already have one,
> scope-file filtering, a declarative plugin DAG (plugins are still wired
> into `runner.py` explicitly per the "Extensibility" gap noted below).

---

## Executive Summary

The framework is a **well-intentioned CLI orchestrator** that wraps external recon tools via async subprocess calls. It has solid security primitives (no `shell=True`, path confinement helpers, log redaction, atomic writes) and a plugin registry pattern.

It is **not yet a production bug bounty platform**. It is a linear pipeline that writes siloed text files per run, trusts tool output blindly, has several correctness bugs, and lacks the intelligence layer required for high-confidence recon at scale.

**Verdict:** Suitable as a foundation. Requires architectural restructuring before it can serve as a primary engagement framework.

### Top 5 Risks

| # | Risk | Impact |
|---|------|--------|
| 1 | Tool failures reported as success (`allow_empty=True`, weak exit-code handling) | False confidence in results |
| 2 | DNS failure fallback feeds unresolved hosts to httpx | Inflated "alive" counts, wasted scan time |
| 3 | Optional tool outputs (naabu, gau, nuclei) never integrated into pipeline | Expensive scans produce dead data |
| 4 | No validation or confidence scoring | Thousands of naabu ports / empty katana files treated as facts |
| 5 | No persistent asset model or historical diffing | Every run is isolated; no engagement memory |

---

## Current Architecture

```
CLI (app.py)
  → Settings (.env)
  → ToolManager (plugin discovery + availability)
  → PipelineRunner (hardcoded stage groups)
      → modules/* (subprocess wrappers)
      → flat files (output/<run_id>/)
  → ReportGenerator (JSON/HTML/MD)
  → Dashboard (Rich TUI)
```

### What Works

- Plugin auto-registration via `__init_subclass__`
- Async subprocess without shell injection
- `SecretRedactingFilter` on logs
- `atomic_write_text()` for most outputs
- Domain input validation with metacharacter blocklist
- Per-run output directories
- Basic test suite (68 tests)

### What Doesn't Scale

- **No unified asset model** — each tool writes its own file format
- **Hardcoded stage groupings** in `runner.py` — adding a plugin requires core edits
- **No DAG** — strictly linear with one concurrent optional batch
- **No SQLite** — cannot query, cluster, or diff across runs
- **No scope engine** — cannot enforce in/out-of-scope per program
- **No confidence layer** — all findings treated equally
- **No infrastructure graph** — hosts are a flat list

---

## Problem Register

### Critical (fix before next engagement)

| ID | File(s) | Problem |
|----|---------|---------|
| C1 | `core/tool_manager.py`, `core/runner.py` | **SKIPPED tools still execute.** `validate_tools()` marks missing optionals as `SKIPPED`, but `_run_single_plugin()` only skips `MISSING`. Enabled-but-absent tools (nuclei, hakrawler, waybackurls) are invoked and fail at runtime. |
| C2 | `utils/subprocess.py` | **`check_tool_available()` accepts any exit code.** Returns true if `returncode is not None`, so a broken binary passing `-h` with exit 1 is marked ready. |
| C3 | `modules/_base.py` | **`allow_empty=True` on all plugins masks failures.** Non-zero exit + zero stdout → `success=True`. User's `katana.txt` (1 line), `waybackurls.txt` (1 line), `nuclei.json` (1 line) are likely empty-failure artifacts presented as completed work. |
| C4 | `modules/_base.py` | **Partial output + non-zero exit = success.** No error surfaced when tool exits badly but prints something. |
| C5 | `core/runner.py` | **No reports on interrupt/error.** `reporter.generate()` skipped on exception/interrupt; partial runs leave no summary. |
| C6 | `utils/subprocess.py` | **Unbounded stdout buffering.** Full stdout loaded into memory before atomic write. 11k+ naabu lines + large httpx JSON = memory pressure / OOM risk. |
| C7 | `core/runner.py` | **DNS failure masked.** Empty `resolved.txt` → copy all subdomains → httpx probes unresolved hosts. User run: 382 subdomains → 167 resolved, but fallback logic may still misrepresent resolution quality. |
| C8 | `config/settings.py` | **Output paths not confined to project root.** `OUTPUT_DIRECTORY`, `RESOLVERS_FILE`, `WORDLIST` accept arbitrary paths. |
| C9 | `app.py` | **Exit code 0 with errors.** Returns success if any `alive_urls` exist, even when `context.errors` is non-empty. |

### High

| ID | File(s) | Problem |
|----|---------|---------|
| H1 | `core/runner.py` | Hardcoded `SUBDOMAIN_PLUGINS`, `URL_DISCOVERY_PLUGINS`, `POST_HTTP_PLUGINS` — violates extensibility goal. |
| H2 | `core/runner.py` | Optional concurrent stage passes wrong `input_path` to plugins that ignore it (gau, waybackurls) vs those that need `alive.txt` (katana, nuclei). |
| H3 | `modules/naabu.py` | **11,718 port lines with no validation.** Naabu output never fed to verification or httpx. Classic false-positive source on CDN/anycast targets. |
| H4 | `modules/gau.py`, `waybackurls.py` | URL archive results isolated — never merged, deduplicated, or passed downstream. |
| H5 | `modules/nuclei.py`, `reporter.py` | Nuclei JSON never parsed into reports or asset model. |
| H6 | `modules/anew.py` | Output `subdomains_anew.txt` never merged back into `subdomains.txt`. |
| H7 | `core/runner.py` | `context.current_tool` race during concurrent optional plugins. |
| H8 | `core/runner.py` | `asyncio.Lock` incomplete — `metadata`, `warnings`, `tool_states` updated without lock. |
| H9 | `utils/subprocess.py` | Tool detection assumes `-h` works; gau version check fails (`unknown shorthand flag: 'v'`). |
| H10 | `config/settings.py` | Single global `TIMEOUT=300` for all tools — subfinder, dnsx (382 hosts), httpx, nuclei, gau all share it. |
| H11 | `modules/hakrawler.py` | `-insecure` always on — TLS verification disabled. |
| H12 | `modules/nuclei.py` | No template/severity filters when enabled — policy and noise risk. |
| H13 | `modules/httpx.py` | CSV write bypasses atomic write / path confinement. |
| H14 | `modules/dnsx.py` | `resolvers_file` not confined to project root. |
| H15 | `core/reporter.py` | Global `reports/statistics.json` overwritten each run — no history. |
| H16 | `core/runner.py` | `PluginResult(success=False)` does not add to `context.errors`. |
| H17 | `modules/dnsx.py` | Duplicate input: `-l file` AND `input_data=read_text()` — doubles memory. |
| H18 | `modules/dnsx.py` | Fragile parsing `line.split()[0]` — garbage can reach httpx. |

### Medium

| ID | File(s) | Problem |
|----|---------|---------|
| M1 | `modules/anew.py`, `unfurl.py` | Bypass `_execute()` — inconsistent status tracking and confinement. |
| M2 | `ui/progress.py` | `create_progress()` dead code — dashboard uses hand-rolled bar. |
| M3 | `config/settings.py` | `enable_jq`, `default_output_format`, `wordlist` — configured but unused. |
| M4 | `utils/validators.py` | Domain regex rejects `*.scope.com`, punycode, some valid BB patterns. |
| M5 | `core/models.py` | `datetime.utcnow()` deprecated; naive timestamps. |
| M6 | `core/runner.py` | No checkpoint/resume. |
| M7 | `tests/` | No integration tests; no tests for dnsx, httpx, naabu, concurrent stage, SKIPPED bug. |
| M8 | `app.py` | `sys.path` hack — not installable as package. |

### Low

| ID | File(s) | Problem |
|----|---------|---------|
| L1 | `ui/dashboard.py` | Unused imports; `build_summary()` called twice. |
| L2 | `modules/gau.py`, `waybackurls.py`, `hakrawler.py` | `input_path` parameter ignored — interface contract violation. |
| L3 | `core/plugin_base.py` | Mutable class-level plugin registry — test isolation issues. |

---

## Observed Run Analysis (`20260629_175526`)

| Artifact | Lines | Assessment |
|----------|-------|------------|
| `subdomains.txt` | 382 | Reasonable |
| `resolved.txt` | 167 | 215 hosts failed DNS — **43% unresolved**; confidence should be MEDIUM/LOW for unresolved |
| `naabu.txt` | 11,718 | **Suspicious** — likely CDN/anycast false positives; needs TCP re-validation |
| `alive.txt` | (check) | Only resolved hosts should be probed |
| `katana.txt` | 1 | **Empty failure** — tool ran but produced nothing useful |
| `waybackurls.txt` | 1 | **Empty failure** — tool missing or timed out |
| `nuclei.json` | 1 | **Empty failure** — likely timeout or no templates |

**Conclusion:** The framework presented this run as largely successful while multiple optional tools produced garbage. No validation layer flagged naabu's 11k ports or empty crawler/scanner output.

---

## Gap Analysis vs Production Platform Requirements

### Reliability & Validation

| Requirement | Status |
|-------------|--------|
| Detect suspicious naabu output | ❌ Missing |
| DNS wildcard detection | ❌ Missing |
| CDN/WAF interference detection | ❌ Missing |
| Rate-limit / timeout spike detection | ❌ Missing |
| TCP re-validation of ports | ✅ Done — `modules/port_verify.py` (`nmap -sV` on naabu findings) |
| Cross-tool verification | ⚠️ Partial — port_verify cross-checks naabu; asn_lookup cross-checks dnsx-resolved IPs |

### Confidence System

| Requirement | Status |
|-------------|--------|
| HIGH / MEDIUM / LOW / UNKNOWN scoring | ✅ Done — `core/confidence.py`, `Confidence` enum on `Host` |
| Multi-tool verification chains | ⚠️ Partial — provenance tracks per-field source/confidence; no explicit chain-of-custody UI |
| Never present LOW as fact | ⚠️ Partial — not fully enforced in every report surface |

### Intelligence Layers

| Layer | Status |
|-------|--------|
| Infrastructure graph | ✅ Done — `core/intelligence/graph.py` |
| ASN intelligence | ✅ Done — `modules/asn_lookup.py` (Team Cymru) |
| TLS intelligence (SANs, issuer, expiry) | ⚠️ Partial — `TlsCertificate` on `Host`; ctlogs.py adds CT-derived cert data |
| DNS intelligence (MX, TXT, SPF, wildcard) | ⚠️ Improved — dnsx now collects A/AAAA/CNAME/MX/TXT/NS/SOA/CAA/SRV/PTR |
| HTTP intelligence (headers, cookies, CSP, hashes) | ⚠️ Partial — normalized into `HttpService`; sensitive headers redacted before persistence |
| Technology fingerprinting with merged confidence | ⚠️ Partial (httpx tech-detect only) |
| Response clustering | ❌ Missing |
| Certificate clustering | ✅ Done — `core/intelligence/clustering.py` |
| IP / favicon clustering | ⚠️ Partial (ASN/technology clustering done; no favicon hashing) |
| WAF detection | ⚠️ Partial — `Host.is_waf`/`waf_provider` fields exist; detection heuristics limited |

### Prioritization

| Requirement | Status |
|-------------|--------|
| Priority scoring (login, api, admin, etc.) | ✅ Done — `core/intelligence/risk.py`, `HostProfile.priority` |
| Dashboard sort by priority | ⚠️ Partial — HTML report supports risk filtering/sorting; TUI dashboard does not yet |

### Historical Recon

| Requirement | Status |
|-------------|--------|
| Persistent storage per engagement | ✅ Done — `core/store.py` (`output/recon.db`) |
| Diff: new/removed hosts, tech, certs, ports | ⚠️ Mostly done — `core/diff.py` covers new/removed hosts/ports/technologies automatically per run; no dedicated cert-diff |
| Change reports | ⚠️ Partial — diff results surface as report warnings, not a standalone change report |

### Output & Dashboard

| Requirement | Status |
|-------------|--------|
| SQLite database | ✅ Done — `core/store.py` |
| Infrastructure graph in TUI | ❌ Missing (graph is built and used for report intelligence, not yet rendered live in the TUI) |
| ASN/CDN/certificate distribution | ⚠️ Partial — present in HTML report technology/risk summaries |
| High-priority targets panel | ⚠️ Partial — "top assets to investigate" in report output, not a live TUI panel |
| False-positive warnings | ✅ Done — port_verify flags naabu false positives; dnsx/whois/subfinder-family failures now surfaced instead of masked |
| Execution timeline | ❌ Missing |
| Screenshots (gowitness/eyewitness) | ❌ Missing |

### Extensibility (stated goal vs reality)

| Goal | Reality |
|------|---------|
| "1 new module, no core changes" | **False** — must edit `runner.py` frozensets, `modules/__init__.py`, `settings.py`, `.env.example` |

---

## Architectural Weaknesses (Structural)

### 1. File-Centric Data Model

Every tool writes ad-hoc text/JSON. There is no canonical `Asset`, `Host`, `Service`, `URL`, or `Finding` type. Downstream stages cannot query upstream results — they re-read files or ignore them.

**Required:** Unified domain model + SQLite (or equivalent) as source of truth.

### 2. Imperative Runner

`PipelineRunner` is a 300-line script with hardcoded stage logic. It should be a **declarative pipeline definition** where plugins declare:

- `inputs: list[AssetType]`
- `outputs: list[AssetType]`
- `stage: PipelineStage`
- `run_mode: sequential | concurrent`
- `confidence_contribution: float`

### 3. No Validation Layer

Tools are black boxes. The framework needs a `ValidationEngine` between tool output and asset storage:

```
Tool Output → Parser → Validator → Confidence Scorer → Asset Store
```

### 4. No Intelligence Engine

Clustering, ASN lookup, WAF detection, and prioritization are cross-cutting concerns that should run **after** collection, not inside individual plugins.

### 5. Plugin Interface Too Thin

`run(context, input_path) -> PluginResult` forces every plugin to manage its own I/O format. Should be:

```python
async def run(self, ctx: PipelineContext, assets: AssetCollection) -> PluginResult
```

### 6. Configuration Sprawl

Feature flags, paths, timeouts, and enable switches are flat env vars. Needs **program profiles**:

```
config/programs/hackerone-example.yaml
```

---

## Security Review Summary

| Area | Status | Notes |
|------|--------|-------|
| Command injection | ✅ Good | `create_subprocess_exec`, no shell |
| Path traversal | ⚠️ Partial | Helpers exist; not applied everywhere |
| Secret logging | ✅ Good | Redaction filter |
| HTML XSS | ✅ Good | `escape_html` in reports |
| Symlink binaries | ✅ Good | Rejected in `validate_binary_path` |
| Memory DoS | ❌ Bad | Unbounded subprocess stdout |
| TLS verification | ❌ Bad | hakrawler `-insecure` |
| Nuclei policy | ⚠️ Risk | No severity/template controls |

---

## Race Conditions & Resource Leaks

| Issue | Location | Fix |
|-------|----------|-----|
| `current_tool` overwrite | `runner._run_single_plugin` | Per-task tool name; lock all context mutations |
| `context.metadata` concurrent writes | gau + waybackurls + katana parallel | Lock or merge via asset store |
| `cancel()` unawaited terminate | `runner.cancel()` | Await termination in pipeline |
| Orphan subprocesses | timeout path | Already kills; verify on all code paths |
| WeakSet process tracking | `subprocess._running_processes` | OK but not comprehensive |

---

## Recommended Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI / TUI                            │
├─────────────────────────────────────────────────────────────┤
│  PipelineEngine (declarative DAG from plugin metadata)      │
├──────────┬──────────┬──────────┬──────────┬───────────────┤
│ Collect  │ Validate │ Score    │ Cluster  │ Prioritize    │
│ (plugins)│ (engine) │(confidence)│(intel)  │ (rules)       │
├──────────┴──────────┴──────────┴──────────┴───────────────┤
│                    AssetStore (SQLite)                      │
├─────────────────────────────────────────────────────────────┤
│  DiffEngine (historical)  │  ReportEngine  │  ExportEngine │
└─────────────────────────────────────────────────────────────┘
```

### New Core Modules (proposed)

| Module | Responsibility |
|--------|----------------|
| `core/assets.py` | Host, Service, URL, Certificate, Finding dataclasses |
| `core/store.py` | SQLite persistence, queries, run metadata |
| `core/validation.py` | Naabu re-check, DNS wildcard, CDN detection, suspicious output |
| `core/confidence.py` | HIGH/MEDIUM/LOW/UNKNOWN scoring rules |
| `core/intelligence/` | ASN, TLS, DNS, HTTP, WAF, clustering |
| `core/prioritization.py` | Keyword-based priority scoring |
| `core/diff.py` | Run-to-run comparison |
| `core/pipeline/` | Declarative DAG executor replacing monolithic runner |

---

## Phased Implementation Plan

### Phase 1 — Correctness (P0, ~1-2 days)

- [ ] Fix C1–C9 (tool skip logic, exit codes, reports on failure, path confinement)
- [ ] Remove DNS fallback or mark unresolved hosts LOW confidence
- [ ] Add stdout size limits to subprocess
- [ ] Wire `PluginResult(success=False)` to errors

### Phase 2 — Asset Model + SQLite (P0, ~2-3 days)

- [ ] Define `Asset` schema
- [ ] SQLite store with runs, hosts, services, urls, findings
- [ ] Parsers for httpx JSON, dnsx output, naabu output
- [ ] All plugins write to store, not just files

### Phase 3 — Validation + Confidence (P1, ~2-3 days)

- [ ] `ValidationEngine` with naabu TCP re-check sampling
- [ ] DNS wildcard probe
- [ ] CDN/WAF fingerprinting from httpx headers
- [ ] Confidence scoring on all assets
- [ ] Suspicious output warnings in dashboard

### Phase 4 — Intelligence (P1, ~3-5 days)

- [ ] ASN lookup (whois/RDAP or external tool)
- [ ] TLS cert parsing from httpx
- [ ] Response clustering (hash-based)
- [ ] Certificate / favicon / IP clustering
- [ ] Infrastructure graph (text-based for TUI)

### Phase 5 — Historical + Dashboard (P2, ~2-3 days)

- [ ] Diff engine (new/removed/changed)
- [ ] Enhanced TUI panels (ASN, CDN, clusters, priorities, warnings)
- [ ] Per-program config profiles

### Phase 6 — Advanced (P3)

- [ ] Gowitness integration
- [ ] Scope engine
- [ ] Checkpoint/resume
- [ ] SARIF / program-specific exports

---

## False-Positive Sources (Known)

| Source | Why | Mitigation |
|--------|-----|------------|
| Naabu on CDN IPs | Anycast responds on many ports | TCP re-validation + CDN detection |
| DNS wildcard | `*.target.com → sinkhole` | Wildcard probe before enumeration |
| httpx on unresolved hosts | DNS fallback | Don't probe unresolved; mark LOW |
| gau/waybackurls noise | Historical dead URLs | Validate with httpx before reporting |
| nuclei default templates | Informational noise | Severity/tag filters |
| Cloudflare "challenge" pages | Looks alive | WAF detection + LOW confidence |

---

## Performance Bottlenecks

| Bottleneck | Impact | Fix |
|------------|--------|-----|
| Sequential subfinder per domain | Slow multi-target | Concurrent domain enum |
| Full stdout buffering | Memory | Stream to temp file with size cap |
| Duplicate DNS queries | Waste | Cache resolver results in store |
| naabu before httpx filter | 11k ports scanned uselessly | Run naabu only on resolved + alive hosts |
| All optional tools concurrent | Resource contention | Separate pools by resource type |
| No httpx rate limit flag | Rate limiting / blocks | Pass `-rate-limit` to httpx |

---

## Architectural Debt

1. Monolithic `runner.py` — must become pipeline engine
2. File-centric I/O — must become SQLite-centric with file export
3. Hardcoded plugin groups — must become plugin-declared metadata
4. Flat `.env` — must become program profiles
5. Test gap — integration tests needed before refactoring
6. `sys.path` hack — package properly with `pyproject.toml` entry points

---

## Conclusion

The framework is a **capable prototype** with good security instincts but **incorrect failure semantics** and **no intelligence layer**. Running it against Coupang with all optional tools enabled produced thousands of unvalidated port findings and multiple empty tool outputs presented as completed work.

**Do not use current naabu output for decision-making without manual validation.**

The path to production is: **fix correctness → add asset store → add validation/confidence → add intelligence → enhance dashboard → add history.**

---

*Review complete. Implementation should begin with Phase 1 (Critical fixes) and Phase 2 (Asset model + SQLite).*
