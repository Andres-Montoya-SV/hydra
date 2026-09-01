# Correlation Engine — Reconciliation Audit & Design (Part 1)

Status: **audit + design only, no implementation.** Written against
`fix/redirect-scope-safety` after the network-confinement work
(`docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md`) closed as READY.

## 0. Why this document exists

An earlier architecture review (git-attributed to Cursor, commit `ae1a78b`)
flagged a real, specific bug: *"Hydra couldn't discover `virusinspector.top`
from `virusbarrier.xyz` automatically — that's not a missing plugin, it's
the architecture."* It proposed four stages: SAN-as-indicator,
certificate-as-evidence, historical field diff, plugin contract. That work
was deliberately postponed while network confinement took priority.

The codebase has since grown `core/intel/` — entities, evidence,
hypotheses, collection attempts, a sealed `CollectionGateway` — none of
which existed when that review was written. Before writing any new
correlation code, this document re-verifies the original bug and the
four-stage plan against what is actually in the repository today, with
every claim backed by a file/line reference or a test run, not by memory of
the earlier review.

**Headline finding: all four stages are already substantially built and
covered by passing tests.** This is not the outcome the brief assumed
going in. Section 4 documents the empirical check (a new fixture that spans
the full engine→SQLite→CLI seam) and why it passes rather than fails, and
Section 3 proposes the one concrete gap this audit did find.

## 1. Current state, with evidence

### 1.1 Two graphs, and how they relate

- `core/intelligence/` — the **Host graph**. `clustering.py` (`compute_clusters`),
  `graph.py` (`build_infrastructure_graph`), `risk.py` (`score_host`),
  `profile.py`, `engine.py` (`IntelligenceEngine.process`). Operates on
  `dict[str, Host]`. Still actively used — `core/registry.py:24` constructs
  it (`self._engine = IntelligenceEngine()`) and every `HostRegistry.finalize()`
  call runs it.
- `core/intel/` — the **Intel graph**. `model.py` (entities, observations,
  evidence, relationships, indicators, hypotheses, collection attempts),
  `engine.py` (`IntelEngine`), `correlate.py` (confidence scoring),
  `scope.py`, `plugin.py`, `cli.py`, `query.py`, `serialize.py`, `explain.py`,
  `diff.py` (top-level `core/diff.py`). First-class typed entities, not a
  `dict[str, Host]`.

These are not competing or drifted systems — they're composed.
`core/registry.py:46-60` (`HostRegistry.finalize`):

```python
result = self._engine.process(hosts)          # Host graph: clusters, risk, profile
self.clusters = result.clusters
self.graph = result.graph
if self.intel_config is not None:
    engine = build_intel(self.intel_config, hosts, self.output_dir)
    self.intel = engine.snapshot()             # Intel graph: entities/relationships
    self.graph = engine.to_infrastructure_graph(host_graph=result.graph)  # merged
```

The Intel graph's `to_infrastructure_graph` call **supersedes** the
published `self.graph` with the richer, entity-based view whenever
`intel_config` is set — which it always is, unconditionally, from
`core/runner.py:1015` (`_finalize_to_store`), before `finalize()` runs. This
is not gated behind follow-up collection or discovery depth: confirmed by
reading `core/intel/engine.py:1553-1566` (`build_intel`) and
`core/runner.py:1009-1054`. (A second, separate `IntelEngine` instance is
built earlier inside `_maybe_collect_followups` at `core/runner.py:768` —
that one is gated behind `enable_followup_collection`/`max_discovery_depth`,
but it exists only to *plan* the bounded follow-up pass; it is not the
engine whose snapshot gets persisted. The persisted graph always comes from
`build_intel` inside `finalize()`.)

Clustering confidence (`core/intelligence/clustering.py`) is not
hand-rolled — it calls `cluster_signal_confidence()` from
`core/intel/correlate.py`, the same confidence-band function the Intel
graph uses. Both graphs score off one shared table.

### 1.2 The original bug: SANs outside the root domain

`modules/ctlogs.py` writes two different outputs from one CT query:

- `ctlogs.jsonl` (`all_certs`) — **every** SAN, unfiltered. Feeds `IntelEngine`.
- `ctlogs_domains.txt` / `subdomains.txt` (`discovered`) — filtered to
  `_names_under_root` (root-domain or subdomain of root only). Feeds active
  collection.

The module's own comment states the design directly: *"Active collection
input stays seed-rooted. Off-root SANs are preserved on the jsonl artifact
and ingested as observations by the intelligence engine — they are not DNS/
HTTP probed."*

`core/intel/engine.py::ingest_ct_records` (lines 298-372) processes every
SAN in the jsonl artifact through `_observe_san`, with no root-domain
filter at that layer. `tests/test_intel_virusbarrier.py::test_old_ct_filter_would_drop_siblings`
verifies both halves directly: the **old** filter (`_extract_names`, kept
as a documented backward-compat alias) drops all 5 siblings; the current
`extract_all_names` keeps all 6. **Verdict: fixed**, and the fix is
regression-tested against the exact bug description.

### 1.3 Certificate identity

`core/intel/model.py::certificate_entity_id(fingerprint_sha256, *, fallback)`
keys on SHA-256 fingerprint first, falls back to a stable hash of
`serial+issuer`, never on "first N SANs." `core/store.py:274`:
`UNIQUE(run_id, entity_id)` — not `UNIQUE(run_id, host)`. **Verdict: fixed.**

### 1.4 Cluster/relationship confidence

`core/intel/correlate.py`:

- `BAND_SCORE` maps a `ConfidenceBand` enum (VERY_HIGH/HIGH/MEDIUM/LOW/VERY_LOW)
  to integers — the integer is a rendering detail behind a named band, not a
  standalone magic number.
- `ipv4_confidence()` / `ipv6_confidence()`: **always MEDIUM**, cloud tenancy
  or dedicated, never HIGH, exactly the "shared IP shouldn't be as strong as
  shared certificate" requirement.
- `shares_certificate_confidence()`: HIGH for small/leaf certs, decaying to
  MEDIUM/LOW as SAN cardinality / eTLD+1 diversity rises (a shared CDN
  wildcard cert won't score as HIGH as a two-name Let's Encrypt cert).

**Verdict: fixed**, and structurally prevents the "shared CDN cert = same
actor" false positive the original review was worried about.

### 1.5 "Never same actor"

Not just an absent string — actively enforced in two places:

- `core/intel/plugin.py`: `FORBIDDEN_ENTITY_PREFIXES` rejects any
  plugin-emitted entity/relationship referencing `actor:`, `owner:`,
  `threat_group:`, `campaign:`, `attribution:`, `person:` before it can
  enter the model at all.
- `core/intel/explain.py`: `_FORBIDDEN` phrase list (`"same owner"`,
  `"same actor"`, `"same threat group"`, `"threat actor"`, `"owned by"`,
  `"attributed to"`) — `explain_relationship()` strips any output line
  matching these before returning text to a human. Defense in depth, not
  just an assertion in a test.

### 1.6 Historical diff (Etapa 3)

`core/diff.py::_host_field_changes` (lines 127-187) diffs, per domain:
`ip` (v4 and v6 separately), `certificate_fingerprint`,
`certificate_san_set` (added/removed, not just presence), `certificate_validity`,
`ports`, `http_status`, `http_title`, `technologies`, `favicon_hash`,
`body_hash`, `asn`, `nameserver`. Plus `_intel_relationship_diff` (confidence
and evidence changes on a relationship over time) and
`_certificate_rotations`. This is field-level diffing across the exact list
the brief asked for (IP, fingerprint, SAN set, ports, technology) and more
— not hostname-appeared/disappeared. `tests/test_intel_diff.py` (5 tests,
all passing) exercises certificate rotation, confidence change, and
evidence change specifically.

### 1.7 Plugin contract, query CLI (Etapa 4)

`core/intel/plugin.py::StructuredEmission` + `validate_emitted_relationship`
is the typed contract: a plugin returns `PluginResult.data["intel"]` with
typed entities/relationships/observations; anything with an attribution
prefix or an unrecognized `RelationshipType`/`ConfidenceBand` is rejected at
validation, not filtered downstream.

`app.py` wires `investigate`, `graph`, `relationships`, `evidence`,
`certificates`, `indicators`, `explain-collection`, `diff` as subcommands
(`app.py:110-150`), each dispatching into `core/intel/cli.py`, which reads
straight from SQLite via `core/intel/query.py::IntelQuery` — no re-scan.
`tests/test_cli_acceptance.py::test_app_py_run_then_investigate_relationships_evidence_diff`
drives this through `app.main()` for a real `run` (with stubbed subprocess
tools) followed by `investigate`/`relationships`/`evidence`/`diff`, and
asserts non-empty, cross-consistent output.

**Verdict: fixed.**

## 2. Reconciling Cursor's four stages

| Stage | Original ask | Status | Evidence |
|---|---|---|---|
| 1. SAN as indicator | Queue off-root SANs as pure observations, scope-fail-closed, never actively probed | **Done** | §1.2, §1.3; `tests/test_intel_virusbarrier.py::test_virusbarrier_seed_collected_siblings_not_probed` |
| 2. Certificate as evidence | Stable cert identity, explicit relationship rows with confidence, never "same actor", shared-IP weaker than shared-cert | **Done** | §1.3, §1.4, §1.5 |
| 3. Historical diff | Field-level diff: IP, fingerprint, SAN set, ports, technology | **Done** | §1.6 |
| 4. Plugin contract + CLI | Plugins emit typed entities/relationships; `investigate`/`graph` CLI over SQLite, no re-scan | **Done** | §1.7 |

None of the four stages is "still pending as originally stated." The plan
this document was asked to produce a design *for* has, in effect, already
been executed — apparently across the same session's earlier compacted
work and/or Cursor's own later commits. That is a surprising result and is
reported as found, not softened.

## 3. What is genuinely still open

**Status update (`feat/passive-dns-correlation` branch): closed.** The
gap below was identified in Part 1 of this document and is now fixed by
`modules/passive_dns.py`. The original Part 1 text is kept as-is beneath
the update for the audit trail, followed by what changed.

One real, verified gap survived the Part 1 audit — found by tracing where
`shares_ipv4` evidence can come from in a *live* run, not just in a test
fixture.

**`shares_ipv4` for an out-of-scope certificate sibling requires a
passive-DNS-style resolution that no collector currently produces.**

`core/intel/engine.py` supports ingesting exactly this
(`ingest_passive_dns_records`, reading a `passive_dns.jsonl` artifact if
present — `core/intel/engine.py:296`). But no plugin in `modules/` writes
`passive_dns.jsonl` today. An out-of-scope sibling is, by design, never
actively DNS-resolved (that would be unauthorized collection), so its IP is
otherwise unknown to the engine.

`tests/test_virusbarrier_e2e.py::test_virusbarrier_pipeline_e2e_seed_only`
already proves this precisely, end-to-end, through the real
`HostRegistry.finalize()` path with no shortcuts: it asserts
`shared_ip == []` for a real seed-only scan of the virusbarrier fixture.
The companion test in the same file,
`test_virusbarrier_shared_ipv4_requires_resolution_evidence`, shows the
edge *does* appear the moment a `passive_dns.jsonl` artifact is present —
confirming the engine-side logic is correct and the gap is purely "no
collector produces that artifact yet," not a modeling defect.

### Closed: `modules/passive_dns.py` (opt-in, `ENABLE_PASSIVE_DNS`)

A new plugin (`stage_order = 46`, after `ctlogs`) queries a fixed
third-party passive-DNS database for hostnames already observed this run
as out-of-scope certificate siblings — never the sibling itself. Two
providers, same additive-optional-key shape as `WPSCAN_API_TOKEN`:

- **Mnemonic PassiveDNS** (`api.mnemonic.no`) — default, no API key.
  Verified against the current published API spec
  (`https://www.docs.mnemonic.no/api/services/pdns/01-public_api.html`):
  `GET https://api.mnemonic.no/pdns/v3/<hostname>?rrType=a`, public data is
  TLP-white only, rate-limited by the provider to **10 requests/minute and
  1000/day**.
- **SecurityTrails** (`api.securitytrails.com`) — optional, additive, only
  queried when `SECURITYTRAILS_API_KEY` is set; a SecurityTrails failure
  never erases a successful Mnemonic result. SecurityTrails' current
  free-tier terms are not clearly published (the vendor is now part of
  Recorded Future) — treat this provider as "works if you have a key,"
  not as a second guaranteed-free source.

Candidate selection (`_sibling_candidates` in `modules/passive_dns.py`)
re-derives the same out-of-scope SAN set `core/intel/engine.py` computes
from `ctlogs.jsonl`, filtered through `allows_active_collection` — capped
at `passive_dns_max_candidates` (default 25). This is a second,
independent computation of the same "which SANs are out-of-scope"
question the engine answers, not a shared call — acceptable because
`ctlogs.jsonl` is data the plugin already has on disk, and it means
`modules/passive_dns.py` never needs to depend on `core/intel/`'s internal
entity state at plugin-run time (which does not exist yet — `IntelEngine`
only runs later, inside `HostRegistry.finalize()`).

Classified `THIRD_PARTY_OBSERVATION` / **F\*** in
`docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md` (Table row + inventory row #30),
same class as `ctlogs`/`threat_intel`: Hydra's own socket only ever
connects to the fixed provider endpoint; the sibling hostname is query
content, never a connection destination.

No engine change was needed — `core/intel/engine.py::ingest_artifacts`
already read `passive_dns.jsonl` if present (line 294-296, from Part 1's
own audit); the gap was purely "nothing produces that file," not a missing
ingestion path. `core/intel/correlate.py`'s confidence logic
(`ipv4_confidence` → always MEDIUM, never HIGH) is untouched and unmodified
— the plugin only supplies data, per the brief's explicit instruction not
to touch that logic.

**Proof it closed the gap, not just that the plugin exists:**
`tests/test_virusbarrier_e2e.py::test_virusbarrier_pipeline_e2e_passive_dns_closes_the_gap`
drives the same real `HostRegistry.finalize()` path as
`test_virusbarrier_pipeline_e2e_seed_only` (no `ingest_passive_resolutions()`
shortcut), with a `passive_dns.jsonl` fixture shaped exactly like this
plugin's own output, and asserts `shared_ip` is non-empty at MEDIUM
confidence. `test_virusbarrier_pipeline_e2e_seed_only` itself was re-run
unmodified and **still asserts `shared_ip == []`** — the plugin is opt-in
(`enable_passive_dns` defaults `False`), so a run without it enabled keeps
exactly the previously-documented behavior. See §4 for full results.

Secondary, lower-priority note (unchanged from Part 1, still open):
`intel_hypotheses` (OPEN / AUTHORIZED_FOR_COLLECTION / REJECTED / RESOLVED)
already exists as the right home for "candidate relationship, not yet
evidence-confirmed" — e.g. a same-registrant guess from WHOIS data before a
shared-certificate or shared-IP edge confirms it. Nothing in this audit
found a caller that populates hypotheses from anything other than
certificate/IP correlation today; extending hypothesis generation to
WHOIS/passive-DNS signals is a reasonable next increment, once passive-DNS
data supplies more corroborating signal to reason over. Not implemented in
this branch — out of scope per the brief ("esto es exclusivamente el
plugin de passive DNS").

## 4. Contract fixture: written, run, and honestly reported

Per the brief, `tests/test_infra_correlation.py` was written against the
real virusbarrier fixture (`tests/fixtures/virusbarrier/`: `httpx.json` with
A `34.75.127.116` and the 6-name `subject_an`; `ctlogs.jsonl` with the same
SAN set; scope confined to `virusbarrier.xyz`), asserting every item in the
brief's checklist:

- all 6 names exist as observations,
- the in-scope seed is collected,
- the 5 out-of-scope siblings are recorded, not probed,
- a `shares_certificate` relationship exists at HIGH confidence with
  fingerprint evidence,
- a `shares_ipv4` relationship exists at MEDIUM (never HIGH) confidence,
- output never contains "actor", "owner", or "same threat",
- the graph is non-empty when queried through the CLI functions
  (`cmd_investigate`/`cmd_relationships`) with the seed as the only target,
  via a real `AssetStore`-persisted snapshot — the same seam
  `app.py investigate`/`relationships` use.

**It passes, 7/7, on first run, unmodified:**

```
tests/test_infra_correlation.py::test_all_six_names_survive_as_observations PASSED
tests/test_infra_correlation.py::test_in_scope_seed_is_collected PASSED
tests/test_infra_correlation.py::test_out_of_scope_siblings_are_recorded_not_probed PASSED
tests/test_infra_correlation.py::test_shared_certificate_relationship_is_high_confidence_with_evidence PASSED
tests/test_infra_correlation.py::test_shared_ipv4_relationship_is_medium_not_high PASSED
tests/test_infra_correlation.py::test_output_never_contains_attribution_language PASSED
tests/test_infra_correlation.py::test_cluster_is_not_empty_for_a_single_hostname_cli_target PASSED
```

**This is reported as-is rather than forced red**, per this engagement's
standing rule against weakening assertions or fabricating failure to
satisfy a checklist. The brief's premise — a still-open architectural gap
matching Cursor's original description — does not hold against current
`HEAD`: `tests/test_intel_virusbarrier.py` (8 tests) already covers nearly
the identical contract at the engine level, and
`tests/test_cli_acceptance.py`/`tests/test_intel_cli.py` already cover the
CLI seam. The new file's only addition is exercising both halves — engine
snapshot through to CLI query — together in one fixture-backed test, which
is still worth keeping as a seam regression, not because it currently
fails.

The one place this audit found a genuine, verifiable gap — `shares_ipv4`
depending on passive-DNS evidence no collector produces yet — is **not**
what `test_infra_correlation.py` exercises faithfully to a live run: like
`test_intel_virusbarrier.py`, its `shares_ipv4` assertion calls
`engine.ingest_passive_resolutions()` directly, an engine-level shortcut,
not something any real collector feeds today. The test that proves the gap
honestly already exists and already passes for the right reason:
`tests/test_virusbarrier_e2e.py::test_virusbarrier_pipeline_e2e_seed_only`
asserts `shared_ip == []` for the real, no-shortcut finalize path — i.e. it
correctly documents today's real limitation instead of hiding it. Section 3
proposes closing that gap with a passive-DNS collector plugin.

## 5. Commit scope

This document plus `tests/test_infra_correlation.py` (a passing regression
test, kept for the reasons in §4) are the only changes in this part. No
stage of the four-stage plan is implemented or modified here — there is
nothing left un-implemented to implement, except the passive-DNS plugin in
§3, which is explicitly deferred pending review of this document.
