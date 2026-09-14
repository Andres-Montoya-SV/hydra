# Hydra — Hardening Round 1 (P0): cache, SSRF re-verification, persistence

**Status: hardening audit + targeted fixes, no feature work.** Branch
`hardening/p0-cache-ssrf-persistence`, cut from `main` after the
documentation consolidation (`docs/ARCHITECTURE.md`/`docs/NETWORK_CONFINEMENT.md`)
and the `fix/dnsx-nodata-soa-false-resolution` merge. Builds on
`docs/FINAL_PROJECT_AUDIT.md` — does not repeat its numbers, only what
changed since.

Every fix below is scoped to a single, well-understood gap, with a real
test that fails without the fix and passes with it (confirmed by actually
reverting each fix locally and re-running its test before finalizing — not
assumed from reading the diff). Two candidate fixes were **tried and
reverted** after real tests exposed that they would have broken correct,
already-tested production behavior — those are documented as findings
with an explicit rationale for *not* forcing them through, per this
round's own instruction not to weaken an invariant just to make a test
pass.

None of the 12 stated invariants were weakened. Two are meaningfully
**strengthened** (5, 10); none of the others needed a code change because
re-verification found them already holding.

---

## Executive summary

| # | Task | Verdict |
|---|---|---|
| 1 | Cache security audit | **Real gap found and fixed** — cache key didn't include scope/attribution identity |
| 2 | Cache/authorization separation | **Already correct** — proven with new explicit tests, nothing changed |
| 3 | STRICT_OPSEC documentation accuracy | **One stale doc reference fixed; one real coverage gap closed** (proxy-routing of the four fixed-third-party plugins was never tested) |
| 4 | SSRF/network primitive re-verification | **No degradation found** — 171 passed, 1 skipped (WebKit unavailable), 0 failed, across all 17 confinement/adversarial test files |
| 5 | SQLite integrity beyond reportability | **Two real gaps found; one fixed, one correctly *not* fixed** with a documented reason and a regression test proving why |
| 6 | Transactional persistence safety | **Real gap found and fixed** — `persist_registry` could lose an entire run's data on a mid-write crash |

---

## Findings

### Finding 1 — cache key missing scope/attribution identity (Task 1)

- **Severity**: Medium
- **Component**: `core/runner.py:PipelineRunner._cache_key`
- **Problem**: `result_cache` (`core/store.py`) is a deliberately global,
  cross-run table — confirmed by reading its schema: no `run_id` column at
  all. The cache key was `sha256(plugin_name + filtered_input_bytes +
  timeout + strict_opsec + outbound_proxy_url)`. It did not include the
  `SCOPE_FILE`'s own identity or the researcher attribution
  header/User-Agent in effect.
- **Impact**: Two different `SCOPE_FILE`s (two different programs or
  engagements) that happen to authorize the byte-identical set of hosts
  for a given plugin would silently collide on the same cache key —
  Program B's run would reuse Program A's already-collected artifact,
  including whatever researcher attribution header/UA it was actually
  fetched under. This is invariant 10 (historical data must never cross
  incompatible scopes), not merely a staleness concern the TTL already
  bounds.
- **What was *not* broken, confirmed rather than assumed**: a target no
  longer authorized under a new `SCOPE_FILE` exclusion can never leak
  through cache, because `_gate_active_input` (`authorize_plugin_input`)
  filters the input file down to only currently-authorized entries
  *before* the filtered file's bytes are ever hashed — an excluded host
  can never enter the hash it would need to collide with. Proven directly
  (`tests/test_cache_authorization_security.py::TestCacheNeverServesAStaleAuthorizationDecision`),
  not inferred.
- **Root cause**: the cache key was designed around "does the plugin's
  actual input differ," not "is the authorization context that produced
  this artifact still the same one asking for it."
- **Fix**: `_cache_key` now also hashes
  `compute_scope_file_hash(settings.scope_file)` and
  `compute_attribution_fingerprint(researcher_attribution_header,
  attribution_user_agent)` — reusing the exact two functions
  `historical_cross_check` (`core/verification/preflight.py`) already uses
  to detect this same class of cross-scope reuse, rather than inventing a
  second notion of "has the context changed."
- **Test**: `tests/test_cache_authorization_security.py::TestCacheKeyIncludesScopeAndAttributionIdentity`
  (7 tests: stable key for identical settings; different `SCOPE_FILE`
  changes the key even with byte-identical filtered input — the exact
  scenario asked for; no-scope-file vs. a scope file; different
  attribution header; different attribution UA; `STRICT_OPSEC`/proxy
  mode change, re-confirmed; different proxy URL under strict mode).

### Finding 2 — cache/authorization separation: already correct (Task 2)

- **Severity**: N/A (no change made)
- **Component**: `core/intel/authorize.py`, `core/collection/*.py`,
  `core/intel/followup.py`
- **Confirmed, not assumed**: grepped `core/collection/*.py` and
  `core/intel/authorize.py` for any mention of "cache" — zero hits. There
  is no code path in the authorization layer that treats cache-restored
  data differently from freshly-discovered data, because there is no
  concept of "cached provenance" once an indicator reaches these
  functions — a plain hostname string is indistinguishable regardless of
  where it came from.
- **Test**: `tests/test_cache_authorization_security.py::TestCacheNeverBypassesAuthorization`
  — `plan_followup_collection` re-authorizes and rejects an out-of-scope
  host even when it carries a claimed `IN_SCOPE` status exactly like a
  cache-restored artifact's ingestion would produce; a direct call to
  `authorize_active_indicator` with the same arguments twice, then with a
  narrower scope, proves there is no hidden memoization to diverge from a
  fresh evaluation.

### Finding 3 — STRICT_OPSEC doc drift + untested proxy-routing for fixed-third-party plugins (Task 3)

- **Severity**: Low (documentation) / Low-Medium (coverage gap)
- **Component**: `docs/NETWORK_CONFINEMENT.md`; `modules/ctlogs.py`,
  `modules/threat_intel.py`, `modules/vuln_match.py`, `modules/passive_dns.py`
- **Problem 1 (doc drift)**: `docs/NETWORK_CONFINEMENT.md` referenced
  "`README.md` § Security Considerations" — that section was renamed
  "Security model" in the prior documentation-consolidation round. Fixed
  in place.
- **Problem 2 (coverage gap)**: the four `THIRD_PARTY_OBSERVATION`
  plugins allowed under `STRICT_OPSEC` (`ctlogs`, `threat_intel`,
  `vuln_match`, `passive_dns`) never touch the target either way, so prior
  audits correctly classified them as not needing target-confinement — but
  none of them had ever been tested for whether the *operator's own*
  connection to the fixed third party (crt.sh, URLhaus, OSV.dev/WPScan,
  Mnemonic/SecurityTrails) actually respects `OUTBOUND_PROXY_URL`. Had one
  of them silently ignored it, `STRICT_OPSEC` would protect the target's
  view of Hydra while leaving the operator's real IP exposed to those
  third parties — an invariant-9 violation (`STRICT_OPSEC` implying a
  capability Hydra can't actually apply).
- **Root cause**: no gap in the code — all four already pass
  `self.settings.outbound_proxy_url` through to
  `utils/network.py:open_url()`. The gap was purely in test coverage and
  documentation completeness.
- **Fix**: `docs/NETWORK_CONFINEMENT.md` corrected and extended with an
  explicit STRICT_OPSEC re-audit section; no code changed (nothing was
  broken).
- **Test**: `tests/test_strict_opsec_proxy_routing.py` (8 tests) —
  monkeypatches each module's `open_url` to capture the real `proxy_url`
  argument for `_fetch_crtsh`, `_query_urlhaus`, `_osv_query`,
  `_wpscan_query`, `_query_mnemonic`, `_query_securitytrails`; plus two
  sanity checks that `STRICT_OPSEC_ALLOWED_PLUGINS` is derived from class
  attributes (not a hand-maintained list that could drift) and that
  `naabu`/`port_verify` remain fully blocked, never quietly "allowed"
  with a confinement claim the code can't back up.

### Finding 4 — SSRF/network primitive re-verification: no degradation (Task 4)

- **Severity**: N/A (no change made)
- **Scope**: the full adversarial confinement suite named in
  `docs/NETWORK_CONFINEMENT.md`'s own "K. Test evidence" section —
  `test_ssrf_destination_policy.py`, `test_crawler_proxy.py`,
  `test_crawler_confinement_live.py`, `test_httpx_confinement_live.py`,
  `test_urllib_confinement_live.py`, `test_redirect_destination_oracle.py`,
  `test_subresource_escape_oracle.py`, `test_alive_txt_integrity_matrix.py`,
  `test_followup_adversarial_oracle.py`, `test_opsec_proxy_chaining.py`,
  `test_collection_gateway.py`, `test_authorized_collection_target.py`,
  `test_no_bypass_network_primitives.py`, `test_untrusted_network_bypass.py`,
  `test_redirect_safety.py`, `test_crawler_proxy_flag_enforcement.py`,
  `test_followup_artifacts.py`, `test_adversarial_matrix.py`.
- **Result**: **171 passed, 1 skipped, 0 failed** (223.44s). The 1 skip is
  the WebKit-dependent subresource test, expected in this environment.
- **Conclusion**: destination-IP validation before connecting, real
  `connect_ip` pinning (no re-resolution after authorization),
  hop-by-hop redirect authorization, and dangerous-scheme rejection are
  all still true today. No code touched, per this task's own instruction.

### Finding 5 — `intel_hypotheses` missing cross-run composite FKs; `intel_indicators.evidence_id` correctly left alone (Task 5)

- **Severity**: Medium (fixed) / informational (documented, not fixed)
- **Component**: `core/store.py` schema
- **Problem**: `intel_entities → intel_observations → intel_evidence →
  intel_relationships` already had composite `FOREIGN KEY(run_id, X)`
  protection (confirmed by reading the schema before touching anything —
  this chain was already done correctly in an earlier round).
  `intel_hypotheses.relationship_id`/`.evidence_id` and
  `intel_indicators.evidence_id` did not: only a bare `FOREIGN
  KEY(run_id) REFERENCES runs(run_id)`, meaning a `relationship_id`/
  `evidence_id` value that is real but belongs to a *different* run could
  not be caught by SQLite at all.
- **Fix applied**: `intel_hypotheses` gained
  `FOREIGN KEY(run_id, relationship_id) REFERENCES intel_relationships(run_id, relationship_id)`
  and `FOREIGN KEY(run_id, evidence_id) REFERENCES intel_evidence(run_id, evidence_id)`.
  Confirmed safe first: the only construction site
  (`core/intel/engine.py:605`) always derives `relationship_id` from a
  real, already-persisted `Relationship` object (via `stable_id(...)`,
  never empty); `evidence_id` was already normalized to `NULL` via `or
  None` at every insert site.
- **Fix tried and reverted**: the same pattern for
  `intel_indicators.evidence_id` → `intel_evidence(run_id, evidence_id)`.
  Adding it broke real, previously-passing tests
  (`test_virusbarrier_e2e.py`, `test_followup_loop.py`,
  `test_infra_correlation.py`) with genuine `sqlite3.IntegrityError`s —
  traced to `core/intel/engine.py`'s `_ingest_a_or_aaaa`, which stores an
  `intel_observations.observation_id` in `Indicator.evidence_id` for
  DNS-resolution-derived indicators, not a real `intel_evidence.evidence_id`.
  This is a genuine, pre-existing semantic overload of the field name
  (sometimes a real evidence row, sometimes "the observation that
  justified discovering this indicator") — fixing it for real means
  renaming/splitting the field or normalizing every write site first,
  which is model/schema redesign out of this round's scope. Documented in
  the schema itself (`core/store.py`) and proven with a real reproduction
  rather than left as a code-reading claim.
- **Also noted, not fixed (lower priority, informational)**:
  `intel_collection_attempts.indicator_id` has the same kind of risk —
  when `self.queue.get(...)` finds no matching queued item (true for every
  seed collection attempt, which is never added to the follow-up queue),
  `core/intel/engine.py` synthesizes a fresh `indicator_id` via
  `stable_id(...)` that never corresponds to a real `intel_indicators`
  row. A composite FK here would break every seed attempt the same way
  the indicators fix did — not attempted, given the pattern was already
  disproven once this round.
- **Tests**: `tests/test_intel_schema_integrity.py` (4 tests) — real
  cross-run rejection for both new FKs (built from a genuine
  `IntelEngine`-produced run against the real virusbarrier fixture, not
  hand-crafted rows), confirmation that `NULL` stays exempt from the
  check (a hypothesis with no relationship/evidence yet must still
  insert), and a test that reproduces the `intel_indicators.evidence_id`
  overload directly against real persisted data (not just cites the
  engine.py line).

### Finding 6 — `persist_registry` was not atomic: a crash mid-write could destroy a run's data (Task 6)

- **Severity**: High
- **Component**: `core/store.py:AssetStore.persist_registry`
- **Problem**: `persist_registry` called `self.clear_run_data(run_id)` —
  its own, independently committed transaction (`clear_run_data` opened
  and closed its own connection) — and only *afterward* opened a second
  connection/transaction for every insert (hosts, clusters, graph, and
  the full intel snapshot: entities, observations, evidence,
  relationships, indicators, hypotheses, attempts).
- **Impact**: a crash between the two transactions (process killed, OOM,
  disk full, power loss — realistic failure modes for a long-running
  recon process, not a contrived scenario) left the run with **all
  prior data deleted and no new data written** — total loss of that run's
  host/intelligence data, not a merely-partial or orphaned-row write.
  Every consumer of that data (reports, CLI queries, the correlation
  engine's next pass) would see an empty run with no indication anything
  had gone wrong beyond the process having crashed.
- **Root cause**: clear-then-rebuild was written as two sequential,
  independent method calls without considering that each opened its own
  transaction.
- **Fix**: `clear_run_data` now accepts an optional existing connection
  (`conn: sqlite3.Connection | None = None`); when given one, it deletes
  on that connection without committing, letting the caller's own
  transaction own the commit/rollback. `persist_registry` now opens one
  connection, runs `clear_run_data` on it, then every insert, all inside
  the same `with self._connect() as conn:` block — one commit, or one
  rollback, never both operations split across two. Standalone callers
  (`conn=None`, the default) keep the exact prior behavior: their own
  immediately-committed transaction.
- **Test**: `tests/test_persistence_transaction_safety.py` (3 tests) — a
  real simulated crash (monkeypatched `_insert_host` raises partway
  through a second `persist_registry` call for the same run) proves the
  *original* data survives intact, not wiped; a successful rerun still
  fully replaces the old host set (the fix didn't accidentally turn
  clear-then-rebuild into rebuild-without-clearing); standalone
  `clear_run_data()` still commits immediately when called with no
  connection.
- **Related, lower-severity, not fixed**: `core/runner.py`'s `run()`
  still calls `record_verification_findings` → `persist_registry` →
  `record_network_requests` → `finish_run` as four separate transactions.
  A crash between them can leave `intel_network_requests` (the
  per-connection audit trail) or `runs.finished_at` missing even though
  the primary host/intelligence data committed successfully. This is an
  audit-trail/telemetry completeness gap, not a security-decision gap —
  nothing in the authorization path reads these fields — and closing it
  properly would mean wrapping the whole `run()` method's persistence in
  one transaction (or a compensating-action pattern), a materially larger
  change than this round's scope. Documented here rather than silently
  left unmentioned. Similarly,
  `core/reportability/cli.py`'s `record_reportability_assessments` →
  `record_reportability_adversarial_reviews` are two separate calls; a
  crash between them loses the adversarial review *row* but not
  correctness — `final_eligibility` (the value every consumer actually
  reads) is already computed and stored on the assessment row itself
  before either call runs.

---

## Files changed

- `core/runner.py` — `_cache_key` now includes scope-file and
  attribution-fingerprint identity (Finding 1).
- `core/store.py` — `intel_hypotheses` composite FKs (Finding 5);
  `intel_indicators`/`upsert_intel_indicators` insert-side `evidence_id`
  normalization (`or None`, harmless correctness improvement kept even
  without the FK); `clear_run_data` accepts an optional connection;
  `persist_registry` runs clear+insert in one transaction (Finding 6).
- `docs/NETWORK_CONFINEMENT.md` — stale `README.md` section reference
  fixed; new STRICT_OPSEC re-audit section (Finding 3). `docs/ARCHITECTURE.md`
  was read and re-confirmed accurate; not touched (nothing in it
  contradicted current code).
- `tests/test_cache_authorization_security.py` (new, 12 tests) — Tasks 1-2.
- `tests/test_strict_opsec_proxy_routing.py` (new, 8 tests) — Task 3.
- `tests/test_intel_schema_integrity.py` (new, 4 tests) — Task 5.
- `tests/test_persistence_transaction_safety.py` (new, 3 tests) — Task 6.

## Quality gate

- `pytest tests/ -q`, 3 consecutive runs, identical every time:
  - Run 1: 880 passed, 10 skipped, 232.56s
  - Run 2: 880 passed, 10 skipped, 230.86s
  - Run 3: 880 passed, 10 skipped, 234.84s
  - (880 = the pre-round baseline plus this round's 27 new tests across
    the four new test files; the 10 skips are the pre-existing
    tool/credential-gated live tests, unrelated to this round.)
- `ruff check .` (touched files): all checks passed.
- `black --check .` (touched files): unchanged.
- `isort --check-only .` (touched files): clean.
- `bandit -c pyproject.toml -r .` (touched files): 0 issues, 3,528 lines
  scanned.
- `mypy core/runner.py core/store.py`: Success, no issues found.

## Remaining risks — stated honestly, by enforcement level

- **Application-level authorization** (the strongest guarantee in this
  codebase): unaffected by this round except where strengthened (Findings
  1, 5). `authorize_active_indicator`/`authorize_collection` remain the
  single source of truth; nothing in this round touched their logic.
- **Proxy-level confinement** (`ScopeEnforcingProxy`/`CollectionGateway`):
  unchanged and re-verified (Finding 4) — real destination-IP pinning for
  every HTTP-speaking collector, no degradation found.
- **OS/container-level isolation**: **still does not exist**, exactly as
  every prior audit has stated. `naabu`/`port_verify`'s raw TCP/SYN
  traffic remains authorization-only, not connection-pinned — this round
  did not change that and does not claim otherwise. A raw-socket bypass of
  any tool's own `-proxy` configuration remains invisible to Hydra by
  construction (`tests/test_untrusted_network_bypass.py`, re-confirmed in
  Finding 4, not newly discovered).
- **Two documented-not-fixed items** (Finding 5's
  `intel_collection_attempts.indicator_id`; Finding 6's multi-transaction
  `run()` sequence and reportability's two-call adversarial-review
  persistence) are real, but neither is a security-authorization gap —
  both are documented explicitly above rather than silently left for a
  future round to rediscover from scratch.

## Round 2 (explicitly not started here)

Reproducibility, broader `mypy`, subprocess hardening, and logging are
out of scope for this round per its own instructions — not evaluated, not
touched.
