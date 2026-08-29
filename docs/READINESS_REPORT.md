# Hydra readiness report

**Date:** 2026-08-29
**Repository:** `Andres-Montoya-SV/hydra`, branch `fix/redirect-scope-safety`
**Method:** forensic runtime audit (`docs/FINAL_SECURITY_AUDIT.md`, `docs/NETWORK_BOUNDARY_AUDIT.md`, `docs/FINAL_NETWORK_BOUNDARY_AUDIT.md`), targeted fixes verified by real subprocess execution, real WebKit browser tests, real SQLite persistence, a real raw-socket bypass demonstration, and a live run against the project's actual authorized target (`virusbarrier.xyz`, per `scope.txt`) — not stubs alone.
**Test proof used:** 439 pytest cases (up from 356 at the start of this security-hardening arc), including a comprehensive parametrized test covering all 19 `active_collection=True` plugins, real-binary crawler-confinement tests, a live production run, a real-SQLite round trip proving the per-destination network authorization audit trail, a real subprocess proving the confinement proxy's raw-socket-bypass limit, and a real-SQLite round trip proving `explain-collection` reconstructs the full causal chain.

**Verdict: READY FOR CONTROLLED BETA**

---

## BEFORE

At the start of this hardening arc, the architecture already had more machinery than a first
read of the code suggested — `authorize_collection()`, a real indicator state machine, evidence-
gated wildcard follow-up, ~15 discovery bounds, `Hypothesis`/`CollectionAttempt` types, a single
plugin choke point in the runner, and correct seed/follow-up artifact isolation all predated this
work. What was missing or broken, confirmed by reading the implementation rather than trusting
docs or tests:

- `authorize_collection()` (the function meant to compose scope+capability+OPSEC) had **zero
  production callers** — every real check went through scope-only paths, with OPSEC enforced as
  a completely separate, uncomposed mechanism.
- katana, hakrawler, and nuclei could reach any host their own internal HTTP client decided to —
  chased redirects, discovered links, OOB interactsh callbacks — with **zero** Hydra visibility
  once launched with an authorized seed.
- The browser's per-request guard did not cover WebSocket connections or `window.open()` popups
  at all — both were structurally outside what `page.route()` can see.
- `asn_lookup.py` had **zero** authorization calls despite declaring itself active-collection.
- `cloud_bucket_enum.py` was gated by a materially weaker mechanism (a one-time flag check) than
  every other active-HTTP plugin, and the underlying `authorize_active_indicator` special case
  for cloud endpoints had a real bug that meant its own opt-in flag could never have worked.
- `CollectionAttempt` rows were only written after a plugin finished — a crash left no attempt
  audit trail, even though the indicator's own status was already crash-safe.
- No typed authorization proof existed; every network primitive accepted a bare `str`.

## AFTER

- `authorize_collection()` is what `core/runner.py:_gate_active_input` — the one place every
  active-collection plugin's input passes through before `plugin.run()` — actually calls.
- `core/collection/crawler_proxy.py:ScopeEnforcingProxy` — a real local HTTP/HTTPS forward proxy
  — authorizes every destination host before connecting, used unconditionally by katana,
  hakrawler, and nuclei. Verified against the real installed binaries, not mocks: a live redirect
  from an authorized seed to a second local server never reaches that server once the tool is
  routed through the proxy.
- The browser's route guard is installed at the `browser_context` level
  (`route()`/`route_web_socket()`), covering every page in the context (closing the popup gap)
  and WebSocket connections (closing that gap) — verified against real WebKit with a bare
  TCP-accept-counting destination proving zero connections for an OOS WebSocket target, and
  empirically confirmed this also covers requests from inside a dedicated Web Worker.
- `asn_lookup.py`'s one active-DNS-resolution path now authorizes each hostname first.
- `cloud_bucket_enum.py` checks `authorize_active_indicator(..., "cloud_bucket_enum")` per URL;
  the underlying bug in `authorize_active_indicator` (opt-in flag being a no-op) is fixed.
- `IntelEngine.claim_attempt()` persists an `IN_FLIGHT` `CollectionAttempt` before the follow-up
  subprocess runs — verified with a real crash simulation querying actual SQLite state.
- `core/collection/target.py:AuthorizedCollectionTarget` — a frozen dataclass constructible only
  via successful authorization — is wired into httpx's redirect-hop resolution.
- All 19 `active_collection=True` plugins are covered by one test proving zero network/subprocess
  primitives are ever called without a `CollectionScope`.
- Two additional latent bugs were found and fixed while writing the tests this arc's mandate
  required: historical diff would have reported every relationship as "changed" on every
  identical re-scan (evidence_id is namespaced by run_id and was being compared directly), and
  `cmd_investigate` presented relationships in a different shape than `cmd_relationships`/the
  HTML/Markdown reporters.
- `intel_network_requests` (`core/store.py`, `core/collection/audit.py`) — a durable, per-
  destination network authorization audit trail distinct from the coarser `intel_collection_attempts`
  (per-plugin-capability) table, populated by `ScopeEnforcingProxy` and httpx's redirect-hop
  resolver, letting the CLI answer "was this host actually contacted, why, under which
  authorization" from SQLite alone, for the two components that make individual per-destination
  decisions. See `docs/NETWORK_BOUNDARY_AUDIT.md` §11.
- `python app.py explain-collection <indicator_id|attempt_id|value>` — reconstructs the full
  causal chain (indicator → hypothesis/authorization → evidence → collection attempts → network
  requests) from SQLite alone, no rescan. `core/intel/query.py:IntelQuery.explain_collection`.
- `PROXY_VERIFIED_TOOLS` (`core/collection/crawler_proxy.py`) and an `UNTRUSTED_NETWORK_TOOL`
  warning (`modules/_base.py:_crawler_confinement`) — the confinement proxy cannot stop a
  collector that opens a raw socket instead of using its configured `-proxy` (proven concretely
  with a real subprocess, `tests/test_untrusted_network_bypass.py`, not merely asserted). Any
  future collector wired into `_crawler_confinement` that isn't in the verified set
  (`katana`/`hakrawler`/`nuclei`, each proven live) now gets an explicit warning instead of a
  silent, unverified confinement claim.

## ARCHITECTURAL CHANGES

New modules:

- `core/collection/__init__.py`, `core/collection/target.py`, `core/collection/crawler_proxy.py`,
  `core/collection/audit.py`

Modified (principal):

- `core/runner.py` — `_gate_active_input` composes OPSEC, not just scope; follow-up loop claims
  `CollectionAttempt` rows before the subprocess runs; `_finalize_to_store` persists
  `context.metadata["network_requests"]` into `intel_network_requests`
- `core/store.py` — `intel_network_requests` table/indexes, `record_network_requests`/
  `get_network_requests`
- `core/intel/query.py` — `explain_collection()` and its private lookup helpers
- `core/intel/cli.py`, `app.py` — `explain-collection` subcommand wired end to end
- `core/collection/crawler_proxy.py` — `PROXY_VERIFIED_TOOLS`
- `modules/_base.py` — `_crawler_confinement` emits `UNTRUSTED_NETWORK_TOOL` for any collector
  not in `PROXY_VERIFIED_TOOLS`
- `core/intel/authorize.py` — cloud-endpoint ALLOW path fixed
- `core/intel/engine.py` — `claim_attempt()`, `AttemptStatus.IN_FLIGHT`
- `core/intel/scope.py` — `authorize_plugin_input`/`authorize_collect_input` compose OPSEC
- `core/intel/query.py` — `investigate()` uses the canonical serializer
- `core/diff.py` — relationship-changed detection uses evidence content, not the run-scoped `evidence_id`
- `modules/asn_lookup.py`, `modules/cloud_bucket_enum.py`, `modules/browser_probe.py`, `modules/httpx.py` — see BEFORE/AFTER above
- `modules/katana.py`, `modules/hakrawler.py`, `modules/nuclei.py` — proxy-confined; hakrawler's actual argv flags fixed (the installed binary doesn't have `-plain`/`-depth`, discovered by running it for real)
- `modules/_base.py` — `_crawler_confinement` async context manager
- `config/settings.py` — `nuclei_enable_interactsh` (default off)

Preserved: structured argv subprocess (no `shell=True`), path confinement, SQLite+WAL+FK,
`STRICT_OPSEC`, fingerprint-first certificates, OOS observation, no Neo4j, no actor/owner
entities, no rewrite of the plugin framework.

## SECURITY INVARIANTS

| Invariant | Status |
|---|---|
| No active network collection without passing centralized authorization | Composed at the choke point (`_gate_active_input`); not yet the *only* call path everywhere (some plugins call the scope-only primitive directly, safe today via the whole-plugin OPSEC skip upstream, but not structurally unified) |
| Authorization ≠ observation | Held throughout; OOS names persist as entities/observations, never as active targets |
| Missing/UNKNOWN/OOS/malformed/unsupported-capability/budget-exhausted all fail closed | Verified for all 19 active-collection plugins in one test |
| Redirects never expand authorization | httpx: per-hop, no bypass found. katana/hakrawler/nuclei: proxy-confined regardless of internal redirect behavior |
| Crawler input authorization ≠ crawler network confinement | Explicitly distinguished; proxy confinement added specifically because input-gating alone was never sufficient |
| Browser subresources gated | Document, iframe, script, stylesheet, image, font, media, xhr, fetch, manifest, WebSocket, Worker, popup — all verified against real WebKit |
| Seed/follow-up artifacts never cross-contaminate | Pre-existing, re-verified correct |
| Wildcard-derived hosts require real evidence, not a plugin's claimed reason | Pre-existing, re-verified correct |
| One canonical relationship serializer | Now true for CLI (`cmd_relationships` and `cmd_investigate`), HTML, Markdown, JSON — `cmd_investigate` was the one holdout, fixed |
| Historical diff detects real relationship changes | Fixed a real bug that would have made it detect a "change" on every re-scan regardless of anything actually changing |

## NETWORK BOUNDARY

Three explicit tiers (`README.md`, `docs/FINAL_SECURITY_AUDIT.md` §7):

1. **Guaranteed by Hydra** — no active-collection plugin without scope; per-hop httpx redirect
   authorization; per-request browser authorization including WebSocket/popup/Worker; proxy
   confinement for katana/hakrawler/nuclei against real binaries.
2. **Guaranteed only when the tool supports it** — CONNECT tunnels are authorized by hostname,
   never TLS-inspected; nuclei's OOB channel is disabled by default because it cannot be
   reconciled with per-host confinement without a third-party allowlist that doesn't exist yet;
   hakrawler's own internal same-host redirect exclusion (observed empirically, not documented)
   currently does primary blocking for that tool specifically.
3. **Requires external network isolation** — a tool bypassing its own configured proxy via a raw
   socket is invisible to the confinement proxy; DNS is not proxied under `STRICT_OPSEC`; nothing
   here claims OS/process-level confinement, and none of the documentation should be read as
   claiming it.

## FOLLOW-UP MODEL

`DISCOVERED → ELIGIBLE → IN_FLIGHT → {COLLECTED, FAILED, NOT_ALLOWED, REJECTED, PARTIAL}`, unchanged
in shape from before this arc (it was already correct) but now backed by `CollectionAttempt` rows
claimed *before* the subprocess that could crash runs, not just after. `overlay_status` still turns
a restored `IN_FLIGHT` into `FAILED`, never `COLLECTED`, and this was independently re-verified
against real SQLite this session, not assumed from the code alone. Seed collection has no
`CollectionAttempt` trail at all yet — see REMAINING LIMITATIONS.

## HYPOTHESIS MODEL

`Hypothesis`/`HypothesisStatus` unchanged this arc — a relationship becomes a hypothesis
(`OPEN`/`REJECTED`), and only `plan_followup_collection`'s independent authorization call (not
the hypothesis itself) can turn that into an actual collection attempt. `authorize_hypothesis()`
only flips a status field; it contains no network code (confirmed by reading `core/intel/engine.py`
in full this session).

## EVIDENCE MODEL

Unchanged and re-verified: `evidence_supports_certificate_followup` requires an actual
`SAN_CONTAINS`/`SHARES_CERTIFICATE` relationship with a non-empty `evidence_id` before trusting a
`CERTIFICATE_SAN`/`SHARED_CERTIFICATE` follow-up reason — a plugin cannot mint that reason string
and skip corroboration. Certificate identity (`identity_kind`: `sha256` → `serial_issuer` →
`unidentified`) never manufactures a fingerprint; has dedicated tests including the 10,000-SAN
case and the live-shaped crt.sh record format.

## HISTORICAL MODEL

`diff_runs` reports relationship appeared/disappeared/changed (confidence increased/decreased,
evidence changed), entity/observation/evidence appeared/disappeared, indicator status changes,
and certificate rotation. **Fixed a real bug this session**: the "evidence changed" comparison
used the raw `evidence_id`, which is namespaced by `run_id` and therefore differs between *any*
two runs regardless of whether anything real changed — meaning every relationship would have
shown as changed on every re-scan. Now compares the relationship's own content. Both scenarios
the mandate specified (same relationship_id + HIGH→MEDIUM; same relationship_id + same confidence
+ new evidence) are tested, plus a third proving a byte-identical re-scan reports zero changes.

## TEST PROOF

```
pytest tests/ -q          → 439 passed
black --check .           → clean (161 files)
isort --check-only .      → clean
ruff check .              → clean
mypy .                    → clean (108 source files)
bandit -c pyproject.toml -r . → 0 issues (Low/Medium/High all 0)
```

Adversarial/live proof beyond unit tests:

- `tests/test_crawler_proxy.py` — raw sockets speaking the proxy protocol directly against
  `ScopeEnforcingProxy`; asserts a destination test server's TCP-accept count, not just the
  proxy's own claimed decision.
- `tests/test_crawler_confinement_live.py` — the **real installed katana and hakrawler
  binaries**, not mocked, against a real local redirect chain.
- `tests/test_browser_probe_scope_guard.py` — real WebKit for subresources, iframe, WebSocket
  (bare-socket-accept-counting destination), and popup escape.
- `tests/test_missing_scope_all_active_plugins.py` — all 19 active-collection plugins, patching
  every network primitive they could reach, asserting zero calls without scope.
- `tests/test_followup_dns_crash_leaves_durable_in_flight_attempt` — a real crash simulation
  querying actual SQLite state afterward, not in-memory state alone.
- `tests/test_network_request_audit_trail.py` — the real `KatanaPlugin`/`_crawler_confinement`
  and the real `HttpxPlugin._resolve_authorized_redirects`, each round-tripped through a real
  SQLite file via `AssetStore.record_network_requests`/`get_network_requests`, asserting the
  persisted `network_attempted`/`network_completed` flags are consistent with the `ALLOW`/`DENY`
  decision for every row (never `network_attempted=1` on a `DENY` row).
- `tests/test_untrusted_network_bypass.py` — a real subprocess opening a real raw
  `socket.connect()` to a real local server, with `HTTP_PROXY`/`HTTPS_PROXY` set exactly as Hydra
  would set them for a confined tool, proving the connection reaches the server anyway (an
  application-level proxy cannot intercept a client that never consults it) — plus real-plugin
  assertions that `HttpxPlugin` (not in `PROXY_VERIFIED_TOOLS`) gets an `UNTRUSTED_NETWORK_TOOL`
  warning from `_crawler_confinement` and `KatanaPlugin` (verified live) does not.
- `tests/test_explain_collection_cli.py` — drives the real `IntelEngine` (hypothesis creation,
  `claim_attempt`/`record_attempt`) and a real `intel_network_requests` insert through real
  SQLite, then asserts `explain-collection` reconstructs the full chain for an authorized
  follow-up target, correctly reports "no indicator/hypothesis/attempt" for a purely-denied
  redirect target, and resolves by `collection_attempt_id` as well as by raw value.
- **Live production run** against `virusbarrier.xyz` (this project's actual configured,
  authorized scope per `scope.txt`) via `python app.py run -d virusbarrier.xyz --run-id
  live_validation_20260829`. Full pipeline, 403.1s, exit code 0: whois → subfinder/ctlogs/
  assetfinder/amass → dnsx → asn_lookup → naabu → port_verify → httpx → soft404_check →
  param_fuzz → cloud_bucket_enum (correctly skipped, not opted in) → vuln_match →
  security_headers → gau/waybackurls/katana/hakrawler/unfurl/nuclei (all through the new
  confinement proxy, confirmed by inspecting the actual running nuclei process's argv:
  `-ni -proxy http://127.0.0.1:56317`).

  **The confinement proxy blocked real out-of-scope connection attempts from real tools during
  this run** — read directly from the run's persisted `warnings_json` in SQLite, not from a test:

  ```
  katana: confinement proxy blocked 1 connection attempt(s) to out-of-scope host(s)
          the tool tried to reach on its own: burpsuite
  nuclei: confinement proxy blocked 6 connection attempt(s) to out-of-scope host(s)
          the tool tried to reach on its own: checkip.amazonaws.com,
          login.microsoftonline.com, www.rdap.net
  httpx:  recorded 4 HTTP redirect(s) out of scope (observation only —
          destination not added to alive.txt)
  ```

  `alive.txt`/`resolved.txt` for the run contain only `virusbarrier.xyz` — none of the
  out-of-scope hosts referenced above, nor any of the other domains nuclei/whois *observed* in
  page content and registration data during the scan (composer.json dependency names, WHOIS
  registrar/nameserver hosts, template metadata references), ever became an active-collection
  target. `browser_probe` failed in this specific run for an unrelated, self-inflicted reason:
  the live run overrode `HOME` to work around this sandbox's `~/.config` permission issue
  (affecting katana), which also moved Playwright's browser-binary cache path — a test-harness
  artifact, not a Hydra defect; the browser guard's own properties were separately verified
  against real WebKit with the real `HOME` in `tests/test_browser_probe_scope_guard.py`.

## REMAINING LIMITATIONS

1. **`authorize_collection()` is the choke-point path, not yet the only path anywhere.**
   `asn_lookup.py`, `whois.py`, `gau.py`, `waybackurls.py` still call the scope-only primitive
   directly for their per-target checks. Safe today (OPSEC for these is enforced upstream at the
   whole-plugin skip in `_run_single_plugin`), but not the single unified call path the full
   `CollectionGateway` would provide.
2. **`AuthorizedCollectionTarget` is proven at one call site (httpx), not retrofit everywhere.**
   Most plugins are not structurally prevented from calling a network primitive with an
   unauthorized string — they are prevented by every current code path correctly checking first,
   which is the same "convention, not construction" gap the mission opened with.
3. **Seed collection has no `CollectionAttempt` audit trail.** Follow-up collection does
   (including pre-claim persistence). This is not a regression — seed collection never had one —
   but it means "reconstruct why a target was collected" from SQLite alone works for follow-up
   attempts and not for the initial seed dnsx/httpx runs.
4. **No third-party-provider allowlist for the confinement proxy.** nuclei's OOB detection is
   disabled by default as a result; re-enabling it means accepting that specific traffic bypasses
   confinement entirely rather than being selectively allowed.
5. **OS/process-level network isolation is out of scope and always will be** — see NETWORK
   BOUNDARY tier 3. This is stated as a limitation, not hidden as a false guarantee.
6. **Host graph (`core/intelligence/graph.py`) was spot-checked, not exhaustively re-audited,
   this session.** What was checked (CDN/ASN/provider edges stay LOW/MEDIUM; `PRESENTS_CERTIFICATE`
   and `resolves_to` are HIGH/VERY_HIGH because they're directly observed facts, matching Intel's
   own semantics for the same fact types) shows no contradiction with Intel, consistent with prior
   dedicated tests (`test_shared_cloud_ip_is_medium_not_ownership`,
   `test_risk_is_not_increased_by_shared_certificate`), but this was not a from-scratch review.
7. **`datetime.utcnow()` deprecation warnings remain** (169 in the current test run); behavior is
   unchanged, cosmetic only.
8. **`intel_network_requests` covers two call sites, not every plugin's network activity.**
   `ScopeEnforcingProxy` (katana/hakrawler/nuclei) and httpx's redirect-hop resolver write rows;
   dnsx, naabu, asn_lookup, cloud_bucket_enum, browser_probe, and the OSINT/passive plugins do
   not — a forensic-completeness gap (those plugins' authorization is still correctly enforced
   and independently tested; they simply leave no per-destination row in this specific table),
   not an authorization bypass. See `docs/NETWORK_BOUNDARY_AUDIT.md` §11.
9. **`ScopeEnforcingProxy` cannot stop a raw-socket bypass — proven, not just disclosed.**
   `tests/test_untrusted_network_bypass.py` shows a subprocess with the confinement proxy's
   environment variables set anyway reaches an out-of-scope server directly, because a raw
   `socket.connect()` never consults `HTTP_PROXY`/`HTTPS_PROXY`. This is a structural limit of any
   application-level proxy, not a bug to fix. The mitigation actually shipped is classification,
   not false confinement: `PROXY_VERIFIED_TOOLS` (`core/collection/crawler_proxy.py`) names only
   katana/hakrawler/nuclei — each individually proven live to honor `-proxy`
   (`test_crawler_confinement_live.py`) — and any future collector wired into
   `_crawler_confinement` outside that set gets an explicit `UNTRUSTED_NETWORK_TOOL` warning
   instead of inheriting an unverified confinement claim. True OS/process-level containment
   (network namespace, firewall egress rule, container policy) remains outside Hydra's own code
   and always will be — see NETWORK BOUNDARY tier 3.

## PROVEN / PARTIALLY PROVEN / UNPROVEN

| Claim | Status | Evidence |
|---|---|---|
| No active-collection plugin runs without `CollectionScope` | **PROVEN** | `test_missing_scope_all_active_plugins.py`, all 19 plugins |
| httpx never auto-follows redirects; every hop is individually authorized | **PROVEN** | `test_redirect_safety.py`, `test_url_normalization_adversarial.py`, real local redirect chains |
| katana/hakrawler/nuclei cannot reach an OOS host **through their own HTTP client** | **PROVEN** | `test_crawler_proxy.py` (raw sockets), `test_crawler_confinement_live.py` (real binaries), live production run |
| katana/hakrawler/nuclei cannot reach an OOS host **under any circumstance, including a raw-socket bypass** | **UNPROVEN — and now proven false** | `test_untrusted_network_bypass.py` demonstrates a raw socket bypasses the proxy entirely; this was never claimed as proven, and is now explicitly disproven rather than left ambiguous |
| Browser subresources (script/image/xhr/fetch/WebSocket/popup/Worker) cannot reach an OOS host | **PROVEN** | `test_browser_probe_scope_guard.py`, real WebKit |
| Cloud-derived hostnames require per-hostname authorization, not a blanket provider rule | **PROVEN** | prior turn's `authorize_active_indicator` fix + regression test |
| Wildcard-derived hosts require real SAN evidence, not a plugin's claimed reason string | **PROVEN** | `evidence_supports_certificate_followup`, existing dedicated tests |
| Follow-up state machine is crash-safe (`IN_FLIGHT` never silently becomes `COLLECTED`) | **PROVEN** | real crash-simulation test querying actual SQLite |
| Seed vs. follow-up artifacts never cross-contaminate | **PROVEN** | pre-existing, re-verified |
| One canonical relationship serializer across CLI/HTML/Markdown/JSON | **PROVEN** | `cmd_investigate`/`cmd_relationships` agreement test |
| Historical diff detects real changes, not `run_id`-namespacing artifacts | **PROVEN** | fixed bug + 3-scenario regression test |
| "Why was this hostname collected?" answerable from SQLite alone | **PROVEN for follow-up collection; UNPROVEN for seed collection** | `explain-collection` + `test_explain_collection_cli.py` walk the full chain for follow-up indicators; seed collection has no `CollectionAttempt`/hypothesis row to walk (documented limitation, unchanged this turn) |
| Every active-collection plugin's authorization is structurally impossible to skip (not just currently correct) | **UNPROVEN** | the `CollectionGateway`/`AuthorizedCollectionTarget`-everywhere retrofit remains open; today's correctness is verified by test and live run, not enforced by the type system at every call site |
| `intel_network_requests` covers every network-issuing component | **PARTIALLY PROVEN** | covers `ScopeEnforcingProxy` and httpx's redirect resolver (the two finest-grained per-destination deciders); dnsx/naabu/asn_lookup/cloud_bucket_enum/browser_probe make correctly-authorized calls but leave no row in this specific table |

## FINAL VERDICT

**READY FOR CONTROLLED BETA**

**P0:** none open. Every CRITICAL/blocking finding from this hardening arc (zero production
callers of `authorize_collection()`, unconfined crawlers, fail-open browser guard gaps,
`asn_lookup`/`cloud_bucket_enum` authorization gaps) is closed and independently verified against
real binaries/browser/SQLite, not asserted from reading the code.

**P1:** the full `CollectionGateway` retrofit (limitations 1–2) — authorization is currently
*correct everywhere it's checked*, not *structurally impossible to skip*; a future plugin could
still call a network primitive with an unauthorized string without the type system stopping it.
This is the single reason the verdict is not `READY`.

**P2:** seed collection has no `CollectionAttempt` trail (limitation 3); no third-party-provider
allowlist for nuclei OOB (limitation 4); host-graph module spot-checked, not exhaustively
re-audited (limitation 6); `datetime.utcnow()` deprecation noise (limitation 7);
`intel_network_requests` coverage is partial (limitation 8); the confinement proxy cannot stop a
raw-socket bypass, mitigated by explicit `PROXY_VERIFIED_TOOLS` classification rather than a false
guarantee (limitation 9, now proven with a real test rather than only disclosed in prose).

**NETWORK ENFORCEMENT COVERAGE:** all active-collection plugins gate on `CollectionScope` before
running (19/19, one parametrized test); katana/hakrawler/nuclei additionally confined at the
socket level by `ScopeEnforcingProxy` regardless of internal redirect/crawl behavior; httpx
authorizes every redirect hop individually before requesting it; browser_probe authorizes every
resource type including WebSocket/popup/Worker at the browser-context level. Per-destination
decisions from the two finest-grained components (crawler proxy, httpx redirects) are now also
durably recorded in `intel_network_requests`, independent of the coarser per-plugin
`intel_collection_attempts` table.

**UNPROVEN PATHS:** a tool bypassing its own configured `-proxy` via a raw socket outside its
HTTP client is invisible to `ScopeEnforcingProxy` — this is no longer merely disclosed, it is
demonstrated with a real subprocess and a real server in `tests/test_untrusted_network_bypass.py`
(application-level proxy, not OS-level isolation; mitigated by `PROXY_VERIFIED_TOOLS`
classification, not by a false confinement claim); DNS resolution itself is not proxied under
`STRICT_OPSEC`; no allowlisted third-party OOB provider path exists, so nuclei interactsh stays
opt-in and unconfined when enabled; seed collection (as opposed to follow-up) has no
`CollectionAttempt` trail for `explain-collection` to walk.

**TEST COUNT:** 439 passed (0 failed, 0 xfail, 0 skipped-as-hidden-failure), up from 356 at the
start of this arc — verified with `pytest tests/ -q` run to completion, plus a clean `black`,
`isort`, `ruff`, `mypy`, and `bandit` pass across the full repository.

**REAL NETWORK VALIDATION:** a live production run against `virusbarrier.xyz` (this project's
actual authorized scope per `scope.txt`) completed in 403.1s, exit 0, with the confinement proxy
blocking real live out-of-scope connection attempts from real katana/nuclei processes — read
directly from the run's persisted SQLite `warnings_json`, not from a mock. Crawler confinement is
additionally verified against the real installed katana and hakrawler binaries in a controlled
local redirect chain, the browser guard against real WebKit, and — this turn — a real subprocess
proving the one thing the confinement proxy cannot do (stop a raw-socket bypass), so the "real
network" proof this turn includes a real demonstration of the boundary's actual edge, not only of
its successes.

**KNOWN LIMITATIONS:** see the nine items enumerated above (REMAINING LIMITATIONS) — none of
them constitute a known, currently-exploitable authorization bypass; each is either a structural
robustness gap (P1) or a documented, deliberately-scoped-out boundary (P2), and limitation 9 is
now backed by a passing test that would fail if the boundary were ever silently claimed to be
stronger than it is.

Use on authorized targets with `SCOPE_FILE` set. Treat katana/hakrawler/nuclei/browser_probe as
still the highest-residual-risk collectors — confinement is real but is a proxy/route-guard
boundary, not OS-level isolation — and run them inside a disposable, network-restricted
container/VM as the existing documentation already instructs for browser_probe specifically.
