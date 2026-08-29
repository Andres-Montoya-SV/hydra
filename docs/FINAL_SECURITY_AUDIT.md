# Hydra Final Security Audit

Current state of the `fix/redirect-scope-safety` branch after `docs/NETWORK_BOUNDARY_AUDIT.md`'s
Phase 0 audit and its two change sets (§8, §9 of that document). This document is the
current-state reference; the other document is the historical changelog of how we got here.
Every claim below is either a direct code citation or an empirically verified test result from
this session — not an inference from documentation, comments, or test names.

---

## 1. Runtime graph

```
python app.py run -d <target>
        │
        ▼
PipelineRunner.run()                              core/runner.py
        │
        ├─ CollectionScope built from seeds/SCOPE_FILE ── core/intel/scope.py
        │
        ├─ SUBDOMAIN_PLUGINS (subfinder, amass, assetfinder)   ─┐  passive, not
        ├─ ctlogs (crt.sh)                                       │  active_collection;
        ├─ anew (local dedupe, no network)                       │  merge into subdomains.txt
        │                                                        │  unfiltered (§4.1 LOW)
        ├─ wildcard_check ── dnsx canaries, own explicit gate ──┘
        │
        ├─ RESOLVE_DNS_PLUGINS (dnsx)  ── _gate_active_input ── plugin.run()
        ├─ asn_lookup                  ── _gate_active_input ── plugin.run()
        ├─ naabu / port_verify         ── _gate_active_input ── plugin.run()
        ├─ httpx                       ── _gate_active_input ── plugin.run() ── hop-by-hop
        │                                                                       redirect auth
        ├─ soft404_check / param_fuzz  ── _gate_active_input ── plugin.run()
        ├─ cloud_bucket_enum           ── _gate_active_input ── plugin.run() ── per-URL auth
        ├─ threat_intel / vuln_match   ── _gate_active_input ── plugin.run() ── 3rd-party APIs
        ├─ POST_HTTP_PLUGINS (katana, hakrawler, nuclei)
        │        └─ _gate_active_input ── plugin.run() ── ScopeEnforcingProxy (-proxy)
        ├─ browser_probe               ── _gate_active_input ── plugin.run() ── Playwright
        │                                                          context-level route guard
        │
        ├─ _maybe_collect_followups()  (bounded loop, up to 2 passes)
        │        engine.eligible_followups() → plan_followup_collection() → claim_attempt()
        │        → _persist_indicators() (durable BEFORE subprocess) → dnsx/httpx → record_attempt()
        │
        └─ finalize → AssetStore.persist_registry() → SQLite → reporter.py / core/intel/cli.py
```

**Single choke point, verified by repo-wide grep, not assumed:** `plugin.run(context, input_path)`
is called from exactly one place, `core/runner.py:_run_single_plugin` (line ~1131). Every
active-collection plugin's `input_path` is rewritten by `_gate_active_input` immediately before
that call.

---

## 2. Collection graph — what each active plugin can reach, and what stops it

| Plugin | Network mechanism | What actually enforces the boundary | Enforcement class |
|---|---|---|---|
| dnsx | subprocess, gated `-l` file | `_gate_active_input` (composed scope+OPSEC) + output re-filtered via `filter_authorized_indicators` | Input-gated, double-checked |
| naabu / port_verify | subprocess, gated `-l`/host list | `_gate_active_input`; port_verify independently re-authorizes `naabu.txt` rather than trusting naabu's prior gate | Input-gated |
| httpx | subprocess, gated `-l`, then per-hop `-u` | `_gate_active_input` for the batch; **`AuthorizedCollectionTarget.authorize()` per redirect hop**, no bypass found on re-verification | Input-gated + **per-hop authorized, typed** |
| katana / hakrawler / nuclei | subprocess, gated `-l`/`-list`/stdin, tool can self-navigate | `_gate_active_input` for the seed list **+ `ScopeEnforcingProxy` for every connection the tool makes on its own** | Input-gated + **proxy-confined** |
| browser_probe | Playwright, gated start URL, page renders arbitrary content | `_gate_active_input` for the start URL + `browser_context.route()`/`route_web_socket()` per request (document/subresource/iframe/websocket/popup, fail-closed on exception) | Input-gated + **per-request authorized** |
| cloud_bucket_enum | direct HTTP to generated cloud hostnames | plugin-entry opt-in flag **+ per-URL `authorize_active_indicator(..., "cloud_bucket_enum")`** (fixed this session — was previously unauthorized per-request) | Input-gated (opt-in) + per-request authorized |
| threat_intel / vuln_match | HTTP to fixed 3rd-party hosts (urlhaus, osv.dev, wpscan) | target data (not the connection host) gated by `allows_active_collection`; connection host is a hardcoded constant, never built from target data | Data-gated, host is fixed |
| soft404_check / param_fuzz | direct HTTP via `core.http_probe.http_get` | per-URL `allows_active_collection` before each request | Per-request authorized |
| asn_lookup | raw socket (TCP whois, UDP DNS) to Team Cymru; `getaddrinfo` fallback | `_output_path`'s `require_collection_scope` (whole plugin) + **`allows_active_collection` per hostname before the `getaddrinfo` fallback specifically** (fixed this session) | Plugin-gated + per-target authorized (the one active-DNS path) |
| whois | subprocess `whois <domain>` | `authorize_active_indicator` per root domain (calls the primitive directly, not either wrapper — cosmetic inconsistency, not a bypass) | Per-request authorized |
| gau / waybackurls | subprocess to archive APIs, per seed domain | `authorize_active_indicator` per domain before each subprocess call | Per-request authorized |
| security_headers | none | n/a — parses already-fetched httpx headers, no network I/O in the file | N/A |
| subfinder / amass / assetfinder / ctlogs | subprocess/HTTP to passive sources, queried by seed domain | seed is inherently authorized (operator-supplied); **not** `active_collection`, so `_gate_active_input` is a no-op for them (moot — none takes file-based targets) | Seed-only, not file-gated |

**No plugin in this table lacks *some* authorization mechanism today** — the asn_lookup and
cloud_bucket_enum gaps from Phase 0 are closed. What remains uneven is the *class* of
enforcement: input-file gating alone (relies on the tool not reaching beyond what it's handed)
vs. per-request/per-hop authorization (survives the tool doing something unexpected) vs. proxy
confinement (survives the tool ignoring Hydra's authorization logic entirely, as long as it
honors its own `-proxy` setting).

---

## 3. Authorization graph — the actual decision paths in production

```
authorize_collection(indicator, scope, capability, strict_opsec, opsec_allowed)   core/intel/authorize.py
        │  composes: scope classification + cloud-endpoint policy + OPSEC
        ▼
   AuthorizationResult{ALLOW|DENY|UNKNOWN, hostname, reason, scope_status}
        │
        ├── .allowed  ──► allows_active_collection() / authorize_active_indicator()  (scope-only convenience wrappers)
        │
        ├── called directly by:
        │     - core/runner.py:_gate_active_input → authorize_plugin_input → authorize_collect_input
        │       (the ONE place scope+OPSEC are composed for every active-collection plugin's input)
        │     - modules/httpx.py:_resolve_authorized_redirects (via AuthorizedCollectionTarget.authorize)
        │     - modules/cloud_bucket_enum.py (per canary/candidate URL)
        │     - core/intel/followup.py:plan_followup_collection (per follow-up candidate)
        │
        └── called (scope-only, no OPSEC) by:
              - modules/asn_lookup.py, modules/whois.py, modules/gau.py, modules/waybackurls.py
                (per-target, direct calls — OPSEC for these plugins is still enforced at the
                whole-plugin level in _run_single_plugin, just not composed into this same call)
              - modules/_base.py:_alive_urls (re-filter before hakrawler/threat_intel/vuln_match read it)
              - core.collection.crawler_proxy.ScopeEnforcingProxy (per connection, real-time)
```

`authorize_collection()` went from **zero production callers** (Phase 0 finding) to being the
actual function `_gate_active_input` calls for every active-collection plugin, plus the httpx
redirect-hop path and cloud_bucket_enum. It is not yet the *only* path — several plugins still
call the scope-only primitive directly, which is safe today because OPSEC for those plugins is
enforced upstream at the whole-plugin skip in `_run_single_plugin`, but it means "one authoritative
decision path" is achieved at the choke point, not literally everywhere a check happens. Closing
that fully is the `CollectionGateway` work (§8 below).

**Fail-closed, verified for all 19 active-collection plugins in one test**
(`tests/test_missing_scope_all_active_plugins.py`): every plugin the codebase declares
`active_collection = True` makes zero calls into `run_command`, `run_command_to_file`, `http_get`,
`open_url`, or `asyncio.open_connection` when `context.collection_scope is None`. Not inferred
from an exception type — asserted on the primitives themselves.

---

## 4. Observation graph — what's allowed to exist without authorizing collection

```
CT logs (ctlogs.py)           ──┐
HTTP Location headers          │
Crawler-discovered URLs        ├──► Observation / Evidence (core/intel/model.py)
Archive results (gau/wayback)  │        │
Redirect chains                │        ▼
                               ─┘   Relationship (confidence-banded, evidence-backed)
                                         │
                                         ▼
                                    Hypothesis (OPEN | AUTHORIZED_FOR_COLLECTION | REJECTED)
                                         │  engine.authorize_hypothesis() only flips OPEN status;
                                         │  it does not itself trigger a network request
                                         ▼
                          plan_followup_collection() re-authorizes independently
                          (evidence_supports_certificate_followup requires a REAL
                          SAN_CONTAINS/SHARES_CERTIFICATE relationship with an
                          evidence_id — a plugin's CERTIFICATE_SAN reason string
                          alone is never trusted)
                                         │
                                         ▼
                              CollectionAttempt (claimed IN_FLIGHT, persisted
                              BEFORE the subprocess runs, for the follow-up path)
```

Verified, not assumed: `core/intel/followup.py:evidence_supports_certificate_followup` checks
for an actual `SAN_CONTAINS` relationship with a non-empty `evidence_id` in the engine's own
relationship table — a plugin cannot spoof `reason=CERTIFICATE_SAN` and skip this (confirmed by
reading the function body; it does not trust `item.reason` alone for `INDEPENDENT_REASONS` other
than `SEED`).

**Redirect observation → collection boundary is never crossed silently.** httpx's
`_redirect_observation` records `scope_status`, `collection_status: NOT_ALLOWED`, and
`raw_artifact`, and the OOS destination is never written to `alive.txt`/`authorized_alive.txt`
(`tests/test_redirect_safety.py`). Confirmed for katana/hakrawler's own internal redirect-follow
too, now that both are proxy-confined (§9 of the other document).

---

## 5. Subprocess graph

Every subprocess-based plugin routes through exactly two functions in `utils/subprocess.py`:
`run_command` (capture stdout) and `run_command_to_file`. No `shell=True` anywhere (grepped).
`modules/_base.py`'s `_execute`/`_execute_self_output`/`_run_tool` are the only callers. The
crawler-confinement proxy (`core/collection/crawler_proxy.py`) does not touch this path — it's a
separate, real TCP listener the subprocess is told to route through via `-proxy`, not a wrapper
around `run_command` itself.

```
plugin.run()
    │
    ├─ self._execute(...) / self._execute_self_output(...) / self._run_tool(...)   modules/_base.py
    │        │
    │        ▼
    │   utils.subprocess.run_command / run_command_to_file
    │        │
    │        ▼
    │   asyncio.create_subprocess_exec(argv, ...)   (no shell=True anywhere)
    │
    └─ [katana|hakrawler|nuclei only] argv includes "-proxy <ScopeEnforcingProxy.proxy_url>"
             │
             ▼
       127.0.0.1:<ephemeral> ── ScopeEnforcingProxy ── authorize(host) ── ALLOW → real destination
                                                                         └─ DENY → 403 / refused CONNECT,
                                                                                    destination never touched
```

---

## 6. Browser network graph

```
browser_probe.run()
    │  require_collection_scope(context) — before even importing playwright
    ▼
_probe_target()
    │  browser_context = await browser.new_context(..., service_workers="block")
    │  await _install_scope_request_guard(browser_context, context, blocked_counts)
    │        │
    │        ├─ browser_context.route("**/*", guard)              — document/iframe/script/
    │        │                                                        style/image/xhr/fetch/
    │        │                                                        manifest/media/other,
    │        │                                                        AND any popup page in
    │        │                                                        this context (context-
    │        │                                                        level, not page-level)
    │        └─ browser_context.route_web_socket("**/*", ws_guard) — WebSocket connections;
    │                                                                 unauthorized ⇒ never
    │                                                                 calls connect_to_server(),
    │                                                                 so no real socket opens
    │  page = await browser_context.new_page()
    │  await page.goto(target["probe_url"], ...)
```

Both guards call `browser_request_decision`/`allow_browser_navigation` →
`allows_active_collection`, fail closed on missing scope and on any exception evaluating the
policy. Verified against real WebKit (not mocked) for: OOS subresources (script/image/fetch),
cross-origin iframe navigation, OOS WebSocket (bare-socket-accept-counting destination proves
zero TCP connections), and a `window.open()` popup to an OOS host.

**Also checked this session, empirically, not assumed:** dedicated Web Workers (`new Worker(...)`,
distinct from Service Workers). A worker's own `fetch()` call to an OOS host was intercepted and
blocked by `browser_context.route()` — the same context-level guard, no separate wiring needed —
verified with a real WebKit run where the destination test server received zero hits.

**Documented, not fixed, residual:** Service Worker *registration* is blocked
(`service_workers="block"`) — a real, separate, unconditional engine-level control — but this is
not the same mechanism as the route guard and isn't scope-aware; it simply prevents any SW from
ever existing in this context. No gap is known here, just two different mechanisms doing two
different jobs.

---

## 6a. Live production validation

Beyond the test suite, a full run of `python app.py run -d virusbarrier.xyz` was executed against
this project's actual configured, authorized scope (`scope.txt`), not a synthetic fixture.
403.1 seconds, exit code 0, every stage completed except `browser_probe` (failed for a reason
specific to this test session's environment — see below, not a code defect).

The confinement proxy blocked real out-of-scope connection attempts from real tools during this
run, read directly from the run's `warnings_json` in SQLite:

```
katana: confinement proxy blocked 1 connection attempt(s) to out-of-scope host(s)
        the tool tried to reach on its own: burpsuite
nuclei: confinement proxy blocked 6 connection attempt(s) to out-of-scope host(s)
        the tool tried to reach on its own: checkip.amazonaws.com,
        login.microsoftonline.com, www.rdap.net
httpx:  recorded 4 HTTP redirect(s) out of scope (observation only —
        destination not added to alive.txt)
```

This is the single strongest piece of evidence in this whole audit: the crawler-confinement
finding this document opens with was not hypothetical. Real nuclei templates, running against a
real authorized target, tried to reach three distinct real third-party hosts, and none of those
connections happened. `alive.txt`/`resolved.txt` for the run contain only `virusbarrier.xyz` —
none of the hosts above, nor any of the domains merely *observed* in page content or WHOIS data
during the scan, ever became an active-collection target.

`browser_probe` failed in this run with `BrowserType.launch: Executable doesn't exist at
.../Library/Caches/ms-playwright/webkit-2336/pw_run.sh` — this run overrode `HOME` to work around
this sandbox's `~/.config` permission issue (which otherwise makes katana refuse to start at
all), and that also moved Playwright's browser-binary cache path out from under it. Self-inflicted
by the validation setup, not a Hydra defect; the browser guard's properties were verified
separately with the real `HOME` in `tests/test_browser_probe_scope_guard.py`.

---

## 7. Remaining trust boundaries — what Hydra does and does not guarantee

### Guaranteed by Hydra (verified this session, at the application level)

- No active-collection plugin issues a network/subprocess call without `CollectionScope` present (all 19 plugins, one test).
- Every HTTP redirect hop httpx follows is individually authorized before the request; the origin request is separately gated.
- Every browser request — document, iframe, every subresource type, and WebSocket, including popups — is authorized before the real network connection, fail-closed on exception.
- katana, hakrawler, and nuclei are routed through a local scope-enforcing proxy for every connection they make beyond their authorized seed list; verified against the real installed binaries, not mocks.
- A follow-up collection attempt is persisted as `IN_FLIGHT` in SQLite before the corresponding subprocess runs (crash leaves a durable trace, not silence) — for the follow-up path specifically.
- A CT-log/wildcard-derived hostname cannot be actively collected on a spoofed `CERTIFICATE_SAN` claim alone; real corroborating evidence is required.
- A generated cloud-bucket hostname is only ever requested if both the `Settings` flag and the `CollectionScope.cloud_collection_allowed` field agree — checked per-request, not just once at plugin entry.

### Guaranteed only when the collector/tool supports enforcement

- **Crawler confinement is proxy-based, not a scope model the tools themselves understand.** It stops any connection to an unauthorized *host*; it cannot stop an authorized-host connection from doing something Hydra wouldn't want (e.g., a legitimate in-scope page triggering a legitimate but unwanted action) — that was never in scope for a network boundary.
- **CONNECT tunnels are not TLS-inspected.** The proxy authorizes by the CONNECT target hostname, then splices bytes. It cannot see (and does not need to see) what happens inside the TLS session — which is correct for a network-boundary tool, but means it is not a content-inspection layer.
- **nuclei's interactsh OOB channel is disabled by default** specifically because it cannot be reconciled with per-host scope confinement without an explicit third-party-provider allowlist (not built). An operator who re-enables it (`NUCLEI_ENABLE_INTERACTSH=true`) accepts that OOB traffic is unproxied, direct contact with ProjectDiscovery's public servers.
- **hakrawler's own internal same-host redirect exclusion** (empirically observed, not documented by the tool) currently does the primary blocking for cross-host redirects on the version tested; the confinement proxy is real defense in depth if that internal behavior changes or a different code path in the tool reaches out, but the two are not the same thing, and this audit does not claim to know hakrawler's internal logic is unconditional.

### Requires external network isolation (outside what Hydra's own code can enforce)

- **A tool that ignores its configured `-proxy` entirely** — a bug in the tool, or a code path in it that uses a raw socket bypassing its own configured HTTP transport — is invisible to `ScopeEnforcingProxy`. Nothing at the OS/process level stops this; only running the whole Hydra process inside a network-namespaced/firewalled sandbox (`iptables`/`pf`/a container network policy) closes this residual, and that is an operational choice outside the application, not a Hydra feature.
- **DNS resolution itself is not proxied.** `STRICT_OPSEC` routes HTTP through a configured proxy but does not force system DNS through it; `core/opsec_check.py:check_dns_leak` already reports this honestly as informational, not a guarantee.
- **The browser's own OS-level process** (WebKit) could, in principle, have an escape this audit didn't test (a Playwright/WebKit bug allowing a request Playwright's own routing APIs don't see). This is a third-party browser-engine risk, not something route-guard code can close from the outside.

**Hydra does not claim, and this document does not claim on Hydra's behalf, universal
process-level or OS-level network confinement.** Every claim above is scoped to what the
application layer actually does and was verified doing.

---

## 8. Findings, ranked, with exact remediation status

| Severity | Finding | Status |
|---|---|---|
| CRITICAL | `authorize_collection()` had zero production callers | **Fixed** — wired into `_gate_active_input`, the choke point every active-collection plugin passes through |
| CRITICAL | katana/hakrawler/nuclei could reach any host their internal HTTP client decided to, with zero Hydra visibility | **Fixed** — `ScopeEnforcingProxy`, verified against real binaries |
| CRITICAL | Browser WebSocket and popup requests bypassed the per-request guard entirely | **Fixed** — context-level `route()`/`route_web_socket()` |
| HIGH | `asn_lookup.py` had zero authorization calls despite `active_collection=True` | **Fixed** |
| HIGH | `cloud_bucket_enum.py` gated by a materially weaker mechanism than every other active-HTTP plugin | **Fixed** — also fixed the underlying `authorize_active_indicator` bug that made its own opt-in flag a no-op |
| MEDIUM | `CollectionAttempt` rows only written after plugin completion — crash window with no audit trail | **Fixed for the follow-up path.** Seed collection still has no `CollectionAttempt` rows at all (not a regression — it never did) |
| MEDIUM | `ReconPlugin.run()` has no structural constraint against direct network library use | **Partially addressed.** `AuthorizedCollectionTarget` exists and is wired into httpx's hop resolution; not retrofitted everywhere — that is the full `CollectionGateway`, still open |
| MEDIUM | Historical diff would report 100% of relationships as changed on every identical re-scan | **Fixed** (new finding, found writing this session's required tests) |
| LOW | `cmd_investigate` used a different relationship shape than `cmd_relationships`/reporter | **Fixed** (new finding) |
| LOW | Enumeration plugins write into shared `subdomains.txt` with no per-name filter of their own | **Not fixed** — safe today because every current consumer re-gates on read; a structural risk for a hypothetical future plugin, not a live one |
| LOW | `whois.py` calls the raw authorization primitive directly and degrades a missing scope to a warning instead of a loud failure | **Not fixed** — cosmetic inconsistency, not a live bypass (the plugin still makes zero requests, per the comprehensive missing-scope test) |
| NOTE | `unfurl_domains.txt` could contain hostnames from query-string values of otherwise-authorized URLs | **Not fixed** — no live consumer of that file exists today |
| CONFIRMED SAFE | httpx's hop-by-hop redirect authorization | No bypass found on two independent reviews |
| CONFIRMED SAFE | threat_intel/vuln_match never let target data become the connection host | Verified |
| CONFIRMED DONE | Seed vs. follow-up artifact isolation | Already correct before this audit began |
| CONFIRMED DONE | Certificate identity (`identity_kind`: sha256/serial_issuer/unidentified, never a manufactured fingerprint) | Already correct, has dedicated tests including the 10,000-SAN case |
| CONFIRMED DONE | Dimensional bounds (entities/relationships/certificates/CT-names-per-cert/etc.) and the 10k-SAN-does-not-starve-seed property | Already correct, has a dedicated test |

---

## 9. What is explicitly still open

1. **The full `CollectionGateway`.** `AuthorizedCollectionTarget` exists and is proven at one call site; most plugins still call `allows_active_collection`/`authorize_active_indicator` directly rather than being structurally prevented from doing anything else. This is the largest remaining piece and was deliberately not attempted as a single mega-change — it touches the call pattern of every plugin.
2. **Unified seed/follow-up `CollectionAttempt` accounting.** Follow-up collection now has pre-claim persistence; seed collection has no `CollectionAttempt` rows at all. The mission's "do not have two incompatible semantics" is not yet met — there's one semantics for follow-up and none for seed, which is at least *consistent* in the sense that nothing lies about seed attempts, but it isn't the unified model asked for.
3. **A true third-party-provider allowlist**, so nuclei's OOB detection and any future legitimate third-party-contact capability doesn't have to be an all-or-nothing default-deny against the confinement proxy.
4. **OS-level/process-level network isolation** is out of scope for this application and always will be — see §7's third tier.
