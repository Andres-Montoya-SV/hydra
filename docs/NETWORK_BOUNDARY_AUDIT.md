# Hydra Network Boundary Audit

**Scope of this document:** Phase 0 of the network-boundary hardening mandate. This is
a forensic trace of the *implementation as it exists on `fix/redirect-scope-safety`*,
not a description of intent. No code was changed to produce this document. Every claim
below was verified against the actual source file and, where a claim concerned a
third-party binary's behavior, against that binary's real `-h` output on this machine
(`katana` 1.x, `hakrawler`, `nuclei` 3.9.0 installed locally) — not against Hydra's
comments about that binary.

Methodology: every plugin module, every `core/intel/*` file, `core/runner.py`,
`core/store.py`, `core/plugin_base.py`, `utils/network.py`, `utils/subprocess.py`,
`core/http_probe.py`, `core/opsec_check.py`, and `core/webhook.py` were read in full.
Every load-bearing claim in this document (redirect-following defaults, the absence of
`authorize_collection()` callers, the `asn_lookup.py` gate gap, the
`CollectionAttempt`-before-claim gap) was independently re-verified by direct grep/read
after the initial pass, not taken on a single reading.

---

## 0. Headline: what already exists vs. what the mission assumed

Before enumerating gaps, one correction to the premise: this is **not** a codebase with
no authorization layer. Reading the implementation (not the docs) shows a materially
more mature system than "logical, ad hoc scope checks scattered per plugin." Specifically,
already present and already correct in the parts that are wired up:

| Already built | Where | Verified behavior |
|---|---|---|
| A composed scope+capability+OPSEC decision function | `core/intel/authorize.py: authorize_collection()` | Correct logic (scope AND capability AND OPSEC), but **zero production callers** — see §2. |
| A real indicator state machine | `core/intel/queue.py: IndicatorQueue` | `DISCOVERED→ELIGIBLE→IN_FLIGHT→{COLLECTED,FAILED,REJECTED,NOT_ALLOWED,PARTIAL}`. `overlay_status()` turns a restored `IN_FLIGHT` into `FAILED`, never invents `COLLECTED`. |
| Evidence-gated wildcard/CT follow-up | `core/intel/followup.py: evidence_supports_certificate_followup`, `wildcard_blocks_active_collection` | A plugin's `CERTIFICATE_SAN` claim is **not** trusted — the engine checks for a real `SAN_CONTAINS` relationship with a non-empty `evidence_id` before allowing a wildcard-zone name to be actively collected. |
| Independent discovery bounds | `core/intel/bounds.py: DiscoveryBounds` | ~15 separate caps already exist (entities, relationships, certificates, CT names/cert, follow-ups, follow-ups/relationship, DNS/HTTP probes, runtime, etc). |
| `Hypothesis` / `CollectionAttempt` first-class types | `core/intel/model.py` | Dataclasses exist and are used — see §3 for exactly how far. |
| A single subprocess-plugin choke point | `core/runner.py: PipelineRunner._run_single_plugin()` | `plugin.run(context, input_path)` is called from **exactly one** place in the whole repo (verified by repo-wide grep). This is a real structural asset Phase 1 can build on. |
| Seed vs. follow-up artifact isolation | `core/intel/artifacts.py`, `core/runner.py` | Already snapshot-once + suffixed sidecars + first-write-wins union + explicit skip-merge-on-exception. See §9 — this phase is **substantially done**, not a gap. |
| One stdlib HTTP chokepoint | `utils/network.py: open_url()` | Only 5 call sites in the whole repo use it; no scattered `requests`/`aiohttp`. |

What is **not** true, and is the real substance of this audit:

- Nothing makes any of the above *structurally mandatory*. `ReconPlugin.run()` (`core/plugin_base.py`) is an unconstrained async method — a plugin can call any network primitive it wants. Every safety property above holds by **convention**, not by construction.
- `authorize_collection()` — the one function whose docstring claims to be the composed authority — is **never called** by any plugin or runner code path.
- Three external crawler/scanner binaries (`katana`, `hakrawler`, `nuclei`) internally follow HTTP redirects **by default**, with **zero** Hydra re-authorization and **zero** proxy interception, once handed a single authorized seed URL.
- The browser guard built in the two preceding change sets is real and fail-closed for everything it intercepts, but has two concrete, unclaimed gaps: WebSocket connections and `window.open()` popups.

---

## 1. Full call-site inventory

Format per row: `CALL SITE → CAPABILITY → INPUT → AUTHORIZATION → NETWORK OPERATION → OUTPUT`. "AUTHORIZATION: NONE" means literally no scope/capability/OPSEC check runs on that specific line before the network operation — not "looks gated," an exact function-name citation or the word NONE.

### 1.1 Passive/enumeration plugins (no direct target-host authorization by design — seeds are the query)

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/subfinder.py:53` | dns/passive-enum | `context.targets[i].domain` (seed) | NONE (seed used directly; no per-call check) | `subfinder -d <domain> -silent -t <n> -timeout 30` | `subfinder.txt` → merged into `subdomains.txt` **unfiltered** |
| `modules/amass.py:58` | dns/passive-enum | `context.targets[i].domain` (seed) | NONE | `amass enum -passive -d <domain> -o <out> -timeout 5` | `amass.txt` → merged into `subdomains.txt` **unfiltered** |
| `modules/assetfinder.py:40` | dns/passive-enum | `context.targets[i].domain` (seed) | NONE | `assetfinder --subs-only <domain>` | `assetfinder.txt` → merged into `subdomains.txt` **unfiltered** |
| `modules/ctlogs.py:123` | http, to `crt.sh` (third party, not target) | `context.targets[i].domain` (seed) | NONE | `open_url("https://crt.sh/?q=%25.<domain>&output=json")` | `ctlogs.jsonl`, `ctlogs_domains.txt` (root-filtered via `_names_under_root`) → merged into `subdomains.txt` |

These four are `active_collection = False` by class attribute, so `core/runner.py:_gate_active_input` never touches their input (moot — none consumes a file-based target list; all query using the operator-supplied seed directly, which is inherently authorized). The residual risk is downstream, not here: **all four merge into the shared `subdomains.txt` with no per-name scope filter of their own.** This is currently safe only because every active consumer of `subdomains.txt` (dnsx, naabu) re-gates on read via `_authorized_input`/`filter_authorized_indicators`. A future plugin that reads `subdomains.txt` directly for active collection without going through that gate would inherit an unfiltered feed. `anew.py` (dedup) and `unfurl.py` (URL parsing) both touch `subdomains.txt`/alive-URL-derived text with the same "no filter of its own, correct only because of what already gates upstream/downstream" property, and neither performs network I/O itself.

### 1.2 DNS / TCP active-collection plugins

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/dnsx.py:76` | dns | authorized `subdomains.txt` derivative | `_authorized_input` (line 38, →`authorize_plugin_input`) **and** output re-filtered via `filter_authorized_indicators` (line 107) before write — double-gated | `dnsx -l <input> -a -aaaa -cname -mx -txt -ns -soa -caa -srv -ptr -resp -json -o <out> -silent -t <n> -retry 2` | `dnsx_records.jsonl`, `resolved.txt` (filtered) |
| `modules/naabu.py:98,328,505` | tcp | authorized `input_path` (line 58) | `_authorized_input` (line 58), transitively covers the tarpit-canary nmap call (l.328) and the naabu re-confirmation pass (l.505) | `naabu -l <input> -silent -c <n> -rate <r>`; `nmap -sV -Pn --version-light -p <ports> <host>` (tarpit canary) | `naabu.txt`, `tarpit_check.jsonl` |
| `modules/wildcard_check.py:108` | dns | synthetic canary names built from `context.targets` + `input_path` roots | `require_collection_scope` (l.58) + **explicit direct** `allows_active_collection` (l.76) on every root **before** any canary is built | `dnsx -l <canaries> -a -silent -resp -t <n> -retry 1` | `wildcard_canaries.txt`, `wildcard_check.jsonl` |
| `modules/port_verify.py:132` | tcp | `naabu.txt` (cross-plugin file) | Re-authorizes independently (l.57-60, `_authorized_input`) rather than trusting naabu's prior gate — the best-practice example in the set | `nmap -sV -Pn --version-light -p <ports> <host>` | `port_verify.jsonl` |
| `modules/whois.py:168` | whois (TCP to registry servers) | `context.targets` roots | `authorize_active_indicator(domain, scope, "whois", "seed_registration")` called **directly** (l.79) — the low-level primitive, not either named wrapper. Also uses `getattr(context, "collection_scope", None)` (l.76) instead of `require_collection_scope` — a missing scope degrades to a per-domain warning instead of the loud `ConfigurationError` every other plugin raises. | `whois <domain>` | `whois.jsonl` |
| **`modules/asn_lookup.py:158,198,347`** | dns (`getaddrinfo` fallback), whois (raw TCP to `whois.cymru.com:43`), dns (raw UDP to `*.asn.cymru.com`) | `context.resolved` / `dnsx_records.jsonl` (already dnsx-gated) | **NONE.** Confirmed by direct grep: zero occurrences of `allows_active_collection`, `authorize_active_indicator`, or `authorize_collection` anywhere in this file. `active_collection = True` and `capability = "asn"` are declared, but nothing in `run()` calls any authorization primitive on the IPs/hostnames it actually uses. Safety today depends **entirely** on dnsx having filtered `context.resolved` upstream — this file re-checks nothing. | Direct `socket.getaddrinfo`; raw `asyncio.open_connection` to `whois.cymru.com:43`; raw UDP `sock_sendto`/`sock_recvfrom` to system/public resolvers for `origin.asn.cymru.com` TXT records | `asn.jsonl` |

**`asn_lookup.py` is the weakest-gated plugin in the codebase that declares itself active-collection.** It is the one file in the entire inventory with `active_collection = True` and *zero* authorization calls of any kind.

### 1.3 HTTP / redirect handling

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/httpx.py:123` | http_probe (initial batch) | authorized host list | `_authorized_input` (l.110) + `require_collection_scope` (l.111) | `httpx -l <input> -silent -json ... -location` (no `-follow-redirects`) | `httpx.json`, `alive.txt`, `httpx_redirects.jsonl` |
| `modules/httpx.py:236` (`_fetch_single_hop`) | http_probe (one authorized redirect hop) | `next_url` from the prior hop's `Location` header | `allows_active_collection(next_url, scope)` (l.197) checked in the caller **strictly before** this call — confirmed no bypass on independent re-read | `httpx -u <url> -silent -json ... -location` | temp `httpx_hop_*.json`, deleted after read |

**Confirmed, no bypass**: every redirect hop httpx follows is individually authorized before the follow-up subprocess call; the loop is bounded (`httpx_max_redirect_hops`, default 10) and breaks without fetching on the first unauthorized hop. This is the one HTTP client in the codebase that matches Phase 4's target model exactly.

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/param_fuzz.py:236,278` | http (baseline + per-parameter canary GET) | `context.httpx_results`/`alive.txt` | `allows_active_collection(url, scope)` (l.206) — gated once at URL selection; per-parameter probes only append a query string to the same already-gated URL/host | `http_get()` (`core/http_probe.py`, stdlib `urllib`) | `param_fuzz.jsonl` |
| `modules/soft404_check.py:120,121` | http (root + random-path canary GET) | `context.httpx_results`/`alive.txt` | `allows_active_collection(host_or_url, scope)` (l.64) | `http_get()` | `soft404_check.jsonl` |
| `modules/security_headers.py` | — | `context.httpx_results` (headers already fetched by httpx) | n/a | **NONE — no network I/O in this file at all.** Confirmed by full read. | `security_headers.jsonl` |

### 1.4 Crawlers / vulnerability scanner (external binaries with their own HTTP client)

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/katana.py:63` | crawl | `authorized_alive.txt`/`alive.txt` | `_authorized_input` (l.32) — **on the seed list only** | `katana -list <alive> -silent -jsonl -c <n> -o <out> -jc` | `katana.jsonl` |
| `modules/hakrawler.py:42` | crawl | `_alive_urls(context)` | `filter_authorized_indicators` inside `_alive_urls` — **on the seed list only** | `hakrawler -plain -depth 2 -insecure` (stdin-fed) | `hakrawler.txt`, `hakrawler.jsonl` |
| `modules/nuclei.py:64` | vuln-scan | `authorized_alive.txt`/`alive.txt` | `_authorized_input` (l.32) — **on the seed list only** | `nuclei -l <alive> -silent -jsonl -o <out> -c <n> -rate-limit <r>` | `nuclei.json` |

**This is the most severe confirmed gap in the system**, verified against the actual installed binaries' `-h` output on this machine, not against Hydra's comments:

- **katana** (`-dr, -disable-redirects ... (default false)`): redirects are followed **by default**, and Hydra never passes `-dr`. `-fs, -field-scope ... (default "rdn")`: link-following scope defaults to the seed's **registered domain**, not the single authorized hostname — so even the crawl-discovery dimension (not just redirects) is broader than what Hydra actually authorized. `-proxy` exists but Hydra never passes it.
- **hakrawler** (`-dr  Disable following HTTP redirects.`): same shape — redirects followed by default, flag exists, Hydra never passes it. No scope-restriction flag exists in this tool at all; only `-subs` (unused) affects same-host-only crawling.
- **nuclei**: global HTTP-template redirect-following (`-fr`/`-fhr`) is correctly left *off* (Hydra doesn't enable it) — but individual templates can declare `redirects: true` in their own YAML and nuclei honors that regardless of the global flag. More significantly: `-ni, -no-interactsh` is never passed, so OOB/blind-vuln templates remain free to contact ProjectDiscovery's public interactsh collaborator servers (`oast.pro`, `oast.live`, `oast.site`, `oast.online`, `oast.fun`, `oast.me`) by default — real outbound network I/O to infrastructure that is neither the authorized target nor an operator-controlled endpoint. `-eh, -exclude-hosts` and `-p, -proxy` both exist and are both unused.
- **None of the three tools is passed `-proxy`.** `httpx` supports `-proxy <outbound_proxy_url>` under `strict_opsec` (`modules/httpx.py`); katana/hakrawler/nuclei do not receive the equivalent, so there is currently no interception point of any kind for their outbound traffic even under `STRICT_OPSEC=true`.

**Conclusion**: "I gave the crawler an authorized seed" is *not* "the crawler is scope-safe" here, exactly as the mission anticipated. Once launched, all three tools can and, per their own default configuration, will make requests to hosts Hydra never independently authorized — chased redirects for katana/hakrawler, OOB interactsh callbacks and template-declared redirect overrides for nuclei.

Cross-check performed: no code path was found where `gau.txt`/`waybackurls.txt` (both fed only by `context.targets[].domain`, each individually authorized via `authorize_active_indicator` before the archive-API subprocess call) is read back in as input to katana/hakrawler/nuclei. Their inputs are independently sourced from `alive.txt`/`authorized_alive.txt`.

### 1.5 Browser automation

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/browser_probe.py:~192` (`page.goto`) | browser (top-level navigation) | `target["probe_url"]` from `_httpx_targets()` (itself triple-checked against `allows_active_collection`) | `browser_request_decision` via the single `page.route("**/*", guard)` installed **before** `goto` | Playwright WebKit navigation | `browser_probe.jsonl` + `browser_probe_raw/<host>.html` |
| Every subresource fired by the rendered (potentially hostile) page — script/stylesheet/image/font/media/xhr/fetch/manifest/other/eventsource/texttrack, and cross-origin `<iframe>` navigations (Playwright reports these as `resource_type == "document"`, `is_navigation_request() == True`) | browser | Fully attacker-influenced page content | `browser_request_decision` per request, fail-closed on exception, fail-closed on missing scope | Allowed → real request; Denied → `route.abort("blockedbyclient")` | Aggregate `blocked_subresources`/`blocked_subresources_total` on the host's `browser_probe.jsonl` record |

**Confirmed real, unclaimed gaps** (the guard's own docstring claims coverage it does not have):

- **WebSocket connections bypass the guard entirely.** Hydra installs the guard exclusively via `page.route("**/*", guard)`. Playwright's `page.route()` does **not** intercept the WebSocket upgrade handshake — that requires the separate `page.routeWebSocket()`/`browserContext.routeWebSocket()` API (available in the pinned `playwright==1.62.0`), which is never called anywhere in `browser_probe.py`. A hostile page's `new WebSocket(wss://evil.example)` connects directly to any host, invisible to `blocked_subresources` and to any log.
- **`window.open()` / `target="_blank"` popups bypass the guard entirely.** The guard is installed on the page-scoped `page.route()`, not `browser_context.route()`, and there is no `browser_context.on("page", ...)` handler anywhere in the file to catch a page Playwright spawns in response to a popup. A new `Page` created in the same `browser_context` (which still shares cookies/storage from the same context) carries **no route handler at all** — fully unrestricted navigation and subresource loading, invisible to `blocked_subresources`, invisible to the `page.on("response", ...)` listener (also page-scoped).
- `service_workers="block"` (context creation option) does correctly prevent Service Worker *registration* at the browser-engine level — a real, useful control — but it is an unconditional engine feature flag, not a scope-aware extension of `browser_request_decision`, and it is a separate mechanism from the route guard.

### 1.6 Threat intelligence / vulnerability database / cloud endpoint probing

| Call site | Capability | Input | Authorization | Network op (actual connection target) | Output |
|---|---|---|---|---|---|
| `modules/threat_intel.py:108` | threat-intel-api | `host` from `_alive_hosts(context)` | `allows_active_collection(host, scope)` (l.127) gates the **value sent as data**, not the connection destination | `open_url()` POST to the **hardcoded** `urlhaus-api.abuse.ch/v1/host/`; `host` travels only as a urlencoded POST field | `threat_intel.jsonl` |
| `modules/vuln_match.py:207,261` | vuln-db-api (OSV.dev / WPScan) | tech name/version fingerprinted by httpx on an already scope-checked landing URL (l.142) | Same pattern — gates the fingerprinted host, not the API connection | POST to hardcoded `api.osv.dev/v1/query`; GET to hardcoded `wpscan.com/api/v3/plugins/{slug}` (`slug` is `quote(..., safe="")`-escaped, cannot break out of the URL path) | `vuln_match.jsonl` |

**Confirmed clean**: neither file has any code path where a target-derived string becomes the actual DNS/TLS connection destination. Both constants (`urlhaus-api.abuse.ch`, `api.osv.dev`, `wpscan.com`) are hardcoded; target data only ever travels as a request body field or an escaped path segment. This is exactly the Phase 8 distinction the mission asks for (target collection vs. provider access), and it is already correctly maintained — but only by convention (nothing stops a future edit from building the connection URL out of `host` instead of the request body).

| Call site | Capability | Input | Authorization | Network op | Output |
|---|---|---|---|---|---|
| `modules/cloud_bucket_enum.py:120,153` | cloud-http — **direct connection to cloud infrastructure, not a third-party API** | Canary probe: locally-generated random token (not target-derived). Main probe: `bucket` built from the seed domain's root label + a fixed suffix list | `require_collection_scope` (once, plugin entry) + a **single global opt-in boolean** `cloud_bucket_enum_authorize_derived`. **No per-hostname `allows_active_collection()` call anywhere in this file.** | GET to `https://{bucket}.s3.amazonaws.com/`, `https://storage.googleapis.com/{bucket}`, `https://{bucket}.blob.core.windows.net/...` — for S3/Azure the target-derived string is interpolated directly into the **DNS hostname** | `cloud_bucket_enum.jsonl`, `cloud_bucket_enum_raw.txt` |

**This is the one plugin where a target-derived string becomes the actual connection hostname**, and it is gated by a materially weaker mechanism (one-time opt-in flag) than every other active-HTTP plugin's per-URL `allows_active_collection()` check — a fact the plugin's own skip-message already partially acknowledges ("cloud-derived endpoints are not seed-scoped"), but the mitigation stops at "requires an explicit env flag," not "requires the same per-host authorization as everything else."

### 1.7 Non-target network paths (correctly out of scope for CollectionScope — noted for completeness, not flagged as gaps)

| File | What it does | Why it's not a target-collection concern |
|---|---|---|
| `core/opsec_check.py` | Raw TCP connect + HTTP GET to `api.ipify.org` (IP-echo) or the operator's own configured proxy | Only runs from the operator-invoked `check-opsec` CLI command, never during a scan. Never touches a target hostname — probes a neutral echo service or the proxy itself, by design (see module docstring). |
| `core/webhook.py` | POST to an operator-configured Slack/Discord webhook URL | Operator-supplied notification sink, not a target or discovered indicator. |
| `utils/network.py` | Shared `open_url()` transport (proxy-aware, certifi-verified TLS) | Pure transport helper; the 5 call sites into it (`ctlogs`, `threat_intel`, `vuln_match`, `opsec_check`, `webhook`) each carry their own authorization context as described above. |

---

## 2. `authorize_collection()` has zero production callers

Repeated, independently: `grep -rn "authorize_collection(" --include="*.py" .` (excluding the function's own definition) returns exactly one call site in the entire repository:

```
tests/test_adversarial_matrix.py:458:    blocked = authorize_collection(
```

Every plugin that performs any authorization check does so via one of:
- `allows_active_collection()` / `filter_authorized_indicators()` / `authorize_plugin_input()` (`core/intel/scope.py`) — **scope only**, no OPSEC parameter exists on these signatures.
- `authorize_active_indicator()` (`core/intel/authorize.py`) — the low-level primitive `authorize_collection()` itself wraps — called directly by `whois.py` and internally by `plan_followup_collection`/`apply_wildcard_seed_dns_policy`. Also scope-only; has no `strict_opsec`/`opsec_allowed` parameters.

OPSEC enforcement is a **separate, independent** mechanism: `core/runner.py:_run_single_plugin` checks `self.settings.strict_opsec and plugin.name not in STRICT_OPSEC_ALLOWED_PLUGINS` and skips the *entire plugin* before `plugin.run()` is even called. This is plugin-granularity (an allowlist of plugin names), not per-request, and it is never composed with the scope decision — they are two independent gates checked at two different places in the runner, not the single documented `authorize_collection()` path the mission (and the function's own docstring) describes.

**Practical consequence**: nothing today prevents scope and OPSEC from silently drifting apart. `authorize_collection()`'s logic is correct and already tested (`test_adversarial_matrix.py`) — it simply isn't wired into any runtime path. This is squarely a Phase 2 fix: replace the two independent gates with calls through this one function, or through a `CollectionGateway` that calls it internally.

---

## 3. `CollectionAttempt` — real, but with a confirmed crash-window gap

`intel_collection_attempts` is a real SQLite table (`core/store.py:368-382`: `id, run_id, attempt_id, indicator_id, value, capability, status, reason, collector, observed_at, artifact`, `UNIQUE(run_id, attempt_id)`), with both an incremental upsert path (`upsert_intel_attempts`, called from `_persist_indicators`) and a full-rewrite path at finalize (`persist_registry`).

`CollectionAttempt` objects are constructed in exactly one place in production code: `IntelEngine.record_attempt()` (`core/intel/engine.py:628`), called from exactly two sites, both in `core/runner.py`, both **after** the corresponding subprocess plugin has already finished and its output file has been parsed:

```
core/runner.py:816   engine.record_attempt(host, capability=DNS_RESOLUTION, success=ok, collector="dnsx", ...)
core/runner.py:869   engine.record_attempt(host, capability=HTTP_COLLECTION, success=ok, collector="httpx", ...)
```

Independently re-verified: `schedule_followup_collection()` (`core/runner.py:603`) claims `ELIGIBLE → IN_FLIGHT` via `engine.eligible_followups(...)` at line 609. `_persist_indicators()` — which writes both the `intel_indicators` table (the IN_FLIGHT claim) and whatever is currently in `engine.attempts` — is called at line 774, **before** the dnsx/httpx subprocess plugins actually run (lines 794/849) and therefore before either `record_attempt()` call exists for this pass. At that exact moment, `engine.attempts` is empty for this claim.

**Consequence**: if the process crashes between the IN_FLIGHT claim (line 609/774) and the corresponding `record_attempt()` call (816/869), the **indicator lifecycle** is crash-safe — `_overlay_indicator_lifecycle()` reads the persisted `IN_FLIGHT` row back on restart and `IndicatorQueue.overlay_status()` explicitly converts it to `FAILED` with `failure_reason = "interrupted_in_flight"` (never `COLLECTED`) — but the **fine-grained `intel_collection_attempts` audit table never gets a row for that specific attempt at all**. The coarse "what happened to this indicator" trace survives a crash; the granular "what actually went out on the wire, when" trace does not. This is exactly Phase 3's "attempt must be persisted BEFORE network I/O whenever possible" requirement, currently unmet.

---

## 4. Every place a network operation can occur with no authorization call at all

Consolidated from §1, this is the literal answer to the mission's Phase 0 question 7/8:

1. **`modules/asn_lookup.py`** — zero authorization calls of any kind on the IPs/hostnames it resolves/queries, despite declaring `active_collection = True`. (§1.2)
2. **`katana`/`hakrawler`/`nuclei` internal redirect-following and, for nuclei, interactsh OOB callbacks and per-template redirect overrides** — once launched with an authorized seed, these binaries' own HTTP clients can reach other hosts with zero Hydra involvement of any kind, gated or otherwise. (§1.4)
3. **Browser WebSocket connections and `window.open()` popups** — entirely outside the route-guard's interception surface; not gated, not logged. (§1.5)
4. **`modules/cloud_bucket_enum.py`**'s per-hostname cloud endpoint connections — gated by a plugin-entry opt-in boolean, not a per-host authorization call. (§1.6)
5. **`subfinder.py`/`amass.py`/`assetfinder.py`/`ctlogs.py`** writing into shared `subdomains.txt` with no per-name filter of their own — currently safe only because every present-day active consumer re-gates on read. A structural risk for future plugins, not a live one today. (§1.1)

Every plugin currently bypasses the *composed* `authorize_collection()` mechanism, because that mechanism has no callers at all (§2) — but every active-collection plugin except `asn_lookup.py` and `cloud_bucket_enum.py` does call *some* scope-only authorization function before its own direct network operations. The bypass that matters is not "a plugin ignores the gate" (rare — asn_lookup and cloud_bucket_enum are the only two) but "an external binary's own internal HTTP client operates below the level Hydra's gate can see at all" (katana/hakrawler/nuclei redirects, nuclei interactsh, browser websockets/popups).

---

## 5. Seed vs. follow-up artifacts — already correct (verified, not assumed)

Directly re-read `core/runner.py:734-972` and `core/intel/artifacts.py`. The design already matches Phase 11's requirement:

- `_copy_if_present` (artifacts.py) only copies a seed snapshot (`resolved_seed.txt`, `alive_seed.txt`, `httpx_seed.json`) if the destination doesn't already exist — frozen exactly once, never overwritten by a later pass.
- Follow-up plugin runs write to **suffixed sidecar files** (`context.metadata["dnsx_output_suffix"]`/`["httpx_output_suffix"]`), never the canonical filenames, so a follow-up pass cannot clobber `resolved.txt`/`alive.txt`/`httpx.json` even mid-run.
- `_merge_dnsx_followup`/`_merge_httpx_followup` recompute the canonical files as a **first-write-wins union** over `[seed snapshot, ..., followup_pass_N]` — seed entries are always in the union regardless of whether any follow-up pass produced anything.
- On a follow-up plugin-chain exception, the merge step is explicitly skipped (`core/runner.py:793-802`, `848-855`) and a warning is added: *"Follow-up DNS crashed; seed DNS artifacts preserved."* / *"Follow-up HTTP crashed; seed HTTP artifacts preserved."*

No code path was found where a failed or partial follow-up corrupts or overwrites seed artifacts. **This phase does not need new architecture — it needs verification tests (Phase 15/17), which do not yet exist.**

---

## 6. Cross-cutting findings, ranked

| Severity | Finding | Phase | Status |
|---|---|---|---|
| **CRITICAL** | `authorize_collection()` (scope+capability+OPSEC composition) has zero production callers. Scope and OPSEC are enforced as two independent, uncomposed mechanisms. | 2 | **Fixed §8** |
| **CRITICAL** | katana/hakrawler follow redirects internally by default with no Hydra re-authorization and no proxy interception; nuclei leaves interactsh (OOB) enabled by default and honors per-template redirect overrides regardless of global flags. None of the three is routed through any interception point. | 6 | Not fixed — needs the crawler containment proxy (Option A), a separate effort |
| **CRITICAL** | Browser: WebSocket connections and `window.open()` popups are completely outside the per-request guard's interception surface (`page.route()` doesn't cover either). | 7 | **Fixed §8** |
| **HIGH** | `asn_lookup.py` performs zero authorization checks despite `active_collection = True`; correctness depends entirely on trusting an upstream plugin's prior gate. | 1, 9 | **Fixed §8** |
| **HIGH** | `cloud_bucket_enum.py` dials real cloud infrastructure hostnames built from target data, gated by a coarser mechanism (one global opt-in flag) than every other active-HTTP plugin's per-host check. | 8 | **Fixed §8** |
| **MEDIUM** | `CollectionAttempt` rows are written only after a plugin completes and its output is parsed — a crash between an `IN_FLIGHT` claim and completion leaves the indicator lifecycle crash-safe but the fine-grained attempt-audit table silently incomplete for that attempt. | 3 | **Fixed §8** (follow-up path only — see §8 for the seed-path residual) |
| **MEDIUM** | `ReconPlugin.run()` has no structural constraint preventing direct network library use — every property above holds by convention, not by construction. Nothing stops a new or edited plugin from bypassing all of it. | 1 | Not fixed — this is the full `CollectionGateway` (Phase 1), a separate effort |
| **LOW** | Enumeration plugins (subfinder/amass/assetfinder/ctlogs) write into shared `subdomains.txt` with no per-name filter of their own; safe today only because current consumers re-gate on read. | 1 | Not fixed — no live consumer exploits this today; deferred |
| **LOW** | `whois.py` calls the raw `authorize_active_indicator` primitive directly (bypassing both named wrapper functions) and reads scope via `getattr(...)` instead of `require_collection_scope`, degrading a missing-scope condition to a warning instead of the loud fail-closed error every other plugin raises. | 2 | Not fixed — cosmetic/consistency issue, not a live bypass; deferred |
| **NOTE** | `unfurl_domains.txt` extracts hostnames from full URL strings, including query-string values — an authorized URL containing a third-party callback/redirect parameter could produce an OOS hostname in that file. Not currently consumed by any other plugin; a latent trap if one is added later. | 5 | Not fixed — no live consumer; deferred |
| **CONFIRMED SAFE** | `httpx.py`'s hop-by-hop redirect authorization has no bypass. | 4 | No action needed |
| **CONFIRMED SAFE** | `threat_intel.py`/`vuln_match.py` never let target-derived data become the actual connection hostname — only fixed third-party hosts, target data travels only as request body/path data. | 8 | No action needed |
| **CONFIRMED DONE** | Seed vs. follow-up artifact isolation already matches the required design. | 11 | No action needed |

---

## 7. What Phase 0 does *not* yet cover

This document traces call sites and their immediate authorization context. It does not yet include: a machine-checkable/automated version of this inventory (Phase 16's static check), the DNS-specific policy questions beyond what's captured in §1.2/§4 (Phase 9), the follow-up-loop hypothesis/evidence wiring beyond what `core/intel/followup.py` already does (Phase 10 — largely satisfied by the existing evidence-gated wildcard logic, per §0), or the reporting/historical/serialization phases (13-14), which are presentation-layer concerns downstream of the network boundary rather than part of it. Those are addressed, where in scope, in the implementation that follows this audit — not retroactively folded into this document.

---

## 8. Bounded gap closure (this change set)

Following the audit, five of the concrete findings above were fixed as a first, reviewable increment — chosen because each was well-understood, bounded in surface area, and didn't require inventing new infrastructure (the `CollectionGateway` itself and the crawler containment proxy are separate, larger efforts, deliberately not attempted here). Each fix was independently verified (real WebKit browser tests for the browser fixes, an actual crash simulation with real SQLite persistence for the attempt-durability fix, a direct empirical check against `authorize_active_indicator`'s output before and after for the cloud-endpoint fix) — not just asserted.

1. **`asn_lookup.py` (§1.2, §4.1):** the `getaddrinfo` fallback in `_resolve_hostnames` — the one place this plugin performs active DNS resolution of its own — now filters `context.resolved` through `allows_active_collection` before resolving, instead of trusting every entry came from dnsx's prior gate. Regression test (`test_infrastructure_plugins.py::test_asn_collect_ips_falls_back_to_resolving_hostnames`) asserts on the call into `_resolve_hostnames` itself — an OOS hostname never reaches it — not just on the filtered IP output.

2. **Browser WebSocket + popup bypass (§1.5):** `_install_scope_request_guard` is now installed on the `browser_context` (via `browser_context.route()` and the newly-added `browser_context.route_web_socket()`) instead of the page. Context-level routing covers every page created in that context, including a `window.open()` popup, and `route_web_socket` closes an unauthorized WebSocket without ever calling `connect_to_server()` — so the real TCP connection is never attempted. Two new tests in `test_browser_probe_scope_guard.py` prove this against a real WebKit browser: `test_websocket_to_out_of_scope_host_never_connects` uses a bare TCP-accept-counting server as the target and asserts **zero** connections were ever accepted (not just that no WS message came back), and `test_window_open_popup_to_out_of_scope_host_is_blocked` proves a popup's own top-level navigation is blocked.

3. **`cloud_bucket_enum.py` weak gate (§1.6):** every canary and candidate URL is now checked against `authorize_active_indicator(url, scope, "cloud_bucket_enum", ...)` immediately before the request, in addition to the existing plugin-entry opt-in flag check. This uncovered and fixed a real latent bug in `authorize_active_indicator` itself (`core/intel/authorize.py`): even with `CollectionScope.cloud_collection_allowed=True`, a generated bucket hostname was falling through to the normal seed-root scope check and getting denied anyway (a bucket name by design never shares a registrable domain with the seed) — meaning the opt-in flag could never actually have authorized anything. Fixed to return `ALLOW` explicitly for the `cloud_bucket_enum` operation once the policy is enabled. A new test (`test_scope_authorization.py::test_cloud_enum_scope_object_governs_even_if_settings_flag_is_stale`) proves the per-host `CollectionScope` object — not the `Settings` flag — is the actual authority, by deliberately constructing a scope object that disagrees with the settings flag.

4. **`authorize_collection()` wired into the real runtime (§2, §4.1):** `core/runner.py:_gate_active_input` — the single choke point every active-collection plugin's input passes through before `plugin.run()` — now calls `authorize_plugin_input(..., capability=plugin.capability, strict_opsec=settings.strict_opsec, opsec_allowed=plugin.name in STRICT_OPSEC_ALLOWED_PLUGINS)`, which threads through to `authorize_collection()` (scope AND OPSEC composed) instead of the scope-only `allows_active_collection`. The separate plugin-level STRICT_OPSEC skip in `_run_single_plugin` still exists as a fast-path (skip a disallowed plugin immediately, without running it pointlessly against an input file that would come back empty) — this is defense in depth beneath it, not a replacement: for every currently-passing scenario the two are provably equivalent (verified: `strict_opsec=False` never triggers the new branch at all; `strict_opsec=True` + an allowed plugin behaves identically). The new test `test_authorization_gate.py::test_gate_active_input_composes_opsec_not_just_scope` calls the gate directly, bypassing the plugin-level skip, and proves a STRICT_OPSEC-disallowed plugin's input is still emptied — the per-indicator gate is correct on its own, not merely correct because the other check usually runs first.

5. **`CollectionAttempt` pre-claim persistence (§3, §4):** `IntelEngine.claim_attempt()` (new) writes an `IN_FLIGHT`-status `CollectionAttempt` (new `AttemptStatus.IN_FLIGHT` enum value) immediately after `core/runner.py`'s follow-up loop claims a DNS or HTTP target and persists it (`_persist_indicators`) **before** `_run_plugin_chain`/`_run_single_plugin` actually invokes dnsx/httpx — closing the exact crash window the audit found. The completing `record_attempt()` call still writes its own SUCCESS/FAILED row afterward (a distinct attempt_id, since the reason differs) — the claim and completion are a two-row trail, not a single overwritten row. **Residual, not fixed:** this closes the gap for the *follow-up* collection path specifically (`schedule_followup_collection`/`_maybe_collect_followups`), which is where the audit found and demonstrated it; the initial *seed* dnsx/httpx invocations don't currently call `record_attempt()`/`claim_attempt()` at all (no `CollectionAttempt` rows exist for seed collection today, in either the old or new code) — extending pre-claim attempt persistence to the seed path, and unifying seed and follow-up onto one accounting model (the mission's Phase 3 "do NOT have a separate seed collection accounting path"), is deferred to the `CollectionGateway` work. New test: `test_followup_loop.py::test_followup_dns_crash_leaves_durable_in_flight_attempt` — simulates a real crash via a raising `_run_plugin_chain`, then queries the actual SQLite `intel_collection_attempts` table (not just in-memory state) and confirms the `IN_FLIGHT` row is there.

**Not attempted in this pass** (per the audit's own severity ranking, these require new infrastructure rather than a bounded fix to existing code, and are left for dedicated follow-up work): the `CollectionGateway` itself (Finding: `ReconPlugin.run()` has no structural constraint), the crawler containment proxy for katana/hakrawler/nuclei, and unifying seed vs. follow-up `CollectionAttempt` accounting into one path.
