# Hydra runtime audit

**Date:** 2026-08-22  
**Entry point traced:** `python app.py run -d <target>`  
**Method of work:** line-by-line reading of `app.py` → `PipelineRunner.run()` → each plugin `run()`, plus artifact create/overwrite/consume. README, `docs/ARCHITECTURE.md`, comments, and green tests were treated as non-authoritative.

This document is the runtime map. Part B of the same change set (HTTP redirect ≠ authorization) is called out where it altered behavior. Everything else listed as a gap is **intentionally unfixed** here.

---

## 1. Process entry

`app.py:cmd_run` loads `Settings.from_env`, constructs `PipelineRunner(settings)`, and awaits `runner.run(domain=..., targets_file=..., run_id=...)`.

With `--no-ui` that call is direct. With the dashboard, `ui/dashboard.py:run_with_dashboard` still ends in the same `PipelineRunner.run()`.

`run()` always:

1. `settings.ensure_directories()`
2. Builds a `PipelineContext`
3. `load_targets(...)` → `context.targets`
4. `_enforce_scope(context.targets)` — **only if `settings.scope_file` is set**. Missing `SCOPE_FILE` is a no-op at this gate (see §8).
5. `context.collection_scope = self._collection_scope_for(context)` — **always** attaches a `CollectionScope`, even when no scope file exists (`CollectionScope.from_seeds(targets, patterns=loaded or [])`).
6. Creates `output/<run_id>/`, `AssetStore` (`output/recon.db`), `HostRegistry`
7. `validate_tools` / optional binary install
8. Writes `targets.txt` from `context.targets`
9. Runs the plugin stages below
10. `_finalize_to_store` → SQLite + reports

Crash path: `finally` may call `_finalize_to_store` again if `not context.finalized and context.subdomains`.

---

## 2. `PipelineRunner.run()` — actual stage order

Order is from `core/runner.py` `run()`, not from plugin `stage_order` alone. Optional plugins later run concurrently.

| Step | Code | Network / subprocess | Input | Authorization before I/O | Output |
|---|---|---|---|---|---|
| WHOIS | `whois` plugin | subprocess `whois <root>` | `context.targets` (not `input_path`) | `_output_path` requires `CollectionScope` object present. Does **not** call `allows_active_collection` per name. Roots come from `parse_hostname(target.domain)[2]`. | `whois.jsonl`, `whois_raw.txt` |
| Subdomain enum | subfinder, assetfinder, amass (`SUBDOMAIN_PLUGINS`) | subprocess per seed | `context.targets` / `targets.txt` | Not in `ACTIVE_COLLECTION_PLUGINS` for subfinder/amass/assetfinder (`active_collection=False`). `_gate_active_input` is a no-op. Queries APIs/sources for the **seed**, but writes whatever names those tools return. | `subfinder.txt` / `amass.txt` / `assetfinder.txt`, merge into **`subdomains.txt`** |
| CT | `ctlogs` | HTTPS to crt.sh | `context.targets` | Not active-collection. Passive discovery. | `ctlogs.jsonl`, `ctlogs_domains.txt`, **appends into `subdomains.txt`** (in-scope and out-of-scope SANs) |
| Dedupe | runner | none | `subdomains.txt` | none | `subdomains.txt` rewritten, `context.subdomains` |
| anew | `anew` | none (local) | `subdomains.txt` | `_output_path` only | `subdomains_anew.txt` |
| Wildcard canary | `wildcard_check` | subprocess dnsx vs random `*.root` | `targets.txt` plus roots parsed from it | `require_collection_scope` + `allows_active_collection` on **roots** before canaries | `wildcard_canaries.txt`, `wildcard_check.jsonl`, `wildcard_check_raw.txt`. Does **not** strip `subdomains.txt`. |
| DNS | `dnsx` | subprocess dnsx | `subdomains.txt` (then gated) | `_gate_active_input` → `authorize_plugin_input`; plugin `_authorized_input` again; output hostnames re-filtered | `resolved.txt` or `resolved_followup.txt`, `dnsx_records.jsonl` / `_followup` |
| Strict OPSEC DNS skip | runner | none locally | `context.subdomains` | `_authorized_names` | writes authorized names to `resolved.txt` without dnsx |
| ASN | `asn_lookup` | TCP whois.cymru.com:43 and/or DNS `origin.asn.cymru.com` | IPs from registry / `dnsx_records.jsonl` / **local `getaddrinfo` on `context.resolved`** | `_output_path` requires scope object. IPs are not hostname-gated. Fallback `_resolve_hostnames` is extra DNS. | `asn.jsonl` |
| Ports | `naabu` | subprocess naabu (+ tarpit canaries) | `resolved.txt` gated | `_authorized_input` | `naabu.txt`, `tarpit_check.jsonl` |
| Port verify | `port_verify` | subprocess nmap | **`naabu.txt` hosts, ignores gated `input_path`** | `_output_path` requires scope object. No per-host `allows_active_collection`. Relies on naabu having been gated. | `port_verify.jsonl` |
| HTTP | `httpx` | subprocess httpx, **no `-follow-redirects`** — one request per authorized hop, `Location` authorized before the next hop is requested | `resolved.txt` gated | `_authorized_input` on **input hosts**; each redirect hop re-checked against `CollectionScope` before httpx is invoked again (§5.4) | `httpx.json`, `alive.txt` (authorized URLs only after Part B), `httpx_redirects.jsonl`, `httpx.csv` |
| Follow-up pass 1 | `_maybe_collect_followups` | dnsx + httpx again | CT/intel eligible names | planner + `_authorized_names` + collector gates | sidecars `*_followup*`, then merge into canonical DNS/HTTP files |
| Soft-404 | `soft404_check` | HTTP GET | httpx records / `alive.txt` / `context.alive_urls` | `require_collection_scope` + `allows_active_collection` per target | `soft404_check.jsonl` |
| Param fuzz | `param_fuzz` | HTTP GET with canary params | live URLs | same per-URL gate | `param_fuzz.jsonl` |
| Cloud buckets | `cloud_bucket_enum` | HTTP GET to `*.s3.amazonaws.com` / GCS / Azure | brand labels from **seeds**, not `SCOPE_FILE` hosts | `require_collection_scope` then **refuses unless** `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED=true`. Derived cloud names are not seed-scoped. | `cloud_bucket_enum.jsonl` |
| Threat intel | `threat_intel` | HTTPS POST URLhaus | hosts parsed from `context.httpx_results` | After Part B: skip hosts that fail `allows_active_collection`. Does not use `alive.txt`. | `threat_intel.jsonl` |
| Vuln match | `vuln_match` | HTTPS OSV.dev / WPScan | techs on httpx records | After Part B: skip records whose **landing URL** is out of scope. Queries third-party DBs, not the redirect host — still treated as “do not attach OOS dest”. | `vuln_match.jsonl` |
| Security headers | `security_headers` | none (parses captured headers) | `context.httpx_results` | no live probe; will describe OOS landing headers if those records remain in `httpx.json` | `security_headers.jsonl` |
| Optional concurrent | gau, waybackurls, katana, hakrawler, unfurl, nuclei | see §3 | runner passes `alive.txt` if non-empty else `resolved.txt`; `_gate_active_input` filters that path for `active_collection=True` plugins | **katana/nuclei previously ignored `input_path` and read `alive.txt`.** After Part B they `_authorized_input` that file. hakrawler uses `_alive_urls()` (re-filters). gau/waybackurls ignore the path and use `context.targets`. | tool-specific |
| Follow-up pass 2 | `_maybe_collect_followups` again | same as pass 1 | same | same | same class of sidecars |
| Browser probe | `browser_probe` | Playwright WebKit **executes page JS** | `_httpx_targets(context.httpx_results)` — not `alive.txt` | After Part B: start URL must be authorized; document navigations to unauthorized hosts are aborted | `browser_probe.jsonl`, `browser_probe_raw/*.html` |
| Finalize | parsers + IntelEngine + SQLite | none | all artifacts | Intel observes OOS names; must not probe | `recon.db`, reports, `assets.json` |

`STRICT_OPSEC`: plugins not in `STRICT_OPSEC_ALLOWED_PLUGINS` are skipped before `plugin.run`. httpx is allowed (proxy). dnsx/naabu/crawlers/scanners are not.

---

## 3. Active operations (runtime truth)

### 3.1 DNS resolution

- **dnsx plugin:** subprocess. Input = gated `subdomains.txt` or `followup_domains.txt`. Writes `resolved.txt` (seed) or `resolved_followup.txt`. JSONL from the binary is **not** re-filtered line-by-line; hostname list written to `resolved*.txt` is filtered. If dnsx succeeds with unparseable output, it falls back to treating **authorized input** as resolved.
- **wildcard_check:** dnsx against random canaries under authorized roots.
- **asn_lookup `_resolve_hostnames`:** `getaddrinfo` on `context.resolved` when JSONL had no IPs.
- **Initial dnsx does not consult wildcard detection.** A catch-all zone still gets every `subdomains.txt` name resolved (gap, not Part B).

### 3.2 HTTP

- **httpx:** no `-follow-redirects`. Input hosts are gated, and httpx makes exactly one request per authorized hop: it reports the `Location` header without fetching it, Hydra checks that destination against `CollectionScope`, and only issues the follow-up httpx request (`-u <url>`) if it is authorized. An out-of-scope `Location` is never requested — not by httpx, not by Hydra — it is only recorded as an observation (§5.4). Bounded by `HTTPX_MAX_REDIRECT_HOPS` (default 10) to avoid an unbounded authorize-then-fetch loop against a redirect cycle.
- **soft404_check / param_fuzz:** stdlib HTTP to live URLs; per-URL `allows_active_collection`.
- **cloud_bucket_enum:** HTTP to cloud endpoints derived from brand tokens, only if the derived-authorize flag is on.
- **gau / waybackurls:** HTTP(S) to archive APIs for **seed** domains (`context.targets`), `capability=url_archive` but `active_collection=True` so `_output_path` requires a scope object. They do not filter discovered archive URLs before writing `gau.txt` / `waybackurls.txt`. Those files are not the default input to katana/nuclei (those use `alive.txt`).

### 3.3 TCP / UDP

- **naabu:** TCP (and configured ports) against gated `resolved.txt`.
- **port_verify:** nmap against hosts listed in `naabu.txt`.

### 3.4 Browser

- **browser_probe:** Playwright WebKit `page.goto(probe_url)`. `probe_url` is taken from httpx `url` (final) unless that host fails the gate, in which case it falls back to the authorized `input`. A route guard aborts **document navigations** whose hostname fails `allows_active_collection`; if evaluating that check itself raises, the guard now aborts too (fail closed — fixed this change set, §8 G-GUARD-1) rather than letting the request through. Subresource loads (CDN images/scripts) are **not** blocked — that is still a network touch of third-party hosts during an in-scope page load, and is **not** the same as seeding those hosts into `alive.txt`. Left as a documented residual.

### 3.5 Threat-intel / vuln APIs

- **threat_intel:** POST host to URLhaus. Host list is now scope-filtered.
- **vuln_match:** POST package/version to OSV (and optional WPScan). Records whose landing URL is out of scope are skipped.

### 3.6 Crawling / scanning

- **katana:** `-list <authorized alive file>`.
- **hakrawler:** stdin = `_alive_urls()` (filtered).
- **nuclei:** `-l <authorized alive file>`.
- Residual: once started on an in-scope URL, katana/hakrawler **follow page links**. Those tools are not given a Hydra-side allowlist of crawl destinations. An in-scope site that links to `login.vendor-cdn.net` can still be crawled by katana itself. That is a separate gap from “OOS redirect landed in `alive.txt`”.

### 3.7 Subprocess inventory

Every `BaseToolPlugin._execute` / `_execute_self_output` / `_run_tool` uses `utils.subprocess.run_command` (no `shell=True`). Built-in plugins use `open_url`, sockets, or Playwright.

---

## 4. Canonical artifacts — create / overwrite / consume

### `targets.txt`

- **Create:** runner, from CLI seeds.
- **Consume:** whois, subdomain plugins (indirectly via `context.targets`), wildcard_check, cloud_bucket_enum.
- Trusted as operator input after `_enforce_scope` when `SCOPE_FILE` is set.

### `subdomains.txt`

- **Create/merge:** subfinder, assetfinder, amass, ctlogs (SANs), runner fallback to seeds, dedupe overwrite.
- **Consume:** dnsx (gated), anew, runner `context.subdomains`.
- **Contains out-of-scope names by design** (CT siblings). That file is an observation union, not an authorization list. dnsx/httpx/naabu must not trust it blindly — they go through `authorize_plugin_input`.

### `resolved.txt` / `dnsx_records.jsonl`

- **Create:** dnsx without suffix (overwrites canonical names).
- **Follow-up:** `resolved_followup.txt` / `dnsx_records_followup.jsonl`; `_merge_dnsx_followup` unions into canonical. Seed `context.resolved` is not replaced inside `DnsxPlugin` when a suffix is set.
- **Consume:** runner HTTP input, naabu, asn_lookup, optional plugins if `alive.txt` is empty.
- Merge re-runs `_authorized_names` on hostnames. JSONL merge is first-write-wins by record identity; it does **not** drop a JSONL row whose `host` is out of scope if dnsx wrote it (should not happen if input was gated).
- **Crash:** follow-up dnsx crash does not replace canonical `resolved.txt` (sidecar missing → merge leaves seed). Confirmed in `tests/test_followup_artifacts.py`.

### `httpx.json` / `alive.txt`

- **Create:** httpx without suffix overwrites both.
- **Follow-up:** `httpx_followup.json`, `alive_followup.txt`. `_merge_httpx_followup` concatenates JSONL into `httpx.json`. Alive merge is `context.alive_urls + extra_alive`, then scope-filtered (Part B).
- **P0 remaining (not fixed here):** `HttpxPlugin.run` always sets `context.alive_urls` to **this invocation**. Follow-up httpx therefore drops seed URLs from the in-memory list before merge. Merge does not re-read seed `alive.txt` from disk. If follow-up HTTP runs, seed liveness used by later collectors can still be destroyed even though OOS URLs are now filtered. Part B only guarantees OOS destinations are not in the merged alive set.
- **Consume (treat as authorized targets unless re-checked):**
  - katana / nuclei — now `_authorized_input` (Part B)
  - hakrawler / unfurl — `_alive_urls` re-filters when scope is attached
  - soft404 / param_fuzz — own per-URL gates
  - runner optional-stage `input_for_optional`
  - cache replay `_apply_cached_artifact` (now `_restrict_alive_to_scope`)
- `httpx.json` **keeps** the raw followed URL (observation). Parsers still attach `HttpService.url` = final URL on the **input** host. Finalize rebuilds `context.alive_urls` from services but skips URLs that fail `allows_active_collection` (Part B).

### `httpx_redirects.jsonl` (Part B)

- Out-of-scope landing URLs with `scope_status` (`OUT_OF_SCOPE` / `UNKNOWN`), `collection_status: NOT_ALLOWED`, `confidence_score: 95`, `raw_artifact: httpx.json` (relative). Not an active target list.

### `followup_domains.txt` / `followup_http_targets.txt`

- Written by `schedule_followup_collection` after planner + `_authorized_names`.
- dnsx/httpx gate again. A corrupted file is not trusted if those plugins run.
- **P1 remaining:** claimed names are stored in `context.metadata["followup_claimed_indicators"]` **before** collectors succeed; the next pass marks them collected. Failed follow-up is not retried.

---

## 5. Redirects — confirmed problem, then Part B

### 5.1 Before Part B (what runtime actually did)

`HttpxPlugin._build_args` always passes `-follow-redirects` and `-location`.

After the binary returns, `run()` did:

```text
url = record.get("url") or record.get("input")
alive_urls.append(url)
write_lines(alive.txt)
context.alive_urls = alive_urls
```

ProjectDiscovery httpx sets `url` to the **final** URL after following redirects. So:

1. Operator authorizes `app.metaversejustice.com` via `SCOPE_FILE`.
2. httpx is only given that host (input gate works).
3. Origin 302s to `https://login.vendor-cdn.net/sso`.
4. httpx fetches the CDN (unavoidable with `-follow-redirects`).
5. **`alive.txt` received the CDN URL.**
6. katana used `-list alive.txt` (ignored runner-gated `input_path`).
7. nuclei used `-l alive.txt`.
8. hakrawler stdin = raw `alive.txt`.
9. `browser_probe._httpx_targets` used `record["url"]` as `probe_url` → Playwright opened the CDN.
10. `threat_intel._alive_hosts` parsed `input or url` → could query URLhaus for the CDN host.

**The independent review’s redirect finding was real.** Input-side `SCOPE_FILE` / `CollectionScope` did not apply to httpx **output**. Discovery of a `Location` header was treated as authorization.

Multi-hop: only the final `url` was written; intermediate in-scope hops were not consulted. A chain `in-scope → in-scope → OOS` still put OOS in `alive.txt`.

### 5.2 After Part B (this change set)

Same `CollectionScope` / `allows_active_collection` / `SCOPE_FILE` patterns. No second allowlist.

- Final URL in scope → `alive.txt` gets that URL (unchanged common case).
- Final URL out of scope / unknown → **not** in `alive.txt`. Authorized origin URL may remain so the in-scope host can still be crawled/scanned. Observation row in `httpx_redirects.jsonl` + `scope_status` on the httpx record.
- katana/nuclei `_authorized_input` the list they pass to the binary.
- `_alive_urls` re-filters.
- browser_probe will not **start** on an OOS URL; document navigations to OOS hosts abort.
- threat_intel / vuln_match skip unauthorized hosts / landings.

Part B (as originally shipped) still let httpx **fetch** the out-of-scope Location once via `-follow-redirects` before Hydra classified the result — that fetch was recorded, not used as a new seed, but the outbound request to the unauthorized host had already happened. §5.4 below closes that.

### 5.3 `SCOPE_FILE` unset (not redesigned here)

`_enforce_scope` does nothing.

`CollectionScope.from_seeds(targets, patterns=[])` still exists. `classify_scope` without patterns: any hostname under the seed’s **registrable domain** is `IN_SCOPE`; other eTLDs are `OUT_OF_SCOPE`.

So without a scope file:

- Redirect `app.example.com` → `cdn.cloudflare.com` is still `OUT_OF_SCOPE` (different registrable domain). Part B still keeps it out of `alive.txt`.
- Redirect `app.example.com` → `www.example.com` is still `IN_SCOPE` (same root). That is the original seed-root design, not “no protection”.
- There is **no** fail-closed “only the exact CLI host” mode unless `SCOPE_FILE` lists it.

Pending (later prompt, not this one): whether missing `SCOPE_FILE` should mean “exact seeds only” vs “seed eTLD+1”. Changing that is a product decision, not a redirect bug.

If `collection_scope` is missing entirely, `require_collection_scope` fails closed for active `_output_path` / `_authorized_input`. Production `run()` always attaches a scope object.

### 5.4 This change set: httpx stops fetching before authorizing

Part B (§5.2) removed the OOS destination from `alive.txt`, but the underlying gap the third independent review flagged was structural: `authorize_httpx_records` is a **filter on results**, not a barrier in front of the request. As long as `HttpxPlugin._build_args` passed `-follow-redirects`, the real HTTP GET to the unauthorized host happened before any Hydra code ran — authorization could only decide what to do with a fetch that had already occurred.

This change removes `-follow-redirects` entirely. `HttpxPlugin._build_args` keeps `-location` (httpx reports the `Location` header) and stops there — httpx never follows it. `HttpxPlugin._resolve_authorized_redirects` then walks the chain itself, one hop at a time:

1. httpx's single request to the authorized input returns; if the response carries `Location`, resolve it to an absolute URL.
2. Check that destination with `allows_active_collection` **before** any request is made to it.
3. Authorized → Hydra invokes httpx again, this time with `-u <url>` against just that one destination, and repeats from step 1 on its response.
4. Not authorized → stop. The destination is recorded as a `httpx_redirects.jsonl` observation (`scope_status`, `collection_status: NOT_ALLOWED`, `raw_artifact`) exactly as before, but **no request was ever sent to it** — not by httpx, not by Hydra.

Hop count is bounded by `Settings.httpx_max_redirect_hops` (env `HTTPX_MAX_REDIRECT_HOPS`, default 10) so a redirect cycle between authorized hosts can't turn into an unbounded authorize-then-fetch loop.

The common case — a single in-scope redirect — is unchanged from the outside: the landing URL still ends up in `alive.txt`, `httpx.json` still carries `scope_status`/`redirect_chain`, and no observation row is written. The only difference is that it now takes one httpx invocation per hop instead of one invocation that follows internally. A chain that goes in-scope → in-scope → OOS now stops fetching at the OOS hop; anything the OOS host might have redirected to next (a hypothetical hop 3) is never discovered, because Hydra never requests hop 2 to find out.

This obsoletes gap **G-REDIR-6** below (previously "confirmed, not fixed" item 6, §8) and the residual noted at the end of §5.2.

---

## 6. Plugin contract (how a plugin knows what it may touch)

There is **no** single function every plugin must call before every packet.

Layers that exist:

1. **`ReconPlugin.active_collection`** — if true, `_output_path` calls `require_collection_scope` (object must exist).
2. **`PipelineRunner._gate_active_input`** — if `plugin.name in ACTIVE_COLLECTION_PLUGINS`, rewrite `input_path` through `authorize_plugin_input` **immediately before cache lookup and `plugin.run`**.
3. **`BaseToolPlugin._authorized_input`** — dnsx, httpx, naabu (and now katana/nuclei) call this themselves.
4. **Ad-hoc `allows_active_collection`** — wildcard_check, soft404, param_fuzz, httpx output (Part B), `_alive_urls`, browser_probe, threat_intel, vuln_match.

Failure modes of this contract (still true after Part B):

| Plugin | Trusts which list? | Re-checks hostname? |
|---|---|---|
| dnsx / httpx / naabu | gated file | yes |
| katana / nuclei | gated alive file (Part B) | yes, via `_authorized_input` |
| hakrawler | `_alive_urls()` | yes if scope attached |
| browser_probe | httpx_results | yes (Part B) |
| threat_intel | httpx_results | yes (Part B) |
| port_verify | `naabu.txt` | **no** |
| whois / gau / waybackurls / ctlogs / subfinder | `context.targets` | object-exists only |
| cloud_bucket_enum | derived cloud FQDNs | separate flag, not `SCOPE_FILE` |
| asn_lookup | IPs | no hostname gate |
| security_headers | httpx_results | no new request |

**Trusted-file vs explicit check:** historically most post-HTTP tools trusted `alive.txt` as already authorized. That was false whenever httpx followed a redirect. Part B makes `alive.txt` a filtered list **and** re-checks at the crawler/scanner boundary.

---

## 7. Crash / timeout vs canonical seed artifacts

| Collector | Canonical overwrite? | Follow-up / sidecar? |
|---|---|---|
| dnsx seed | Yes — writes `resolved.txt` in place | suffix `_followup` avoids clobber; merge is additive |
| dnsx crash mid-follow-up | Seed files remain if sidecar absent | claimed indicators still burned (gap) |
| httpx seed | Yes — `httpx.json` + `alive.txt` | suffix `_followup` |
| httpx follow-up merge | JSON concatenated; alive union **from memory + sidecar**, not seed file + sidecar | seed `alive.txt` can still be wiped (gap) |
| subfinder/amass/assetfinder/ctlogs | Merge into `subdomains.txt` (union) | OOS names accumulate as observations |
| katana/nuclei | Own output files | do not rewrite `alive.txt` |
| Cache hit | Copies cached artifact; httpx special-cases existing `httpx.json` as `apply_path` | can restore an old `alive.txt`; Part B now re-filters context URLs, not necessarily the file on disk until a writer runs |

`finally` finalize-on-interrupt can persist a partial registry if `subdomains` is non-empty.

---

## 8. Gaps found (including Part B confirm/reject)

### Fixed in this change set (Part B only)

- **G-REDIR-1 (confirmed, fixed):** httpx final URL was copied into `alive.txt` without `allows_active_collection`.
- **G-REDIR-2 (confirmed, fixed):** katana/nuclei ignored gated `input_path` and scanned `alive.txt`.
- **G-REDIR-3 (confirmed, fixed):** browser_probe started on httpx `url` (final).
- **G-REDIR-4 (confirmed, fixed):** threat_intel / vuln_match could take the OOS landing as the subject.
- **G-REDIR-5 (confirmed, fixed):** multi-hop used only the final URL; filter now keys off the landing host.
- **G-REDIR-6 (confirmed, fixed — this change set, §5.4):** httpx no longer fetches an out-of-scope `Location` at all. `-follow-redirects` is removed; each hop is authorized before httpx is invoked again for it. Previously "confirmed, not fixed" item 6 below.
- **G-GUARD-1 (confirmed, fixed — this change set):** `browser_probe`'s in-page navigation guard (`_install_scope_navigation_guard`) fell open (`route.continue_()`) if evaluating `allow_browser_navigation` raised. It now aborts the navigation (fail closed) and logs the exception. The happy-path authorization logic (`scope is None → False`) was already correct; only the exception handler around it was fail-open.

### Confirmed, **not** fixed (later prompts)

1. **Follow-up HTTP clobbers seed `alive.txt` / `context.alive_urls`.** Same class as the old DNS clobber. Default `ENABLE_FOLLOWUP_COLLECTION=true`.
2. **Follow-up claims indicators before success.** Failed names are not retried.
3. **No `PipelineRunner.run()` E2E with an in-scope follow-up hostname** (virusbarrier fixture SANs are all OOS). Tests passing ≠ that path works.
4. **Wildcard DNS:** initial dnsx still resolves junk under a catch-all. Follow-up planner exempts `CERTIFICATE_SAN`. Plugin emissions can set that reason.
5. **Crawler link-follow:** katana/hakrawler, once started in-scope, can still request OOS links they discover themselves. Part B only stops **seeding** those URLs from httpx redirects.
6. **Browser subresources** to third-party hosts during an in-scope navigation are not gated (scripts/images/iframes/fetch can still reach unauthorized hosts even though document navigation is fail-closed). Planned as a follow-up `EgressPolicy`/subresource-guard prompt, not addressed here.
7. **Host clusters / `graph_edges` / `assets.json`** remain a second correlation story vs `intel_relationships`.
8. **Certificate identity, SAN bounds, intel queue durability** — engine exists; not re-audited as “done”. Queue is not a SQLite source of truth for IN_FLIGHT/FAILED.
9. **`port_verify` trusts `naabu.txt`.** Fine if naabu was gated; not a second check.
10. **Cloud bucket enum** probes non-seed cloud FQDNs when the derived flag is on.
11. **ASN `getaddrinfo` fallback** is extra DNS on resolved names.
12. **Reporting:** Markdown intel lines omit fingerprints; `export_run_json` omits intel tables.
13. **Two follow-up invocations per run** (after httpx and after optional plugins). Bounded by depth, not one-shot, not persisted as queue history.
14. **All of the above authorization is logical, not a network-level egress boundary.** A buggy plugin that skips the gate can still reach an unauthorized host; nothing at the socket/process level enforces `CollectionScope`. Planned as a follow-up `EgressPolicy` prompt, not addressed here.

### `SCOPE_FILE` missing

Not “no redirect protection”. Seed-root `CollectionScope` still classifies other eTLDs as out of scope. Exact-host-only programs need `SCOPE_FILE`. Do not change that default in this prompt.

---

## 9. What this audit is not

It does not claim Hydra is an iterative relationship engine. The live path is still: seeds → tools → files → Host/Intel snapshot → SQLite → reports, plus at most two bounded follow-up collector passes. Correlation (`SHARES_CERTIFICATE`, etc.) is computed in-process at finalize from artifacts, not by walking a durable hypothesis graph.

Later prompts should pick **one** gap at a time (alive clobber, queue, crawler link-follow, certificate identity, …) the same way this prompt picked redirects.
