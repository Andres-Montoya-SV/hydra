# Hydra architecture audit (forensic baseline)

**Date:** 2026-08-24  
**Entry point traced:** `python app.py run -d <target>`  
**Method:** line-by-line reading of `app.py` → `PipelineRunner.run()` → plugin `run()`, artifact create/overwrite/consume, `IntelEngine`, SQLite, reporters, CLI. README, prior docs, and green tests were treated as non-authoritative.

This document is the real runtime map **before** the Attack Surface Intelligence control-loop refactor. It is not a design wish list.

---

## 1. Process entry

`app.py:main` → `load_settings` → `cmd_run` → `PipelineRunner(settings).run(domain=..., targets_file=..., run_id=...)`.

`--no-ui` calls `runner.run` directly. With the dashboard, `ui/dashboard.py:run_with_dashboard` still ends in the same `PipelineRunner.run()`.

`run()` always:

1. `settings.ensure_directories()`
2. Builds `PipelineContext`
3. `load_targets(...)` → `context.targets`
4. `_enforce_scope(context.targets)` — **only if `settings.scope_file` is set**. Missing `SCOPE_FILE` is a no-op at this gate.
5. `context.collection_scope = CollectionScope.from_seeds(...)` — **always** attached, even without a scope file. Presence of this object is **not** authorization of a hostname.
6. Creates `output/<run_id>/`, `AssetStore` (`output/recon.db`), `HostRegistry`
7. `validate_tools` / optional binary install
8. Writes `targets.txt`
9. Runs plugin stages (below)
10. `_finalize_to_store` → HostRegistry parsers → `IntelligenceEngine` clusters/graph → `IntelEngine` snapshot → SQLite → reports/CLI artifacts

Crash path: `finally` may call `_finalize_to_store` again if `not context.finalized and context.subdomains`.

There is **no** central `authorize_active_indicator` primitive. Authorization is a scatter of `allows_active_collection`, `authorize_plugin_input`, `require_collection_scope`, and ad-hoc checks. `collection_scope != None` is used as a gate in `_output_path` for `active_collection=True` plugins — that only proves a scope object exists.

---

## 2. Actual stage order (`PipelineRunner.run`)

| Step | Code | Network / subprocess | Input | Authorization before I/O | Output |
|---|---|---|---|---|---|
| WHOIS | `whois` | subprocess `whois <root>` | `context.targets` (ignores `input_path`) | Scope object required to write output. No per-name `allows_active_collection`. | `whois.jsonl`, `whois_raw.txt` |
| Subdomain enum | subfinder, assetfinder, amass | subprocess per seed | `targets.txt` | `active_collection=False`. `_gate_active_input` is a no-op. Queries for the **seed**, writes whatever names the tool returns. | tool files, merge into **`subdomains.txt`** |
| CT | `ctlogs` | HTTPS crt.sh | `context.targets` | Passive. Not in `ACTIVE_COLLECTION_PLUGINS`. | `ctlogs.jsonl`, `ctlogs_domains.txt`, **appends into `subdomains.txt`** (in-scope and OOS SANs) |
| Dedupe | runner | none | `subdomains.txt` | none | rewritten `subdomains.txt`, `context.subdomains` |
| anew | `anew` | none | `subdomains.txt` | `_output_path` only | `subdomains_anew.txt` |
| Wildcard canary | `wildcard_check` | subprocess dnsx vs random `*.root` | `targets.txt` + parsed roots | `allows_active_collection` on **roots** | `wildcard_check.jsonl`. **Does not strip `subdomains.txt`.** Initial dnsx still resolves DNS-only junk under a catch-all. |
| DNS | `dnsx` | subprocess dnsx | `subdomains.txt` gated | `_gate_active_input` + plugin `_authorized_input`; output hostnames re-filtered | `resolved.txt` or `resolved{suffix}.txt`, `dnsx_records{suffix}.jsonl` |
| Strict OPSEC DNS skip | runner | none locally | `context.subdomains` | `_authorized_names` | authorized names written to `resolved.txt` without dnsx |
| ASN | `asn_lookup` | TCP whois.cymru.com / DNS + possible `getaddrinfo` | IPs / `context.resolved` | Scope object. IPs are not hostname-gated. | `asn.jsonl` |
| Ports | `naabu` | subprocess naabu | `resolved.txt` gated | `_authorized_input` | `naabu.txt` |
| Port verify | `port_verify` | subprocess nmap | **`naabu.txt`, ignores gated `input_path`** | Scope object only. Relies on naabu having been gated. | `port_verify.jsonl` |
| HTTP | `httpx` | subprocess httpx **`-follow-redirects`** | `resolved.txt` gated | Input hosts gated. Final URL classified; OOS landing **not** written to `alive.txt` (redirect observation). Tool still **fetches** the OOS Location once. | `httpx.json`, `alive.txt`, `httpx_redirects.jsonl` |
| Follow-up pass 1 | `_maybe_collect_followups` | dnsx + httpx again | Intel eligible names | planner + `_authorized_names` + collector gates | sidecars then merge into canonical files |
| Soft-404 / param fuzz | HTTP GET | alive / httpx records | per-URL `allows_active_collection` | jsonl |
| Cloud buckets | HTTP GET to derived cloud FQDNs | seeds | refused unless `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED` | jsonl |
| Threat intel | HTTPS URLhaus | hosts from httpx records | skip unauthorized hosts | jsonl |
| Vuln match | HTTPS OSV / WPScan | techs on httpx records | skip OOS landing URLs | jsonl |
| Optional concurrent | gau, waybackurls, katana, hakrawler, nuclei, unfurl | see §3 | runner passes `alive.txt` if non-empty else `resolved.txt`; gated for `active_collection=True` | katana/nuclei `_authorized_input` that file. hakrawler `_alive_urls()` re-filters. **gau/waybackurls ignore the path and use `context.targets`.** | tool-specific |
| Follow-up pass 2 | `_maybe_collect_followups` again | same | same | same | same sidecar class |
| Browser probe | Playwright WebKit | httpx URLs | start URL authorized; document navigations leaving scope aborted. **Subresources (CDN) not gated.** | jsonl + raw HTML |
| Finalize | parsers + both intelligence engines | none | all artifacts | Intel may observe OOS; must not probe | `recon.db`, reports |

`STRICT_OPSEC`: plugins not in `STRICT_OPSEC_ALLOWED_PLUGINS` skipped before `plugin.run`. httpx allowed (proxy). dnsx/naabu/crawlers/scanners are not.

---

## 3. SOURCE → TRANSFORMATION → ACTIVE COLLECTOR → AUTHORIZATION → ARTIFACT → PERSISTENCE

| SOURCE | TRANSFORMATION | ACTIVE COLLECTOR | AUTHORIZATION CHECK | OUTPUT ARTIFACT | PERSISTENCE |
|---|---|---|---|---|---|
| CLI `-d` / targets file | `load_targets` / `normalize_domain` | none | `_enforce_scope` only if `SCOPE_FILE` | `targets.txt` | run row `targets_json` at finalize |
| Seeds | subfinder/amass/assetfinder APIs | those tools | seed is operator-supplied; outputs ungated | `subdomains.txt` (union) | HostRegistry parsers → `hosts` / intel DOMAIN entities |
| Seeds | crt.sh JSON | `ctlogs` | passive | `ctlogs.jsonl`, names merged into `subdomains.txt` | intel CERTIFICATE + SAN_CONTAINS + indicators |
| `subdomains.txt` | line list | `dnsx` | `authorize_plugin_input` then plugin re-check; **wildcard policy not applied** | `resolved.txt`, `dnsx_records.jsonl` | DNS records / RESOLVES_TO |
| `resolved.txt` | host list | `httpx` | input gated; **redirect destination re-classified for alive set only** | `httpx.json`, `alive.txt` | HTTP services, TLS certs |
| CT SAN / TLS SAN | `IntelEngine._observe_san` | follow-up dnsx/httpx | planner `allows_active_collection` + wildcard reason **string** | `followup_domains.txt`, `resolved_followup.txt`, `alive_followup.txt` | merge into canonical; SQLite at **finalize only** |
| `alive.txt` | URL list | katana, nuclei, hakrawler, soft404, param_fuzz | re-filter / `_authorized_input` | crawler/scanner artifacts | parsers |
| httpx records | host extract | threat_intel, browser_probe, vuln_match | per-host/URL checks (uneven) | jsonl | metadata / findings |
| Seed brand labels | permute bucket names | `cloud_bucket_enum` | explicit derived-cloud flag | jsonl | URLs |
| Seeds | archive APIs | gau, waybackurls | seeds only; **discovered archive URLs not re-authorized as future probe targets** (not default crawler input) | `gau.txt`, `waybackurls.txt` | URL parsers |
| Host fields | `IntelligenceEngine.compute_clusters` / `build_infrastructure_graph` | none | none | in-memory graph | `clusters`, `graph_nodes`, `graph_edges` |
| Artifacts | `IntelEngine.ingest_*` + `correlate` | none | observation of OOS allowed | snapshot | `intel_*` tables |

---

## 4. Every place network I/O can occur

| Location | What is contacted | How hostname is obtained | Authorization today |
|---|---|---|---|
| `utils/subprocess.run_command` | child binary (dnsx, httpx, subfinder, …) | argv built by plugin | plugin-specific |
| `utils/network.open_url` | crt.sh, URLhaus, OSV, WPScan, opsec check, webhook | plugin/settings | plugin-specific |
| `modules/wildcard_check` | dnsx canaries | seed roots | root must be in scope |
| `modules/dnsx` | recursive resolvers / system DNS | gated input file | `authorize_plugin_input` |
| `modules/httpx` | target HTTP(S), **including redirect Location** | gated hosts; Location from server | input gated; destination **not** re-authorized before fetch |
| `modules/naabu` | TCP to resolved hosts | gated `resolved.txt` | input gated |
| `modules/port_verify` | nmap to naabu hosts | `naabu.txt` | **no second hostname gate** |
| `modules/asn_lookup` | Cymru / `getaddrinfo` | IPs or resolved names | scope object only |
| `modules/whois` | whois servers | registrable root of seed | scope object only |
| `modules/katana` / `hakrawler` | crawl from start URLs | authorized alive list | start gated; **in-page links not Hydra-authorized** |
| `modules/nuclei` | HTTP to list URLs | authorized alive list | list gated |
| `modules/browser_probe` | Playwright document + **subresources** | httpx URL | document navigations gated; subresources not |
| `modules/soft404_check` / `param_fuzz` | HTTP GET | alive/httpx | per-URL |
| `modules/cloud_bucket_enum` | derived cloud endpoints | brand from seeds | fail closed unless derived policy |
| `modules/threat_intel` | urlhaus-api.abuse.ch | httpx hosts | skip unauthorized hosts |
| `modules/vuln_match` | OSV / WPScan APIs | techs | skip OOS landing |
| `modules/gau` / `waybackurls` | archive APIs | **seeds**, not input file | seeds |
| `core/webhook.py` | operator webhook | settings | not target collection |
| `core/opsec_check.py` | proxy / IP echo | settings | diagnostic |

No `shell=True`. No `os.system`. Subprocess is argv lists with path confinement and output caps.

---

## 5. Every place a hostname/URL/IP/cert/ASN/NS/HTTP/tech becomes a collector input

| Producer | Consumer |
|---|---|
| `subdomains.txt` | dnsx (gated), context.subdomains |
| `resolved.txt` | httpx, naabu, optional plugins if alive empty, `context.resolved` |
| `alive.txt` | katana, nuclei, hakrawler, soft404, param_fuzz, optional input, **follow-up HTTP merge (buggy — see §7)** |
| `httpx.json` | parsers, IntelEngine, threat_intel, browser_probe, vuln_match, security_headers |
| `ctlogs.jsonl` | IntelEngine SANs → follow-up indicators |
| `dnsx_records.jsonl` | parsers, IntelEngine resolutions |
| `naabu.txt` | port_verify **ungated** |
| Intel queue ELIGIBLE | `followup_domains.txt` / `followup_http_targets.txt` → dnsx/httpx |
| Plugin `StructuredEmission.followups` | queue with **plugin-supplied reason string** (can be `CERTIFICATE_SAN`) |
| Redirect `url` field | historically alive.txt; now classified; **still fetched** |
| Derived `bucket.s3.amazonaws.com` | cloud_bucket_enum only if policy |

---

## 6. Artifact and follow-up code paths (search results)

### `alive.txt`

- **Written by:** `modules/httpx.py` (`alive{suffix}.txt`), follow-up merge, cache replay, `_finalize_to_store` rebuild from hosts.
- **Read by:** katana, nuclei, hakrawler (`_alive_urls`), soft404, param_fuzz, runner optional-plugin input, threat_intel runner arg (plugin actually uses httpx records), browser_probe runner arg (plugin uses httpx records).
- **P0:** `_merge_httpx_followup` unions `context.alive_urls` (follow-up invocation overwrites this to follow-up-only) with `alive_followup.txt`. **Does not re-read seed `alive.txt`.** Empty or partial follow-up HTTP can destroy seed liveness.

### `resolved.txt`

- **Written by:** dnsx (`resolved{suffix}.txt`), OPSEC skip path, `_merge_dnsx_followup`.
- **Read by:** httpx, naabu, runner after DNS, optional plugins if no alive.
- DNS merge is additive from canonical + `resolved_followup.txt` + `context.resolved`. Crash without sidecar leaves seed. **Not pass-numbered.** Follow-up still uses suffix `_followup` not `_followup_<pass>`. Canonical is rewritten in place after merge (seed not snapshotted to `resolved_seed.txt`).

### `subdomains.txt`

- Observation union. Contains OOS CT siblings by design. dnsx must not trust it; it goes through `authorize_plugin_input`. **Wildcard detection does not filter this file before seed dnsx.**

### Collectors invoked

| Tool | Invoked from | Input trust |
|---|---|---|
| dnsx | runner DNS stage + follow-up | gated file |
| httpx | runner HTTP + follow-up | gated file |
| katana | optional concurrent | `_authorized_input` of alive/resolved |
| nuclei | optional concurrent | same |
| hakrawler | optional concurrent | `_alive_urls()` re-filter |
| browser_probe | after optional | httpx records + navigation guard |
| threat_intel | after HTTP | httpx hosts + skip OOS |
| gau / waybackurls | optional | seeds |
| **No `authorized_alive.txt` canonical view.** | | |

### Follow-up indicators / COLLECTED

- `schedule_followup_collection` claims ELIGIBLE → IN_FLIGHT, writes follow-up input files.
- `context.metadata["followup_claimed_indicators"]` stores claimed names **before collectors succeed**.
- Next pass: `engine.queue.mark_collected` for `previously_claimed` **unconditionally**.
- After dnsx/httpx return, **all plan targets** are `mark_collected` even if the collector wrote zero rows or crashed after claim.
- Queue lives in a **fresh `IntelEngine` per pass**. Durable SQLite `intel_indicators` is written only at finalize. Crash vs never-discovered is not distinguishable mid-run.
- `CollectionStatus` has `NOT_COLLECTED`, `ELIGIBLE`, `IN_FLIGHT`, `COLLECTED`, `NOT_ALLOWED`, `REJECTED`, `FAILED`. **No `DISCOVERED`.** `FAILED` is only applied from `IN_FLIGHT` and is barely used by the runner.

---

## 7. Intelligence vs control loop

**Claimed architecture (README):** collect → intelligence → authorized follow-up → evidence → relationship → persistence → explanation.

**Actual architecture:**

```
seed collection (subfinder/CT/dnsx/httpx)
    → optional plugins
    → _maybe_collect_followups  (IntelEngine ingest artifacts, plan, dnsx/httpx suffix)
    → optional plugins again? no — second follow-up after optional
    → browser_probe
    → _finalize_to_store (HostRegistry + IntelligenceEngine clusters + IntelEngine snapshot)
    → SQLite + reports
```

Intelligence **does** run inside `_maybe_collect_followups` before follow-up collectors. That is a real loop, not a post-hoc sidecar **for indicator generation**. It is still a sidecar for:

- evidence/relationship persistence (finalize only)
- indicator lifecycle (metadata, not SQLite until the end)
- Host correlation (`compute_clusters` / `build_infrastructure_graph` assigns **HIGH** CDN and ASN edges independently of IntelEngine bands)
- `assets.json` (`export_run_json`) exports hosts/clusters/graph **without** `intel_relationships`
- Markdown/HTML/CLI format relationships independently (no `serialize_relationship`)

`CERTIFICATE_SAN` follow-up: planner treats the **enum value** as independent evidence for wildcard exemption. Plugin emissions can set `reason=CERTIFICATE_SAN` with **empty `evidence_id`**. `_observe_san` stores `evidence_id=name_obs.observation_id` (observation id, not `intel_evidence.evidence_id`). Planner does **not** verify that a certificate entity, SAN observation, and evidence row exist.

---

## 8. Dual correlation truth

| Surface | Source | Confidence semantics |
|---|---|---|
| CLI investigate / relationships / evidence | `intel_relationships` + `explain_relationship` | IntelEngine bands |
| HTML / Markdown intel sections | SQLite `intel_relationships` (ad-hoc formatting) | same rows, different presentation |
| `assets.json` | Host + clusters + host graph | **omits intel tables** |
| Host graph `served_by` CDN | `build_infrastructure_graph` | **HIGH** |
| Host graph ASN `belongs_to` | same | **HIGH** |
| Host clusters CDN/ASN | `cluster_signal_confidence` | **LOW** (already aligned with intel) |
| Intel SHARES_ASN / favicon / body hash | correlate.py | LOW unless corroborated |
| Intel SHARES_IPV4 on cloud | MEDIUM `shared_cloud_tenancy` | |

Host is treated as a source of correlation edges, not only a projection.

---

## 9. Invariants vs runtime (pre-refactor)

| Invariant | Runtime |
|---|---|
| No active collection without a concrete authorized indicator | Mostly true for dnsx/httpx/naabu **inputs**. False for httpx **redirect fetch**, katana **in-page links**, browser **subresources**, port_verify **naabu.txt trust**, initial dnsx **wildcard junk**, claimed-before-success follow-up. |
| Observation ≠ collection | OOS CT names are observed. They can still be **resolved** by seed dnsx if they pass `authorize_plugin_input` (in-scope eTLD). OOS eTLDs are withheld from dnsx. Wildcard DNS-only names **are** resolved if in-scope. |
| COLLECTED only after success | **False.** Claimed names and plan targets are marked COLLECTED regardless of collector output. |
| No relationship without evidence | Intel `_relate` requires an observation and creates evidence. Host graph CDN/ASN edges have **no evidence_id**. |
| No HIGH correlation without independent evidence | **False** for Host graph CDN/ASN. Intel pairwise SHARES_CERTIFICATE is capped; SAN_CONTAINS is hub-style. |
| No claim of collection before success | **False** for follow-up. |

---

## 10. Safety controls that must be preserved

- Structured subprocess argv; no `shell=True`
- Path confinement (`validate_output_path`, `atomic_write_text`)
- Output line caps
- SQLite + WAL + `foreign_keys`
- `STRICT_OPSEC` plugin allowlist + proxy requirement
- Fingerprint-first certificate identity (`core/intel/tls.py`, unidentified CT does not emit SHARES_CERTIFICATE)
- OOS observation + NOT_ALLOWED entity status
- Attribution restrictions (no actor/owner/campaign entities)
- Bounded discovery settings (`MAX_DISCOVERY_DEPTH`, probe caps, entity/relationship caps)
- Deterministic relationship IDs including certificate fingerprint identity

---

## 11. What tests currently prove vs do not prove

**Prove (with caveats):** authorize_plugin_input drops OOS from collector input; virusbarrier siblings are not DNS/HTTP probed; redirect OOS not added to alive.txt; follow-up DNS sidecar merge preserves seed DNS **when `_maybe_collect_followups` is called with pre-seeded artifacts**; IntelEngine unit ingest.

**Do not prove:** `PipelineRunner.run()` with an **in-scope** follow-up host (`www`) actually running follow-up DNS **and** HTTP and unioning seed alive; COLLECTED iff collector succeeded; CERTIFICATE_SAN reason forgery; wildcard blocking seed dnsx; CLI/HTML/Markdown/JSON consuming one serializer; durable indicator lifecycle across crash; `python app.py run` as the CLI entry with stubbed network.

`tests/test_pipeline_runner_e2e.py` uses virusbarrier SANs that are **all OOS except the seed**, so follow-up HTTP is stubbed to empty and **never exercises authorized follow-up collection**. Copying fixtures into `output_dir` then calling finalize is used in other tests — that is not a runtime E2E.

---

## 12. Refactor target (not yet true)

The production control loop must become:

```
seed / indicator
  → authorization (ALLOW | DENY | UNKNOWN fail-closed)
  → bounded collection
  → normalized entity
  → observation + provenance
  → evidence
  → relationship
  → hypothesis / follow-up indicator (evidence_id required)
  → bounded follow-up collection (immutable sidecars)
  → authorized atomic union
  → new evidence
  → correlation
  → durable SQLite history
  → explanation (one serializer)
```

Host remains the attack-surface **projection**. Intel entities/observations/evidence/relationships are the intelligence source of truth.
