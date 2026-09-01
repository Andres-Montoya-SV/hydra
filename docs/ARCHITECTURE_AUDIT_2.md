# Architecture Audit 2 — Network Capability Inventory

Written as its own checkpoint, before any code in Parts 2–7 of the
"Sprint Final de Arquitectura de Colección" is touched. Every prior
architecture document (`ARCHITECTURE.md`, `ARCHITECTURE_AUDIT.md`,
`FINAL_NETWORK_CONFINEMENT_AUDIT.md`, `READINESS_REPORT.md`, `RUNTIME_AUDIT.md`)
was treated as **untrusted** while producing this one — every row below was
verified by reading the current `run()` body of the module in question, not by
trusting what an earlier document claimed. Where this audit disagrees with an
earlier one (there is exactly one case — `RUNTIME_AUDIT.md` §5.4's httpx claim
is confirmed still accurate, no disagreements found), it says so explicitly.

## 1. Real execution path (traced from `app.py`, not assumed)

```
app.py:main()
  -> cmd_run() -> _external_mode_preflight() (classify owned/external, apply
     conservative defaults, confirm active modules if external)
  -> PipelineRunner.run(domain, targets_file, run_id)
       1. load_targets()                         — parse/validate CLI input
       2. _enforce_scope()                        — fail closed if SCOPE_FILE set
          and any target is outside it
       3. collection_scope = _collection_scope_for() — always attaches a
          CollectionScope (even with no SCOPE_FILE: seed-eTLD+1 fallback)
       4. Stage WHOIS (single plugin, before enumeration)
       5. Stage SUBFINDER — subdomain_plugins: subfinder, assetfinder, amass
       6. Stage DEDUPE — subdomains.txt rewritten
       7. anew (optional dedupe pass)
       8. wildcard_check — canary DNS probe before trusting passive enum
       9. Stage DNSX — resolve subdomains.txt -> resolved.txt
      10. asn_lookup — enrich resolved IPs
      11. Stage HTTPX — probe resolved hosts -> alive.txt / httpx.json
          (redirect hops authorized one at a time inside this stage)
      12. Optional/enrichment stage — parallel where independent:
          ctlogs, katana, hakrawler, gau, waybackurls, unfurl, nuclei,
          naabu -> port_verify, browser_probe, soft404_check, param_fuzz,
          cloud_bucket_enum, threat_intel, vuln_match, security_headers
      13. IntelEngine.finalize() — passive correlation, SQLite persistence
          (intel_hypotheses, intel_collection_attempts, entities,
          relationships, certificates)
      14. Follow-up collection pass (bounded, `MAX_DISCOVERY_DEPTH`) —
          re-enters authorization for every follow-up indicator before any
          of the same active plugins touch it again
      15. Reporting — Markdown + HTML summary (`core/reporter.py`) and JSON
          metadata, from persisted state only. Corrected from an earlier,
          imprecise "HTML/JSON/CSV" characterization of this step:
          `core/reporter.py` has no CSV writer at all (verified — only
          `_write_markdown_overview`/`_write_html_summary`); `httpx.csv` is a
          side artifact the `httpx` binary itself writes as part of its own
          probe output (`modules/httpx.py`), not a Hydra report format.
```

Confirmed by reading `core/runner.py:PipelineRunner.run()` end to end this
session (not assumed from a stage-name list) — matches the summary in
`docs/RUNTIME_AUDIT.md` §2 with no discrepancies found.

## 2. Method — how "every network-capable operation" was actually found

Ran, over `core/`, `modules/`, `config/`, `utils/`:

```
grep -rl "^import requests\|^import httpx\|^import aiohttp\|import urllib\|
  import socket\b\|from socket\|asyncio.open_connection\|create_connection\|
  urlopen\|playwright"
grep -rl "run_command\|subprocess\."
```

Every file that matched was read in full (or to the point of the network call)
this session — 26 plugin modules, `core/http_probe.py`, `core/webhook.py`,
`core/opsec_check.py`, `core/collection/{crawler_proxy,ssrf,gateway,target}.py`,
`utils/network.py`, `utils/subprocess.py`. No file was classified from its
name or a docstring alone.

## 3. Classification table

| Component | Network type | Directed at target? | Current enforcement | Requires gateway? | Requires proxy? | Risk |
|---|---|---|---|---|---|---|
| `soft404_check` | Python urllib (`core/http_probe.py`) | Yes | **`CollectionGateway`** — `AuthorizedCollectionTarget` for root + independently re-authorized canary, `gateway.http_get()` type-checked at runtime | Already done | Already done (gateway-owned `ScopeEnforcingProxy`) | Low |
| `param_fuzz` | Python urllib | Yes | **`CollectionGateway`** — baseline + every one of ~130 per-parameter probes independently authorized | Already done | Already done | Low |
| `cloud_bucket_enum` | Python urllib | Yes (generated bucket hostname, opt-in) | **`CollectionGateway`** — canary + candidate URLs, `cloud_collection_allowed` enforced per-URL via `operation="cloud_bucket_enum"` | Already done | Already done | Low |
| `httpx` (seed probe + redirect hops) | Subprocess (`httpx` binary) | Yes | `AuthorizedCollectionTarget.authorize_verbose()` pre-authorizes every redirect hop **before** the follow-up request is issued (no `-follow-redirects`); binary itself launched with `-proxy <ScopeEnforcingProxy>` unconditionally | N/A — not an in-process Python client, cannot literally hold a `CollectionGateway` instance; already uses the same sealed `AuthorizedCollectionTarget` primitive `CollectionGateway` wraps | Already done | Low |
| `browser_probe` (navigation + all subresource types) | Playwright/WebKit | Yes | WebKit launched with `proxy=<ScopeEnforcingProxy>`; `_install_scope_request_guard` routes every request (`document`, `script`, `image`, `stylesheet`, `font`, `xhr`, `fetch`, `websocket`, cross-origin iframe nav) through `browser_request_decision` -> `allows_active_collection` | N/A — same reasoning as httpx (Playwright is not a Python HTTP client `CollectionGateway.http_get()` can wrap) | Already done | Low |
| `katana` | Subprocess | Yes (own redirect/link discovery beyond the gated `-list`) | `-proxy <ScopeEnforcingProxy>` always passed via `_crawler_confinement` | N/A (binary) | **Confirm, not yet asserted by a static test** — see Part 2.2/2.3 | Low, pending confirmation |
| `hakrawler` | Subprocess | Yes | `-proxy <ScopeEnforcingProxy>` always passed | N/A (binary; no `-H`/header flag exists on the installed version) | Confirm | Low, pending confirmation |
| `nuclei` | Subprocess | Yes | `-proxy <ScopeEnforcingProxy>` always passed; `-ni` (no interactsh) unless operator opts in | N/A (binary) | Confirm | Low, pending confirmation |
| `naabu` | Subprocess, raw TCP/SYN port scan | Yes | Authorized target list only (`_gate_active_input`); **no connection-level confinement** — a SYN/connect port scanner cannot be routed through an HTTP forward proxy at all | No — architecturally incompatible with `ScopeEnforcingProxy` (not an HTTP-speaking client) | No (not proxyable) | **Medium** — real, honest residual: enforcement is authorization-only, not connection-pinned. Tarpit/portspoof canary check (`NAABU_TARPIT_CHECK`) and confirm-before-trust (`NAABU_CONFIRM_OPEN_PORTS`) are result-integrity controls, not confinement |
| `port_verify` (nmap) | Subprocess, TCP connect + service probe | Yes (naabu's already-open ports) | Same as naabu — consumes `naabu.txt`, no per-host `allows_active_collection` of its own, relies on naabu's upstream gate | No (same reason) | No | Medium, same residual as naabu |
| `dnsx` (seed + follow-up) | Subprocess, DNS query | Yes (query is *about* the target hostname) | `_gate_active_input` -> `authorize_plugin_input` before every resolution; output re-filtered | No — DNS resolution has no proxyable "connection to a resolved destination" for `ScopeEnforcingProxy` to intercept (UDP/TCP:53 to the *resolver*, not the target) | N/A | Low |
| `wildcard_check` | Subprocess (dnsx binary), DNS query | Yes (canary subdomains of the seed root) | `require_collection_scope` + `allows_active_collection` on roots before generating canaries | No, same reason as dnsx | N/A | Low |
| `whois` (registration lookup) | Subprocess (system `whois` client), raw TCP:43 | **Yes, indirectly** — the WHOIS server queried is selected by the target's TLD/registrar (via IANA referral chasing inside the system client), not a value Hydra chooses | **None at the connection level** — `run_command` execs the system binary directly; no proxy, no per-connection authorization beyond "this domain was an authorized target to begin with" | Not cleanly — `ScopeEnforcingProxy` speaks HTTP/CONNECT, not the WHOIS wire protocol; forcing it through would require either a WHOIS-aware proxy (new component) or reimplementing the client with raw sockets Hydra controls | No (current binary can't use one) | **Medium** — real gap, not previously documented this precisely. Low *exploitability* (whois is read-only registry lookup, destination is registry infrastructure keyed by public TLD data, not attacker-influenceable), but it is a genuine unconfined direct connection outside every other enforcement pattern in this document. See Part 2 recommendation. |
| `asn_lookup` | Python `asyncio.open_connection` (TCP `whois.cymru.com:43`) + DNS fallback | No — **`FIXED_THIRD_PARTY`**: hardcoded `_CYMRU_WHOIS_HOST`; target IPs are query *content* | N/A (fixed destination) | No | No | Low |
| `threat_intel` (URLhaus) | Python urllib (`utils.network.open_url`) | No — `FIXED_THIRD_PARTY`: hardcoded `_URLHAUS_HOST_ENDPOINT`; host is POST content | N/A | No | No (uses operator's own `outbound_proxy_url` for OPSEC, unrelated to target confinement) | Low |
| `vuln_match` (OSV.dev, WPScan) | Python urllib | No — `FIXED_THIRD_PARTY`: hardcoded `_OSV_QUERY`/`_WPSCAN_PLUGIN`; package/version is query content | N/A | No | No | Low |
| `ctlogs` (crt.sh) | Python urllib | No — `FIXED_THIRD_PARTY`: hardcoded crt.sh endpoint; seed domain is a query parameter | N/A | No | No | Low |
| `gau` | Subprocess, queries archive/OSINT APIs baked into the binary | No — **`FIXED_THIRD_PARTY`**: destination is the archive services `gau` itself talks to (not Hydra-chosen, not the target); target domain is the `--subs` argument, i.e. query data | No — there is no single "the target" connection to gate; `active_collection=True` here gates *which domains get queried as data*, not a target connection | No | Low. **Correction to the sprint's own tentative list**: Part 2.2 named `gau` as something to migrate to `CollectionGateway`; per this table's own classification rule ("hostname is data sent to a third party, not the connection destination") it does not qualify — see Part 2 for the actual disposition |
| `waybackurls` | Subprocess, web.archive.org | No — `FIXED_THIRD_PARTY`, same reasoning as `gau` | No | No | No | Low. Same correction as `gau` |
| `subfinder` | Subprocess, many internal OSINT sources | No (`active_collection` not set, defaults `False`) — **`PASSIVE_ONLY`** from Hydra's own model | N/A — Hydra doesn't choose or see the binary's internal per-source destinations | No | No | Low. The binary itself makes many real third-party queries Hydra cannot observe or confine — an inherent property of wrapping a compiled OSINT tool, not a Hydra gap |
| `amass` | Subprocess, many internal OSINT sources | No, same as subfinder | N/A | No | No | Low, same caveat |
| `assetfinder` | Subprocess, internal OSINT sources | No, same as subfinder | N/A | No | No | Low, same caveat |
| `anew` | Subprocess, stdin/stdout only | No — **`LOCAL_ONLY`** | N/A | No | No | None |
| `unfurl` | Subprocess, stdin/stdout only | No — **`LOCAL_ONLY`** | N/A | No | No | None |
| `security_headers` | None — reads already-collected httpx JSON | No — **`PASSIVE_ONLY`** (verified: no network primitive anywhere in the file) | N/A | No | No | None |
| `core/webhook.py` | Python HTTP POST | No — operator-configured URL (Settings, not discovered intelligence). Not "third party" in the target-data sense either — this is genuinely a 5th, unnamed bucket: **`CONTROL_PLANE`** (matches the term already used informally in `FINAL_NETWORK_CONFINEMENT_AUDIT.md`) | N/A | No | No | None |
| `core/opsec_check.py` (diagnostic probe) | Python HTTP | No — hardcoded probe host / operator's own `OUTBOUND_PROXY_URL` — `CONTROL_PLANE` | N/A | No | No | None |
| IntelEngine / correlation / SQLite / reporting | None | No — **`PASSIVE_ONLY`** / **`LOCAL_ONLY`** | N/A | No | No | None |

### On the 4-class taxonomy vs. what was actually found

The brief defines 4 classes; the real codebase needs a 5th label,
**`CONTROL_PLANE`**, for operator-configured infrastructure that is neither
target-derived nor a fixed Hydra-owned research endpoint (webhook URL, OPSEC
diagnostic probe). This is not a new finding — `FINAL_NETWORK_CONFINEMENT_AUDIT.md`
already used this exact term for the same two call sites — but it is worth
stating explicitly here since Part 1 asked for a strict 4-way split and the
honest answer is "4 classes plus one pre-existing, narrow exception, not 4
classes forced to fit."

## 4. What Part 2 actually needs to do, given this table

The sprint's own tentative list for Part 2.2 (`katana, hakrawler, nuclei, gau,
waybackurls, whois`, plus `threat_intel`/`vuln_match` "where applicable") is
**not** what this audit supports unmodified:

- `katana`, `hakrawler`, `nuclei`: **already proxy-confined**. Part 2.2's real
  work here is *confirming* (with a static test, Part 2.3) that every one of
  the three always receives `-proxy`, not adding confinement that doesn't
  exist yet.
- `gau`, `waybackurls`: **`FIXED_THIRD_PARTY`**, per this table's own rule.
  Forcing them onto `CollectionGateway` would be applying target-scope
  connection rules to a connection that is never made to the target — exactly
  the anti-pattern Part 1 warns against for OSV.dev/crt.sh. No migration
  needed; `active_collection=True` here is correctly gating query *data*, not
  a connection.
- `whois`: genuinely unresolved gap, but not a `CollectionGateway` migration
  either — see the table row. Needs its own design decision (WHOIS-aware
  proxy vs. Python-native raw-socket client vs. documented accepted risk),
  not a mechanical port of the existing pattern.
- `threat_intel`, `vuln_match`: **`FIXED_THIRD_PARTY`**, confirmed. No
  migration applicable.
- `naabu`, `port_verify`: architecturally cannot be proxy-confined (raw
  TCP/SYN, not HTTP). Their real gap is documented above as a residual risk,
  not something Part 2's gateway work can close.

## 5. Noted, not implemented (correlation/intelligence engine — out of scope this sprint)

Per the explicit instruction not to touch the correlation engine in this
sprint, one observation surfaced while tracing the execution path is recorded
here for a future round: `IntelEngine.finalize()`'s Host-graph vs. Intel-graph
reconciliation reads `context.resolved`/`context.alive_urls` as the
authoritative "what was actually collected" set, while
`intel_collection_attempts` is the durable per-indicator ledger — the two are
not currently cross-validated against each other for consistency (e.g., a host
present in `alive.txt` with no corresponding `SUCCESS` `CollectionAttempt` row,
or vice versa) at finalize time. Not a security defect — no path was found
where this could turn a denied/failed attempt into a false "collected" claim
in the current code — but worth a dedicated audit pass in the correlation
project mentioned in the sprint's own scope note.
