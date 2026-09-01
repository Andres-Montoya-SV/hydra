# Hydra current-state architecture

**Date:** 2026-08-29
**Method:** runtime code, not README / prior reports. Entry: `python app.py run -d <target>` → `PipelineRunner.run()`.
**Rule:** observation is not authorization. Tests and comments were treated as untrusted; every claim below was verified this session (real subprocess runs, real WebKit tests, real SQLite persistence) — see `docs/FINAL_SECURITY_AUDIT.md` for full detail and exact citations.

This file is superseded in detail by `docs/FINAL_SECURITY_AUDIT.md` (the current authoritative
audit) and `docs/NETWORK_BOUNDARY_AUDIT.md` (the changelog of how the architecture got here). It
stays as a short, current-state map — not the previous revision's stale snapshot.

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

Network sinks (actual I/O) and what gates each one today:

| Sink | Module | Hostname source | Gate today |
|---|---|---|---|
| subprocess argv | `utils/subprocess.py` (no `shell=True`) | plugin argv | plugin-specific |
| dnsx | `modules/dnsx.py` | authorized input file | `_gate_active_input` (scope+OPSEC composed) + output re-filtered |
| httpx | `modules/httpx.py` | authorized input, then per-hop `-u` | `_gate_active_input` for the batch; **`AuthorizedCollectionTarget.authorize()` per redirect hop** — no `-follow-redirects`, never fetches an unauthorized `Location` |
| naabu / nmap | naabu, port_verify | authorized resolved / naabu list | `_gate_active_input`; port_verify independently re-authorizes rather than trusting naabu |
| katana / hakrawler / nuclei | respective modules | `authorized_alive.txt` / `_alive_urls()` | input gated **+ `ScopeEnforcingProxy` (`core/collection/crawler_proxy.py`) for every connection the tool makes on its own** — verified against the real installed binaries |
| Playwright | `modules/browser_probe.py` | httpx URLs | fail-closed on missing scope; `browser_context.route()`/`route_web_socket()` authorize every document/subresource/iframe/WebSocket request, including popups |
| urllib HTTPS | ctlogs, threat_intel, vuln_match, cloud_bucket_enum, param_fuzz, soft404_check | seeds / hosts / derived | per-request `allows_active_collection`/`authorize_active_indicator`; threat_intel/vuln_match connect to fixed third-party hosts, target data never becomes the connection host |
| sockets | `modules/asn_lookup.py` | resolved IPs / hostnames | Team Cymru query itself is data-gated (IPs from dnsx's prior gate); the `getaddrinfo` fallback — the one place this plugin does its own active DNS — is hostname-gated via `allows_active_collection` |
| whois binary | `modules/whois.py` | target roots | `authorize_active_indicator` per root |
| gau / waybackurls | archive APIs | seeds | per-seed `authorize_active_indicator` |
| cloud_bucket_enum | derived FQDNs | brand permute | plugin-entry policy flag **+ per-URL `authorize_active_indicator(..., "cloud_bucket_enum")`** |

No `os.system`, no `shell=True` execution, no `requests`/`aiohttp` in-tree.

---

## Invariant vs implementation

| Invariant | Current | Correction needed |
|---|---|---|
| A. Observation ≠ authorization | CT SANs, redirects, crawler discoveries all observed; OOS never enters canonical alive/resolved | none known |
| B. Fail closed without CollectionScope | `require_collection_scope` enforced for all 19 `active_collection=True` plugins, verified in one parametrized test that patches every network primitive | none known |
| C. One authorization API | `authorize_collection()` (scope+capability+OPSEC) is what `_gate_active_input` — the single choke point every active-collection plugin passes through — actually calls | not yet the *only* call path: several plugins (`asn_lookup`, `whois`, `gau`, `waybackurls`) still call the scope-only primitive directly for their per-target checks (safe today because OPSEC for them is enforced upstream at the whole-plugin skip, but not composed into that same call) |
| D. Redirects never expand authorization | httpx: per-hop authorization via `AuthorizedCollectionTarget`, no bypass on two independent reviews. katana/hakrawler: proxy-confined. | none known for these three; other plugins don't follow redirects at all |
| E. alive/resolved derived, not mutated ad hoc | seed snapshots + follow-up sidecars + atomic authorized union, verified pre-existing and correct | none known |
| F. COLLECTED only on success | queue has real DISCOVERED→ELIGIBLE→IN_FLIGHT→{COLLECTED,FAILED,REJECTED,NOT_ALLOWED,PARTIAL} transitions; `overlay_status` turns a restored IN_FLIGHT into FAILED, never COLLECTED | still hostname-level, not capability-level (DNS success + HTTP fail is one indicator, not two independent capability outcomes) |
| G. Collection attempts first-class | `intel_collection_attempts` table exists; `claim_attempt()` persists IN_FLIGHT before the follow-up subprocess runs | seed collection has no `CollectionAttempt` rows at all — not unified with the follow-up model |
| Hypothesis type | `Hypothesis`/`HypothesisStatus` exist, `authorize_hypothesis`/`reject_hypothesis`; a hypothesis never itself triggers collection | none known |
| Intel is correlation truth | `intel_relationships` is authoritative; Host graph/clusters remain a separate projection | none known (Host does not contradict Intel; not deeply re-audited this pass) |
| Certificate identity | `identity_kind`: sha256 → serial_issuer → unidentified; SHARES_CERTIFICATE requires an identified kind; never a manufactured fingerprint | none known; has dedicated tests including the live-shaped crt.sh record format |
| Wildcard | seed DNS policy + follow-up evidence gate (`evidence_supports_certificate_followup` requires a real relationship, not a plugin-claimed reason) | none known |
| Cloud endpoints | `CollectionScope.cloud_collection_allowed` + per-URL check, both must agree | none known — was broken (opt-in flag was a no-op), fixed this session |
| STRICT_OPSEC vs scope | composed via `authorize_collection(strict_opsec=..., opsec_allowed=...)` at the choke point; independent whole-plugin skip remains as a fast path beneath it | none known |
| RelationshipView | `serialize_relationship()` used by CLI (`cmd_relationships` and now `cmd_investigate`), Markdown, HTML, JSON | none known — `cmd_investigate` was on a separate unserialized path, fixed this session |
| CI format | `black`/`isort`/`ruff`/`mypy`/`bandit` all clean | none known |

---

## Follow-up / intelligence loop (as coded)

Pass 0: seed collect (enum files → gated dnsx input) → httpx → snapshot seed DNS/HTTP.

Pass 1+: `IntelEngine.ingest_artifacts` → `correlate` → `plan_followup_collection` (authorize + evidence + wildcard + budget) → `claim_attempt()` + persist (durable before the subprocess runs) → sidecar collect → authorized union → `record_attempt()` + persist.

Stop: `MAX_DISCOVERY_DEPTH`, probe budgets, `MAX_RUNTIME`. Second `_maybe_collect_followups` pass exists after optional plugins.

**Residual:** `COLLECTED` is still hostname-level, not per-capability. Seed collection has no `CollectionAttempt` audit trail (follow-up does).

---

## Network boundary (new since the previous revision of this document)

`core/collection/` holds the two new primitives:

- `target.py: AuthorizedCollectionTarget` — a frozen dataclass constructible only via `.authorize(...)` returning non-None on ALLOW. Wired into `modules/httpx.py`'s redirect-hop resolution as a concrete demonstration; not yet retrofitted across every plugin (that is the full `CollectionGateway`, still open).
- `crawler_proxy.py: ScopeEnforcingProxy` — a local HTTP/HTTPS forward proxy that authorizes every destination host before connecting, used unconditionally by katana/hakrawler/nuclei. Real TCP-level containment for exactly what it covers; not TLS interception, not a claim about a tool that bypasses its own configured proxy. Full detail: `docs/FINAL_SECURITY_AUDIT.md` §6-7.

---

## SQLite

WAL + `foreign_keys=ON` on connect. Intel tables: entities, observations, evidence, relationships,
indicators (+ lifecycle columns), `intel_hypotheses`, `intel_collection_attempts`. Truncation
flags on `runs`.

---

## Reporting

CLI (`cmd_relationships`, `cmd_investigate`)/HTML/MD/JSON all use `serialize_relationship`. Host
clusters/graph remain a reporting projection, not a second correlation source of truth.

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
- No active-collection plugin makes a network call without a scope (all 19, one test)
- Crawlers cannot reach an out-of-scope host their own internal client decides to request

---

## Implementation order for what's still open

1. Full `CollectionGateway`: retrofit `AuthorizedCollectionTarget` (or an equivalent) as the
   required parameter for every plugin's actual network-issuing call, not just httpx's redirect
   hops.
2. Unify seed and follow-up `CollectionAttempt` accounting into one model.
3. Per-capability (not per-hostname) `COLLECTED` status.
4. A real third-party-provider allowlist for the confinement proxy, so nuclei's OOB detection
   doesn't have to be all-or-nothing.
