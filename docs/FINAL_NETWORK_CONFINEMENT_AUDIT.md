# Hydra Final Network Confinement Audit

**Date:** 2026-08-30
**Method:** forensic grep across `core/` and `modules/` for every network-capable
primitive (`socket.`, `asyncio.open_connection`, `asyncio.start_server`, `.getaddrinfo`,
`urllib.request`, `requests.`, `httpx.` (Python lib — not present), `aiohttp.` (not
present), Playwright launch/route calls, and every subprocess-based external binary),
then tracing each hit to its actual caller and destination source — not assumed safe
because a plugin happens to call an `authorize()` function somewhere upstream.

This document is the flat inventory the mission asks for. It does not repeat the
narrative already written and independently verified in `docs/NETWORK_BOUNDARY_AUDIT.md`
and `docs/FINAL_NETWORK_BOUNDARY_AUDIT.md` (prior turns) — it is the artifact this
turn's mission specifically requires, cross-checked against the current tree.

## The core finding that drove this turn's work

Before this turn, **every network-issuing component in Hydra resolved DNS and
connected to its target independently of the Python-level authorization check that
ran before it.** `AuthorizedCollectionTarget` (httpx redirect hops) validated one
hostname/IP; the real httpx binary then resolved and connected a second time, on its
own, invisibly. The same was true for Playwright (browser_probe) and for every
`urllib.request` call in `soft404_check`/`param_fuzz`/`cloud_bucket_enum`. Only
katana/hakrawler/nuclei were actually confined at the connection level, via
`ScopeEnforcingProxy` — and that confinement was treated as a crawler-specific
solution rather than the general mechanism it actually is.

**This turn generalizes it.** `ScopeEnforcingProxy` is now the connection-level
enforcement point for six components, not three: katana, hakrawler, nuclei, httpx,
browser_probe (via Playwright's `proxy=` launch option), and the shared
`core/http_probe.py:http_get()` helper used by soft404_check/param_fuzz/
cloud_bucket_enum. In every case the resolve → validate → connect-to-validated-IP
step now happens at the proxy, not a second, independent, unobserved resolution by
the client.

## Table

| Network surface | Caller | Destination source | Hostname authorization? | DNS/IP validation? | Can DNS re-happen after auth? | Final socket destination controlled? | Bypasses CollectionGateway? | Classification | Disposition |
|---|---|---|---|---|---|---|---|---|---|
| Crawler discovery (katana/hakrawler/nuclei) | `modules/katana.py`/`hakrawler.py`/`nuclei.py` via `_crawler_confinement` | URLs discovered internally by the tool | Yes (`ScopeEnforcingProxy._authorize_with_reason` → `allows_active_collection`) | Yes (`core/collection/ssrf.py`, since prior turn) | **No** — proxy connects to the IP it just resolved+validated, never re-resolves | Yes — pinned to `connect_ip` | No (unless the binary opens a raw socket bypassing `-proxy` entirely — see UNTRUSTED_NETWORK_TOOL below) | TARGET_COLLECTION | **GUARANTEED** (for traffic that respects `-proxy`) |
| httpx seed probe | `modules/httpx.py:run()` | gated input file | Yes (`authorize_plugin_input`) | Yes — **new this turn**, via the confinement proxy | **No** — new this turn; httpx now launched with `-proxy <ScopeEnforcingProxy>` unconditionally (default mode and strict-opsec-without-external-proxy mode) | Yes — pinned to `connect_ip` | No (same raw-socket caveat as any subprocess) | TARGET_COLLECTION | **GUARANTEED** |
| httpx redirect hop | `modules/httpx.py:_resolve_authorized_redirects`/`_fetch_single_hop` | `Location` header, walked hop-by-hop | Yes (`AuthorizedCollectionTarget.authorize_verbose`) | Yes, twice: once in Python (`core/collection/ssrf.py`, prior turn) as a fast pre-check, once at the proxy (this turn) as the actual connection gate | **No** — the proxy connection is what's pinned; the Python pre-check is defense-in-depth, not the enforcement boundary | Yes | No | TARGET_COLLECTION | **GUARANTEED** |
| httpx via external OPSEC proxy (`strict_opsec` + `OUTBOUND_PROXY_URL` set) | `modules/httpx.py` → `_crawler_confinement` → `ScopeEnforcingProxy(upstream_proxy_url=...)` | operator-configured external proxy | Yes — Hydra's own scope check runs *before* anything is forwarded to the external proxy (**closed this turn**; httpx no longer talks to `OUTBOUND_PROXY_URL` directly at all) | Hydra-side (best-effort, own resolution) only — the external proxy still resolves independently at its own network location once the CONNECT/GET is forwarded to it | Yes, past the upstream hop — this is now a scoped, documented property of using an external proxy at all, not an unclosed gap: Hydra's own socket never touches the target directly in this mode | Not the final hop (the external proxy decides that) | Not by *Hydra's own socket* (which only ever touches the configured upstream proxy) | TARGET_COLLECTION | **GUARANTEED at the authorization layer (an unauthorized destination never reaches the external proxy); PROXY_CONFINED, not IP-pinned, past the upstream hop — inherent to chaining through an external proxy, not a bug** |
| browser_probe navigation/subresources | `modules/browser_probe.py:run()` | httpx-alive URL + everything the loaded page references | Yes (`browser_context.route()`/`route_web_socket()` → `allows_active_collection`) | Yes — **new this turn**, via `playwright.webkit.launch(proxy=confinement_proxy.proxy_url)` | **No** — new this turn | Yes — WebKit's own network stack connects through the proxy, not just the JS-visible `route()` layer | No (same raw-socket caveat if WebKit itself had an internal bypass, which live testing did not find) | TARGET_COLLECTION | **GUARANTEED** |
| browser_probe via external OPSEC proxy | `modules/browser_probe.py:run()` → `ScopeEnforcingProxy(upstream_proxy_url=...)` | operator-configured external proxy | Yes — same chaining fix as httpx (**closed this turn**) | Hydra-side only, same as httpx | Yes, past the upstream hop — same scoped, documented property as httpx | Not the final hop | Not by Hydra's own socket | TARGET_COLLECTION | **GUARANTEED at the authorization layer; PROXY_CONFINED past the upstream hop, same as httpx** |
| soft404_check / param_fuzz / cloud_bucket_enum (urllib via `core/http_probe.py:http_get`) | `modules/soft404_check.py`, `modules/param_fuzz.py`, `modules/cloud_bucket_enum.py` | already-alive host / candidate cloud bucket hostname | Yes (`allows_active_collection`/`authorize_active_indicator` per URL) | Yes — **new this turn**, via `http_get(url, proxy_url=confinement_proxy.proxy_url)` | **No** — new this turn | Yes | No | TARGET_COLLECTION | **GUARANTEED** |
| DNS resolution (dnsx, seed + follow-up) | `modules/dnsx.py`, `core/intel/followup.py` | gated input / eligible follow-up indicator | Yes | N/A — a DNS *query about* the hostname is not itself a connection to a resolved destination | N/A | N/A | No | TARGET_COLLECTION (query only) | **GUARANTEED** (authorization-wise; SSRF policy doesn't apply to a resolution query with no follow-on connection) |
| Port scan (naabu) | `modules/naabu.py` | gated input file | Yes | No | N/A (naabu does its own TCP connect scanning against ports on an already-authorized host string, not attacker-influenced) | No | Same raw-socket caveat as any subprocess | TARGET_COLLECTION | **INPUT_GATED_ONLY** |
| ASN lookup (target IP → ASN) | `modules/asn_lookup.py` | resolved target IPs, sent as WHOIS/DNS query *content* to `whois.cymru.com:43` (fixed) or Cymru's DNS zone (fixed) | Yes, for the hostname resolved | N/A for the resolution step; the actual TCP/UDP connection destination (`_CYMRU_WHOIS_HOST`) is a hardcoded constant, never target-derived | N/A | Yes — destination is a fixed constant | No | THIRD_PARTY_OBSERVATION (fixed destination; target data is query content, not the connection target) | **GUARANTEED** |
| Cloud bucket enumeration destination itself (`*.s3.amazonaws.com` etc.) | `modules/cloud_bucket_enum.py` | generated bucket hostname (opt-in, `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED`) | Yes, per-candidate (`authorize_active_indicator`) | Yes — new this turn (same `http_get`+proxy fix as soft404/param_fuzz above) | No | Yes | No | TARGET_COLLECTION | **GUARANTEED** |
| WHOIS (registration lookup) | `modules/whois.py` | seed domain | Yes | No | N/A — subprocess-based external `whois` client, not urllib | Subprocess-internal | Same raw-socket caveat | TARGET_COLLECTION (registration metadata, not HTTP content) | **INPUT_GATED_ONLY** |
| gau / waybackurls (passive archive query) | `modules/gau.py`, `modules/waybackurls.py` | seed domain, queried *against* a fixed third-party archive host | Yes (gates whether the seed is queried at all) | N/A — destination is the archive service, not the target | N/A | Yes — fixed third-party host | Same raw-socket caveat | THIRD_PARTY_OBSERVATION | **INPUT_GATED_ONLY** |
| threat_intel (URLhaus) | `modules/threat_intel.py` | `_URLHAUS_HOST_ENDPOINT` (hardcoded); target hostname is POST body content | Yes (gates which hosts are queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| vuln_match (OSV.dev, WPScan) | `modules/vuln_match.py` | `_OSV_QUERY`/`_WPSCAN_PLUGIN` (hardcoded); target-derived data is POST body / URL path segment, not hostname | Yes (gates which findings are queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| CT logs (crt.sh) | `modules/ctlogs.py` | fixed crt.sh endpoint; seed domain is a query parameter | Yes (gates the seed being queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| Webhook notifications | `core/webhook.py` | operator-configured webhook URL (Settings, not discovered intelligence) | N/A — not target-derived | N/A | N/A | Yes — operator-fixed | No | CONTROL_PLANE | **GUARANTEED** |
| OPSEC diagnostics (`check-opsec`) | `core/opsec_check.py` | hardcoded probe name (`"example.com"`) / operator's own `OUTBOUND_PROXY_URL` | N/A — not target-derived | N/A | N/A | Yes | No | CONTROL_PLANE | **GUARANTEED** |
| Raw-socket bypass of any of the above tools' own proxy configuration | any subprocess, hypothetically | arbitrary | N/A — never reaches the proxy at all | N/A | N/A | **No** | **Yes, by construction** | N/A | **EXPLICITLY_UNTRUSTED** — see `PROXY_VERIFIED_TOOLS`/`UNTRUSTED_NETWORK_TOOL` below |

## PROXY_VERIFIED_TOOLS (updated this turn)

`core/collection/crawler_proxy.py:PROXY_VERIFIED_TOOLS` now lists **five** confirmed-live
entries, up from three: `katana`, `hakrawler`, `nuclei` (prior turns), plus **`httpx`**
and **`browser_probe`**, both added this turn after live verification:

- `tests/test_httpx_confinement_live.py` — the real installed httpx binary, routed
  through the real proxy via `-proxy`. Proves both directions (authorized target
  reached; in-scope hostname resolving to a private IP gets zero real connections)
  against a real local server.
- `tests/test_browser_confinement_live.py` — real WebKit, launched by the real
  `BrowserProbePlugin.run()` with Playwright's `proxy=` launch option pointed at the
  real confinement proxy. Same two directions, real local server.
- `tests/test_urllib_confinement_live.py` — the real `Soft404CheckPlugin.run()`
  (representative of all three `http_get`-based plugins, which share the identical
  call shape) against a real local server, same two directions.

`soft404_check`/`param_fuzz`/`cloud_bucket_enum` are not external subprocess binaries
(they are Hydra's own Python code calling `urllib.request` directly) — `PROXY_VERIFIED_TOOLS`
specifically tracks *external binaries whose respect for a `-proxy` CLI flag can't be
assumed*, so this classification doesn't apply to them the same way; their proxy usage
is proven the same way browser_probe's is — a live test against a real server — and is
documented as such rather than silently folded into `PROXY_VERIFIED_TOOLS`.

## OPSEC proxy chaining (closed this turn)

Previously documented as a deliberate exception: when `STRICT_OPSEC=true` and
`OUTBOUND_PROXY_URL` was configured, httpx and browser_probe routed through the
**external** operator-configured proxy *directly*, bypassing Hydra's local
confinement proxy entirely. A prior turn's mission explicitly overrode that scoping
decision and made closing it mandatory. Fixed by adding `upstream_proxy_url` to
`ScopeEnforcingProxy` (`core/collection/crawler_proxy.py`): the topology is now

```
collector -> ScopeEnforcingProxy -> upstream_proxy_url (OUTBOUND_PROXY_URL) -> Internet
```

never `collector -> upstream_proxy_url -> Internet` directly. httpx, browser_probe, and
the three urllib-based plugins all removed their own separate "use the external proxy
directly" branch and now unconditionally go through `_crawler_confinement`
(`modules/_base.py`), which passes `Settings.outbound_proxy_url` as
`upstream_proxy_url` to the local proxy. Hydra's scope + best-effort SSRF check
(`_authorize_with_reason`) always runs *before* a CONNECT/GET is ever forwarded to the
external proxy — an unauthorized destination never reaches it.

**What this does and does not provide, stated exactly as the mission demanded:** the
external proxy still resolves the target hostname itself, from its own network
location, once Hydra forwards the request to it — Hydra cannot observe or control that
resolution, so the destination-IP *pinning* `ScopeEnforcingProxy` normally guarantees
does not extend past the upstream hop. This is a structural property of using an
external proxy at all (Hydra's own socket only ever touches the configured upstream
proxy in this mode, never the target directly), not a partial implementation.

Verified three ways: `tests/test_opsec_proxy_chaining.py` proves, with a second real
`ScopeEnforcingProxy` instance standing in as the external proxy, that (1) an
authorized destination is actually forwarded through and reached, with the external
proxy showing exactly that one connection; (2) an out-of-scope destination is refused
by Hydra's own proxy and the external proxy shows **zero** activity for it; (3) an
in-scope hostname resolving (per Hydra's own resolver) to a private IP is refused the
same way, before ever reaching the external proxy. A fourth, manual check drove the
**real installed httpx binary** through this exact chain (`httpx -proxy <Hydra proxy>`
→ chained external proxy → real destination server) and confirmed the real destination
was reached with the external proxy correctly logging the forwarded connection.

## Raw-socket bypass: honestly unresolvable by an application-level proxy

`tests/test_untrusted_network_bypass.py` (prior turn) proves concretely that a process
ignoring its own `-proxy`/launch-time proxy configuration and opening a raw socket
directly is invisible to `ScopeEnforcingProxy` — no test this turn found a way to close
this with application-level code, because it is not fixable at that level by
construction. Hydra does not claim otherwise: `PROXY_VERIFIED_TOOLS` names only the
five components individually proven live; any other collector wired into
`_crawler_confinement` gets an explicit `UNTRUSTED_NETWORK_TOOL` warning
(`modules/_base.py`) instead of a silent, unverified confinement claim. True OS/process-
level containment (network namespace, egress firewall rule, container policy) remains
outside Hydra's own code, stated as a limitation, not hidden as a guarantee.

## Static architectural guard (new this turn): security by construction, not convention

Every fix in this multi-turn arc — httpx's own DNS resolution bypassing validation,
browser_probe's WebKit connecting outside `route()`'s visibility, three urllib plugins
never using the confinement proxy by default — was found by manual/forensic audit, one
per turn. Nothing stopped the *next* one from being introduced silently.
`tests/test_no_bypass_network_primitives.py` closes that specific gap: it statically
scans every `modules/*.py` file (AST-based, not a regex) for a direct import of
`requests`/`aiohttp`/`urllib.request`, or a direct call to
`socket.socket`/`socket.create_connection`/`asyncio.open_connection`/
`asyncio.start_server`/`asyncio.open_unix_connection`, and **fails the test suite**
unless that file is in an explicit allowlist with a stated reason (the four
`THIRD_PARTY_OBSERVATION` modules — `ctlogs.py`, `threat_intel.py`, `vuln_match.py`,
`asn_lookup.py` — each connects to a fixed, hardcoded endpoint, verified by re-reading
every one this turn).

This is deliberately narrow — an import/call-site scanner, not a data-flow analysis of
whether a given URL is target-derived. It cannot prove a new collector's destination is
safe. What it guarantees: a future contributor cannot add `requests.get(target_url)`
to a new collector module and have it pass the test suite silently — the guard fails,
naming the exact file and primitive, forcing a human decision (fix it, or add an
allowlist entry with a reason a reviewer can evaluate) before it ships. Two tests prove
the scanner isn't a no-op: one plants a synthetic `requests.get(url)` file and confirms
it's flagged; another plants `import asyncio; asyncio.open_connection(...)` (proving
call-site detection, not just import-site — `asyncio` itself is imported everywhere
legitimately, so only the specific attribute-access call is prohibited).

**Honest limit:** this is a regression guard, not a sandbox. It does not stop
`getattr(requests, "get")(url)`, a dynamically constructed import, or a new raw
primitive this list doesn't yet name. It raises the cost of reintroducing a known bug
class from "nobody notices" to "a human must explicitly justify it in a diff reviewers
can see" — that is the entire, deliberately bounded claim.

## What was checked and found already correct (not touched)

- `modules/asn_lookup.py`'s WHOIS-over-TCP (`whois.cymru.com:43`) and DNS-based ASN
  fallback connect to a **hardcoded** third-party endpoint — target-derived IPs are
  query *content*, never the connection destination. Correctly excluded from
  target-collection SSRF rules per this turn's own classification guidance
  (`TARGET_COLLECTION` vs. `THIRD_PARTY_OBSERVATION`) — changing this would be
  applying target-scope rules to a legitimate, fixed-destination API for no security
  benefit.
- `modules/threat_intel.py` (URLhaus), `modules/vuln_match.py` (OSV.dev, WPScan),
  `modules/ctlogs.py` (crt.sh), `modules/gau.py`/`modules/waybackurls.py` (web.archive.org)
  all connect to hardcoded, allowlisted third-party hosts with target data only in the
  query body/path/parameters — same correct classification, same no-op disposition.
- `core/webhook.py`, `core/opsec_check.py` — operator-configured or hardcoded-diagnostic
  destinations, never derived from discovered intelligence — `CONTROL_PLANE`, correctly
  excluded.

## Fixed this turn (all verified against real servers/binaries/engines, not mocks)

1. httpx seed probe + every redirect hop now routed through `ScopeEnforcingProxy`
   (`-proxy` flag, unconditional outside the external-OPSEC-proxy exception).
2. browser_probe's WebKit instance now launched with `proxy=` pointed at the same
   confinement proxy — closing the gap where `route()` decided abort/continue from a
   hostname string without ever resolving or pinning the actual destination IP.
3. `soft404_check`, `param_fuzz`, `cloud_bucket_enum` — all three call the same
   `core/http_probe.py:http_get(url, proxy_url=...)` helper, which already supported a
   proxy parameter; all three now pass the confinement proxy's URL instead of `None`
   in the default (non-external-proxy) configuration.
4. `PROXY_VERIFIED_TOOLS` grew from `{katana, hakrawler, nuclei}` to
   `{katana, hakrawler, nuclei, httpx, browser_probe}`, each addition backed by a new
   live test against a real binary/engine, not a documentation claim.

Live production check (not a synthetic test): `HttpxPlugin.run()` against the actual
authorized target `virusbarrier.xyz` recorded the confinement proxy blocking **15 real
out-of-scope connection attempts** the real httpx binary tried to make on its own
(`cybermedic.buzz`, `defendervault.shop`, `safesentinel.lol`, `shieldvertex.mom`,
`virusinspector.top`) while the authorized connection to `virusbarrier.xyz` (resolved
IP `34.75.127.116`) completed successfully — read directly from
`context.metadata["network_requests"]`/`context.warnings`, not asserted.
