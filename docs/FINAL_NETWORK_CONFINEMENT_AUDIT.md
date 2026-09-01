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
| soft404_check (via `CollectionGateway`) | `modules/soft404_check.py` | already-alive host + its derived canary URL | Yes — **structural this turn**: `_probe_host` receives `AuthorizedCollectionTarget` objects (both root and canary, independently authorized), never a raw URL string; `gateway.http_get()` raises `TypeError` on anything else | Yes, via the gateway's owned confinement proxy | No | Yes | No | TARGET_COLLECTION | **GUARANTEED, structurally** — see the `CollectionGateway` section below |
| param_fuzz / cloud_bucket_enum (via `CollectionGateway`) | `modules/param_fuzz.py`, `modules/cloud_bucket_enum.py` | already-alive host + per-parameter probe URL / candidate cloud bucket hostname | Yes — **structural this turn**: every baseline, per-parameter probe, canary, and candidate URL is authorized via `gateway.authorize(raw, operation=...)`, returning an `AuthorizedCollectionTarget` — never a raw URL string reaches `gateway.http_get()`; `cloud_bucket_enum`'s `CollectionScope.cloud_collection_allowed` opt-in is enforced per-URL through the same `operation="cloud_bucket_enum"` label (`core/intel/authorize.py:_CLOUD_BUCKET_ENUM_OPERATIONS`), preserving the fix from the operation-string mismatch bug below without reintroducing it | Yes, via the gateway's owned confinement proxy | No | Yes | No | TARGET_COLLECTION | **GUARANTEED, structurally** — same pattern as `soft404_check` above |
| DNS resolution (dnsx, seed + follow-up) | `modules/dnsx.py`, `core/intel/followup.py` | gated input / eligible follow-up indicator | Yes | N/A — a DNS *query about* the hostname is not itself a connection to a resolved destination | N/A | N/A | No | TARGET_COLLECTION (query only) | **GUARANTEED** (authorization-wise; SSRF policy doesn't apply to a resolution query with no follow-on connection) |
| Port scan (naabu) | `modules/naabu.py` | gated input file | Yes | No | N/A (naabu does its own TCP connect scanning against ports on an already-authorized host string, not attacker-influenced) | No | Same raw-socket caveat as any subprocess | TARGET_COLLECTION | **INPUT_GATED_ONLY — architecturally not proxy-confinable.** naabu performs raw TCP/SYN operations, which cannot be routed through an HTTP forward proxy at all; confinement here is authorization-only (target must already be in scope before the scan starts), never connection-pinned to a validated destination IP the way HTTP/WHOIS targets are. `NAABU_TARPIT_CHECK`/`NAABU_CONFIRM_OPEN_PORTS` are result-integrity controls (is this "open" port real), not a connection-level boundary. Closing this for real needs OS-level enforcement (a network namespace or firewall rule around the whole process) — out of scope for this sprint's application-level confinement work. |
| Port verification (nmap) | `modules/port_verify.py` | naabu's already-open ports (`naabu.txt`) | Indirect only — relies on naabu's own upstream input gate; no per-host `allows_active_collection` check of its own | No | N/A, same reasoning as naabu | No | Same raw-socket/service-probe caveat as naabu | TARGET_COLLECTION | **INPUT_GATED_ONLY, same residual as naabu** — nmap's TCP-connect + service-detection probes are equally unproxyable; this is not a separate, worse gap than naabu's, just naabu's already-documented limitation inherited by its own downstream verifier. |
| ASN lookup (target IP → ASN) | `modules/asn_lookup.py` | resolved target IPs, sent as WHOIS/DNS query *content* to `whois.cymru.com:43` (fixed) or Cymru's DNS zone (fixed) | Yes, for the hostname resolved | N/A for the resolution step; the actual TCP/UDP connection destination (`_CYMRU_WHOIS_HOST`) is a hardcoded constant, never target-derived | N/A | Yes — destination is a fixed constant | No | THIRD_PARTY_OBSERVATION (fixed destination; target data is query content, not the connection target) | **GUARANTEED** |
| Cloud bucket enumeration destination itself (`*.s3.amazonaws.com` etc.) | `modules/cloud_bucket_enum.py` | generated bucket hostname (opt-in, `CLOUD_BUCKET_ENUM_AUTHORIZE_DERIVED`) | Yes, per-candidate (`authorize_active_indicator`) | Yes — new this turn (same `http_get`+proxy fix as soft404/param_fuzz above) | No | Yes | No | TARGET_COLLECTION | **GUARANTEED** |
| WHOIS (registration lookup) | `modules/whois.py` | seed domain | Yes | No | N/A — subprocess-based external `whois` client, not urllib | Subprocess-internal | Same raw-socket caveat | TARGET_COLLECTION (registration metadata, not HTTP content) | **INPUT_GATED_ONLY** |
| gau / waybackurls (passive archive query) | `modules/gau.py`, `modules/waybackurls.py` | seed domain, queried *against* a fixed third-party archive host | Yes (gates whether the seed is queried at all) | N/A — destination is the archive service, not the target | N/A | Yes — fixed third-party host | Same raw-socket caveat | THIRD_PARTY_OBSERVATION | **INPUT_GATED_ONLY** |
| threat_intel (URLhaus) | `modules/threat_intel.py` | `_URLHAUS_HOST_ENDPOINT` (hardcoded); target hostname is POST body content | Yes (gates which hosts are queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| vuln_match (OSV.dev, WPScan) | `modules/vuln_match.py` | `_OSV_QUERY`/`_WPSCAN_PLUGIN` (hardcoded); target-derived data is POST body / URL path segment, not hostname | Yes (gates which findings are queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| CT logs (crt.sh) | `modules/ctlogs.py` | fixed crt.sh endpoint; seed domain is a query parameter | Yes (gates the seed being queried) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** |
| Passive DNS (Mnemonic / optional SecurityTrails) | `modules/passive_dns.py` | fixed `api.mnemonic.no`/`api.securitytrails.com` endpoints; out-of-scope certificate-sibling hostname is a query path/param, never a connection destination | Yes (gates which siblings are queried — must already be an out-of-scope observation from this run's `ctlogs.jsonl`, capped at `passive_dns_max_candidates`) | N/A — destination is fixed | N/A | Yes — fixed | No | THIRD_PARTY_OBSERVATION | **GUARANTEED** — Hydra's own socket never connects to the sibling hostname; it asks a fixed third party what it has historically observed |
| Webhook notifications | `core/webhook.py` | operator-configured webhook URL (Settings, not discovered intelligence) | N/A — not target-derived | N/A | N/A | Yes — operator-fixed | No | CONTROL_PLANE | **GUARANTEED** |
| OPSEC diagnostics (`check-opsec`) | `core/opsec_check.py` | hardcoded probe name (`"example.com"`) / operator's own `OUTBOUND_PROXY_URL` | N/A — not target-derived | N/A | N/A | Yes | No | CONTROL_PLANE | **GUARANTEED** |
| Raw-socket bypass of any of the above tools' own proxy configuration | any subprocess, hypothetically | arbitrary | N/A — never reaches the proxy at all | N/A | N/A | **No** | **Yes, by construction** | N/A | **EXPLICITLY_UNTRUSTED** — see `PROXY_VERIFIED_TOOLS`/`UNTRUSTED_NETWORK_TOOL` below |

## PROXY_VERIFIED_TOOLS (updated this turn)

`core/collection/crawler_proxy.py:PROXY_VERIFIED_TOOLS` now lists **eight** confirmed-live
entries, up from five: `katana`, `hakrawler`, `nuclei`, `httpx`, `browser_probe` (prior turns),
plus **`soft404_check`, `param_fuzz`, and `cloud_bucket_enum`**, all three added this turn after
each got its own dedicated live test — a prior version of this document argued they didn't need
one because they share `soft404_check`'s exact `http_get(url, proxy_url=...)` call shape. That
argument turned out to be wrong: writing `param_fuzz`'s and `cloud_bucket_enum`'s own live tests
is exactly what surfaced the real `_CLOUD_BUCKET_ENUM_OPERATIONS` authorization-mismatch bug
documented above, which a shared-code-path assumption would have missed entirely (the bug was in
`ScopeEnforcingProxy`'s re-check, not in `http_get` — a layer the "shared call shape" argument
never actually examined).

- `tests/test_httpx_confinement_live.py` — the real installed httpx binary, routed
  through the real proxy via `-proxy`. Proves both directions (authorized target
  reached; in-scope hostname resolving to a private IP gets zero real connections)
  against a real local server.
- `tests/test_browser_confinement_live.py` — real WebKit, launched by the real
  `BrowserProbePlugin.run()` with Playwright's `proxy=` launch option pointed at the
  real confinement proxy. Same two directions, real local server.
- `tests/test_urllib_confinement_live.py` — the real `.run()` method of all three
  `http_get`-based plugins (`soft404_check`, `param_fuzz`, `cloud_bucket_enum`) against a
  real local server: authorized-reaches-through, in-scope-hostname-resolving-private-IP-
  denied, `cloud_bucket_enum`'s cloud-opt-in-required and cloud-opt-in-granted cases, and
  the genuine-DNS-failure-never-false-positives regression test for the bug above.

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

## Sealed `AuthorizedCollectionTarget` + `CollectionGateway` (new this turn)

**The gap.** `AuthorizedCollectionTarget` was a plain `@dataclass(frozen=True)` — `frozen`
blocks *mutation after construction*, not construction itself. Any caller could write
`AuthorizedCollectionTarget(raw="https://evil.example", hostname="evil.example",
scheme="https", port=None, capability="http_probe", reason="fabricated",
scope_identity=(...))` directly and get an object indistinguishable from a real
authorization proof — every downstream consumer (`_fetch_single_hop`, now
`CollectionGateway.http_get`) would treat it as legitimate. The class's own docstring
claimed "there is no public constructor path that skips the check," which was not true.

**The fix.** `AuthorizedCollectionTarget.__post_init__` now unconditionally raises
`TypeError`. Since `dataclasses.replace()` also always calls `__init__`
(`cls(**changes)` under the hood), it fails identically — closing the classic escape
hatch a naive sentinel-default "seal" would leave open (replace() carries forward
unchanged field values, including a leaked sentinel, while overriding just the field
an attacker wants to forge). The only way to obtain an instance is `_construct()`, a
private classmethod that builds the object via `object.__new__` + direct
`object.__setattr__`, bypassing `__init__` entirely — called only from
`authorize_verbose()`. Four tests in `tests/test_authorized_collection_target.py`
prove this: direct construction with a forged out-of-scope hostname raises; a forged
field set copied from a *real* authorized target's own `dataclasses.asdict()` output
(with just the hostname swapped) still raises; and `dataclasses.replace()` on a real
target raises identically.

**Honest limit, stated as plainly as the class's own docstring now does:** this is
sealed against the threat model that matters here — a plugin author accidentally or
conventionally fabricating a capability the way they'd construct any other dataclass.
It is not sealed against a caller who deliberately imports and calls the
leading-underscore `_construct()` classmethod with a hand-built field set — Python has
no language construct that prevents that, and claiming otherwise would be a false
guarantee. That level of deliberate circumvention is what code review and the static
guard (`tests/test_no_bypass_network_primitives.py`) are for, not the type system.

**`core/collection/gateway.py:CollectionGateway`.** The single object this whole arc's
`AuthorizedCollectionTarget` design was building toward: `gateway.authorize(raw)`
returns an `AuthorizedCollectionTarget | None` (the same fail-closed decision, unchanged);
`gateway.http_get(target)` accepts *only* that sealed type — not `str` — checked with
an explicit `isinstance` at runtime (not just a type hint a caller could `# type:
ignore` past), and owns the confinement-proxy lifecycle so the actual request is
routed through it automatically. `modules/soft404_check.py` was migrated onto it this
turn as the concrete demonstration: `_probe_host` now receives `AuthorizedCollectionTarget`
objects for both the root URL and its derived canary URL (independently
re-authorized, not assumed safe by association with the root), and cannot construct a
request from a bare string even if it wanted to. Verified with 8 new tests
(`tests/test_collection_gateway.py`, including two proving `http_get` rejects a plain
string and a hand-built fake-shaped object) plus the existing real-local-server suite
(`tests/test_urllib_confinement_live.py`) and a real run against the actual
authorized target `virusbarrier.xyz` (real DNS resolution, real request, real
skip-with-zero-requests for an out-of-scope host).

**Update (closing turn): `param_fuzz.py` and `cloud_bucket_enum.py` are now also on
`CollectionGateway`** — the same structural pattern as `soft404_check`, no longer a
deferred increment. `param_fuzz` authorizes every baseline URL and every one of its
~130 per-parameter probe URLs independently (the probe is derived from an
already-authorized baseline but re-authorized rather than assumed safe by
association, mirroring `soft404_check`'s root/canary pattern). `cloud_bucket_enum`
authorizes every canary and candidate bucket URL the same way, with its
`Settings.cloud_bucket_enum_authorize_derived` entry-level opt-in (checked once, at
plugin entry) staying a separate, coarser gate from the per-URL
`CollectionScope.cloud_collection_allowed` check that `gateway.authorize(url,
operation="cloud_bucket_enum")` now performs on every request — the same operation
string the cloud-endpoint opt-in gate keys off (see the operation-string-mismatch bug
below), not reintroduced by this migration. Verified against the existing real-local-
server suite (`tests/test_urllib_confinement_live.py`, unchanged call shape, all
passing) plus two new tests proving `gateway.http_get()` rejects a raw string with
`TypeError` for each plugin's own `CollectionGateway` construction, mirroring
`tests/test_collection_gateway.py`'s generic proof.

## SCOPE_FILE path exclusions (new turn): scope is now path-aware, not just host-aware

Before this turn, every authorization decision in this whole arc — `classify_scope`,
`authorize_active_indicator`, `AuthorizedCollectionTarget`, `ScopeEnforcingProxy` — was
purely hostname-based: an authorized domain/wildcard authorized *every path* under it.
A real bug-bounty program's scope is frequently narrower than that: `*.bancoplata.mx`
authorized in general, with `/*/whistleblowing` on that domain and `platacard.mx`
explicitly carved out as out of scope regardless of the wildcard. There was no way to
express that in a `SCOPE_FILE` at all.

**The mechanism.** A `SCOPE_FILE` line prefixed with `!` (`!bancoplata.mx/*/whistleblowing`)
is parsed by `core/scope.py:split_scope_patterns` into a `(domain, path_glob)` pair, kept
on `CollectionScope.path_exclusions` — separate from the ordinary `scope_patterns` tuple,
so `host_in_scope` never sees exclusion syntax as a (harmlessly inert) positive pattern.
`core/scope.py:url_path_excluded` matches a full URL's hostname (exact or subdomain)
against every configured exclusion, and the path as a **subtree prefix**: it excludes the
named path and everything beneath it, matched by whole `/`-separated segment (each segment
compared with `fnmatch`, so a `*` matches one segment, not an arbitrary run of characters)
— not by a single exact-match `fnmatch.fnmatch(path, glob)` over the whole string, which
would only ever protect the literal landing path and silently leave every subpath (almost
always where the actual sensitive mechanism lives — a report form is rarely at the bare
landing URL a program names) reachable. See "A third real bug" below.

**Where it's enforced — the same single choke point as everything else in this arc.**
`core/intel/authorize.py:authorize_active_indicator` checks `path_exclusions` immediately
after hostname parsing, **before** the cloud-endpoint opt-in gate and before ordinary
domain/wildcard matching — an exclusion wins over any positive match, including a
wildcard, by construction, not by convention. Every caller that already funnels through
this one function inherits path-exclusion enforcement automatically and for free:
`allows_active_collection` (browser_probe's route guard — Playwright reports the real,
decrypted request URL with path, so this is real enforcement, not a hostname
approximation), `authorize_collection` → `AuthorizedCollectionTarget.authorize()` (httpx's
redirect-hop authorization, and every `CollectionGateway`-based plugin: soft404_check,
param_fuzz, cloud_bucket_enum), and — new this turn —
`ScopeEnforcingProxy._authorize_with_reason`, extended to pass the full absolute URL
(not just the bare host) for **plain-HTTP** crawler traffic (katana/hakrawler/nuclei/httpx
via `-proxy`), since the path is actually visible to this proxy for a plain HTTP request
in a way it structurally is not for a `CONNECT`-tunneled HTTPS one.

**Honest limit, stated plainly.** A `CONNECT` tunnel (HTTPS, the overwhelming majority of
real traffic) is spliced byte-for-byte with no TLS interception — this proxy has never
seen the decrypted path for any check, host-level scope included, and path exclusions are
no different: they simply do not apply to HTTPS crawler traffic that never goes through
Python's own URL-aware authorization first. This is the same pre-existing, already-audited
limitation as every other CONNECT-target check in this document, not a new gap introduced
by this feature.

Verified with `tests/test_scope_path_exclusions.py`: parsing/matching unit tests, direct
`authorize_active_indicator`/`allows_active_collection`/`AuthorizedCollectionTarget`
DENY/ALLOW tests, and two real-local-server tests driving `ScopeEnforcingProxy` directly
over plain HTTP proving the excluded path never reaches the server while a sibling path on
the same domain does.

### A third real bug: the first version of `url_path_excluded` protected the wrong thing

The initial implementation used `fnmatch.fnmatch(path, path_glob)` directly on the whole
path string — an exact-match glob, not a prefix. Manually verified against a real scope
before this was caught:

```python
allows_active_collection('https://bancoplata.mx/es/whistleblowing', scope)          # -> False (correct)
allows_active_collection('https://bancoplata.mx/es/whistleblowing/reportar', scope) # -> True  (WRONG)
```

`/*/whistleblowing` only ever matched that exact path string; any additional segment
(`/reportar`, `/submit`, `/formulario/paso2`, a query string) fell outside the glob and
came back **authorized**. This is close to the worst possible shape for this specific bug:
a bug-bounty program almost never marks the bare landing page as its sensitive exclusion —
it marks a section, and the actual report-submission mechanism the exclusion exists to
protect nearly always lives one or more segments deeper. The bug protected exactly the
part that mattered least and left exposed exactly the part the exclusion was written for.

**The fix.** `url_path_excluded` now splits both the URL path and the pattern into
`/`-separated segments and requires every leading pattern segment to match (each segment
compared independently with `fnmatch`, so a `*` matches one segment, never crosses a `/`)
— the URL path may have any number of additional trailing segments beyond the pattern and
still be excluded. Segment equality also fixes a second, smaller risk in the same
direction: a URL that merely shares a text *prefix* with an excluded segment
(`/es/whistleblowing-info` against a pattern ending in `whistleblowing`) is a different
segment and is correctly never excluded — the fix is subtree-prefix by segment, not
substring-prefix by character.

Verified against the exact six cases manually checked during triage: the two-segment-deeper
subpath and the query-string case are now excluded; the same-text-different-segment case
and unrelated paths/hosts remain authorized. Same static architectural guard
(`tests/test_no_bypass_network_primitives.py`) and every other exclusion-consuming call
site (`authorize_active_indicator`, `ScopeEnforcingProxy`) needed no changes — the fix is
fully contained in the one function that does the actual path comparison.

## A real bug found by writing real tests, not assumed away (this turn)

Adding live tests for `param_fuzz`/`cloud_bucket_enum` (see `PROXY_VERIFIED_TOOLS` above) —
rather than assuming they were equally proven because they share `soft404_check`'s exact
`http_get(url, proxy_url=...)` call shape — surfaced a real, previously-undetected bug specific
to `cloud_bucket_enum`, live-confirmed against a run against `virusbarrier.xyz` (which showed
`param_fuzz: UNTRUSTED_NETWORK_TOOL` in its warnings, prompting the investigation) and then
reproduced deterministically:

**The bug.** `ScopeEnforcingProxy._authorize_with_reason` re-checked every destination via
`allows_active_collection(host, scope)`, which internally calls `authorize_active_indicator(...,
operation="active_collection", ...)` — a hardcoded, generic operation label. `cloud_bucket_enum.py`'s
own pre-check correctly authorizes a generated bucket hostname via `authorize_active_indicator(url,
scope, "cloud_bucket_enum", ...)`, which requires the *literal* operation string
`"cloud_bucket_enum"` to unlock the explicit cloud-collection opt-in path (`CollectionScope.
cloud_collection_allowed`). The proxy's generic re-check never supplied that string, so it always
fell through to ordinary registrable-domain scope matching — which a generated bucket hostname
(`{bucket}.s3.amazonaws.com`) can never pass — and denied every single candidate with a bare local
403, **even when the operator had explicitly opted into cloud collection**.

**The consequence.** `cloud_bucket_enum.py`'s own classifier (`_classify`) treats a bare HTTP 403
with no distinguishing body as `"exists_private"` for GCS and Azure (a real cloud provider's
access-denied signal looks exactly like this). Since the proxy's own denial *is* a bare 403, every
GCS/Azure candidate that reached the confinement proxy was misclassified as an existing,
access-restricted bucket — a live test run showed 106 "existing buckets" out of 159 candidates,
an obviously-wrong ~67% hit rate. This was not a security bypass (nothing was ever actually
reached that shouldn't have been — if anything the plugin was *more* restrictive than intended),
but it silently made the plugin's actual output useless from the moment it was retrofitted onto
the confinement proxy.

**The fix.** `authorize_active_indicator`'s cloud-endpoint gate now accepts a small explicit set,
`_CLOUD_BUCKET_ENUM_OPERATIONS = {"cloud_bucket_enum", "cloud_enum"}` (`core/intel/authorize.py`)
— the plugin's own literal operation string, and its declared `capability` (`"cloud_enum"`, what
`ScopeEnforcingProxy` actually has available to it). `ScopeEnforcingProxy._authorize_with_reason`
now calls `authorize_active_indicator(host, self.scope, self.capability, "confinement_proxy_recheck")`
directly instead of the generic `allows_active_collection`, so its re-check applies the exact same
special-case logic the plugin's own pre-check does. A real run against `virusbarrier.xyz` with
cloud collection explicitly authorized now correctly reports **0** existing buckets (verified: none
of the 53 randomly-generated candidate names are real allocated buckets), not 106.

**A related, non-security accuracy limitation surfaced by the same investigation, verified safe:**
Azure and GCS candidate names that genuinely don't exist normally produce a real DNS NXDOMAIN —
`cloud_bucket_enum.py`'s own `_is_dns_failure` already special-cases this as the expected "not
taken" signal for Azure. With the destination-IP/SSRF layer now resolving DNS *before* `http_get`
ever runs, a genuine NXDOMAIN is caught by `ScopeEnforcingProxy`'s own resolution and denied as
`dns_resolution_failed` — correctly fail-closed — but the CONNECT tunnel failure this produces
surfaces to `http_get` as `status_code=None, error="<urlopen error Tunnel connection failed: 403
Forbidden>"`, a string `_is_dns_failure` doesn't recognize, so `_classify` reports `"unknown"`
instead of the more informative `"not_found"`. Verified via
`tests/test_urllib_confinement_live.py::test_cloud_bucket_enum_genuine_dns_failure_never_reports_false_exists`
that this never degrades into a false `"exists_private"`/`"public_listable"` — the safety property
that actually matters — even though the accuracy of the "not found" signal is diminished for this
one heuristic. Not fixed this turn: doing so well means either fragile string-matching on urllib's
internal error text, or a larger change to make the audit trail distinguish "denied for security
reasons" from "the plugin's own DNS-failure heuristic," which is a real, bounded increment for a
future turn, not a security gap today.

## A second real bug found by adding the test the mission specifically asked for

Adding an explicit test for the mission's own named dangerous-scheme list (`file:`, `data:`,
`javascript:`, `vbscript:`, `about:`, plus the pre-existing `gopher:`/`ftp:`/`blob:`) surfaced
that `modules/httpx.py`'s scheme check only looked at `urlparse(next_url).scheme` when `"://" in
next_url` — true for `file://`, `gopher://`, `ftp://`, and `blob:https://...` (which embeds
`://`), but **false** for `javascript:`, `data:`, `vbscript:`, and `about:`, none of which use a
`//` authority component at all. Those four schemes silently skipped the explicit scheme check
and fell through to ordinary hostname-based authorization instead — which still denied them today
(they have no parseable hostname), so this was never an actual bypass, but it meant the *wrong*
check was doing the denying, for the wrong reason, in a way that was fragile rather than
guaranteed. Fixed by computing `urlparse(next_url).scheme` unconditionally — `urlparse` correctly
extracts a scheme from both `scheme://netloc/...` and single-colon `scheme:opaque` forms. All 8
dangerous schemes now produce the specific `blocked_scheme:...` audit reason, verified in
`tests/test_url_normalization_adversarial.py::test_httpx_redirect_rejects_dangerous_schemes`
(parametrized over all 8, asserting both zero requests issued and the exact audit-trail reason).

## Host graph vs. Intel confidence: confirmed non-contradictory, not just spot-checked

A prior turn's own "REMAINING LIMITATIONS" repeatedly listed this as "spot-checked, not
exhaustively re-audited." This turn traced it to a definitive answer: `core/intelligence/
clustering.py:compute_clusters` (the Host-cluster confidence assignment) imports
`cluster_signal_confidence` directly from `core/intel/correlate.py` — the same module Intel's own
relationship correlation uses — and that function's own docstring states its purpose plainly:
"Map Host-view clusters onto the same named bands as IntelEngine." ASN/CDN/WAF/CIDR/favicon/
body_hash all map to `ConfidenceBand.LOW` in that one shared function; large (≥20-member)
certificate clusters are downgraded to `MEDIUM` instead of the default `HIGH` — matching this
turn's mission's own explicit correlation-rules guidance without needing new code. Separately,
`IntelEngine.to_infrastructure_graph()` derives its own graph edges directly from `self.
relationships` using `band_score(rel.confidence)` — the identical confidence value already
computed for the canonical Intel relationship, not an independent recomputation. There is one
function computing Host-cluster confidence and one path deriving the Intel-projected graph's
confidence from Intel's own relationships — not two competing correlation engines that could
silently disagree.

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

## Decision record: `gau`/`waybackurls` do NOT belong on `CollectionGateway`

`docs/ARCHITECTURE_AUDIT_2.md` (the network-capability audit for the
"Sprint Final de Arquitectura de Colección") re-examined every plugin from
first principles and initially tentative-listed `gau`/`waybackurls` alongside
`katana`/`hakrawler`/`nuclei` as migration candidates. On inspection this was
wrong, and is recorded here explicitly so a future round doesn't propose it
again by the same mistake: `gau`/`waybackurls` are `THIRD_PARTY_OBSERVATION`
(row above, already correctly classified before this sprint) — they never
connect to the target at all. `gau --subs <domain>` and `waybackurls`'s stdin
domain both query archive infrastructure (web.archive.org, Common Crawl, OTX,
etc.) that the binaries themselves choose; the seed domain is the *query
argument*, not a connection destination Hydra picks or could redirect through
a target-scoped proxy. Routing them through `CollectionGateway` or
`ScopeEnforcingProxy` would apply target-destination-authorization semantics
to a connection that is never made to the target — exactly the anti-pattern
this document already rejects for OSV.dev, crt.sh, and URLhaus. Their
`active_collection=True` flag correctly gates *which domain strings* get sent
as query data (an operator-authorization concern, since even the domain name
itself is being disclosed to a third party), not a connection to authorize.
No code change follows from this — the existing `INPUT_GATED_ONLY`
disposition was already correct.

---

# FINAL ADVERSARIAL NETWORK-CONFINEMENT PROOF

Everything below this line is a fresh, from-scratch forensic pass — every
existing claim above (including this document's own prior sections) was
treated as unverified until re-confirmed against current code and, where a
claim concerns runtime behavior, a real running process. Sections 19–20 of
the source prompt for this round (intelligence/correlation truth and
reporting reproducibility) are explicitly out of scope — see "Known
limitations" (Section L) for what was noticed but not evaluated.

## A. Complete network primitive inventory

Method: `grep -rl` across `core/`, `modules/`, `config/`, `utils/`, `app.py`,
`ui/` for every primitive named in the audit brief (`socket`, `asyncio.open_*`/
`start_server`, `urllib`, `requests`, `httpx`, `aiohttp`, `playwright`), plus a
separate sweep for `subprocess`/`run_command` (external binaries). Every
matching file was opened and read this round, not classified from its name.

| # | Location | Primitive | Prod/Test | Destination controlled by Hydra? | Class |
|---|---|---|---|---|---|
| 1 | `core/collection/gateway.py:CollectionGateway.http_get()` | urllib (via `core/http_probe.py`) | Prod | Yes — only accepts `AuthorizedCollectionTarget` (runtime `isinstance` check) | **A** |
| 2 | `core/http_probe.py:http_get()` | urllib | Prod (internal primitive) | N/A at this layer — protected by being unreachable except via #1, see Section 23 finding below | **A** (as of this round's fix) |
| 3 | `modules/soft404_check.py` | via #1 | Prod | Yes | **A** |
| 4 | `modules/param_fuzz.py` | via #1 | Prod | Yes | **A** |
| 5 | `modules/cloud_bucket_enum.py` | via #1 | Prod | Yes, plus `cloud_collection_allowed` opt-in | **A** |
| 6 | `modules/httpx.py` (subprocess binary + `AuthorizedCollectionTarget.authorize_verbose()` per redirect hop) | subprocess + `-proxy` | Prod | Yes | **B** |
| 7 | `modules/browser_probe.py` (Playwright/WebKit) | `proxy=` + `route()` guard | Prod | Yes | **B** |
| 8 | `modules/katana.py` (subprocess binary) | `-proxy` | Prod | Yes (connection-level); input pre-gated | **B** |
| 9 | `modules/hakrawler.py` (subprocess binary) | `-proxy` | Prod | Yes (connection-level); input pre-gated | **B** |
| 10 | `modules/nuclei.py` (subprocess binary) | `-proxy`, `-ni` unless opt-in | Prod | Yes (connection-level); input pre-gated | **B** |
| 11 | `core/collection/whois_client.py` (native TCP:43) | `asyncio.open_connection` | Prod | Yes — every hop's IP validated via `core/collection/ssrf.py` before connecting | **B*** (not HTTP-proxyable; same SSRF mechanism applied directly per hop) |
| 12 | `modules/naabu.py` (subprocess, raw TCP/SYN) | subprocess | Prod | Authorization-only; **not proxy-confinable at all** (architectural, documented) | **C** |
| 13 | `modules/port_verify.py` (subprocess nmap) | subprocess | Prod | Same as #12 | **C** |
| 14 | `modules/dnsx.py` (subprocess) | DNS query | Prod | Input-gated; DNS query has no "destination IP of the target" | **D** |
| 15 | `modules/wildcard_check.py` (subprocess dnsx) | DNS query | Prod | Same as #14 | **D** |
| 16 | `modules/ctlogs.py` | urllib, fixed crt.sh | Prod | Fixed destination; domain is query param | **F*** (fixed 3rd-party, not target-directed) |
| 17 | `modules/threat_intel.py` | urllib, fixed URLhaus | Prod | Fixed destination; host is POST body | **F*** |
| 18 | `modules/vuln_match.py` | urllib, fixed OSV.dev/WPScan | Prod | Fixed destination | **F*** |
| 19 | `modules/asn_lookup.py` | `asyncio.open_connection` fixed `whois.cymru.com:43` + DNS zone | Prod | Fixed destination; IPs are query content | **F*** |
| 20 | `modules/gau.py` | subprocess, internal archive APIs | Prod | Binary-internal, fixed-ish (archive.org/Common Crawl/OTX); domain is `--subs` argument | **F*** |
| 21 | `modules/waybackurls.py` | subprocess, web.archive.org | Prod | Same as #20 | **F*** |
| 22 | `modules/subfinder.py`/`amass.py`/`assetfinder.py` | subprocess, many internal OSINT sources | Prod | Binary-internal; `active_collection` not set (defaults False) | **F** (passive discovery, not Hydra-directed) |
| 23 | `modules/anew.py`, `modules/unfurl.py` | subprocess, stdin/stdout only | Prod | No network at all | **F** |
| 24 | `modules/security_headers.py` | none (reads existing httpx JSON) | Prod | No network at all | **F** |
| 25 | `core/webhook.py` | urllib | Prod | Fixed/operator-configured URL, not target-derived | **F*** (`CONTROL_PLANE`) |
| 26 | `core/opsec_check.py` | `socket.create_connection` (operator's own proxy), `socket.getaddrinfo("example.com", 443)` (hardcoded diagnostic) | Prod (diagnostic command only) | Operator-configured / hardcoded constant | **F*** (`CONTROL_PLANE`) |
| 27 | `core/dependencies/validation.py` | `asyncio.create_subprocess_exec` (`<binary> --version`/`--help`) | Prod | Local process only, no network destination | **F** |
| 28 | `IntelEngine`/correlation/SQLite/reporting | none | Prod | No network at all | **F** |
| 29 | `tests/test_*_confinement_live.py`, `test_crawler_proxy.py`, `test_opsec_proxy_chaining.py`, `test_scope_path_exclusions.py`, `test_ssrf_destination_policy.py`, etc. | real local `socketserver`/`asyncio.start_server` | Test only | Local-only, ephemeral, adversarial harness | **E** |
| 30 | `modules/passive_dns.py` | urllib, fixed `api.mnemonic.no` (default, no key) + optional `api.securitytrails.com` (`SECURITYTRAILS_API_KEY`) | Prod (opt-in, `ENABLE_PASSIVE_DNS`) | Fixed destination; out-of-scope sibling hostname is query path/param content, never dialed directly | **F*** (fixed 3rd-party, not target-directed — same class as `ctlogs`/`threat_intel`) |

`*` marks a note on the classification, not a different letter than shown —
the A–G taxonomy given for this audit has no clean bucket for "fixed,
non-target-derived third-party API" or "operator-configured control-plane
destination"; both get folded into **F** with an explicit annotation rather
than invented new letters, consistent with `docs/ARCHITECTURE_AUDIT_2.md`'s
own finding that this codebase's real shape needs one more label than a
strict 4-way (there, 5-way) split provides. Row 11 (WHOIS) similarly isn't
literally "ScopeEnforcingProxy controlled" (WHOIS isn't HTTP, so the HTTP
forward proxy doesn't apply) but IS destination-IP-validated per hop by the
identical mechanism `ScopeEnforcingProxy` itself calls — closer to B than to
anything else on offer.

## B. Runtime call graph (production paths, runner → socket)

Traced this round by re-reading `core/runner.py:PipelineRunner.run()` top to
bottom (not assumed from `docs/ARCHITECTURE_AUDIT_2.md`'s prior trace, though
it agrees) — full stage order already documented there; the network-relevant
chains are:

```
PipelineRunner.run()
  → _run_plugin_chain(subfinder/assetfinder/amass)     → F (internal OSINT, not Hydra-directed)
  → _run_single_plugin(dnsx)                            → D
  → asn_lookup                                          → F*
  → _run_plugin_chain(httpx)                             → B  (AuthorizedCollectionTarget per redirect hop, -proxy)
  → optional/enrichment stage (parallel where independent):
      ctlogs                                             → F*
      katana / hakrawler / nuclei                        → B  (-proxy, PROXY_VERIFIED_TOOLS)
      gau / waybackurls                                  → F*
      unfurl                                             → F  (no network)
      naabu → port_verify                                → C  (unproxyable, input-gated only)
      browser_probe                                      → B  (proxy=, route() guard)
      soft404_check / param_fuzz / cloud_bucket_enum      → A  (CollectionGateway)
      threat_intel                                       → F*
      vuln_match                                         → F*
      security_headers                                   → F  (no network)
      whois                                               → B* (native client, per-hop SSRF)
  → IntelEngine.finalize() / SQLite persistence           → F
  → _maybe_collect_followups() (re-enters authorization
    for every follow-up indicator before the SAME plugins
    above touch it again)                                → same classes as above, per plugin
  → reporting (Markdown/HTML/JSON, core/reporter.py)      → F
```

## C. Authorization map

| Path class | Authorization mechanism | Where enforced |
|---|---|---|
| A | `AuthorizedCollectionTarget.authorize()` (sealed, runtime `isinstance`-checked by `CollectionGateway.http_get()`) | `core/collection/target.py`, `core/collection/gateway.py` |
| B (httpx) | `AuthorizedCollectionTarget.authorize_verbose()` per redirect hop, before the follow-up request; `-proxy` for anything the binary decides to fetch beyond the gated `-list` | `modules/httpx.py`, `core/collection/crawler_proxy.py` |
| B (browser_probe) | `browser_request_decision()` → `allow_browser_navigation()` → `allows_active_collection()` for every resource type; `proxy=` for WebKit's own network stack | `modules/browser_probe.py`, `core/collection/crawler_proxy.py` |
| B (katana/hakrawler/nuclei) | Gated `-list`/stdin input (`_authorized_input`) for the seed; `ScopeEnforcingProxy._authorize_with_reason()` (via `-proxy`) for anything discovered afterward | `modules/_base.py:_crawler_confinement`, `core/collection/crawler_proxy.py` |
| B* (whois) | `core/collection/ssrf.py:validate_destination_ips_async()` per referral hop | `core/collection/whois_client.py` |
| C (naabu/port_verify) | `_gate_active_input`/authorized target list only, before the scan starts — no per-connection check possible | `modules/naabu.py`, `modules/port_verify.py` |
| D (dnsx/wildcard_check) | `authorize_plugin_input`/`allows_active_collection` on the name list before resolution | `modules/dnsx.py`, `modules/wildcard_check.py` |
| F* (fixed third-party) | Authorizes *which target string* is disclosed as query data, not a connection | per-module (ctlogs/threat_intel/vuln_match/asn_lookup/gau/waybackurls) |

Every path in classes A/B/B\* independently re-validates the **destination
IP**, not just the hostname, via `core/collection/ssrf.py` — this is the
DNS-rebinding/TOCTOU closure, re-verified live in Section G/I below.

## D. External tool map — what Hydra can and cannot constrain

| Tool | Input gated? | Internal navigation confined? | Mechanism | Residual risk |
|---|---|---|---|---|
| `httpx` | Yes | Yes — no `-follow-redirects`; each hop is re-authorized in Python before the next request | `AuthorizedCollectionTarget` + `-proxy` | Only a raw-socket bypass inside the binary itself (never observed; see `tests/test_untrusted_network_bypass.py`) |
| `katana` | Yes | Yes — proxy-confined | `-proxy` | Same raw-socket caveat |
| `hakrawler` | Yes | Yes — proxy-confined (also appears to refuse cross-host redirects internally without `-subs`, verified empirically, not from docs) | `-proxy` | Same raw-socket caveat |
| `nuclei` | Yes | Yes — proxy-confined; interactsh OOB disabled by default | `-proxy`, `-ni` | Same raw-socket caveat; OOB opt-in is an explicit, documented exception |
| `dnsx` / `wildcard_check` | Yes | N/A (DNS query, not a connection) | `authorize_plugin_input` | None beyond DNS's own nature |
| `naabu` / `port_verify` | Yes | **No — architecturally impossible.** Raw TCP/SYN cannot be routed through an HTTP forward proxy. | Authorized input list only | **Documented, accepted residual** (confirmed still accurately reflected in this doc and `README.md` — see Section D confirmation below) |
| `subfinder`/`amass`/`assetfinder` | Seed only | No visibility into internal per-source queries at all | N/A — not `active_collection` | Binary-internal OSINT queries are outside Hydra's observation, an inherent property of wrapping these tools, not a confinement gap (nothing here is target-*collection*, it's discovery) |
| `gau`/`waybackurls` | Seed domain only | N/A — never connects to the target | N/A (F\*) | None — destination is never the target |
| WHOIS (native client) | Root domain | Yes — every hop of its own referral chain (IANA → registry → registrar) is Hydra's own connection, SSRF-validated | `core/collection/whois_client.py` | None beyond the SSRF policy's own known blocklist scope |

**naabu/port_verify confirmation** (per this round's explicit instruction to
re-confirm, not re-litigate): `README.md` § Security Considerations and this
document's own `naabu`/`port_verify` table rows (added last round) both still
state the same thing verified here again — re-read both files this round,
text unchanged and accurate, no drift found.

### A real bypass-pattern gap found this round (Section 23), fixed immediately

Searching specifically for `urlopen(...)`/direct primitive use "outside the
gateway/proxy architecture" (per this round's Section 23) surfaced that
`tests/test_no_bypass_network_primitives.py` — the static guard that fails
CI if a `modules/*.py` file imports `requests`/`aiohttp`/`urllib.request` or
calls a raw socket/asyncio primitive directly — did **not** cover a plugin
importing `core.http_probe.http_get` directly. That function is Hydra's own
internal urllib primitive, the one `CollectionGateway.http_get()` itself
calls after checking its caller passed a real `AuthorizedCollectionTarget` —
but nothing stopped a *different* module from importing it directly and
calling `http_get(raw_url, ...)`, skipping that check entirely, since the
check lives one layer up (in `CollectionGateway`), not inside `http_get()`
itself (which structurally cannot refuse a plain string — `CollectionGateway`
has to hand it one, `target.raw`, after authorization already happened).

Verified no module currently does this (`grep` across `modules/`: zero
hits other than the sanctioned `core/collection/gateway.py`, which lives
outside `modules/` and is unaffected by this guard) — this was a **latent
architectural gap** (class **G**, nothing preventing it), not an active
bypass. Closed by adding `core.http_probe` to the guard's prohibited dotted
imports, plus a new synthetic test proving the guard now catches it
(`test_guard_detects_direct_import_of_hydras_own_http_probe_primitive`).
Zero G-class paths remain in production as of this commit.

## E. Browser map

```
BrowserProbePlugin.run()
  → _httpx_targets() re-filters CollectionScope (missing scope → skip)
  → _crawler_confinement() starts ScopeEnforcingProxy
  → playwright.webkit.launch(proxy=confinement_proxy.proxy_url)
  → _install_scope_request_guard (context.route + route_web_socket)
       → browser_request_decision → allow_browser_navigation
            → missing scope = DENY
            → allows_active_collection(url)
  → page.goto(authorized)
```

Covered resource types (Playwright `resource_type`, real WebKit): document
(including iframe navigation), script, image, stylesheet, font, xhr, fetch,
websocket, beacon. An authorized page embedding `localhost` script/image/
css/font/iframe/beacon produced **zero** hits on the evil destination
server (`tests/test_subresource_escape_oracle.py::test_browser_probe_subresources_never_reach_evil`,
5/5 consecutive runs with cached WebKit).

DNS rebinding for the browser: an in-scope hostname resolving to loopback
is refused by the proxy before WebKit connects
(`tests/test_browser_confinement_live.py`).

Honest limit: Playwright `proxy=` is an application-level HTTP proxy. A
WebKit internal path that ignored launch-time proxy configuration would
not be visible. Live testing did not find one. HTTPS `CONNECT` tunnels
are authorized by host, not decrypted path.

## F. SSRF matrix

`core/collection/ssrf.py:classify_ip` + `ScopeEnforcingProxy` authorize
path. For every address in the required matrix, authorization is DENY and
`asyncio.open_connection` is never called
(`tests/test_ssrf_destination_policy.py::test_proxy_never_opens_a_socket_to_required_forbidden_ip`).

| IP | Resolution | Authorization | Proxy | Actual connection |
|---|---|---|---|---|
| 127.0.0.1 / 127.0.0.2 | stub / literal | DENY `blocked_range:127.0.0.0/8` | refuse | ZERO (live loopback server oracle) |
| 10.0.0.1 / 10.255.255.255 | stub | DENY `10.0.0.0/8` | refuse | ZERO sockets |
| 172.16.0.1 / 172.31.255.254 | stub | DENY `172.16.0.0/12` | refuse | ZERO sockets |
| 192.168.0.1 | stub | DENY `192.168.0.0/16` | refuse | ZERO sockets |
| 169.254.169.254 | stub | DENY `169.254.0.0/16` | refuse | ZERO sockets |
| 100.64.0.1 | stub | DENY `100.64.0.0/10` | refuse | ZERO sockets |
| 224.0.0.1 | stub | DENY `224.0.0.0/4` | refuse | ZERO sockets |
| 0.0.0.0 | stub | DENY `0.0.0.0/8` | refuse | ZERO sockets |
| ::1 | stub | DENY `::1/128` | refuse | ZERO sockets |
| fc00::1 | stub | DENY `fc00::/7` | refuse | ZERO sockets |
| fe80::1 | stub | DENY `fe80::/10` | refuse | ZERO sockets |
| ::ffff:127.0.0.1 | stub | DENY (mapped → 127.0.0.1) | refuse | ZERO sockets |
| ::ffff:10.0.0.1 | stub | DENY (mapped → 10.0.0.1) | refuse | ZERO sockets |

TOCTOU/rebinding: `_authorize_with_reason` returns `connect_ip`;
`asyncio.open_connection(connect_ip, port)` uses that IP, never a second
lookup of the hostname. Proven by spy and by the live loopback-oracle
test.

## G. Redirect proof

Authorized seed `127.0.0.1` → Location variants. Evil server = `localhost`
(different hostname, same machine). Real installed `httpx` binary.

| Variant | Authorized server | Evil server |
|---|---|---|
| Absolute `http://localhost:.../secret` | hit | ZERO (`test_httpx_confinement_live`) |
| Scheme-relative `//localhost:.../secret` | hit | ZERO (`test_redirect_destination_oracle`) |
| Relative `/relative-hop` (same host) | follow-up hit | n/a (authorization-preserving) |
| `javascript:` / `vbscript:` / `data:` / `about:` / `file:` | hit (first hop only) | ZERO + `blocked_scheme:` audit |

Production run (`python app.py run -d virusbarrier.xyz`, run-id
`confinement-proof-20260831`): httpx observed 5 OOS redirect destinations
(`cybermedic.buzz`, `defendervault.shop`, `safesentinel.lol`,
`shieldvertex.mom`, `virusinspector.top`). All recorded
`OUT_OF_SCOPE` / `NOT_ALLOWED`. Confinement proxy: **15 DENY**,
`network_attempted=false`, `network_completed=false`. `alive.txt` contains
only `https://virusbarrier.xyz`.

## H. Crawler proof

Authorized HTML page embeds `<a>`, `<script>`, `<img>`, `<link>`,
`<iframe>` pointing at `localhost`. Real binaries:

* katana — authorized page fetched; evil server ZERO
* hakrawler — authorized page fetched; evil server ZERO
* nuclei — same `-proxy` / `ScopeEnforcingProxy` path. Flag enforcement:
  `tests/test_crawler_proxy_flag_enforcement.py`. **Now also confirmed live
  with the real, unbounded default template corpus** (production re-run,
  `confinement-proof-final`, 2026-08-31): nuclei's own templates attempted
  `checkip.amazonaws.com` (2x) and `login.microsoftonline.com` (2x) —
  neither is virusbarrier.xyz or a subdomain of it. All 4 attempts recorded
  `decision=DENY, reason=out_of_scope, network_attempted=0,
  network_completed=0` in `intel_network_requests` — the confinement proxy
  refused before ever opening a socket, exactly like the httpx redirect
  destinations below. This closes the "not re-driven with the unbounded
  template corpus" caveat this row previously carried.

Redirect-escape (302 to `localhost`) already proven live for katana and
hakrawler in `tests/test_crawler_confinement_live.py`.

## I. DNS rebinding proof

Allowed DNS answer A (public) vs forbidden answer B (loopback/RFC1918):
the proxy connects only to the IP it just validated (`connect_ip`). A
second lookup is not performed. Live: in-scope hostname resolving to
127.0.0.1 → real local server receives ZERO connections (proxy, httpx
binary, WebKit).

## J. CollectionGateway coverage

Internal target-directed HTTP collectors:

| Plugin | Through gateway? | Can it HTTP without gateway? |
|---|---|---|
| soft404_check | Yes | No — `http_get` is the gateway method; static guard blocks `core.http_probe` import |
| param_fuzz | Yes | No |
| cloud_bucket_enum | Yes | No |

Exceptions (not HTTP-to-target, not applicable):

* httpx / katana / hakrawler / nuclei / browser_probe — Class B (proxy)
* naabu / port_verify — Class C (raw TCP, unproxyable)
* dnsx / wildcard_check — Class D
* ctlogs / threat_intel / vuln_match / asn_lookup / gau / waybackurls —
  Class F* (fixed third-party)
* whois — Class B* (native TCP:43 + per-hop SSRF)
* webhook / opsec_check — Class F* (control plane)

Gateway coverage of applicable internal HTTP collectors: **100%**.

`gateway.http_get("https://evil.example")` raises `TypeError`.
`dataclasses.replace`, direct construction, and field-forged copies raise
`TypeError`. `copy`/`deepcopy`/`pickle` cannot retarget an authorized
object. `object.__new__` can allocate an empty instance — deliberate
same-process execution, outside the plugin threat model.

## K. Test evidence

Adversarial confinement suite (164 tests + 1 skip without WebKit env):

```
.venv/bin/pytest tests/test_ssrf_destination_policy.py \
  tests/test_crawler_proxy.py tests/test_crawler_confinement_live.py \
  tests/test_httpx_confinement_live.py tests/test_urllib_confinement_live.py \
  tests/test_redirect_destination_oracle.py tests/test_subresource_escape_oracle.py \
  tests/test_alive_txt_integrity_matrix.py tests/test_followup_adversarial_oracle.py \
  tests/test_opsec_proxy_chaining.py tests/test_collection_gateway.py \
  tests/test_authorized_collection_target.py tests/test_no_bypass_network_primitives.py \
  tests/test_untrusted_network_bypass.py tests/test_redirect_safety.py \
  tests/test_crawler_proxy_flag_enforcement.py tests/test_followup_artifacts.py \
  tests/test_adversarial_matrix.py
```

Results: **5/5 consecutive** — 164 passed, 1 skipped, 0 failed each run
(~208s/run). The skip is
`test_browser_probe_subresources_never_reach_evil` when
`PLAYWRIGHT_BROWSERS_PATH` is unset.

Browser destination-oracle suite with cached WebKit
(`PLAYWRIGHT_BROWSERS_PATH=$HOME/Library/Caches/ms-playwright`):
**5/5 consecutive** — 10 passed, 0 failed.

xdist (`-n 2`), same confinement set plus browser tests:
**2/2** — 174 passed, 0 failed.

Complete suite (`.venv/bin/pytest` with WebKit path set):
**5/5 consecutive** — 610 passed / 0 failed / 0 skipped each run
(~230s/run).

Production path:

```
SCOPE_FILE=tests/fixtures/virusbarrier/scope.txt \
OWNED_DOMAINS=virusbarrier.xyz \
.venv/bin/python app.py --no-banner -e output/confinement-proof.env \
  run -d virusbarrier.xyz --no-ui --run-id confinement-proof-20260831
```

Repo-root `scope.txt` (Banco Plata) was **not** used. Output:
`output/confinement-proof-20260831`. Seed
`alive.txt`/`resolved.txt`/`subdomains.txt` contain only `virusbarrier.xyz`.
SQLite `intel_network_requests`: 4 ALLOW (virusbarrier.xyz), 15 DENY
(OOS, `network_completed=0`). Indicators: seed `COLLECTED`; OOS SANs
`NOT_ALLOWED`.

## L. Known limitations / out of scope for this audit

### Honest residuals (not hidden; not treated as new findings)

1. **naabu / port_verify** — raw SYN/TCP, architecturally unproxyable.
   Input-gated only. Confirmed still documented here and in README.
2. **Raw-socket bypass of `-proxy`** — an external binary that ignores
   its proxy flag is invisible to `ScopeEnforcingProxy`. Proven in
   `tests/test_untrusted_network_bypass.py`. OS-level confinement is
   outside Hydra.
3. **HTTPS CONNECT path exclusions** — no TLS interception; path
   exclusions apply to plain HTTP and to Python/Playwright URL-aware
   checks, not to encrypted CONNECT tunnels.
4. **External OPSEC proxy chaining** — after Hydra ALLOWs and forwards,
   the upstream proxy resolves independently. Hydra's own socket never
   touches an unauthorized destination.
5. **Fixed third-party / control-plane destinations (F\*)** — crt.sh,
   URLhaus, OSV, WPScan, Cymru, archive binaries, webhook, OPSEC
   diagnostics. Destination is not CollectionScope-derived. Taxonomy
   has no cleaner letter.
6. **Seed-path `intel_collection_attempts`** — follow-up writes attempt
   rows; a seed-only production run reconstructs via
   `intel_indicators` + `intel_network_requests` (0 attempt rows for
   `confinement-proof-20260831` because every extra SAN was
   `NOT_ALLOWED` and follow-up HTTP never started). Not a confinement
   bypass.
7. **Operational noise on the live run** — WHOIS rate-limited (plugin
   FAILED, not COLLECTED); crt.sh HTTP 502 (0 CT records from that
   API; SANs still observed from the live TLS certificate httpx
   grabbed). Process exit 1 because WHOIS is recorded as an error.
   Confinement still held.

### Out of scope this audit (Sections 19–20 exclusion)

* Host graph vs. Intel graph reconciliation
* Certificate-as-evidence identity / SAN merging
* Unified reporting serializer (`serialize_relationship` /
  `relationship_view`)
* Whether `IntelEngine.finalize()` treats `context.alive_urls` as the
  correlation authority

Noted while tracing, not evaluated, not blocking READY/NOT READY:

* The Host table records OOS SAN names as `hosts` rows (observation).
  Their `collection_status` is `NOT_ALLOWED`. This is Section 22
  (observe ≠ collect), not a network-path failure.

### Release gate

No G-class production path remains. Destination-server oracles for
HTTP, redirects, crawlers, browser subresources, SSRF/rebinding, poisoned
`alive.txt`, and follow-up 302-to-evil all recorded ZERO unauthorized
connections. Real `python app.py run` against `virusbarrier.xyz` recorded
ZERO completed unauthorized connections.

**Verdict: READY** (network confinement scope only).
