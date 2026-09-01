# Hydra Final Network Boundary Audit

**Date:** 2026-08-29
**Method:** re-verified by grepping the current tree for every call site of
`authorize_collection`, `authorize_active_indicator`, `allows_active_collection`,
and `authorize_plugin_input` (not by trusting the prior turns' docs, though
this session's own history — `docs/NETWORK_BOUNDARY_AUDIT.md`,
`docs/FINAL_SECURITY_AUDIT.md` — is where the deep narrative for each row
lives; this document is the flat table the mission text asks for, cross-
checked against the live grep output below, not a restatement of belief).

This document does not repeat the full narrative already written and
independently verified in `docs/NETWORK_BOUNDARY_AUDIT.md` (11 sections) and
`docs/FINAL_SECURITY_AUDIT.md`. It is the flat table those documents were
missing, plus the two genuinely new rows this turn adds: the raw-socket
bypass proof (row 14) and the `explain-collection` reconstruction path
(row 15, not itself a network operation).

## Verified inventory of `active_collection=True` plugins

```
grep -rl "active_collection = True" modules/
```

19 files: `asn_lookup`, `browser_probe`, `cloud_bucket_enum`, `dnsx`, `gau`,
`hakrawler`, `httpx`, `katana`, `naabu`, `nuclei`, `param_fuzz`, `port_verify`,
`security_headers`, `soft404_check`, `threat_intel`, `vuln_match`,
`waybackurls`, `whois`, `wildcard_check`. All 19 are covered by
`tests/test_missing_scope_all_active_plugins.py`, which patches every
network/subprocess primitive each plugin could reach and asserts none of
them are ever called with `context.collection_scope is None`.

## Table

| Network operation | Caller | Target source | Authorization API | Destination-IP validated? | Enforcement boundary | Fail closed? | Auditable? | Test |
|---|---|---|---|---|---|---|---|---|
| DNS resolution (seed) | `modules/dnsx.py` | gated input file | `authorize_plugin_input` at `_gate_active_input` (`core/runner.py:210`) | No — a DNS *query* about the hostname, not itself a connection to a resolved IP | plugin input choke point | Yes | `intel_indicators`/`intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| DNS resolution (follow-up) | `core/intel/followup.py:250,260` | `IndicatorQueue.eligible_followups` | `authorize_active_indicator(host, scope, "dnsx", "seed_dns")` | No, same reasoning | pre-claim `CollectionAttempt` persisted before subprocess (`claim_attempt`) | Yes | `intel_collection_attempts` (IN_FLIGHT row survives a crash) | `test_followup_loop.py`, crash test in `test_followup_artifacts.py` |
| HTTP probe (seed) | `modules/httpx.py` | gated input file | `authorize_plugin_input` | **No — documented gap.** The operator's own typed seed hostname is not resolved and IP-checked before the first request. See "What this turn does not close" below. | plugin input choke point | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| HTTP redirect hop | `modules/httpx.py:_resolve_authorized_redirects` | `Location` header, walked hop-by-hop (no `-follow-redirects`) | `AuthorizedCollectionTarget.authorize_verbose(...)` (`core/collection/target.py`) | **Yes — new this turn.** `validate_destination_ips()` (`core/collection/ssrf.py`) resolves the hostname and denies a blocked IP (loopback/RFC1918/link-local/CGNAT/metadata/multicast/reserved) unless `scope.allow_private_network_targets` | per-hop authorization; `_fetch_single_hop` takes the authorized target object, not a string; dangerous schemes (`file:`/`ftp:`/`gopher:`/`data:`/`javascript:`/`blob:`) rejected before authorization is even attempted | Yes (`blocked_target`, loop stops; DNS resolution failure/empty answer also fails closed) | `intel_network_requests` (per-hop `request_id`, now including `resolved_ip`) | `test_redirect_safety.py`, `test_url_normalization_adversarial.py`, `test_network_request_audit_trail.py`, `test_ssrf_destination_policy.py` (**new**) |
| Port scan | `modules/naabu.py` | gated input file | `authorize_plugin_input` | No | plugin input choke point | Yes | `intel_collection_attempts` | `test_naabu.py`, `test_missing_scope_all_active_plugins.py` |
| ASN lookup (target-derived) | `modules/asn_lookup.py:145` | `context.resolved` hosts | `allows_active_collection(h, scope)` per host | No | per-hostname filter before lookup | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Cloud bucket enumeration | `modules/cloud_bucket_enum.py:121,170` | generated bucket hostname | `authorize_active_indicator(...)`, explicit `cloud_collection_allowed` opt-in (`core/intel/authorize.py`) | No | per-generated-hostname check — **not** a blanket `*.s3.amazonaws.com` rule | Yes (denied unless explicitly opted in; the opt-in-flag-was-a-no-op bug found and fixed in a prior turn) | `intel_collection_attempts` | prior turn's `authorize_active_indicator` regression test |
| WHOIS (target-derived) | `modules/whois.py:79` | seed domain | `authorize_active_indicator(domain, scope, "whois", "seed_registration")` | No | per-plugin-input check | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| gau / waybackurls (passive archive query) | `modules/gau.py:40`, `modules/waybackurls.py:40` | seed domain, queried against a third-party archive API (not the target's own infrastructure) | `authorize_active_indicator(t.domain, scope, ..., "seed_archive")` gates whether the seed is queried at all | No | plugin input check; the network destination itself (web.archive.org) is intentionally outside `CollectionScope`, documented as a non-target network path | Yes for the seed-gating decision | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Threat intel / vuln enrichment (target-derived) | `modules/threat_intel.py:127`, `modules/vuln_match.py:142` | already-alive host/landing URL | `allows_active_collection(host, scope)` | No | per-URL filter before enrichment call | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Wildcard DNS check | `modules/wildcard_check.py:76` | candidate wildcard-derived domain | `allows_active_collection(domain, scope)` | No | per-domain filter | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Crawler discovery (katana/hakrawler/nuclei) | `modules/katana.py`, `hakrawler.py`, `nuclei.py` via `modules/_base.py:_crawler_confinement` | URLs the tool discovers/crawls internally, not the gated input file | `ScopeEnforcingProxy._authorize_with_reason` (socket-level, not input-level) | **Yes — new this turn.** Same `core/collection/ssrf.py` policy, applied after the hostname-scope check passes; the proxy then connects to the exact resolved IP it validated, not a fresh lookup (DNS-rebinding/TOCTOU closed) | local HTTP/HTTPS forward proxy: authorizes every `CONNECT`/absolute-URI request before opening a socket | Yes (missing scope, parse error, DNS resolution failure, and authorization exceptions all deny — verified in `test_crawler_proxy.py`, `test_ssrf_destination_policy.py`) | `intel_network_requests` (now including `resolved_ip`) + `proxy.denied` warnings | `test_crawler_proxy.py` (raw sockets), `test_crawler_confinement_live.py` (real katana/hakrawler binaries), `test_ssrf_destination_policy.py` (**new**) |
| Browser navigation/subresources | `modules/browser_probe.py` | every request the loaded page issues: document, iframe, script, image, xhr, fetch, WebSocket, popup, Worker | `browser_context.route()`/`route_web_socket()` calling `allows_active_collection` | **No — documented gap**, unchanged this turn. Playwright's routing API only exposes true/false to decide abort/continue; wiring async DNS resolution into that synchronous-looking callback path was not attempted this turn (see "What this turn does not close") | browser-context-level route interception (not page-level — covers every page/popup opened in the context) | Yes (missing scope and exceptions both deny) | warnings only (no `intel_network_requests` row yet — documented gap) | `test_browser_probe_scope_guard.py` (real WebKit) |
| **Raw-socket bypass of an external tool's own configured `-proxy`** | any subprocess-based collector, hypothetically | arbitrary — outside any HTTP client's proxy-selection logic entirely | **none reachable** — an application-level HTTP/HTTPS forward proxy cannot see a connection that never speaks the proxy protocol | N/A | **none** — this is the honest, proven boundary of `ScopeEnforcingProxy` | **No** — this is the one row in this table where the answer is no, by design of what an application-level proxy can do | No (no OS-level visibility) | `tests/test_untrusted_network_bypass.py` (a real subprocess opening a real raw socket to a real local server, proven to reach it) |
| (not a network operation) `explain-collection` reconstruction | `core/intel/query.py:IntelQuery.explain_collection` | n/a — reads persisted rows only | n/a | n/a | n/a | n/a | Yes — this **is** the auditability mechanism for every row above that has one | `tests/test_explain_collection_cli.py` |

## What is genuinely new in this pass vs. prior turns

Everything above except the last two rows restates, with a fresh grep
cross-check, conclusions this security-hardening arc already reached and
verified in turns 1–6 (see `docs/NETWORK_BOUNDARY_AUDIT.md` for the full
per-item narrative and `docs/READINESS_REPORT.md` for the consolidated
BEFORE/AFTER). Two things are actually new this turn:

1. **The raw-socket bypass is now proven, not just asserted.** Prior turns'
   documentation already said, in prose, that a tool bypassing its own
   `-proxy` configuration is outside what `ScopeEnforcingProxy` can see.
   `tests/test_untrusted_network_bypass.py` demonstrates this concretely: a
   real subprocess with `HTTP_PROXY`/`HTTPS_PROXY` set (as Hydra would set
   them for a confined tool) opens a raw `socket.connect()` and reaches a
   real local "evil" server anyway, because a raw socket never consults
   either environment variable. Because that gap is real and cannot be
   closed by an application-level proxy alone, `core/collection/crawler_proxy.py`
   now defines `PROXY_VERIFIED_TOOLS = {"katana", "hakrawler", "nuclei"}` —
   the only collectors whose real installed binaries have actually been
   driven through `test_crawler_confinement_live.py` and shown to honor
   `-proxy`. `modules/_base.py:_crawler_confinement` emits an explicit
   `UNTRUSTED_NETWORK_TOOL` warning (verified by
   `test_untrusted_network_bypass.py`) for any future collector added to
   this mechanism that is not in that set, instead of silently inheriting an
   unverified confinement claim.

2. **`explain-collection` (Phase 13's ask).** `python app.py explain-collection
   <indicator_id | collection_attempt_id | value>` reconstructs, from SQLite
   alone, why an indicator was or wasn't collected: its discovery reason and
   scope/collection status, the hypothesis that made it eligible (or why it
   was rejected), the relationship/evidence that supported the hypothesis,
   every collection attempt (collector, capability, outcome, artifact), and
   every per-destination network-request decision for that hostname. Verified
   end-to-end against real SQLite rows produced by the real `IntelEngine` in
   `tests/test_explain_collection_cli.py`, including the case where the
   identifier has no indicator/hypothesis/attempt at all (an out-of-scope
   redirect target that only ever produced a `DENY` row in
   `intel_network_requests`) — proving the command doesn't silently fabricate
   a chain where none exists.

## DNS/SSRF destination-IP validation (this turn)

Every authorization primitive audited above — before this turn — decided ALLOW/DENY from a
**hostname string** against `CollectionScope`. None of them resolved DNS or looked at the IP a
connection would actually reach. Confirmed by grep before writing any code: `ipaddress` appeared
only in `core/intel/cloud.py` and `modules/asn_lookup.py` for cloud-provider CIDR *correlation*
(identifying that an IP belongs to AWS/GCP/Azure for intelligence purposes), never for blocking a
connection; no DNS resolution call existed anywhere in the authorization path
(`core/intel/scope.py`, `core/intel/authorize.py`, `core/collection/target.py`). This is the exact
"`allowed.example` → resolves to `10.0.0.1`" gap: a hostname that clears scope authorization by
name says nothing about the address a connection actually reaches, now or after a DNS answer
changes between authorization and connection (rebinding).

**New module: `core/collection/ssrf.py`.** A fixed, scope-independent blocklist —
`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT), `127.0.0.0/8`, `169.254.0.0/16` (link-local,
which covers the `169.254.169.254` cloud-metadata address), `172.16.0.0/12`, `192.168.0.0/16`,
`198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4` for IPv4; `::1/128`, `fc00::/7` (ULA),
`fe80::/10` (link-local), `ff00::/8` (multicast) for IPv6 — plus `is_multicast`/`is_reserved`/
`is_unspecified` as a catch-all. `classify_ip()` is pure (no I/O, 18 parametrized cases in
`tests/test_ssrf_destination_policy.py`, covering every named range plus two ordinary public
addresses that must pass). `validate_destination_ips()`/`validate_destination_ips_async()` resolve
a hostname (or accept an IP literal directly) and apply `classify_ip()` to every resolved address,
failing closed on a resolver exception or an empty answer — never treating either as harmless.

**`CollectionScope.allow_private_network_targets: bool = False`** (mirroring the existing
`cloud_collection_allowed` opt-in pattern) is the only way a private/loopback/link-local/CGNAT/
metadata destination is ever connected to — exactly the mission's requirement that "if an operator
explicitly authorizes a private range, that must be represented explicitly in CollectionScope"
rather than silently allowed because the hostname happened to be in scope.

**Wired into the two call sites that actually open a connection on a hostname's behalf:**

1. `AuthorizedCollectionTarget.authorize()`/`authorize_verbose()` (`core/collection/target.py`,
   httpx redirect-hop resolution) — after the existing hostname/scope/OPSEC check passes, the
   hostname is resolved and validated; a blocked IP returns `None` exactly like any other DENY, and
   `authorize_verbose()` additionally reports *which* gate failed (`out_of_scope` vs.
   `blocked_range:...`/`dns_resolution_failed`/`dns_resolution_empty`) so the audit trail doesn't
   collapse two different denial reasons into one string. Also rejects `file:`/`ftp:`/`gopher:`/
   `data:`/`javascript:`/`blob:` redirect schemes outright, before authorization is even attempted.
2. `ScopeEnforcingProxy._authorize_with_reason()` (`core/collection/crawler_proxy.py`, crawler
   confinement) — same policy, applied after the existing hostname-scope check. **Also closes the
   TOCTOU/rebinding gap directly**: the proxy previously called `asyncio.open_connection(host,
   port)`, re-resolving `host` a second time at connect — a window where DNS could legitimately
   answer differently than what was just checked. It now connects to `decision.connect_ip`, the
   exact address `validate_destination_ips_async()` just validated, never re-resolving the
   hostname. Proven directly in `tests/test_ssrf_destination_policy.py` by spying on
   `asyncio.open_connection`'s actual call arguments (the IP, not the hostname string) and by two
   real end-to-end tests: a real local TCP server that receives **zero** connections when an
   in-scope hostname (DNS monkeypatched, since no live authority lets a test control a real
   hostname's resolution on demand) resolves to it by default, and receives a real connection only
   once `allow_private_network_targets=True` is set explicitly.

**Verified against the actual authorized target, not just synthetic tests:**
```
>>> validate_destination_ips("virusbarrier.xyz")
DestinationDecision(allowed=True, reason='allowed', resolved_ips=('34.75.127.116',))
>>> AuthorizedCollectionTarget.authorize_verbose("https://virusbarrier.xyz/", scope, capability="http_probe", operation="httpx_redirect_hop")
(AuthorizedCollectionTarget(... resolved_ips=('34.75.127.116',)), 'in_scope')
```
Real DNS resolution, real production target, real ALLOW — the new layer does not silently break
the one production scan this project actually runs.

**What this turn does not close** (stated plainly, not left to be discovered later):

- **The initial seed request itself is not destination-IP validated.** An operator who runs
  `python app.py run -d internal-service.corp` — a hostname that resolves to an internal
  address — still gets that first httpx probe unchecked; only httpx's *redirect hops* and the
  crawler proxy's *discovered* connections go through `core/collection/ssrf.py`. Retrofitting the
  seed-request path (`modules/httpx.py`'s first request, `modules/dnsx.py`, `modules/naabu.py`,
  and the rest of the plugins in the table above) is the same "not every call site, only the two
  most valuable ones" bounded-increment choice this whole arc has made repeatedly — scoped
  honestly here rather than silently assumed covered.
- **`browser_probe.py` is not destination-IP validated.** Playwright's `route()`/
  `route_web_socket()` callbacks decide abort/continue synchronously from `allows_active_collection`
  alone; adding an async DNS resolution + IP check into that specific callback shape was not
  attempted this turn.
- **DNS resolution itself (dnsx) is not treated as an SSRF-relevant operation** — querying what a
  hostname's DNS records *are* is not the same as connecting to a resolved address, so it is
  correctly excluded from this table's "destination-IP validated" column rather than incorrectly
  marked as a gap.
- **Found and fixed while writing this section, not left open:** IPv4-mapped IPv6 literals
  (`::ffff:10.0.0.1`) parse as a plain `IPv6Address` under Python's `ipaddress` module, which is
  not in `_BLOCKED_V6` — a real bypass of the blocklist for exactly the kind of dual-stack
  encoding trick SSRF filters are known to miss. `classify_ip()` now detects `addr.ipv4_mapped`
  and reclassifies against the IPv4 blocklist instead; `tests/test_ssrf_destination_policy.py`
  covers a blocked-private, blocked-loopback, and allowed-public case in this encoding.

## Known, explicitly documented gap this table makes unavoidable to see

Row "Raw-socket bypass" is not a defect introduced this turn — it is a
structural limit of any application-level proxy, stated in
`core/collection/crawler_proxy.py`'s own docstring since it was written, and
now backed by a passing test that would fail loudly if someone later claimed
otherwise. `PROXY_VERIFIED_TOOLS` and the `UNTRUSTED_NETWORK_TOOL` warning
are the honest response the mission's Phase 16 asks for: Hydra does not
claim to stop this bypass, and any future collector that isn't verified the
same way katana/hakrawler/nuclei were gets flagged instead of silently
trusted.
