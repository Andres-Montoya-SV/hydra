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

| Network operation | Caller | Target source | Authorization API | Enforcement boundary | Fail closed? | Auditable? | Test |
|---|---|---|---|---|---|---|---|
| DNS resolution (seed) | `modules/dnsx.py` | gated input file | `authorize_plugin_input` at `_gate_active_input` (`core/runner.py:210`) | plugin input choke point | Yes | `intel_indicators`/`intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| DNS resolution (follow-up) | `core/intel/followup.py:250,260` | `IndicatorQueue.eligible_followups` | `authorize_active_indicator(host, scope, "dnsx", "seed_dns")` | pre-claim `CollectionAttempt` persisted before subprocess (`claim_attempt`) | Yes | `intel_collection_attempts` (IN_FLIGHT row survives a crash) | `test_followup_loop.py`, crash test in `test_followup_artifacts.py` |
| HTTP probe (seed) | `modules/httpx.py` | gated input file | `authorize_plugin_input` | plugin input choke point | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| HTTP redirect hop | `modules/httpx.py:_resolve_authorized_redirects` | `Location` header, walked hop-by-hop (no `-follow-redirects`) | `AuthorizedCollectionTarget.authorize(...)` (`core/collection/target.py`) | per-hop authorization; `_fetch_single_hop` takes the authorized target object, not a string | Yes (`blocked_target`, loop stops) | `intel_network_requests` (per-hop `request_id`) | `test_redirect_safety.py`, `test_url_normalization_adversarial.py`, `test_network_request_audit_trail.py` |
| Port scan | `modules/naabu.py` | gated input file | `authorize_plugin_input` | plugin input choke point | Yes | `intel_collection_attempts` | `test_naabu.py`, `test_missing_scope_all_active_plugins.py` |
| ASN lookup (target-derived) | `modules/asn_lookup.py:145` | `context.resolved` hosts | `allows_active_collection(h, scope)` per host | per-hostname filter before lookup | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Cloud bucket enumeration | `modules/cloud_bucket_enum.py:121,170` | generated bucket hostname | `authorize_active_indicator(...)`, explicit `cloud_collection_allowed` opt-in (`core/intel/authorize.py`) | per-generated-hostname check — **not** a blanket `*.s3.amazonaws.com` rule | Yes (denied unless explicitly opted in; the opt-in-flag-was-a-no-op bug found and fixed in a prior turn) | `intel_collection_attempts` | prior turn's `authorize_active_indicator` regression test |
| WHOIS (target-derived) | `modules/whois.py:79` | seed domain | `authorize_active_indicator(domain, scope, "whois", "seed_registration")` | per-plugin-input check | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| gau / waybackurls (passive archive query) | `modules/gau.py:40`, `modules/waybackurls.py:40` | seed domain, queried against a third-party archive API (not the target's own infrastructure) | `authorize_active_indicator(t.domain, scope, ..., "seed_archive")` gates whether the seed is queried at all | plugin input check; the network destination itself (web.archive.org) is intentionally outside `CollectionScope`, documented as a non-target network path | Yes for the seed-gating decision | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Threat intel / vuln enrichment (target-derived) | `modules/threat_intel.py:127`, `modules/vuln_match.py:142` | already-alive host/landing URL | `allows_active_collection(host, scope)` | per-URL filter before enrichment call | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Wildcard DNS check | `modules/wildcard_check.py:76` | candidate wildcard-derived domain | `allows_active_collection(domain, scope)` | per-domain filter | Yes | `intel_collection_attempts` | `test_missing_scope_all_active_plugins.py` |
| Crawler discovery (katana/hakrawler/nuclei) | `modules/katana.py`, `hakrawler.py`, `nuclei.py` via `modules/_base.py:_crawler_confinement` | URLs the tool discovers/crawls internally, not the gated input file | `ScopeEnforcingProxy._authorize_with_reason` (socket-level, not input-level) | local HTTP/HTTPS forward proxy: authorizes every `CONNECT`/absolute-URI request before opening a socket | Yes (missing scope, parse error, and authorization exceptions all deny — verified in `test_crawler_proxy.py`) | `intel_network_requests` (this turn) + `proxy.denied` warnings | `test_crawler_proxy.py` (raw sockets), `test_crawler_confinement_live.py` (real katana/hakrawler binaries) |
| Browser navigation/subresources | `modules/browser_probe.py` | every request the loaded page issues: document, iframe, script, image, xhr, fetch, WebSocket, popup, Worker | `browser_context.route()`/`route_web_socket()` calling `allows_active_collection` | browser-context-level route interception (not page-level — covers every page/popup opened in the context) | Yes (missing scope and exceptions both deny) | warnings only (no `intel_network_requests` row yet — documented gap) | `test_browser_probe_scope_guard.py` (real WebKit) |
| **Raw-socket bypass of an external tool's own configured `-proxy`** | any subprocess-based collector, hypothetically | arbitrary — outside any HTTP client's proxy-selection logic entirely | **none reachable** — an application-level HTTP/HTTPS forward proxy cannot see a connection that never speaks the proxy protocol | **none** — this is the honest, proven boundary of `ScopeEnforcingProxy` | **No** — this is the one row in this table where the answer is no, by design of what an application-level proxy can do | No (no OS-level visibility) | `tests/test_untrusted_network_bypass.py` (**new this turn** — a real subprocess opening a real raw socket to a real local server, proven to reach it) |
| (not a network operation) `explain-collection` reconstruction | `core/intel/query.py:IntelQuery.explain_collection` | n/a — reads persisted rows only | n/a | n/a | n/a | Yes — this **is** the auditability mechanism for every row above that has one | `tests/test_explain_collection_cli.py` (**new this turn**) |

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
