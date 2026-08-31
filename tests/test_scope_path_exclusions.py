"""SCOPE_FILE path exclusions (`!domain/path-glob`) — a bug-bounty program can
authorize a wildcard domain while explicitly carving out a specific path
(e.g. `*.bancoplata.mx` minus `/*/whistleblowing`) as out of scope.

Exclusions are enforced in `authorize_active_indicator` (core/intel/authorize.py),
the single function every active-collection authorization path already funnels
through: `allows_active_collection` (browser_probe's route guard),
`authorize_collection` -> `AuthorizedCollectionTarget.authorize()` (httpx
redirect hops, and every `CollectionGateway`-based plugin: soft404_check,
param_fuzz, cloud_bucket_enum), and `ScopeEnforcingProxy._authorize_with_reason`
(katana/hakrawler/nuclei/httpx via the confinement proxy, for plain-HTTP
traffic where the path is actually visible to the proxy — CONNECT/HTTPS
remains host-level only, same pre-existing limit as everything else about a
CONNECT tunnel).

An exclusion only ever matches a full URL — a bare hostname has no path to
exclude, so it can never trigger one; this is intentional, not a gap (there is
nothing to fail closed against without a path).
"""

from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from core.collection.crawler_proxy import ScopeEnforcingProxy
from core.collection.target import AuthorizedCollectionTarget
from core.http_probe import http_get
from core.intel.authorize import authorize_active_indicator
from core.intel.scope import CollectionScope, allows_active_collection
from core.models import DomainTarget, PipelineContext
from core.scope import load_scope_patterns, split_scope_patterns, url_path_excluded
from modules.browser_probe import allow_browser_navigation


def _bank_scope(**kwargs: object) -> CollectionScope:
    return CollectionScope.from_seeds(
        ["bancoplata.mx"],
        patterns=[
            "*.bancoplata.mx",
            "*.platacard.mx",
            "!bancoplata.mx/*/whistleblowing",
            "!platacard.mx/*/whistleblowing",
        ],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# core/scope.py — pure parsing/matching helpers
# ---------------------------------------------------------------------------


def test_split_scope_patterns_separates_exclusions_from_positive_patterns() -> None:
    positive, exclusions = split_scope_patterns(
        [
            "*.bancoplata.mx",
            "*.platacard.mx",
            "!bancoplata.mx/*/whistleblowing",
            "!platacard.mx/*/whistleblowing",
        ]
    )
    assert positive == ["*.bancoplata.mx", "*.platacard.mx"]
    assert set(exclusions) == {
        ("bancoplata.mx", "/*/whistleblowing"),
        ("platacard.mx", "/*/whistleblowing"),
    }


def test_load_scope_patterns_preserves_exclusion_path_case(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "*.Bancoplata.MX\n!bancoplata.mx/*/Whistleblowing\n",
        encoding="utf-8",
    )
    patterns = load_scope_patterns(scope_file)
    # Positive domain pattern is lowercased, as before.
    assert "*.bancoplata.mx" in patterns
    # Exclusion path keeps its original case — URL paths are case-sensitive.
    assert "!bancoplata.mx/*/Whistleblowing" in patterns


def test_url_path_excluded_matches_wildcard_segment_and_subdomain() -> None:
    exclusions = [("bancoplata.mx", "/*/whistleblowing")]
    assert url_path_excluded("https://bancoplata.mx/es/whistleblowing", exclusions)
    assert url_path_excluded("https://www.bancoplata.mx/en/whistleblowing", exclusions)
    assert not url_path_excluded("https://bancoplata.mx/es/careers", exclusions)
    assert not url_path_excluded("https://otherbank.mx/es/whistleblowing", exclusions)


def test_url_path_excluded_never_matches_a_bare_hostname() -> None:
    # No scheme/path at all — nothing to exclude, must never DENY on this
    # alone (a bare hostname indicator is handled by ordinary domain scope
    # matching, not path exclusion).
    exclusions = [("bancoplata.mx", "/*")]
    assert not url_path_excluded("bancoplata.mx", exclusions)


def test_url_path_excluded_covers_the_full_subtree_not_just_the_exact_path() -> None:
    """Regression for a real bug: the first implementation compared the whole
    path with a single `fnmatch.fnmatch(path, glob)` call, which is an
    *exact*-match glob — `/*/whistleblowing` matched only that literal path
    string, so `/es/whistleblowing/reportar` (one segment deeper, exactly
    where a program's actual report-submission mechanism usually lives) came
    back authorized instead of excluded. `url_path_excluded` must exclude the
    named path AND its entire subtree, matched by whole path segment (not
    substring) so a same-text-prefixed sibling segment is never excluded."""
    exclusions = [("bancoplata.mx", "/*/whistleblowing")]

    # 1. Exact excluded path.
    assert url_path_excluded("https://bancoplata.mx/es/whistleblowing", exclusions)
    # 2. One segment deeper — this is the case that used to wrongly ALLOW.
    assert url_path_excluded("https://bancoplata.mx/es/whistleblowing/reportar", exclusions)
    # 3. Multiple segments deeper.
    assert url_path_excluded("https://bancoplata.mx/es/whistleblowing/formulario/paso2", exclusions)
    # 4. A DIFFERENT path segment that merely starts with the same text must
    #    NOT be excluded — segment equality, not substring containment.
    assert not url_path_excluded("https://bancoplata.mx/es/whistleblowing-info", exclusions)
    # 5. Unrelated subdomain path — no relation to the exclusion at all.
    assert not url_path_excluded("https://sub.bancoplata.mx/algo", exclusions)
    # 6. Unrelated path on the same domain.
    assert not url_path_excluded("https://bancoplata.mx/es/otra-cosa", exclusions)

    # Trailing slash and a query string must not defeat the subtree match.
    assert url_path_excluded("https://bancoplata.mx/es/whistleblowing/", exclusions)
    assert url_path_excluded("https://bancoplata.mx/en/whistleblowing?ref=x", exclusions)


def test_allows_active_collection_covers_the_full_subtree_end_to_end() -> None:
    """Same six cases as above, through the real end-to-end path — this is
    the exact shape of the manual verification script that surfaced the bug:
    `allows_active_collection(url, scope)` against a real `CollectionScope`."""
    scope = _bank_scope()

    assert not allows_active_collection("https://bancoplata.mx/es/whistleblowing", scope)
    assert not allows_active_collection("https://bancoplata.mx/es/whistleblowing/reportar", scope)
    assert not allows_active_collection(
        "https://bancoplata.mx/es/whistleblowing/formulario/paso2", scope
    )
    assert allows_active_collection("https://bancoplata.mx/es/whistleblowing-info", scope)
    assert allows_active_collection("https://sub.bancoplata.mx/algo", scope)
    assert allows_active_collection("https://bancoplata.mx/es/otra-cosa", scope)


def test_collection_scope_from_seeds_parses_scope_file_exclusions(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "*.bancoplata.mx\n"
        "*.platacard.mx\n"
        "!bancoplata.mx/*/whistleblowing\n"
        "!platacard.mx/*/whistleblowing\n",
        encoding="utf-8",
    )
    scope = CollectionScope.from_seeds(["bancoplata.mx"], scope_file=scope_file)
    assert set(scope.scope_patterns) == {"*.bancoplata.mx", "*.platacard.mx"}
    assert set(scope.path_exclusions) == {
        ("bancoplata.mx", "/*/whistleblowing"),
        ("platacard.mx", "/*/whistleblowing"),
    }


# ---------------------------------------------------------------------------
# core/intel/authorize.py — the shared authoritative decision function
# ---------------------------------------------------------------------------


def test_authorize_active_indicator_denies_excluded_path_even_when_domain_authorized() -> None:
    scope = _bank_scope()
    result = authorize_active_indicator(
        "https://bancoplata.mx/es/whistleblowing", scope, "active_collection", "test"
    )
    assert not result.allowed
    assert result.reason == "excluded_path_out_of_scope"


def test_authorize_active_indicator_denies_excluded_path_on_authorized_subdomain() -> None:
    scope = _bank_scope()
    result = authorize_active_indicator(
        "https://sub.platacard.mx/pt/whistleblowing", scope, "active_collection", "test"
    )
    assert not result.allowed
    assert result.reason == "excluded_path_out_of_scope"


def test_authorize_active_indicator_allows_non_excluded_path_on_same_domain() -> None:
    scope = _bank_scope()
    result = authorize_active_indicator(
        "https://sub.bancoplata.mx/algo", scope, "active_collection", "test"
    )
    assert result.allowed


def test_allows_active_collection_denies_excluded_path() -> None:
    scope = _bank_scope()
    assert not allows_active_collection("https://bancoplata.mx/es/whistleblowing", scope)
    assert allows_active_collection("https://sub.bancoplata.mx/algo", scope)


# ---------------------------------------------------------------------------
# browser_probe's route guard (used for every resource type, not just
# top-level navigation) — direct call, no real browser needed.
# ---------------------------------------------------------------------------


def test_browser_probe_allow_navigation_denies_excluded_path(tmp_path: Path) -> None:
    context = PipelineContext(
        targets=[DomainTarget(domain="bancoplata.mx")],
        output_dir=tmp_path,
        collection_scope=_bank_scope(),
    )
    assert not allow_browser_navigation("https://bancoplata.mx/es/whistleblowing", context)
    assert allow_browser_navigation("https://sub.bancoplata.mx/algo", context)


# ---------------------------------------------------------------------------
# AuthorizedCollectionTarget / CollectionGateway — soft404_check, param_fuzz,
# cloud_bucket_enum, and httpx's redirect-hop authorization all go through
# this exact classmethod.
# ---------------------------------------------------------------------------


def test_authorized_collection_target_denies_excluded_path() -> None:
    scope = _bank_scope()
    target = AuthorizedCollectionTarget.authorize(
        "https://bancoplata.mx/es/whistleblowing",
        scope,
        capability="param_fuzz",
        operation="param_fuzz_baseline",
    )
    assert target is None


def test_authorized_collection_target_allows_non_excluded_path() -> None:
    scope = _bank_scope()
    target = AuthorizedCollectionTarget.authorize(
        "https://sub.bancoplata.mx/algo",
        scope,
        capability="param_fuzz",
        operation="param_fuzz_baseline",
        validate_destination_ip=False,  # no real DNS for a fake domain in this test
    )
    assert target is not None
    assert target.hostname == "sub.bancoplata.mx"


# ---------------------------------------------------------------------------
# ScopeEnforcingProxy — plain-HTTP crawler traffic (katana/hakrawler/nuclei/
# httpx via -proxy) sees the path, unlike a CONNECT tunnel, so the exclusion
# is enforced here too. Real local server, real proxy, monkeypatched DNS
# (bancoplata.mx is not a domain this test controls).
# ---------------------------------------------------------------------------


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


class _CountingHandler(_QuietHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"reached")


def _serve(handler_cls: type) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port, thread


@pytest.fixture
def target_server() -> Iterator[int]:
    _CountingHandler.hits = []
    httpd, port, thread = _serve(_CountingHandler)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_crawler_proxy_denies_excluded_path_for_plain_http(
    tmp_path: Path, target_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = _bank_scope(allow_private_network_targets=True)
    proxy = ScopeEnforcingProxy(scope, capability="katana")
    await proxy.start()
    try:
        # http_get is a blocking urllib call — it must run off the event
        # loop the proxy's own asyncio server needs to service the request,
        # exactly like every other live test in this repo that drives
        # ScopeEnforcingProxy through core/http_probe.py:http_get.
        response = await asyncio.to_thread(
            http_get,
            f"http://bancoplata.mx:{target_server}/es/whistleblowing",
            timeout=5,
            proxy_url=proxy.proxy_url,
        )
    finally:
        await proxy.stop()
    assert (
        response.status_code == 403
    ), "excluded path must get the proxy's own denial, not a timeout"
    assert _CountingHandler.hits == [], "an excluded path must never reach the real server"


@pytest.mark.asyncio
async def test_crawler_proxy_allows_non_excluded_path_for_plain_http(
    tmp_path: Path, target_server: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", _fake_resolve)
    scope = _bank_scope(allow_private_network_targets=True)
    proxy = ScopeEnforcingProxy(scope, capability="katana")
    await proxy.start()
    try:
        response = await asyncio.to_thread(
            http_get,
            f"http://bancoplata.mx:{target_server}/algo",
            timeout=5,
            proxy_url=proxy.proxy_url,
        )
    finally:
        await proxy.stop()
    assert response.status_code == 200
    assert _CountingHandler.hits == ["/algo"], "a non-excluded in-scope path must reach the server"
