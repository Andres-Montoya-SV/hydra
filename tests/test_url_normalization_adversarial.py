"""Adversarial hostname/URL normalization: the classic bug class behind most
real-world SSRF and scope-bypass vulnerabilities.

Two layers are tested:
1. The authorization primitive itself (`allows_active_collection`) against a
   battery of crafted indicator strings.
2. The actual httpx redirect-hop resolution path (`_resolve_authorized_redirects`)
   against the same tricks delivered as a `Location` header — proving the real
   code path never issues the follow-up request, not just that the primitive
   would deny the string in isolation.

None of these are hypothetical: userinfo-confusion, protocol-relative
redirects, and subdomain-confusion are well-known real-world techniques for
tricking naive host-parsing into authorizing the wrong destination.
"""

from __future__ import annotations

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope, allows_active_collection
from modules.httpx import HttpxPlugin

SCOPE = CollectionScope.from_seeds(["allowed.test"], patterns=["allowed.test"])


@pytest.fixture(autouse=True)
def _fake_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """`allowed.test` is a synthetic `.test` name that never resolves. These
    cases exercise hostname/URL-confusion authorization, not the
    destination-IP SSRF layer (tested on its own in
    tests/test_ssrf_destination_policy.py) — stub DNS to a fixed
    public-looking address so that orthogonal, real-DNS-dependent check
    doesn't turn a URL-confusion test into a DNS-resolution test by
    accident. IP-literal cases in this file (127.0.0.1, ::1) are denied by
    hostname/scope classification before this stub is ever consulted, so
    they still exercise real, unmodified behavior.
    """
    monkeypatch.setattr("core.collection.ssrf.resolve_hostname", lambda host: ["203.0.113.10"])


@pytest.mark.parametrize(
    "indicator,expected,label",
    [
        # userinfo confusion: the host is what comes AFTER '@', never before.
        (
            "https://allowed.test@oos.test/",
            False,
            "userinfo used to smuggle allowed host, real host is OOS",
        ),
        (
            "https://oos.test@allowed.test/",
            True,
            "userinfo happens to look like OOS, real host is allowed",
        ),
        # IP literals must not bypass domain-based scope.
        ("https://127.0.0.1/", False, "IPv4 literal, scope is a domain"),
        ("http://[::1]/", False, "IPv6 literal, scope is a domain"),
        ("http://[::1]:8080/path", False, "IPv6 literal with port"),
        # subdomain confusion: a misleading label prefix must not fool suffix matching.
        (
            "https://allowed.test.oos.test/",
            False,
            "allowed.test as a misleading label, real host is oos.test",
        ),
        ("allowed.test.oos.test", False, "same, bare host form"),
        # a REAL subdomain of the authorized domain is legitimately in scope
        # (existing, deliberate policy — host_in_scope treats an exact
        # pattern as covering its subdomains too; not something this test
        # changes or should change).
        (
            "oos.test.allowed.test",
            True,
            "genuine subdomain of allowed.test, label is just confusing",
        ),
        # normalization must not create false negatives for the common case.
        ("allowed.test.", True, "trailing dot"),
        ("ALLOWED.TEST", True, "case"),
        ("allowed.test:8443", True, "bare host:port"),
        ("HTTPS://ALLOWED.TEST/CASE", True, "case, full URL"),
        # encoding tricks must not merge into the authorized hostname.
        ("https://allowed.test%2eevil.com/", False, "percent-encoded dot appended"),
        ("https://allowed.test%00.evil.com/", False, "null-byte trick"),
        # unrelated punycode literal must not be confused with anything.
        ("https://xn--80ak6aa92e.com/", False, "unrelated punycode literal"),
    ],
)
def test_allows_active_collection_resists_url_confusion(
    indicator: str, expected: bool, label: str
) -> None:
    assert (
        allows_active_collection(indicator, SCOPE) is expected
    ), f"{label}: {indicator!r} should be allowed={expected}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location,should_request,label",
    [
        ("//oos.test/path", False, "protocol-relative redirect resolves to OOS host"),
        ("https://allowed.test@oos.test/x", False, "userinfo smuggling in a Location header"),
        ("https://127.0.0.1/admin", False, "IPv4 literal in a Location header"),
        ("http://[::1]/admin", False, "IPv6 literal in a Location header"),
        ("https://allowed.test%2eevil.com/", False, "percent-encoded dot in a Location header"),
        ("https://allowed.test.oos.test/", False, "subdomain-confusion label in a Location header"),
        ("HTTPS://ALLOWED.TEST/CASE", True, "same host, different case — must still be followed"),
        ("/relative/path", True, "relative redirect on the same host — must still be followed"),
    ],
)
async def test_httpx_redirect_hop_resists_url_confusion(
    location: str, should_request: bool, label: str
) -> None:
    """Exercises the real `_resolve_authorized_redirects` code path, not just
    the authorization primitive in isolation — proves the follow-up httpx
    subprocess call is never reached for a disguised OOS destination."""
    settings = Settings(project_root=".")
    plugin = HttpxPlugin(settings)
    requested: list[str] = []

    async def fake_fetch(context, target, *, suffix, record_index, hop):
        requested.append(target.raw)
        return None

    plugin._fetch_single_hop = fake_fetch  # type: ignore[method-assign]
    record = {
        "input": "allowed.test",
        "host": "allowed.test",
        "url": "https://allowed.test/foo",
        "status_code": 302,
        "location": location,
    }
    await plugin._resolve_authorized_redirects(None, record, SCOPE, "", 0)

    if should_request:
        assert requested, f"{label}: expected the authorized hop to actually be requested"
    else:
        assert requested == [], f"{label}: {location!r} must never reach the follow-up request"
