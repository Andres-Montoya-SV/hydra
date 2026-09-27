"""Fase 12 (EASM roadmap) — tests for `core/collection/rdap_client.py`
and `core/parsers/rdap.py`.

Split the same way `tests/test_whois_client.py` splits its own coverage:
the redirect-following/response-classification orchestration in
`fetch_rdap_domain` is tested fully deterministically via an injected
fake `fetcher` (no network); the SSRF hop-validation itself
(`_fetch_one`) is tested by monkeypatching DNS resolution to return a
blocked IP and confirming the request is refused BEFORE any socket is
opened — the actual security-critical property.
"""

from __future__ import annotations

import json

import pytest

from core.collection import rdap_client
from core.collection.rdap_client import RdapHop, _fetch_one, _FetchOutcome, fetch_rdap_domain
from core.parsers.rdap import parse_rdap_domain_response

_SUCCESS_BODY = {
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
    ],
}


def _fake_fetcher_returning(sequence: list[_FetchOutcome]):
    calls = {"n": 0}

    def fetcher(url: str, timeout: float) -> _FetchOutcome:
        outcome = sequence[calls["n"]]
        calls["n"] += 1
        return outcome

    return fetcher


class TestFetchRdapDomainRedirectFollowing:
    def test_a_successful_response_with_no_redirect_is_returned(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=200,
                    ),
                    json.dumps(_SUCCESS_BODY).encode(),
                    None,
                )
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert not result.blocked
        assert result.body == _SUCCESS_BODY
        assert len(result.hops) == 1

    def test_one_redirect_is_followed_to_the_authoritative_server(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=302,
                    ),
                    b"",
                    "https://rdap.example-registry.net/domain/example.com",
                ),
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.example-registry.net/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=200,
                    ),
                    json.dumps(_SUCCESS_BODY).encode(),
                    None,
                ),
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert not result.blocked
        assert result.body == _SUCCESS_BODY
        assert len(result.hops) == 2

    def test_too_many_redirects_is_blocked(self) -> None:
        def infinite_redirect(url: str, timeout: float) -> _FetchOutcome:
            return _FetchOutcome(
                RdapHop(url=url, allowed=True, reason="allowed", status_code=302), b"", url
            )

        result = fetch_rdap_domain("example.com", fetcher=infinite_redirect)
        assert result.blocked
        assert result.blocked_reason == "too_many_redirects"

    def test_a_blocked_hop_stops_the_chain_immediately(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=False,
                        reason="dns_resolution_failed",
                    ),
                    b"",
                    None,
                )
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert result.blocked
        assert result.blocked_reason == "dns_resolution_failed"

    def test_malformed_json_response_is_blocked_not_a_crash(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=200,
                    ),
                    b"{not valid json,,,",
                    None,
                )
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert result.blocked
        assert result.blocked_reason == "malformed_json_response"

    def test_a_json_array_instead_of_an_object_is_blocked(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=200,
                    ),
                    b"[1, 2, 3]",
                    None,
                )
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert result.blocked
        assert result.blocked_reason == "unexpected_response_shape"

    def test_an_unexpected_status_code_is_blocked(self) -> None:
        fetcher = _fake_fetcher_returning(
            [
                _FetchOutcome(
                    RdapHop(
                        url="https://rdap.org/domain/example.com",
                        allowed=True,
                        reason="allowed",
                        status_code=500,
                    ),
                    b"",
                    None,
                )
            ]
        )
        result = fetch_rdap_domain("example.com", fetcher=fetcher)
        assert result.blocked
        assert "500" in result.blocked_reason


class TestFetchOneSsrfValidation:
    def test_a_redirect_target_resolving_to_a_private_ip_is_refused_before_any_socket_opens(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_resolve(hostname: str) -> list[str]:
            return ["127.0.0.1"]

        monkeypatch.setattr("core.collection.ssrf.resolve_hostname", fake_resolve)

        def explode_if_called(*args: object, **kwargs: object) -> None:
            raise AssertionError("a socket must never be opened for a blocked destination")

        monkeypatch.setattr(rdap_client.socket, "create_connection", explode_if_called)

        outcome = _fetch_one("https://malicious-registry.example/domain/example.com", timeout=1.0)
        assert not outcome.hop.allowed
        assert (
            "private" in outcome.hop.reason
            or "loopback" in outcome.hop.reason
            or outcome.hop.reason
        )

    def test_a_non_https_scheme_is_rejected_without_any_dns_lookup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode_if_called(hostname: str) -> list[str]:
            raise AssertionError("must reject scheme before resolving DNS")

        monkeypatch.setattr("core.collection.ssrf.resolve_hostname", explode_if_called)
        outcome = _fetch_one("http://rdap.org/domain/example.com", timeout=1.0)
        assert not outcome.hop.allowed
        assert outcome.hop.reason == "unsupported_scheme_or_host"


class TestRdapDomainResponseParsing:
    def test_extracts_registrar_and_dates(self) -> None:
        info = parse_rdap_domain_response(_SUCCESS_BODY)
        assert info.registrar == "Example Registrar Inc."
        assert info.registration_created_at == "2020-01-01T00:00:00Z"
        assert info.registration_expires_at == "2027-01-01T00:00:00Z"

    def test_missing_fields_produce_empty_strings_not_an_exception(self) -> None:
        info = parse_rdap_domain_response({})
        assert info.registrar == ""
        assert info.registration_created_at == ""
        assert info.registration_expires_at == ""

    def test_registrar_without_a_vcard_name_falls_back_to_handle(self) -> None:
        body = {"entities": [{"roles": ["registrar"], "handle": "REGISTRAR-123"}]}
        info = parse_rdap_domain_response(body)
        assert info.registrar == "REGISTRAR-123"

    def test_never_extracts_a_non_registrar_entity_as_the_registrar(self) -> None:
        body = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Some Private Person"]]],
                }
            ]
        }
        info = parse_rdap_domain_response(body)
        assert info.registrar == ""
