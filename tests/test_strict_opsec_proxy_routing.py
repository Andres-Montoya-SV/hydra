"""Security audit (hardening round 1, Task 3): every plugin allowed under
STRICT_OPSEC (`strict_opsec_allowed = True`) must not silently imply a
capability Hydra cannot actually apply (invariant 9). The target-directed
plugins (httpx, browser_probe, soft404_check, param_fuzz, cloud_bucket_enum)
are already proven proxy-confined by the live confinement suite
(tests/test_*_confinement_live.py) — not re-tested here.

What had never been directly tested: the four `THIRD_PARTY_OBSERVATION`
plugins allowed under STRICT_OPSEC (`ctlogs`, `threat_intel`, `vuln_match`,
`passive_dns`) never touch the target either way, but under STRICT_OPSEC
the *operator's own* connection to the fixed third party (crt.sh, URLhaus,
OSV.dev/WPScan, Mnemonic/SecurityTrails) must itself be proxied — otherwise
STRICT_OPSEC would protect the target's view of Hydra while leaving the
operator's real IP exposed to those third parties. Each test below proves
the real network-issuing function actually receives the configured
`OUTBOUND_PROXY_URL`, not just that the plugin *could* pass it along.
"""

from __future__ import annotations

import json
from urllib.request import Request

import pytest

_PROXY = "http://127.0.0.1:39999"


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, _n: int = -1) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestCtlogsRoutesThroughOperatorProxy:
    def test_fetch_crtsh_forwards_outbound_proxy_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from modules import ctlogs

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(b"[]")

        monkeypatch.setattr(ctlogs, "open_url", fake_open_url)
        ctlogs._fetch_crtsh("example.com", 10, "hydra/1.0", _PROXY)
        assert captured["proxy_url"] == _PROXY


class TestThreatIntelRoutesThroughOperatorProxy:
    def test_query_urlhaus_forwards_outbound_proxy_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modules import threat_intel

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(json.dumps({"query_status": "no_results"}).encode())

        monkeypatch.setattr(threat_intel, "open_url", fake_open_url)
        threat_intel._query_urlhaus("evil.example", "fake-key", 10, "hydra/1.0", _PROXY)
        assert captured["proxy_url"] == _PROXY


class TestVulnMatchRoutesThroughOperatorProxy:
    def test_osv_query_forwards_outbound_proxy_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from modules import vuln_match

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(json.dumps({"vulns": []}).encode())

        monkeypatch.setattr(vuln_match, "open_url", fake_open_url)
        vuln_match._osv_query(
            "some-package", "1.0.0", timeout=10, proxy_url=_PROXY, user_agent="hydra/1.0"
        )
        assert captured["proxy_url"] == _PROXY

    def test_wpscan_query_forwards_outbound_proxy_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modules import vuln_match

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(json.dumps({}).encode())

        monkeypatch.setattr(vuln_match, "open_url", fake_open_url)
        vuln_match._wpscan_query(
            "woocommerce",
            "1.0.0",
            token="fake-token",  # noqa: S106 - test double, never a real credential
            timeout=10,
            proxy_url=_PROXY,
            user_agent="hydra/1.0",
        )
        assert captured["proxy_url"] == _PROXY


class TestPassiveDnsRoutesThroughOperatorProxy:
    def test_query_mnemonic_forwards_outbound_proxy_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modules import passive_dns

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(json.dumps({"answer": []}).encode())

        monkeypatch.setattr(passive_dns, "open_url", fake_open_url)
        passive_dns._query_mnemonic("sibling.example", 10, "hydra/1.0", _PROXY)
        assert captured["proxy_url"] == _PROXY

    def test_query_securitytrails_forwards_outbound_proxy_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from modules import passive_dns

        captured: dict[str, object] = {}

        def fake_open_url(request: Request, *, timeout: int, proxy_url: str | None = None):
            captured["proxy_url"] = proxy_url
            return _FakeResponse(json.dumps({"records": []}).encode())

        monkeypatch.setattr(passive_dns, "open_url", fake_open_url)
        passive_dns._query_securitytrails("sibling.example", "fake-key", 10, "hydra/1.0", _PROXY)
        assert captured["proxy_url"] == _PROXY


class TestStrictOpsecAllowedPluginsMatchClassAttributesExactly:
    """Sanity check on this audit's own scoping claim, mirroring the
    equivalent check for ACTIVE_COLLECTION_PLUGINS: STRICT_OPSEC_ALLOWED_PLUGINS
    is derived from `strict_opsec_allowed=True`, not a hand-maintained list
    that could silently drift as new plugins are added."""

    def test_derived_set_matches_declared_class_attributes(self) -> None:
        from core.collectors import STRICT_OPSEC_ALLOWED_PLUGINS, plugin_classes

        declared = {
            cls.name for cls in plugin_classes() if getattr(cls, "strict_opsec_allowed", False)
        }
        assert declared == STRICT_OPSEC_ALLOWED_PLUGINS
        assert declared

    def test_naabu_and_port_verify_are_not_allowed_under_strict_opsec(self) -> None:
        """naabu/port_verify's raw TCP/SYN traffic architecturally cannot
        be proxy-confined — they must stay entirely blocked under
        STRICT_OPSEC, not quietly "allowed" with a confinement claim the
        code can't back up."""
        from core.collectors import STRICT_OPSEC_ALLOWED_PLUGINS

        assert "naabu" not in STRICT_OPSEC_ALLOWED_PLUGINS
        assert "port_verify" not in STRICT_OPSEC_ALLOWED_PLUGINS
