"""Isolated tests for Hydra infrastructure intelligence plugins."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import Host, Port
from core.collection.whois_client import WhoisChainResult
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import (
    ASNParser,
    BrowserProbeParser,
    CtlogsParser,
    HttpxParser,
    PortVerifyParser,
    TarpitCheckParser,
    ThreatIntelParser,
    WhoisParser,
)
from core.provenance import record_observation
from modules.asn_lookup import (
    AsnLookupPlugin,
    _collect_ips,
    _format_exc,
    _parse_cymru_whois,
    _query_cymru,
)
from modules.browser_probe import _url_host
from modules.ctlogs import _extract_names
from modules.httpx import HttpxPlugin
from modules.port_verify import PortVerifyPlugin, _normalize_state, _parse_nmap_output
from modules.threat_intel import _has_online_url
from modules.whois import WhoisPlugin, _parse_whois
from utils.files import read_jsonl, write_jsonl, write_lines

_SCOPE = CollectionScope.from_seeds(
    [
        "metaversejustice.com",
        "www.metaversejustice.com",
        "example.com",
        "virusbarrier.xyz",
        "a.example.com",
        "b.example.com",
    ]
)


def test_whois_parser_normalizes_registration(tmp_path: Path) -> None:
    raw = """
    Domain Name: VIRUSBARRIER.XYZ
    Registrar: NameCheap, Inc.
    Creation Date: 2024-01-02T03:04:05Z
    Registry Expiry Date: 2027-01-02T03:04:05Z
    Name Server: DNS1.EXAMPLE.NET
    Name Server: DNS2.EXAMPLE.NET
    """
    parsed = _parse_whois(raw)
    parsed["domain"] = "virusbarrier.xyz"
    write_jsonl(tmp_path / "whois.jsonl", [parsed])

    hosts, warnings = WhoisParser().parse(tmp_path)

    assert not warnings
    assert hosts[0].registrar == "NameCheap, Inc."
    assert hosts[0].registration_expires_at == "2027-01-02T03:04:05Z"
    assert hosts[0].nameservers == ["dns1.example.net", "dns2.example.net"]


def test_whois_parser_prefers_registrar_dates_over_iana_referral_dates(tmp_path: Path) -> None:
    """Regression test for a real virusbarrier.xyz WHOIS response.

    .xyz is delegated via IANA with a `refer:` line, so the raw response
    concatenates two blocks: a generic IANA block about the TLD itself
    (lowercase `created:`/`changed:` — the TLD's OWN delegation dates, e.g.
    2014-02-06/2025-08-12) followed by the actual per-domain registrar block
    (`Creation Date:`/`Updated Date:` — 2026-07-22). The parser must return
    the registrar block's dates, not the TLD's.
    """
    raw = """% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.nic.xyz

domain:       XYZ

organisation: XYZ.COM LLC
address:      4425 Spring Mountain Rd., Suite 2
address:      Las Vegas NV 89102
address:      United States of America (the)

contact:      technical
name:         CTO
organisation: CentralNic
e-mail:       tld.ops@centralnic.com

nserver:      GENERATIONXYZ.NIC.XYZ 212.18.249.42
whois:        whois.nic.xyz

status:       ACTIVE
remarks:      Registration information: https://nic.xyz

created:      2014-02-06
changed:      2025-08-12
source:       IANA

# whois.nic.xyz

Domain Name: VIRUSBARRIER.XYZ
Registry Domain ID: D633493768-CNIC
Registrar WHOIS Server: whois.spaceship.com
Registrar URL: https://www.spaceship.com/
Updated Date: 2026-07-22T01:53:28.0Z
Creation Date: 2026-07-22T01:53:27.0Z
Registry Expiry Date: 2027-07-22T23:59:59.0Z
Registrar: Spaceship, Inc.
Registrar IANA ID: 3862
Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
Name Server: LAUNCH2.SPACESHIP.NET
Name Server: LAUNCH1.SPACESHIP.NET
DNSSEC: signedDelegation
Registrar Abuse Contact Email: abuse@spaceship.com
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2026-08-04T18:46:53.0Z <<<

# whois.spaceship.com
"""
    parsed = _parse_whois(raw)

    assert parsed["created_at"] == "2026-07-22T01:53:27.0Z", (
        f"Expected the registrar's Creation Date, got the IANA TLD "
        f"delegation date instead: {parsed['created_at']!r}"
    )
    assert parsed["updated_at"] == "2026-07-22T01:53:28.0Z", (
        f"Expected the registrar's Updated Date, got the IANA TLD "
        f"delegation date instead: {parsed['updated_at']!r}"
    )
    assert parsed["expires_at"] == "2027-07-22T23:59:59.0Z"
    assert parsed["registrar"] == "Spaceship, Inc."
    assert parsed["nameservers"] == ["launch2.spaceship.net", "launch1.spaceship.net"]


def test_whois_parser_simple_com_domain_unaffected_by_referral_fix(tmp_path: Path) -> None:
    """A direct (non-referral) .com WHOIS response has a single block and
    must keep working exactly as before the referral-chain fix."""
    raw = """
    Domain Name: SAVVYSHOPGUIDE.COM
    Registry Domain ID: 2837462938_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.namecheap.com
    Updated Date: 2026-01-15T09:12:03Z
    Creation Date: 2023-05-10T14:22:01Z
    Registry Expiry Date: 2027-05-10T14:22:01Z
    Registrar: NameCheap, Inc.
    Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
    Name Server: DNS1.REGISTRAR-SERVERS.COM
    Name Server: DNS2.REGISTRAR-SERVERS.COM
    """
    parsed = _parse_whois(raw)

    assert parsed["created_at"] == "2023-05-10T14:22:01Z"
    assert parsed["updated_at"] == "2026-01-15T09:12:03Z"
    assert parsed["registrar"] == "NameCheap, Inc."
    assert parsed["nameservers"] == ["dns1.registrar-servers.com", "dns2.registrar-servers.com"]


@pytest.mark.asyncio
async def test_whois_plugin_queries_root_domain_not_full_hostname(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: WHOIS registries (Verisign for .com, and
    equivalents for other TLDs) index registrable/root domains only, never
    subdomains. Querying "www.metaversejustice.com" directly returns "No
    match for domain ..." and leaves the plugin with only the generic IANA
    block about the .com TLD itself. The plugin must always reduce each
    target to its root domain before querying.
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="www.metaversejustice.com")]

    plugin = WhoisPlugin(settings)
    queried_domains: list[str] = []

    async def fake_query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        queried_domains.append(domain)
        raw = (
            "Domain Name: METAVERSEJUSTICE.COM\n"
            "Registrar: NameCheap, Inc.\n"
            "Creation Date: 2024-03-10T00:00:00Z\n"
            "Registry Expiry Date: 2027-03-10T00:00:00Z\n"
        )
        return WhoisChainResult(hops=(), raw=raw, blocked=False)

    monkeypatch.setattr("modules.whois.query_whois_chain", fake_query_whois_chain)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert queried_domains == [
        "metaversejustice.com"
    ], f"whois must be queried with the root domain, got: {queried_domains}"
    assert result.success

    raw_text = (output_dir / "whois_raw.txt").read_text(encoding="utf-8")
    assert "No match for domain" not in raw_text
    assert "www.metaversejustice.com" not in raw_text
    assert "===== metaversejustice.com =====" in raw_text

    records = read_jsonl(output_dir / "whois.jsonl")
    assert records[0]["domain"] == "metaversejustice.com"
    assert records[0]["created_at"] == "2024-03-10T00:00:00Z"


@pytest.mark.asyncio
async def test_whois_plugin_reduces_deep_subdomain_to_root_domain(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deeper subdomain (booking.staging.metaversejustice.com) must also
    collapse to the same root domain, not be queried as-is."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="booking.staging.metaversejustice.com")]

    plugin = WhoisPlugin(settings)
    queried_domains: list[str] = []

    async def fake_query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        queried_domains.append(domain)
        return WhoisChainResult(
            hops=(),
            raw="Domain Name: METAVERSEJUSTICE.COM\nRegistrar: NameCheap, Inc.\n",
            blocked=False,
        )

    monkeypatch.setattr("modules.whois.query_whois_chain", fake_query_whois_chain)
    await plugin.run(context, output_dir / "resolved.txt")

    assert queried_domains == ["metaversejustice.com"]


@pytest.mark.asyncio
async def test_whois_plugin_uses_short_timeout_and_retries_on_timeout(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """WHOIS must not inherit the global 300s timeout; retry with backoff."""
    settings.whois_timeout = 25
    settings.whois_retries = 2
    settings.whois_retry_delay_seconds = 0  # keep the unit test fast
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="metaversejustice.com")]

    plugin = WhoisPlugin(settings)
    calls: list[float] = []

    async def flaky_query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        calls.append(timeout)
        if len(calls) == 1:
            raise TimeoutError("Timed out after 25s")
        return WhoisChainResult(
            hops=(),
            raw="Domain Name: METAVERSEJUSTICE.COM\nRegistrar: NameCheap, Inc.\n",
            blocked=False,
        )

    monkeypatch.setattr("modules.whois.query_whois_chain", flaky_query_whois_chain)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert result.success
    assert calls == [25, 25]
    assert (output_dir / "whois.jsonl").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_whois_plugin_distinguishes_rate_limit_from_timeout(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings.whois_retries = 1
    settings.whois_retry_delay_seconds = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="metaversejustice.com")]

    plugin = WhoisPlugin(settings)

    async def rate_limited_query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        return WhoisChainResult(
            hops=(), raw="Rate limit exceeded. Try again later.\n", blocked=False
        )

    monkeypatch.setattr("modules.whois.query_whois_chain", rate_limited_query_whois_chain)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert not result.success
    assert any("rate limited" in w.lower() for w in context.warnings)


@pytest.mark.asyncio
async def test_whois_plugin_dedupes_targets_sharing_a_root_domain(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the user passes both "www.example.com" and "example.com" as
    separate targets in the same run, the root domain must only be queried
    once against the WHOIS registry."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [
        DomainTarget(domain="www.example.com"),
        DomainTarget(domain="example.com"),
        DomainTarget(domain="app.example.com"),
    ]

    plugin = WhoisPlugin(settings)
    queried_domains: list[str] = []

    async def fake_query_whois_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        queried_domains.append(domain)
        return WhoisChainResult(
            hops=(), raw="Domain Name: EXAMPLE.COM\nRegistrar: NameCheap, Inc.\n", blocked=False
        )

    monkeypatch.setattr("modules.whois.query_whois_chain", fake_query_whois_chain)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert queried_domains == ["example.com"]
    assert result.lines_produced == 1


@pytest.mark.asyncio
async def test_whois_plugin_surfaces_a_blocked_referral_hop_without_discarding_partial_data(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the native WHOIS client's referral chain is blocked partway
    (core/collection/whois_client.py: an intermediate hop resolved to a
    private/loopback IP), the plugin must not silently succeed with a clean
    record — the raw text already obtained is kept in whois_raw.txt, but no
    parsed record is added to whois.jsonl, and a warning names why."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="example.com")]

    plugin = WhoisPlugin(settings)

    async def blocked_chain(domain: str, *, timeout: float) -> WhoisChainResult:
        return WhoisChainResult(
            hops=(),
            raw="whois:        whois.private-registry.test\n",
            blocked=True,
            blocked_reason="blocked_range:10.0.0.0/8",
        )

    monkeypatch.setattr("modules.whois.query_whois_chain", blocked_chain)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert not result.success
    assert read_jsonl(output_dir / "whois.jsonl") == []
    raw_text = (output_dir / "whois_raw.txt").read_text(encoding="utf-8")
    assert "whois.private-registry.test" in raw_text
    assert any("referral chain" in w.lower() for w in context.warnings)


@pytest.mark.asyncio
async def test_asn_lookup_warns_when_no_ips_available(settings: Settings, tmp_path: Path) -> None:
    """Skip must surface an explicit warning — not a silent tools_skipped entry."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    (output_dir / "dnsx_records.jsonl").write_text("", encoding="utf-8")
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.resolved = []

    plugin = AsnLookupPlugin(settings)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert result.skipped
    assert "no resolved ips" in (result.message or "").lower()
    assert any("no resolved ips" in w.lower() for w in context.warnings)
    assert context.tool_states["asn_lookup"].error_message
    assert "no resolved ips" in context.tool_states["asn_lookup"].error_message.lower()


@pytest.mark.asyncio
async def test_asn_collect_ips_falls_back_to_resolving_hostnames(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When dnsx_records.jsonl is empty but resolved hostnames exist, resolve them —
    but only the ones CollectionScope actually authorizes. This is the one place
    asn_lookup performs active DNS resolution of its own; an out-of-scope entry in
    ``context.resolved`` must never reach ``_resolve_hostnames`` at all."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    (output_dir / "dnsx_records.jsonl").write_text("", encoding="utf-8")
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.resolved = ["example.com", "evil-out-of-scope.test"]

    resolved_calls: list[list[str]] = []

    async def fake_resolve(hostnames: list[str]) -> set[str]:
        resolved_calls.append(list(hostnames))
        return {"93.184.216.34"}

    monkeypatch.setattr("modules.asn_lookup._resolve_hostnames", fake_resolve)

    ips = await _collect_ips(context)
    assert ips == ["93.184.216.34"]
    # The out-of-scope hostname was filtered before _resolve_hostnames was ever called.
    assert resolved_calls == [["example.com"]]


def test_format_exc_never_empty_for_bare_timeout_error() -> None:
    """Regression: TimeoutError() stringifies to '' and produced 'unavailable: '."""
    detail = _format_exc(TimeoutError(), fallback="timed out contacting whois.cymru.com")
    assert detail
    assert "TimeoutError" in detail
    assert "whois.cymru.com" in detail


@pytest.mark.asyncio
async def test_asn_lookup_warning_not_empty_when_connection_fails(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If Cymru lookup fails, the warning must include a real cause string."""
    settings.asn_lookup_timeout = 5
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    write_jsonl(
        output_dir / "dnsx_records.jsonl",
        [{"host": "www.metaversejustice.com", "a": ["173.236.247.198"]}],
    )
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)

    async def boom(_ips: list[str]) -> list[dict[str, str]]:
        raise TimeoutError()  # empty str(exc) — the exact bug from 20260806_185622

    monkeypatch.setattr("modules.asn_lookup._query_cymru", boom)
    plugin = AsnLookupPlugin(settings)
    result = await plugin.run(context, output_dir / "resolved.txt")

    assert result.success  # soft-fail: scan continues
    assert context.warnings
    warning = context.warnings[0]
    assert warning.startswith("ASN Lookup unavailable: ")
    assert warning != "ASN Lookup unavailable: "
    assert "TimeoutError" in warning


def test_parse_cymru_whois_real_dreamhost_example() -> None:
    """Fixture from a real ``whois -h whois.cymru.com`` response for 173.236.247.198."""
    raw = (
        "Bulk mode; whois.cymru.com [2026-08-06]\n"
        "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
        "26347   | 173.236.247.198  | 173.236.128.0/17    | US | arin     | 2010-03-30 "
        "| DREAMHOST-AS - New Dream Network, LLC, US\n"
    )
    records = _parse_cymru_whois(raw)
    assert len(records) == 1
    assert records[0]["asn"] == "26347"
    assert records[0]["ip"] == "173.236.247.198"
    assert records[0]["bgp_prefix"] == "173.236.128.0/17"
    assert "DREAMHOST" in records[0]["as_name"].upper()


@pytest.mark.asyncio
async def test_query_cymru_falls_back_to_dns_when_tcp_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TCP :43 empty → DNS IP-to-ASN must still return DreamHost ASN 26347 shape."""

    async def empty_tcp(_ips: list[str]) -> list[dict[str, str]]:
        raise OSError("whois.cymru.com:43 accepted TCP but returned no WHOIS data")

    async def fake_dns(ips: list[str]) -> list[dict[str, str]]:
        return [
            {
                "asn": "26347",
                "ip": ips[0],
                "bgp_prefix": "173.236.128.0/17",
                "country": "US",
                "registry": "arin",
                "allocated": "2010-03-30",
                "as_name": "DREAMHOST-AS - New Dream Network, LLC, US",
            }
        ]

    monkeypatch.setattr("modules.asn_lookup._query_cymru_tcp", empty_tcp)
    monkeypatch.setattr("modules.asn_lookup._query_cymru_dns", fake_dns)
    records = await _query_cymru(["173.236.247.198"])
    assert records[0]["asn"] == "26347"
    assert "DREAMHOST" in records[0]["as_name"].upper()


def test_asn_parser_maps_cymru_record_to_dns_host(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "dnsx_records.jsonl",
        [{"host": "virusbarrier.xyz", "a": ["34.75.127.116"]}],
    )
    write_jsonl(
        tmp_path / "asn.jsonl",
        [
            {
                "ip": "34.75.127.116",
                "asn": "396982",
                "bgp_prefix": "34.64.0.0/10",
                "country": "US",
                "registry": "arin",
                "allocated": "2018-09-28",
                "as_name": "GOOGLE-CLOUD-PLATFORM",
            }
        ],
    )

    hosts, warnings = ASNParser().parse(tmp_path)

    assert not warnings
    assert hosts[0].domain == "virusbarrier.xyz"
    assert hosts[0].asn == "396982"
    assert hosts[0].cidr == "34.64.0.0/10"
    assert hosts[0].provider == "GOOGLE-CLOUD-PLATFORM"


def test_ctlogs_parser_normalizes_historical_sans(tmp_path: Path) -> None:
    names = _extract_names(
        "*.savvyshopguide.com\ncheckout.savvyshopguide.com\noutside.example",
        "savvyshopguide.com",
    )
    write_lines(tmp_path / "ctlogs_domains.txt", sorted(names))

    hosts, warnings = CtlogsParser().parse(tmp_path)

    assert not warnings
    assert {host.domain for host in hosts} == {
        "savvyshopguide.com",
        "checkout.savvyshopguide.com",
    }
    assert all(host.discovery_sources == ["ctlogs"] for host in hosts)


def test_port_verify_parser_rejects_naabu_false_positive(tmp_path: Path) -> None:
    nmap_output = """
    PORT     STATE    SERVICE VERSION
    37/tcp   filtered time
    4899/tcp open     radmin  Radmin remote administration
    8888/tcp closed   sun-answerbook
    """
    parsed = _parse_nmap_output(nmap_output)
    assert parsed[37]["state"] == "filtered"
    assert parsed[4899]["service"] == "radmin"
    assert _normalize_state("open|filtered") == "filtered"

    write_jsonl(
        tmp_path / "port_verify.jsonl",
        [
            {
                "host": "virusbarrier.xyz",
                "port": 37,
                "protocol": "tcp",
                "naabu_state": "open",
                "nmap_state": "filtered",
                "service": "time",
                "version": "",
            },
            {
                "host": "virusbarrier.xyz",
                "port": 4899,
                "protocol": "tcp",
                "naabu_state": "open",
                "nmap_state": "open",
                "service": "radmin",
                "version": "Radmin remote administration",
            },
        ],
    )
    verified_hosts, warnings = PortVerifyParser().parse(tmp_path)
    assert not warnings

    host = Host(domain="virusbarrier.xyz")
    host.ports.extend(
        [
            Port(host=host.domain, port=37),
            Port(host=host.domain, port=4899),
        ]
    )
    host.merge_from(verified_hosts[0])

    filtered = next(port for port in host.ports if port.port == 37)
    opened = next(port for port in host.ports if port.port == 4899)
    assert filtered.verification_state == "filtered"
    assert filtered.confidence_score == 10
    assert not filtered.validated
    assert opened.verification_state == "verified_open"
    assert opened.validated
    assert opened.service == "radmin"


def test_parse_nmap_output_never_reports_open_for_filtered_or_closed() -> None:
    """Regression test using real nmap -sV output captured against
    virusbarrier.xyz at different times, covering genuinely open ports,
    genuinely filtered/closed ports, and the specific 5060/sip line that
    triggered this investigation (uncertain-service "?" suffix, no VERSION
    column). The parser must never normalize a filtered/closed line to
    "open", regardless of how the SERVICE/VERSION columns are formatted.
    """
    # July capture: 80/443 genuinely open, real nginx banner.
    genuinely_open = """
    PORT    STATE SERVICE VERSION
    80/tcp  open  http    nginx
    443/tcp open  ssl/http nginx
    """
    parsed = _parse_nmap_output(genuinely_open)
    assert _normalize_state(parsed[80]["state"]) == "open"
    assert _normalize_state(parsed[443]["state"]) == "open"

    # August capture: legacy ports, all filtered by the firewall.
    all_filtered = """
    PORT     STATE    SERVICE VERSION
    37/tcp   filtered time
    79/tcp   filtered finger
    111/tcp  filtered rpcbind
    1720/tcp filtered h323q931
    4899/tcp filtered radmin
    8888/tcp filtered sun-answerbook
    """
    parsed = _parse_nmap_output(all_filtered)
    for port in (37, 79, 111, 1720, 4899, 8888):
        assert _normalize_state(parsed[port]["state"]) == "filtered"

    # The exact line that triggered this bug report: no VERSION column,
    # and nmap's own service-uncertainty "?" is on the SERVICE field only
    # in some captures, not this one — must still resolve to "filtered".
    sip_filtered = "PORT     STATE    SERVICE VERSION\n5060/tcp filtered sip\n"
    parsed = _parse_nmap_output(sip_filtered)
    assert _normalize_state(parsed[5060]["state"]) == "filtered"
    assert parsed[5060]["service"] == "sip"

    # A service name ending in "?" (nmap's own low-confidence marker) must
    # not affect state parsing in either direction.
    open_with_uncertain_service = (
        "PORT     STATE SERVICE      VERSION\n8080/tcp open  http-proxy?\n"
    )
    parsed = _parse_nmap_output(open_with_uncertain_service)
    assert _normalize_state(parsed[8080]["state"]) == "open"
    assert parsed[8080]["service"] == "http-proxy?"

    filtered_with_uncertain_service = "PORT     STATE    SERVICE VERSION\n5060/tcp filtered sip?\n"
    parsed = _parse_nmap_output(filtered_with_uncertain_service)
    assert _normalize_state(parsed[5060]["state"]) == "filtered"

    # Closed must never resolve to open either.
    closed_line = "PORT   STATE  SERVICE VERSION\n22/tcp closed ssh\n"
    parsed = _parse_nmap_output(closed_line)
    assert _normalize_state(parsed[22]["state"]) == "closed"


def test_parse_nmap_output_is_deterministic_for_fixed_input() -> None:
    """The parser must be a pure function of its input: feeding the exact
    same real nmap capture in repeatedly must always yield the exact same
    parsed result. This isolates the parser itself from the separate,
    already-confirmed issue that naabu/nmap's *live observations* can be
    inconsistent across runs against certain shared-hosting targets — that
    inconsistency must never be blamed on non-deterministic parsing.
    """
    real_capture = """Starting Nmap 7.97 ( https://nmap.org ) at 2026-08-06 09:39 -0700
Nmap scan report for www.metaversejustice.com (173.236.247.198)
Host is up (0.021s latency).

PORT      STATE SERVICE     VERSION
646/tcp   open  ldp?
1029/tcp  open  ms-lsa?
5432/tcp  open  postgresql?
32768/tcp open  filenet-tms?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.41 seconds
"""
    first = _parse_nmap_output(real_capture)
    for _ in range(10):
        again = _parse_nmap_output(real_capture)
        assert again == first, "parser must be deterministic for identical input"

    assert {port: obs["state"] for port, obs in first.items()} == {
        646: "open",
        1029: "open",
        5432: "open",
        32768: "open",
    }


@pytest.mark.asyncio
async def test_port_verify_writes_raw_nmap_artifact_per_host(
    settings: Settings, tmp_path: Path
) -> None:
    """Regression test: port_verify must persist nmap's raw stdout per host
    (mirroring whois_raw.txt), and reference it via a `raw_artifact` field
    in port_verify.jsonl — without this, there is no way to audit whether
    the parser read nmap's response correctly, which is exactly what made
    the earlier filtered-vs-open parsing bug hard to diagnose.
    """
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    write_lines(output_dir / "naabu.txt", ["www.metaversejustice.com:5432"])

    plugin = PortVerifyPlugin(settings)
    real_nmap_stdout = "PORT     STATE SERVICE      VERSION\n" "5432/tcp open  postgresql?\n"

    async def fake_run_command(args, **kwargs):
        return 0, real_nmap_stdout, ""

    import modules.port_verify as port_verify_module

    original_run_command = port_verify_module.run_command
    port_verify_module.run_command = fake_run_command
    try:
        context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
        result = await plugin.run(context, output_dir / "resolved.txt")
    finally:
        port_verify_module.run_command = original_run_command

    assert result.success
    records = read_jsonl(output_dir / "port_verify.jsonl")
    assert len(records) == 1
    raw_artifact = records[0]["raw_artifact"]
    assert raw_artifact is not None
    assert not Path(str(raw_artifact)).is_absolute()

    raw_path = output_dir / str(raw_artifact)
    assert raw_path.exists()
    assert raw_path.parent.name == "port_verify_raw"
    raw_content = raw_path.read_text(encoding="utf-8")
    assert "5432/tcp open  postgresql?" in raw_content
    assert "nmap" in raw_content  # command line is recorded


@pytest.mark.asyncio
async def test_port_verify_does_not_bleed_state_between_separate_runs(
    settings: Settings, tmp_path: Path
) -> None:
    """Two sequential runs against different hosts/ports (simulating two
    pipeline runs) must never mix results: each run's port_verify.jsonl and
    raw artifacts must reflect only that run's own naabu findings."""
    plugin = PortVerifyPlugin(settings)

    async def make_fake_run_command(stdout_by_port: dict[int, str]):
        async def fake_run_command(args, **kwargs):
            # args ends with the host; -p value is the second-to-last "-p" pair
            port_arg = args[args.index("-p") + 1]
            ports = [int(p) for p in port_arg.split(",")]
            lines = ["PORT     STATE SERVICE VERSION"]
            for port in ports:
                lines.append(stdout_by_port[port])
            return 0, "\n".join(lines), ""

        return fake_run_command

    import modules.port_verify as port_verify_module

    original_run_command = port_verify_module.run_command

    # Run 1: host A, port 646 open.
    output_dir_1 = tmp_path / "run1"
    output_dir_1.mkdir()
    write_lines(output_dir_1 / "naabu.txt", ["hosta.example.com:646"])
    port_verify_module.run_command = await make_fake_run_command({646: "646/tcp   open  ldp?"})
    try:
        context1 = PipelineContext(output_dir=output_dir_1, collection_scope=_SCOPE)
        await plugin.run(context1, output_dir_1 / "resolved.txt")
    finally:
        port_verify_module.run_command = original_run_command

    # Run 2: host B, a completely different port, must not see host A/646.
    output_dir_2 = tmp_path / "run2"
    output_dir_2.mkdir()
    write_lines(output_dir_2 / "naabu.txt", ["hostb.example.com:5432"])
    port_verify_module.run_command = await make_fake_run_command(
        {5432: "5432/tcp  open  postgresql?"}
    )
    try:
        context2 = PipelineContext(output_dir=output_dir_2, collection_scope=_SCOPE)
        await plugin.run(context2, output_dir_2 / "resolved.txt")
    finally:
        port_verify_module.run_command = original_run_command

    records1 = read_jsonl(output_dir_1 / "port_verify.jsonl")
    records2 = read_jsonl(output_dir_2 / "port_verify.jsonl")

    assert [(r["host"], r["port"]) for r in records1] == [("hosta.example.com", 646)]
    assert [(r["host"], r["port"]) for r in records2] == [("hostb.example.com", 5432)]

    # Raw artifacts must also be isolated per run directory (relative paths).
    assert records1[0]["raw_artifact"].startswith("port_verify_raw/")
    assert records2[0]["raw_artifact"].startswith("port_verify_raw/")
    assert (output_dir_1 / records1[0]["raw_artifact"]).exists()
    assert (output_dir_2 / records2[0]["raw_artifact"]).exists()


def test_urlhaus_parser_creates_high_severity_finding(tmp_path: Path) -> None:
    record = {
        "query_host": "savvyshopguide.com",
        "query_status": "ok",
        "urls": [
            {
                "url": "https://savvyshopguide.com/payload",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["scareware", "redirector"],
            }
        ],
    }
    assert _has_online_url(record)
    write_jsonl(tmp_path / "threat_intel.jsonl", [record])
    hosts, warnings = ThreatIntelParser().parse(tmp_path)
    assert not warnings
    finding = hosts[0].findings[0]
    assert finding.template_id == "urlhaus-known-malicious"
    assert finding.severity == "high"
    assert "scareware" in finding.description
    assert finding.confidence_score == 95


def test_browser_probe_parser_detects_destination_change(tmp_path: Path) -> None:
    assert _url_host("https://payload.example/path") == "payload.example"
    write_jsonl(
        tmp_path / "browser_probe.jsonl",
        [
            {
                "host": "savvyshopguide.com",
                "httpx_final_url": "https://savvyshopguide.com/",
                "browser_final_url": "https://payload.example/landing",
                "redirect_chain": [
                    "https://savvyshopguide.com/",
                    "https://payload.example/landing",
                ],
                "cloaking_suspected": True,
            }
        ],
    )
    hosts, warnings = BrowserProbeParser().parse(tmp_path)
    assert not warnings
    finding = hosts[0].findings[0]
    assert finding.template_id == "cloaking-detected"
    assert finding.severity == "medium"
    assert "payload.example" in finding.description


def test_tarpit_check_parser_flags_host_and_creates_informational_finding(
    tmp_path: Path,
) -> None:
    write_jsonl(
        tmp_path / "tarpit_check.jsonl",
        [
            {
                "host": "www.metaversejustice.com",
                "tarpit_suspected": True,
                "canary_ports": [6, 9999, 23456, 54321],
                "canary_open_ports": [6, 9999, 23456],
                "probe_technique": "nmap -sV -Pn",
                "raw_artifact": str(tmp_path / "tarpit_check_raw" / "www.metaversejustice.com.txt"),
            }
        ],
    )
    hosts, warnings = TarpitCheckParser().parse(tmp_path)
    assert not warnings
    assert len(hosts) == 1
    host = hosts[0]
    assert host.domain == "www.metaversejustice.com"
    assert host.tarpit_suspected is True
    assert host.tarpit_canary_ports == [6, 9999, 23456, 54321]

    # Exactly one formal Finding — future risk/intelligence logic that
    # iterates host.findings (not just the loose tarpit_suspected flag)
    # must see this reliability signal.
    assert len(host.findings) == 1
    finding = host.findings[0]
    assert finding.template_id == "tarpit-detected"
    assert finding.severity == "info"
    assert finding.source == "tarpit_check"
    assert "3/4" in finding.description
    assert "6" in finding.description and "54321" in finding.description
    assert "nmap -sV" in finding.description


def test_tarpit_check_parser_does_not_flag_host_on_normal_canary_response(
    tmp_path: Path,
) -> None:
    write_jsonl(
        tmp_path / "tarpit_check.jsonl",
        [
            {
                "host": "example.com",
                "tarpit_suspected": False,
                "canary_ports": [21111, 33222, 44333, 55444],
                "canary_open_ports": [],
            }
        ],
    )
    hosts, warnings = TarpitCheckParser().parse(tmp_path)
    assert not warnings
    host = hosts[0]
    assert host.tarpit_suspected is False
    assert host.findings == []


def test_provenance_omits_analyst_local_path() -> None:
    observation = record_observation(
        tool="httpx",
        field="hostname",
        value="example.com",
        confidence=90,
        artifact_path="/Users/private-analyst/scans/httpx.json",
    )
    assert observation.artifact_path == "httpx.json"


def test_httpx_strict_opsec_uses_proxy_without_direct_side_probes(
    tmp_path: Path,
) -> None:
    """httpx never talks to `OUTBOUND_PROXY_URL` directly — it always routes
    through Hydra's local confinement proxy, which chains to the external
    proxy internally (`ScopeEnforcingProxy.upstream_proxy_url`,
    `core/collection/crawler_proxy.py`) only after Hydra's own
    authorization/SSRF check passes. `_build_args` receiving a
    `confinement_proxy_url` (what `run()` actually passes — always the local
    proxy address) is what proves this: the external proxy URL itself never
    appears in httpx's own argv.
    """
    settings = Settings(
        project_root=tmp_path,
        strict_opsec=True,
        outbound_proxy_url="http://proxy.example:8080",
    )
    plugin = HttpxPlugin(settings)
    context = PipelineContext(output_dir=tmp_path, collection_scope=_SCOPE)
    args = plugin._build_args(
        context,
        tmp_path / "hosts.txt",
        tmp_path / "httpx.json",
        confinement_proxy_url="http://127.0.0.1:54321",
    )
    assert "-proxy" in args
    assert "http://127.0.0.1:54321" in args
    assert "http://proxy.example:8080" not in args
    assert "-tls-grab" not in args
    assert "-tls-probe" not in args
    assert "-ip" not in args
    assert "-cname" not in args
    assert "-include-response-header" in args


def test_httpx_parser_redacts_session_cookies_and_auth_headers(tmp_path: Path) -> None:
    write_jsonl(
        tmp_path / "httpx.json",
        [
            {
                "url": "https://app.example.com/",
                "input": "app.example.com",
                "status_code": 200,
                "header": {
                    "Set-Cookie": "session=super-secret-token; Path=/",
                    "Authorization": "Bearer abc123",
                    "Server": "nginx",
                    "Content-Security-Policy": "default-src 'self'",
                },
            }
        ],
    )
    hosts, warnings = HttpxParser().parse(tmp_path)
    assert not warnings
    headers = hosts[0].http_services[0].headers
    assert "set-cookie" not in headers
    assert "authorization" not in headers
    assert headers["server"] == "nginx"


def test_merged_headers_injects_researcher_header_when_configured(
    tmp_path: Path,
) -> None:
    settings = Settings(
        project_root=tmp_path,
        x_hackerone_researcher="my-h1-handle",
    )
    headers = settings.merged_headers()
    assert headers["X-HackerOne-Researcher"] == "my-h1-handle"

    settings.strict_opsec = True
    settings.outbound_proxy_url = "http://proxy.example:8080"
    assert settings.merged_headers() == {}
