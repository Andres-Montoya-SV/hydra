"""`modules/amass.py`: parsing amass v4's real `-o` output.

amass v4's `-o`/`-oA` output is a relationship-graph transcript, one line
per discovered fact — `"<endpoint> (<Type>) --> <relation> --> <endpoint>
(<Type>)"` — not a plain subdomain-per-line list. `AMASS_HACKERONE_V4_REAL_OUTPUT`
below is the exact, real, captured stdout/`-o` content from a real
installed amass v4.2.0 running `amass enum -d hackerone.com -o <file>
-timeout 1` (2026-09-14) — not a synthesized approximation. It includes
real `(Netblock)`, `(IPAddress)`, `(ASN)`, and `(RIROrganization)` lines
alongside `(FQDN)` ones, and real third-party infrastructure
(`aspmx.l.google.com`, `hacker0x01.github.io`) hackerone.com's own DNS
records point at but that are not hackerone.com subdomains — exactly the
data `_extract_amass_fqdns` must tell apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.amass import AmassPlugin, _extract_amass_fqdns
from utils.files import read_lines

# Real captured amass v4.2.0 output — `amass enum -d hackerone.com -o
# <file> -timeout 1`, run live against the real binary, 2026-09-14.
AMASS_HACKERONE_V4_REAL_OUTPUT = """\
hackerone.com (FQDN) --> mx_record --> alt1.aspmx.l.google.com (FQDN)
hackerone.com (FQDN) --> mx_record --> aspmx.l.google.com (FQDN)
hackerone.com (FQDN) --> mx_record --> aspmx3.googlemail.com (FQDN)
hackerone.com (FQDN) --> mx_record --> aspmx2.googlemail.com (FQDN)
hackerone.com (FQDN) --> mx_record --> alt2.aspmx.l.google.com (FQDN)
hackerone.com (FQDN) --> ns_record --> a.ns.hackerone.com (FQDN)
hackerone.com (FQDN) --> ns_record --> b.ns.hackerone.com (FQDN)
mta-sts.hackerone.com (FQDN) --> cname_record --> hacker0x01.github.io (FQDN)
fwdkim1.hackerone.com (FQDN) --> cname_record --> spfmx1.domainkey.freshemail.io (FQDN)
support.hackerone.com (FQDN) --> cname_record --> 2fe254e58a0ea8096400b2fda121ee35.freshdesk.com (FQDN)
api.hackerone.com (FQDN) --> a_record --> 104.18.36.214 (IPAddress)
api.hackerone.com (FQDN) --> a_record --> 172.64.151.42 (IPAddress)
api.hackerone.com (FQDN) --> aaaa_record --> 2a06:98c1:3109::ac40:972a (IPAddress)
api.hackerone.com (FQDN) --> aaaa_record --> 2a06:98c1:310c::6812:24d6 (IPAddress)
104.16.0.0/14 (Netblock) --> contains --> 104.18.36.214 (IPAddress)
172.64.144.0/20 (Netblock) --> contains --> 172.64.151.42 (IPAddress)
2a06:98c1:3109::/48 (Netblock) --> contains --> 2a06:98c1:3109::ac40:972a (IPAddress)
2a06:98c1:310c::/48 (Netblock) --> contains --> 2a06:98c1:310c::6812:24d6 (IPAddress)
13335 (ASN) --> managed_by --> CLOUDFLARENET - Cloudflare, Inc. (RIROrganization)
13335 (ASN) --> announces --> 104.16.0.0/14 (Netblock)
13335 (ASN) --> announces --> 172.64.144.0/20 (Netblock)
13335 (ASN) --> announces --> 2a06:98c1:3109::/48 (Netblock)
13335 (ASN) --> announces --> 2a06:98c1:310c::/48 (Netblock)
aspmx3.googlemail.com (FQDN) --> a_record --> 172.253.135.27 (IPAddress)
aspmx3.googlemail.com (FQDN) --> aaaa_record --> 2800:3f0:4003:c14::1a (IPAddress)
pmbounces.hackerone.com (FQDN) --> cname_record --> pm.mtasv.net (FQDN)
172.253.135.0/24 (Netblock) --> contains --> 172.253.135.27 (IPAddress)
2800:3f0:4003::/48 (Netblock) --> contains --> 2800:3f0:4003:c14::1a (IPAddress)
15169 (ASN) --> managed_by --> GOOGLE - Google LLC (RIROrganization)
15169 (ASN) --> announces --> 172.253.135.0/24 (Netblock)
15169 (ASN) --> announces --> 2800:3f0:4003::/48 (Netblock)
"""

_EXPECTED_HACKERONE_SUBDOMAINS = [
    "a.ns.hackerone.com",
    "api.hackerone.com",
    "b.ns.hackerone.com",
    "fwdkim1.hackerone.com",
    "hackerone.com",
    "mta-sts.hackerone.com",
    "pmbounces.hackerone.com",
    "support.hackerone.com",
]


class TestExtractAmassFqdnsAgainstRealV4Output:
    def test_real_hackerone_transcript_yields_exactly_the_real_subdomains(self) -> None:
        lines = AMASS_HACKERONE_V4_REAL_OUTPUT.splitlines()
        result = _extract_amass_fqdns(lines, "hackerone.com")
        assert result == _EXPECTED_HACKERONE_SUBDOMAINS

    def test_netblock_ipaddress_asn_rirorganization_lines_never_leak_in(self) -> None:
        lines = AMASS_HACKERONE_V4_REAL_OUTPUT.splitlines()
        result = _extract_amass_fqdns(lines, "hackerone.com")
        for garbage in (
            "104.16.0.0/14",
            "104.18.36.214",
            "13335",
            "CLOUDFLARENET - Cloudflare, Inc.",
            "2a06:98c1:3109::ac40:972a",
        ):
            assert garbage not in result

    def test_third_party_infrastructure_fqdns_are_excluded(self) -> None:
        """hackerone.com's own MX/CNAME records point at real third-party
        FQDNs (Google's mail servers, a GitHub Pages CNAME target, a
        Freshdesk-hosted support portal) — none of these are hackerone.com
        subdomains and must never be reported as ones."""
        lines = AMASS_HACKERONE_V4_REAL_OUTPUT.splitlines()
        result = _extract_amass_fqdns(lines, "hackerone.com")
        for third_party in (
            "alt1.aspmx.l.google.com",
            "aspmx.l.google.com",
            "aspmx3.googlemail.com",
            "aspmx2.googlemail.com",
            "alt2.aspmx.l.google.com",
            "hacker0x01.github.io",
            "spfmx1.domainkey.freshemail.io",
            "2fe254e58a0ea8096400b2fda121ee35.freshdesk.com",
            "pm.mtasv.net",
        ):
            assert third_party not in result

    def test_bare_hostname_lines_are_tolerated_and_still_domain_filtered(self) -> None:
        """Defensive tolerance for a differently-shaped amass.txt (e.g. one
        this same function already cleaned on a prior pass) — a line with
        no relationship-transcript structure is treated as a bare hostname,
        still subject to the domain-suffix filter."""
        result = _extract_amass_fqdns(
            ["www.hackerone.com", "unrelated.example.com", ""], "hackerone.com"
        )
        assert result == ["www.hackerone.com"]

    def test_empty_input_returns_empty_list(self) -> None:
        assert _extract_amass_fqdns([], "hackerone.com") == []

    def test_malformed_lines_do_not_crash_and_are_skipped(self) -> None:
        malformed = [
            "this is not amass output at all",
            "(FQDN) --> missing_left_side",
            "hackerone.com (FQDN) -->",
            "   ",
        ]
        # None of these match the transcript shape, so each is treated as
        # a bare hostname per the tolerance above — none happen to be
        # hackerone.com or a subdomain of it, so all are filtered out.
        # The real assertion is that this doesn't raise.
        result = _extract_amass_fqdns(malformed, "hackerone.com")
        assert result == []


def _context(tmp_path: Path, domain: str = "hackerone.com") -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain=domain)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([domain], patterns=[f"*.{domain}", domain]),
    )


def _mock_execute_self_output(raw_transcript: str):
    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        output_path.write_text(raw_transcript, encoding="utf-8")
        line_count = len([ln for ln in raw_transcript.splitlines() if ln.strip()])
        return PluginResult(success=True, output_path=output_path, lines_produced=line_count)

    return fake


@pytest.mark.asyncio
async def test_amass_plugin_writes_clean_subdomains_not_the_raw_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end through AmassPlugin.run(): amass.txt must contain the
    extracted subdomains, never the raw relationship-graph lines — this
    is the exact regression this whole module's fix closes."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AmassPlugin(settings)
    monkeypatch.setattr(
        plugin, "_execute_self_output", _mock_execute_self_output(AMASS_HACKERONE_V4_REAL_OUTPUT)
    )

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    amass_txt = read_lines(context.output_dir / "amass.txt")
    assert amass_txt == _EXPECTED_HACKERONE_SUBDOMAINS
    for line in amass_txt:
        assert "-->" not in line
        assert "(FQDN)" not in line
    assert set(_EXPECTED_HACKERONE_SUBDOMAINS).issubset(set(context.subdomains))


@pytest.mark.asyncio
async def test_amass_plugin_empty_output_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real, legitimate amass outcome: passive sources found nothing
    (confirmed live — a 2-minute unrestricted enum against a real domain in
    this dev environment returned zero results). Must not crash and must
    not report false subdomains."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AmassPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(""))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    assert read_lines(context.output_dir / "amass.txt") == []


@pytest.mark.asyncio
async def test_amass_plugin_malformed_output_does_not_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive: a truncated/corrupted -o file (e.g. amass killed mid-write
    by the outer subprocess timeout) must not crash the pipeline."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    plugin = AmassPlugin(settings)
    garbage = "hackerone.com (FQDN) --> ns_record --> a.ns.hackerone.com (FQD"  # cut mid-line
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(garbage))

    result = await plugin.run(context, context.output_dir / "input.txt")

    assert result.success
    # The truncated line doesn't match the transcript regex, so it's
    # tolerated as a bare hostname — which doesn't equal/end with
    # ".hackerone.com" either, so it's correctly dropped, not crashed on.
    assert read_lines(context.output_dir / "amass.txt") == []
