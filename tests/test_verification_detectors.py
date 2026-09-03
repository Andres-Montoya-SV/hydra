"""core/verification/detectors.py — one test class per B.2 detector, each
using the real fixture from the original incident where one exists.
"""

from __future__ import annotations

from core.verification.detectors import (
    detect_dnsx_nodata_as_resolved,
    detect_naabu_nmap_port_disagreement,
    detect_security_headers_key_mismatch,
    detect_whois_block_specificity,
)
from core.verification.model import ContradictionSeverity

# ---------------------------------------------------------------------------
# Item 6 — dnsx NODATA. Same real record shape as tests/test_dnsx.py's
# fishbowlapp.com fixture (jenkins.api.fishbowlapp.com and siblings).
# ---------------------------------------------------------------------------

FISHBOWL_NODATA_RECORD = {
    "host": "jenkins.api.fishbowlapp.com",
    "soa": [{"name": "fishbowlapp.com", "ns": "irma.ns.cloudflare.com"}],
    "status_code": "NOERROR",
}
FISHBOWL_RESOLVED_RECORD = {
    "host": "api.fishbowlapp.com",
    "a": ["104.18.32.42"],
    "status_code": "NOERROR",
}


class TestDetectDnsxNodataAsResolved:
    def test_fishbowlapp_nodata_counted_as_resolved_is_flagged(self) -> None:
        finding = detect_dnsx_nodata_as_resolved(
            FISHBOWL_NODATA_RECORD,
            was_counted_resolved=True,
            raw_artifact="dnsx_records.jsonl",
        )
        assert finding is not None
        assert finding.severity is ContradictionSeverity.INVALIDATES
        assert finding.host == "jenkins.api.fishbowlapp.com"
        assert "NODATA" in finding.evidence

    def test_nodata_correctly_not_counted_is_not_flagged(self) -> None:
        """The fix (modules/dnsx.py) already excludes this host — nothing
        to flag when the interpretation already agrees with the evidence."""
        finding = detect_dnsx_nodata_as_resolved(FISHBOWL_NODATA_RECORD, was_counted_resolved=False)
        assert finding is None

    def test_real_a_record_counted_as_resolved_is_not_flagged(self) -> None:
        finding = detect_dnsx_nodata_as_resolved(
            FISHBOWL_RESOLVED_RECORD, was_counted_resolved=True
        )
        assert finding is None

    def test_non_nodata_shape_is_not_flagged(self) -> None:
        """NXDOMAIN or another status entirely is not this detector's
        pattern — no soa-only NOERROR shape to compare against."""
        finding = detect_dnsx_nodata_as_resolved(
            {"host": "nope.example.com", "status_code": "NXDOMAIN"},
            was_counted_resolved=True,
        )
        assert finding is None


# ---------------------------------------------------------------------------
# Item 2 — security_headers underscore/hyphen mismatch. Same real header
# dict shape as tests/test_security_headers.py's creator.stripchat.com
# fixture.
# ---------------------------------------------------------------------------

STRIPCHAT_REAL_HTTPX_HEADER = {
    "server": "cloudflare",
    "strict_transport_security": "max-age=31536000; includeSubDomains",
    "x_frame_options": "deny",
}


class TestDetectSecurityHeadersKeyMismatch:
    def test_stripchat_headers_falsely_claimed_missing_are_flagged(self) -> None:
        finding = detect_security_headers_key_mismatch(
            STRIPCHAT_REAL_HTTPX_HEADER,
            ["strict-transport-security", "x-frame-options", "content-security-policy"],
            host="creator.stripchat.com",
            raw_artifact="security_headers_raw/creator.stripchat.com.txt",
        )
        assert finding is not None
        assert finding.severity is ContradictionSeverity.INVALIDATES
        assert "strict-transport-security" in finding.claim
        assert "x-frame-options" in finding.claim
        # content-security-policy is genuinely absent — must not be flagged.
        assert "content-security-policy" not in finding.claim

    def test_genuinely_missing_headers_are_not_flagged(self) -> None:
        finding = detect_security_headers_key_mismatch(
            {"server": "nginx"},
            ["strict-transport-security", "x-frame-options"],
        )
        assert finding is None

    def test_no_missing_headers_at_all_is_not_flagged(self) -> None:
        finding = detect_security_headers_key_mismatch(STRIPCHAT_REAL_HTTPX_HEADER, [])
        assert finding is None


# ---------------------------------------------------------------------------
# Item 1 — WHOIS registrar-vs-TLD block. Exact real virusbarrier.xyz (.xyz /
# IANA referral) fixture from
# tests/test_infrastructure_plugins.py::test_whois_parser_prefers_registrar_dates_over_iana_referral_dates.
# ---------------------------------------------------------------------------

VIRUSBARRIER_WHOIS_RAW = """% IANA WHOIS server
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


class TestDetectWhoisBlockSpecificity:
    def test_tld_delegation_date_claimed_as_creation_date_is_flagged(self) -> None:
        """The exact original bug: 2014-02-06 (the .xyz TLD's own IANA
        delegation date) claimed as virusbarrier.xyz's creation date."""
        finding = detect_whois_block_specificity(
            VIRUSBARRIER_WHOIS_RAW,
            "2014-02-06",
            host="virusbarrier.xyz",
            raw_artifact="whois_raw.txt",
        )
        assert finding is not None
        assert finding.severity is ContradictionSeverity.INVALIDATES
        assert "2014-02-06" in finding.claim

    def test_registrar_creation_date_is_not_flagged(self) -> None:
        """The fix (modules/whois.py::_authoritative_block): the real,
        already-correct registrar-block date must never be flagged."""
        finding = detect_whois_block_specificity(
            VIRUSBARRIER_WHOIS_RAW,
            "2026-07-22T01:53:27.0Z",
            host="virusbarrier.xyz",
        )
        assert finding is None

    def test_no_referral_chain_is_not_flagged(self) -> None:
        """A single 'Domain Name:' block (the common case — most .com
        queries never see a referral) has nothing to disambiguate."""
        raw = "Domain Name: EXAMPLE.COM\nRegistrar: NameCheap, Inc.\nCreation Date: 2020-01-01\n"
        finding = detect_whois_block_specificity(raw, "2020-01-01", host="example.com")
        assert finding is None

    def test_empty_claimed_date_is_not_flagged(self) -> None:
        finding = detect_whois_block_specificity(VIRUSBARRIER_WHOIS_RAW, None)
        assert finding is None
        assert detect_whois_block_specificity(VIRUSBARRIER_WHOIS_RAW, "") is None


# ---------------------------------------------------------------------------
# Item 3 — naabu/nmap disagreement. Same real port-37/virusbarrier.xyz
# fixture as tests/test_infrastructure_plugins.py::
# test_port_verify_parser_rejects_naabu_false_positive.
# ---------------------------------------------------------------------------


class TestDetectNaabuNmapPortDisagreement:
    def test_naabu_open_nmap_filtered_is_downgraded_not_invalidated(self) -> None:
        finding = detect_naabu_nmap_port_disagreement(
            "open",
            "filtered",
            host="virusbarrier.xyz",
            port=37,
            raw_artifact="port_verify.jsonl",
        )
        assert finding is not None
        assert finding.severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE
        assert finding.host == "virusbarrier.xyz"

    def test_naabu_open_nmap_closed_is_also_flagged(self) -> None:
        finding = detect_naabu_nmap_port_disagreement("open", "closed", host="x", port=8888)
        assert finding is not None
        assert finding.severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE

    def test_agreement_is_not_flagged(self) -> None:
        """Real fixture's port 4899: naabu open, nmap also open — agreement,
        no finding."""
        finding = detect_naabu_nmap_port_disagreement(
            "open", "open", host="virusbarrier.xyz", port=4899
        )
        assert finding is None

    def test_naabu_not_open_is_not_this_detectors_pattern(self) -> None:
        finding = detect_naabu_nmap_port_disagreement("closed", "filtered")
        assert finding is None
