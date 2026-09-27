"""Fase 11 (EASM roadmap) — pure parser tests for
`core/parsers/nmap_import.py` and `core/parsers/masscan_import.py`. No
database, no network: fixed byte-string fixtures, exact expected
records. Malformed input handling is the phase's own required focus —
one bad sub-record must never abort an otherwise-valid report, but bad
top-level syntax/shape must fail closed with zero ambiguity.
"""

from __future__ import annotations

import pytest

from core.parsers.imported_hosts import ImportParseError
from core.parsers.masscan_import import parse_masscan_json
from core.parsers.nmap_import import parse_nmap_xml

_VALID_NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="www.example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports>
</host>
</nmaprun>"""


class TestNmapXmlParsing:
    def test_parses_host_ip_hostnames_and_ports(self) -> None:
        hosts = parse_nmap_xml(_VALID_NMAP_XML)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.ip_address == "192.0.2.10"
        assert host.hostnames == ("www.example.com",)
        assert len(host.ports) == 2
        ssh = next(p for p in host.ports if p.port == 22)
        assert ssh.protocol == "tcp"
        assert ssh.state == "open"
        assert ssh.service_name == "ssh"
        assert ssh.product == "OpenSSH"
        assert ssh.version == "8.9"

    def test_host_without_any_address_is_skipped_not_a_crash(self) -> None:
        xml = b"""<nmaprun><host><status state="up"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
        </host></nmaprun>"""
        assert parse_nmap_xml(xml) == []

    def test_port_with_impossible_portid_is_skipped(self) -> None:
        xml = b"""<nmaprun><host>
        <address addr="192.0.2.1" addrtype="ipv4"/>
        <ports>
        <port protocol="tcp" portid="999999"><state state="open"/></port>
        <port protocol="tcp" portid="not-a-number"><state state="open"/></port>
        <port protocol="tcp" portid="443"><state state="open"/></port>
        </ports>
        </host></nmaprun>"""
        hosts = parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert [p.port for p in hosts[0].ports] == [443]

    def test_malformed_xml_syntax_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_nmap_xml(b"<nmaprun><host>this is not closed")

    def test_wrong_root_element_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_nmap_xml(b"<somethingelse><host/></somethingelse>")

    def test_empty_bytes_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_nmap_xml(b"")

    def test_billion_laughs_style_entity_expansion_is_rejected(self) -> None:
        malicious = (
            b'<?xml version="1.0"?>\n'
            b"<!DOCTYPE nmaprun [\n"
            b'<!ENTITY a "1234567890">\n'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            b"]>\n"
            b'<nmaprun><host><address addr="&b;" addrtype="ipv4"/></host></nmaprun>'
        )
        with pytest.raises(ImportParseError):
            parse_nmap_xml(malicious)

    def test_two_hosts_with_multiple_records_both_parse(self) -> None:
        xml = b"""<nmaprun>
        <host><address addr="192.0.2.1" addrtype="ipv4"/></host>
        <host><address addr="192.0.2.2" addrtype="ipv4"/></host>
        </nmaprun>"""
        hosts = parse_nmap_xml(xml)
        assert {h.ip_address for h in hosts} == {"192.0.2.1", "192.0.2.2"}


class TestMasscanJsonParsing:
    def test_parses_ip_and_ports(self) -> None:
        payload = (
            b'[{"ip": "192.0.2.20", "ports": ['
            b'{"port": 443, "proto": "tcp", "status": "open", "service": {"name": "https"}}'
            b"]}]"
        )
        hosts = parse_masscan_json(payload)
        assert len(hosts) == 1
        assert hosts[0].ip_address == "192.0.2.20"
        assert hosts[0].ports[0].port == 443
        assert hosts[0].ports[0].service_name == "https"

    def test_multiple_port_entries_for_the_same_ip_are_grouped_into_one_host(self) -> None:
        payload = (
            b'[{"ip": "192.0.2.20", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},'
            b'{"ip": "192.0.2.20", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]}]'
        )
        hosts = parse_masscan_json(payload)
        assert len(hosts) == 1
        assert {p.port for p in hosts[0].ports} == {80, 443}

    def test_empty_bytes_returns_empty_list(self) -> None:
        assert parse_masscan_json(b"") == []

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_masscan_json(b"{not: valid json,,,")

    def test_masscan_trailing_comma_on_interrupted_scan_is_tolerated(self) -> None:
        payload = (
            b'[{"ip": "192.0.2.1", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},]'
        )
        hosts = parse_masscan_json(payload)
        assert len(hosts) == 1

    def test_non_array_top_level_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_masscan_json(b'{"ip": "192.0.2.1"}')

    def test_entry_missing_ip_is_skipped(self) -> None:
        payload = b'[{"ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]'
        assert parse_masscan_json(payload) == []

    def test_port_with_impossible_number_is_skipped(self) -> None:
        payload = (
            b'[{"ip": "192.0.2.1", "ports": [{"port": 999999, "proto": "tcp", "status": "open"}]}]'
        )
        assert parse_masscan_json(payload) == []

    def test_not_valid_utf8_raises(self) -> None:
        with pytest.raises(ImportParseError):
            parse_masscan_json(b"\xff\xfe\x00\x01")
