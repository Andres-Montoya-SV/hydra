"""Fase 04 (EASM roadmap) — pure observation/evidence derivation
(`api/observation_identity.py`). No database, same discipline as
`tests/test_asset_identity.py`: fixed `Host` fixtures, exact assertions
on what `observations_for_host` derives.
"""

from __future__ import annotations

from api.observation_identity import (
    OBSERVATION_TYPE_DNS_POSTURE_TAG,
    OBSERVATION_TYPE_DNS_RECORD_PRESENT,
    OBSERVATION_TYPE_DOMAIN_RESOLVED,
    OBSERVATION_TYPE_PORT_OPEN,
    OBSERVATION_TYPE_SECURITY_HEADER_PRESENT,
    OBSERVATION_TYPE_TECHNOLOGY_DETECTED,
    OBSERVATION_TYPE_URL_DISCOVERED,
    observations_for_host,
)
from core.assets import URL, DnsRecord, Host, HttpService, Port, TechnologyFinding


class TestObservationsForHost:
    def test_a_bare_host_produces_exactly_one_domain_resolved_observation(self) -> None:
        host = Host(domain="example.com", discovery_sources=["dnsx"])
        drafts = observations_for_host(host)
        assert len(drafts) == 1
        assert drafts[0].observation_type == OBSERVATION_TYPE_DOMAIN_RESOLVED
        assert drafts[0].identity_key == "domain:example.com"
        assert drafts[0].evidence.source == "dnsx"

    def test_a_port_produces_a_port_open_observation_with_the_ports_own_evidence(self) -> None:
        host = Host(
            domain="example.com",
            ports=[
                Port(host="example.com", port=443, protocol="tcp", source="naabu", service="https")
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_PORT_OPEN
        ]
        assert len(drafts) == 1
        assert drafts[0].identity_key == "port:example.com:443:tcp"
        assert drafts[0].evidence.source == "naabu"
        assert drafts[0].evidence.detail == "https"

    def test_a_dns_record_produces_its_own_observation(self) -> None:
        host = Host(
            domain="example.com",
            dns_records=[
                DnsRecord(host="example.com", record_type="A", value="1.2.3.4", source="dnsx")
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_DNS_RECORD_PRESENT
        ]
        assert len(drafts) == 1
        assert drafts[0].identity_key == "dns_record:example.com:A:1.2.3.4"
        assert drafts[0].evidence.source == "dnsx"

    def test_dns_security_tags_become_temporal_posture_observations(self) -> None:
        host = Host(
            domain="example.com",
            dns_records=[
                DnsRecord(
                    host="example.com",
                    record_type="TXT",
                    value="v=spf1 +all",
                    source="dnsx",
                    security_tags=["spf", "weak-spf"],
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_DNS_POSTURE_TAG
        ]
        assert {d.evidence.detail for d in drafts} == {"spf", "weak-spf"}
        assert {d.identity_key for d in drafts} == {"dns_record:example.com:TXT:v=spf1 +all"}
        assert all(d.asset_type == "dns_record" for d in drafts)

    def test_duplicate_dns_security_tags_are_collapsed(self) -> None:
        host = Host(
            domain="example.com",
            dns_records=[
                DnsRecord(
                    host="example.com",
                    record_type="CAA",
                    value='0 issue "letsencrypt.org"',
                    source="dnsx",
                    security_tags=[
                        "certificate-authority-policy",
                        "certificate-authority-policy",
                    ],
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_DNS_POSTURE_TAG
        ]
        assert len(drafts) == 1
        assert drafts[0].evidence.detail == "certificate-authority-policy"

    def test_a_url_produces_its_own_observation(self) -> None:
        host = Host(
            domain="example.com",
            urls=[URL(url="https://example.com/admin", host="example.com", source="httpx")],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_URL_DISCOVERED
        ]
        assert len(drafts) == 1
        assert drafts[0].identity_key == "url:https://example.com/admin"
        assert drafts[0].evidence.source == "httpx"

    def test_a_detected_technology_is_attached_to_the_domain_asset_not_a_new_asset_type(
        self,
    ) -> None:
        host = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=90)],
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_TECHNOLOGY_DETECTED
        ]
        assert len(drafts) == 1
        assert drafts[0].identity_key == "domain:example.com"
        assert drafts[0].evidence.detail == "nginx"
        assert drafts[0].evidence.confidence_score == 90

    def test_a_versioned_technology_preserves_version_in_cross_run_evidence(self) -> None:
        host = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    technologies=[
                        TechnologyFinding(
                            name="nginx",
                            version="1.26.2",
                            source="whatweb",
                            confidence=80,
                        )
                    ],
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_TECHNOLOGY_DETECTED
        ]
        assert len(drafts) == 1
        assert drafts[0].evidence.detail == "nginx@1.26.2"
        assert drafts[0].evidence.source == "whatweb"

    def test_a_present_security_header_is_attached_to_the_domain_asset(self) -> None:
        host = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    source="httpx",
                    confidence_score=80,
                    security_headers={"Strict-Transport-Security": "max-age=63072000"},
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_SECURITY_HEADER_PRESENT
        ]
        assert len(drafts) == 1
        assert drafts[0].identity_key == "domain:example.com"
        assert drafts[0].evidence.detail == "Strict-Transport-Security"
        assert drafts[0].evidence.source == "httpx"
        assert drafts[0].evidence.confidence_score == 80

    def test_multiple_technologies_produce_one_observation_each(self) -> None:
        host = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    technologies=[
                        TechnologyFinding(name="nginx", source="httpx", confidence=90),
                        TechnologyFinding(name="react", source="wappalyzer", confidence=70),
                    ],
                )
            ],
        )
        drafts = [
            d
            for d in observations_for_host(host)
            if d.observation_type == OBSERVATION_TYPE_TECHNOLOGY_DETECTED
        ]
        assert {d.evidence.detail for d in drafts} == {"nginx", "react"}

    def test_identical_evidence_content_is_equal_across_two_separately_built_hosts(self) -> None:
        """The exact equality `api/control_db.py::find_or_create_evidence`
        relies on for real deduplication across runs — two Host objects
        built independently (standing in for the same fact re-observed
        on two different runs) must produce an `EvidenceContent` that
        compares equal, or the dedup in the DB layer would never fire."""
        host_run_1 = Host(
            domain="example.com", ports=[Port(host="example.com", port=22, source="naabu")]
        )
        host_run_2 = Host(
            domain="example.com", ports=[Port(host="example.com", port=22, source="naabu")]
        )

        drafts_1 = [
            d
            for d in observations_for_host(host_run_1)
            if d.observation_type == OBSERVATION_TYPE_PORT_OPEN
        ]
        drafts_2 = [
            d
            for d in observations_for_host(host_run_2)
            if d.observation_type == OBSERVATION_TYPE_PORT_OPEN
        ]
        assert drafts_1[0].evidence == drafts_2[0].evidence
