"""Fase 08 Exposure identity tests."""

from api.exposure_identity import exposure_from_finding, normalize_exposure_location


def test_query_and_fragment_do_not_split_exposure_identity() -> None:
    a = normalize_exposure_location(
        "https://Admin.Example.com:443/login?next=/a#top", "admin.example.com"
    )
    b = normalize_exposure_location(
        "https://admin.example.com/login?next=/b", "admin.example.com"
    )
    assert a == b == "https://admin.example.com/login"


def test_non_default_port_remains_part_of_location_identity() -> None:
    assert (
        normalize_exposure_location(
            "https://admin.example.com:8443/login?x=1", "admin.example.com"
        )
        == "https://admin.example.com:8443/login"
    )


def test_info_finding_is_not_promoted_to_exposure() -> None:
    assert (
        exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "wildcard-dns-detected",
                "severity": "info",
                "name": "Wildcard DNS",
                "source": "wildcard_check",
            },
            asset_id="asset-1",
        )
        is None
    )


def test_security_finding_becomes_deterministic_exposure_draft() -> None:
    draft = exposure_from_finding(
        {
            "host": "admin.example.com",
            "template_id": "exposed-admin-panel",
            "severity": "HIGH",
            "name": "Exposed admin panel",
            "source": "nuclei",
            "url": "https://admin.example.com/login?session=redacted",
            "description": "Administrative interface is Internet reachable",
            "confidence_score": 120,
        },
        asset_id="asset-domain",
    )
    assert draft is not None
    assert draft.asset_id == "asset-domain"
    assert draft.source == "nuclei"
    assert draft.template_id == "exposed-admin-panel"
    assert draft.location == "https://admin.example.com/login"
    assert draft.severity == "high"
    assert draft.confidence_score == 100


def test_malformed_finding_fails_closed() -> None:
    assert exposure_from_finding({}, asset_id="asset-1") is None
    assert (
        exposure_from_finding(
            {
                "host": "example.com",
                "template_id": "x",
                "severity": "high",
                "source": "",
            },
            asset_id="asset-1",
        )
        is None
    )
