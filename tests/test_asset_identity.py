"""Fase 03 (EASM roadmap) — pure reconciliation logic
(`api/asset_identity.py`). No database, no I/O: every test here
constructs fixed `Host`/`ExistingAsset` fixtures and asserts the exact
decision `reconcile_observation`/`reconcile_host_observations` makes —
the phase's own "función pura, testeable con fixtures fijos,
determinística" requirement.

The real-persistence side of this (the `assets`/`asset_identifiers`
tables, and the backfill that calls this pure logic against real scan
history) is in `tests/test_asset_backfill.py`.
"""

from __future__ import annotations

from api.asset_identity import (
    ASSET_TYPE_CLOUD_STORAGE,
    ASSET_TYPE_DNS_RECORD,
    ASSET_TYPE_DOMAIN,
    ASSET_TYPE_PORT,
    ASSET_TYPE_URL,
    IDENTIFIER_TYPE_IP,
    AssetObservation,
    ExistingAsset,
    cloud_storage_identity_key,
    cloud_storage_observation,
    dns_record_identity_key,
    domain_identity_key,
    identities_for_host,
    port_identity_key,
    reconcile_host_observations,
    reconcile_observation,
    url_identity_key,
)
from core.assets import URL, DnsRecord, Host, Port


def _counting_id_factory():
    counter = iter(f"new-{i}" for i in range(1000))
    return lambda: next(counter)


class TestIdentityKeyFormat:
    def test_domain_key_reuses_the_entity_id_type_colon_key_format(self) -> None:
        assert domain_identity_key("Example.COM.") == "domain:example.com"

    def test_url_key_normalizes_via_core_assets_normalize_http_url(self) -> None:
        assert url_identity_key("HTTP://Example.com:80/foo/") == "url:http://example.com/foo"

    def test_port_key_is_stable_regardless_of_protocol_casing(self) -> None:
        assert port_identity_key(host="example.com", port=443, protocol="TCP") == (
            "port:example.com:443:tcp"
        )

    def test_dns_record_key_normalizes_type_case_and_value_case(self) -> None:
        assert (
            dns_record_identity_key(host="example.com", record_type="a", value="1.2.3.4")
            == "dns_record:example.com:A:1.2.3.4"
        )


class TestIdentitiesForHost:
    def test_a_bare_host_produces_exactly_one_domain_observation(self) -> None:
        host = Host(domain="example.com")
        observations = identities_for_host(host)
        assert len(observations) == 1
        assert observations[0].asset_type == ASSET_TYPE_DOMAIN
        assert observations[0].identity_key == "domain:example.com"

    def test_ips_become_identifiers_on_the_domain_observation_never_their_own_asset(
        self,
    ) -> None:
        host = Host(domain="example.com", ips=["1.2.3.4", "5.6.7.8"])
        observations = identities_for_host(host)
        assert len(observations) == 1
        assert set(observations[0].identifiers) == {
            (IDENTIFIER_TYPE_IP, "1.2.3.4"),
            (IDENTIFIER_TYPE_IP, "5.6.7.8"),
        }

    def test_ports_dns_records_and_urls_each_produce_their_own_observation(self) -> None:
        host = Host(
            domain="example.com",
            ports=[Port(host="example.com", port=443, protocol="tcp")],
            dns_records=[DnsRecord(host="example.com", record_type="A", value="1.2.3.4")],
            urls=[URL(url="https://example.com/", host="example.com", source="httpx")],
        )
        observations = identities_for_host(host)
        types = {o.asset_type for o in observations}
        assert types == {ASSET_TYPE_DOMAIN, ASSET_TYPE_PORT, ASSET_TYPE_DNS_RECORD, ASSET_TYPE_URL}


class TestCloudStorageIdentity:
    def test_provider_qualifies_bucket_identity(self) -> None:
        assert (
            cloud_storage_identity_key(provider="S3", resource_name="Example-Assets")
            == "cloud_storage:s3:example-assets"
        )
        assert (
            cloud_storage_identity_key(provider="gcs", resource_name="Example-Assets")
            == "cloud_storage:gcs:example-assets"
        )

    def test_cloud_observation_uses_url_as_secondary_identifier_only(self) -> None:
        observation = cloud_storage_observation(
            {
                "provider": "s3",
                "resource_name": "example-assets",
                "url": "https://example-assets.s3.amazonaws.com/",
            }
        )
        assert observation.asset_type == ASSET_TYPE_CLOUD_STORAGE
        assert observation.identity_key == "cloud_storage:s3:example-assets"
        assert observation.identifiers == (("url", "https://example-assets.s3.amazonaws.com/"),)


class TestReconciliationIsDeterministic:
    def test_the_same_observation_against_the_same_existing_state_always_decides_the_same_way(
        self,
    ) -> None:
        observation = AssetObservation(asset_type=ASSET_TYPE_DOMAIN, identity_key="domain:x.com")
        existing = {"domain:x.com": ExistingAsset("asset-1", ASSET_TYPE_DOMAIN, "domain:x.com")}

        first = reconcile_observation(
            observation=observation,
            existing_by_identity_key=existing,
            new_asset_id=lambda: "unused",
        )
        second = reconcile_observation(
            observation=observation,
            existing_by_identity_key=existing,
            new_asset_id=lambda: "unused",
        )
        assert first == second
        assert first.is_new is False
        assert first.asset_id == "asset-1"

    def test_an_unseen_identity_key_always_creates_a_new_asset(self) -> None:
        observation = AssetObservation(asset_type=ASSET_TYPE_DOMAIN, identity_key="domain:new.com")
        decision = reconcile_observation(
            observation=observation,
            existing_by_identity_key={},
            new_asset_id=lambda: "brand-new-id",
        )
        assert decision.is_new is True
        assert decision.asset_id == "brand-new-id"

    def test_processing_order_of_multiple_observations_does_not_change_outcomes(self) -> None:
        host = Host(
            domain="example.com",
            ports=[Port(host="example.com", port=443, protocol="tcp")],
        )
        existing: dict[str, ExistingAsset] = {}
        forward = reconcile_host_observations(
            host=host, existing_by_identity_key=dict(existing), new_asset_id=_counting_id_factory()
        )
        backward = reconcile_host_observations(
            host=host,
            existing_by_identity_key=dict(existing),
            new_asset_id=_counting_id_factory(),
        )
        assert {(d.asset_type, d.identity_key, d.is_new) for d in forward} == {
            (d.asset_type, d.identity_key, d.is_new) for d in backward
        }


class TestReappearanceNeverCreatesADuplicate:
    def test_an_asset_missing_from_one_runs_lookup_and_present_in_the_next_reconciles_to_the_same_row(
        self,
    ) -> None:
        existing = {
            "domain:example.com": ExistingAsset("asset-1", ASSET_TYPE_DOMAIN, "domain:example.com")
        }
        host = Host(domain="example.com")

        # Run N+2 (the domain "disappeared" from run N+1's own harvest,
        # e.g. a transient DNS failure) still finds the SAME existing
        # asset row, because the lookup is built from everything ever
        # recorded, not from run N+1's own (empty, for this domain) output.
        decisions = reconcile_host_observations(
            host=host, existing_by_identity_key=existing, new_asset_id=lambda: "should-not-be-used"
        )
        assert len(decisions) == 1
        assert decisions[0].is_new is False
        assert decisions[0].asset_id == "asset-1"


class TestSharedIpNeverMergesTwoDifferentAssets:
    """The adversarial case the phase's own prompt requires: two
    different real domains (standing in for two different
    organizations' assets, isolation itself is proven at the DB layer in
    tests/test_asset_backfill.py) that currently share an IP (a shared
    CDN) must never be treated as the same asset just because an `ip`
    identifier happens to match."""

    def test_two_domains_sharing_an_ip_reconcile_to_two_separate_assets(self) -> None:
        shared_ip = "203.0.113.9"
        host_a = Host(domain="a.example.com", ips=[shared_ip])
        host_b = Host(domain="b.example.com", ips=[shared_ip])

        existing: dict[str, ExistingAsset] = {}
        ids = _counting_id_factory()
        decisions_a = reconcile_host_observations(
            host=host_a, existing_by_identity_key=existing, new_asset_id=ids
        )
        for d in decisions_a:
            existing[d.identity_key] = ExistingAsset(d.asset_id, d.asset_type, d.identity_key)
        decisions_b = reconcile_host_observations(
            host=host_b, existing_by_identity_key=existing, new_asset_id=ids
        )

        assert decisions_a[0].is_new is True
        assert decisions_b[0].is_new is True
        assert decisions_a[0].asset_id != decisions_b[0].asset_id
        # Both legitimately carry the same IP as an identifier, on their
        # own, separate assets — never a reason to unify them.
        assert decisions_a[0].identifiers == ((IDENTIFIER_TYPE_IP, shared_ip),)
        assert decisions_b[0].identifiers == ((IDENTIFIER_TYPE_IP, shared_ip),)

    def test_an_ip_appearing_in_the_existing_lookup_is_never_treated_as_an_identity_key(
        self,
    ) -> None:
        """`existing_by_identity_key` is keyed by (type-prefixed)
        identity_key, e.g. "domain:a.example.com" — an IP string like
        "203.0.113.9" is never a valid key shape in that dict, so even a
        caller that (bug) tried to look one up would get a clean miss,
        never an accidental hit against an unrelated domain asset."""
        existing = {
            "domain:a.example.com": ExistingAsset(
                "asset-a", ASSET_TYPE_DOMAIN, "domain:a.example.com"
            )
        }
        observation = AssetObservation(
            asset_type=ASSET_TYPE_DOMAIN,
            identity_key="domain:b.example.com",
            identifiers=((IDENTIFIER_TYPE_IP, "203.0.113.9"),),
        )
        decision = reconcile_observation(
            observation=observation,
            existing_by_identity_key=existing,
            new_asset_id=lambda: "asset-b",
        )
        assert decision.is_new is True
        assert decision.asset_id == "asset-b"
