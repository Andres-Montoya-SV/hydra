"""Conservative, configurable discovery bounds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config.settings import Settings


@dataclass(frozen=True)
class DiscoveryBounds:
    """Hard caps for iterative collection. Defaults are conservative."""

    max_discovery_depth: int = 1
    max_followup_indicators: int = 50
    max_domains_per_source: int = 20
    max_collection_budget: int = 200
    max_http_probes: int = 200
    max_dns_probes: int = 200
    max_runtime_seconds: int = 3600
    max_entities: int = 5000
    max_relationships: int = 20000
    max_ct_names_per_certificate: int = 200
    max_certificates: int = 500
    max_ips: int = 2000
    max_url_entities: int = 4000
    max_technology_entities: int = 500
    max_followups_per_relationship: int = 20
    max_relationships_per_signal: int = 64
    enable_followup_collection: bool = True

    @classmethod
    def from_settings(cls, settings: Settings) -> DiscoveryBounds:
        return cls(
            max_discovery_depth=settings.max_discovery_depth,
            max_followup_indicators=settings.max_followup_indicators,
            max_domains_per_source=settings.max_domains_per_source,
            max_collection_budget=settings.max_collection_budget,
            max_http_probes=settings.max_http_probes,
            max_dns_probes=settings.max_dns_probes,
            max_runtime_seconds=settings.max_runtime_seconds,
            max_entities=settings.max_entities,
            max_relationships=settings.max_relationships,
            max_ct_names_per_certificate=settings.max_ct_names_per_certificate,
            max_certificates=settings.max_certificates,
            max_ips=settings.max_ips,
            max_url_entities=getattr(settings, "max_url_entities", 4000),
            max_technology_entities=getattr(settings, "max_technology_entities", 500),
            max_followups_per_relationship=getattr(
                settings, "max_followups_per_relationship", settings.max_domains_per_source
            ),
            max_relationships_per_signal=getattr(settings, "max_relationships_per_signal", 64),
            enable_followup_collection=settings.enable_followup_collection,
        )
