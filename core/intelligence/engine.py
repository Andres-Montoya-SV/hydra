"""Intelligence processing pipeline — validation, confidence, profile, cluster, graph, risk."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from core.assets import Host, InfrastructureCluster, InfrastructureGraph
from core.confidence import update_host_confidence
from core.intelligence.clustering import compute_clusters
from core.intelligence.graph import build_infrastructure_graph
from core.intelligence.profile import profile_host
from core.intelligence.risk import score_host
from core.validation.engine import (
    apply_host_warnings,
    validate_dns_resolution,
    validate_naabu_ports,
)


@dataclass
class IntelligenceResult:
    hosts: dict[str, Host]
    clusters: list[InfrastructureCluster] = field(default_factory=list)
    graph: InfrastructureGraph = field(default_factory=InfrastructureGraph)
    warnings: list[str] = field(default_factory=list)


class IntelligenceEngine:
    """Transform normalized hosts into actionable infrastructure intelligence."""

    def process(self, hosts: dict[str, Host]) -> IntelligenceResult:
        warnings: list[str] = []

        all_domains = list(hosts.keys())
        resolved = [d for d, h in hosts.items() if h.dns_resolved]
        dns_warnings, _ = validate_dns_resolution(all_domains, resolved)
        warnings.extend(dns_warnings)

        all_ports = [p for h in hosts.values() for p in h.ports]
        if all_ports:
            agg = Host(domain="_aggregate")
            warnings.extend(validate_naabu_ports(agg, all_ports))

        # Propagate wildcard DNS from root hosts to their discovered children
        # BEFORE confidence scoring, so passively-only subdomains under a
        # wildcard root are demoted (see core/confidence.score_subdomain).
        _propagate_wildcard_dns(hosts)

        for host in hosts.values():
            enrich_host_infrastructure(host)
            apply_host_warnings(host)
            update_host_confidence(host)
            host.profile = profile_host(host, hosts)
            score_host(host)

        clusters = compute_clusters(hosts)
        graph = build_infrastructure_graph(hosts, clusters)

        return IntelligenceResult(
            hosts=hosts,
            clusters=clusters,
            graph=graph,
            warnings=warnings,
        )


_CLOUD_IP_RANGES: tuple[tuple[str, str], ...] = (
    ("AWS", "3.0.0.0/8"),
    ("AWS", "13.32.0.0/15"),
    ("AWS", "52.0.0.0/8"),
    ("AWS", "54.0.0.0/8"),
    ("Cloudflare", "104.16.0.0/12"),
    ("Cloudflare", "172.64.0.0/13"),
    ("Cloudflare", "188.114.96.0/20"),
    ("GCP", "34.0.0.0/8"),
    ("GCP", "35.184.0.0/13"),
    ("Azure", "20.0.0.0/8"),
    ("Azure", "40.64.0.0/10"),
)


def _propagate_wildcard_dns(hosts: dict[str, Host]) -> None:
    """Mark child hosts when their registrable root has wildcard DNS."""
    wildcard_roots = {
        (host.root_domain or host.domain) for host in hosts.values() if host.dns_wildcard
    }
    if not wildcard_roots:
        return
    for host in hosts.values():
        root = host.root_domain or host.domain
        if root in wildcard_roots:
            host.dns_wildcard = True


def enrich_host_infrastructure(host: Host) -> None:
    """Populate cloud/provider fields from local IP, ASN, DNS, and HTTP hints."""
    provider = _detect_cloud_provider(host)
    if provider:
        host.cloud_provider = provider
        host.provider = host.provider or provider
    if host.cloud_provider:
        host.cloud_region = _infer_region(host)


def _detect_cloud_provider(host: Host) -> str | None:
    signals = " ".join(
        [
            host.provider or "",
            host.asn_org or "",
            host.cdn_provider or "",
            " ".join(record.value for record in host.dns_records),
            " ".join(svc.webserver or "" for svc in host.http_services),
        ]
    ).lower()
    if "cloudflare" in signals:
        return "Cloudflare"
    if any(token in signals for token in ("amazon", "aws", "cloudfront", "elb.amazonaws.com")):
        return "AWS"
    if any(token in signals for token in ("google", "gcp", "googleusercontent")):
        return "GCP"
    if any(token in signals for token in ("azure", "microsoft", "windows.net")):
        return "Azure"
    for ip in host.ips:
        provider = _provider_from_ip(ip)
        if provider:
            return provider
    return None


def _provider_from_ip(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, cidr in _CLOUD_IP_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr):
                return provider
        except ValueError:
            continue
    return None


def _infer_region(host: Host) -> str | None:
    blob = " ".join(record.value for record in host.dns_records).lower()
    for token in ("us-east-1", "us-west-2", "eu-west-1", "ap-northeast-2", "ap-southeast-1"):
        if token in blob:
            return token
    return None
