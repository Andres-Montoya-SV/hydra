"""Infrastructure and application clustering engine."""

from __future__ import annotations

from collections import defaultdict

from core.assets import Host, InfrastructureCluster


def compute_clusters(hosts: dict[str, Host]) -> list[InfrastructureCluster]:
    """Detect infrastructure and application clusters across all hosts."""
    clusters: list[InfrastructureCluster] = []
    idx = 0

    cluster_fns = [
        ("ip", _cluster_by_ip, "Hosts sharing IP address"),
        ("asn", _cluster_by_asn, "Hosts in same ASN"),
        ("cidr", _cluster_by_cidr, "Hosts in same CIDR"),
        ("cdn", _cluster_by_cdn, "Hosts behind same CDN"),
        ("waf", _cluster_by_waf, "Hosts behind same WAF"),
        ("favicon", _cluster_by_favicon, "Hosts sharing favicon hash"),
        ("title", _cluster_by_title, "Application cluster — shared HTTP title"),
        ("technology", _cluster_by_technology, "Hosts sharing primary technology"),
        ("certificate", _cluster_by_certificate, "Hosts sharing TLS certificate SAN"),
        ("body_hash", _cluster_by_body_hash, "Hosts with identical response body"),
        ("redirect", _cluster_by_redirect, "Hosts with identical redirect chain"),
        ("webserver", _cluster_by_webserver, "Hosts sharing web server fingerprint"),
    ]

    for cluster_type, fn, description in cluster_fns:
        groups = fn(hosts)
        for signal, members in groups.items():
            if len(members) < 2:
                continue
            cluster_id = f"{cluster_type}_{idx}"
            idx += 1
            cluster = InfrastructureCluster(
                cluster_id=cluster_id,
                cluster_type=cluster_type,
                signal=signal[:200],
                members=sorted(set(members)),
                confidence=_cluster_confidence(cluster_type, len(members)),
                description=description,
            )
            clusters.append(cluster)
            for domain in cluster.members:
                if domain in hosts:
                    hosts[domain].cluster_ids[cluster_type] = cluster_id

    return clusters


def _cluster_confidence(cluster_type: str, size: int) -> int:
    base = {"ip": 90, "favicon": 95, "body_hash": 95, "certificate": 92, "title": 85}.get(
        cluster_type, 75
    )
    return min(100, base + min(size, 10))


def _cluster_by_ip(hosts: dict[str, Host]) -> dict[str, list[str]]:
    ip_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for ip in host.ips:
            ip_map[ip].append(host.domain)
    return {k: v for k, v in ip_map.items() if len(v) > 1}


def _cluster_by_asn(hosts: dict[str, Host]) -> dict[str, list[str]]:
    asn_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if host.asn:
            asn_map[host.asn].append(host.domain)
    return {k: v for k, v in asn_map.items() if len(v) > 1}


def _cluster_by_cidr(hosts: dict[str, Host]) -> dict[str, list[str]]:
    cidr_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if host.cidr:
            cidr_map[host.cidr].append(host.domain)
    return {k: v for k, v in cidr_map.items() if len(v) > 1}


def _cluster_by_cdn(hosts: dict[str, Host]) -> dict[str, list[str]]:
    cdn_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if host.cdn_provider:
            cdn_map[host.cdn_provider].append(host.domain)
    return {k: v for k, v in cdn_map.items() if len(v) > 1}


def _cluster_by_waf(hosts: dict[str, Host]) -> dict[str, list[str]]:
    waf_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if host.waf_provider:
            waf_map[host.waf_provider].append(host.domain)
    return {k: v for k, v in waf_map.items() if len(v) > 1}


def _cluster_by_favicon(hosts: dict[str, Host]) -> dict[str, list[str]]:
    fav_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            if svc.favicon_hash:
                fav_map[svc.favicon_hash].append(host.domain)
    return {k: v for k, v in fav_map.items() if len(v) > 1}


def _cluster_by_title(hosts: dict[str, Host]) -> dict[str, list[str]]:
    title_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            if svc.title and len(svc.title.strip()) > 3:
                title_map[svc.title.strip()].append(host.domain)
    return {k: v for k, v in title_map.items() if len(v) > 1}


def _cluster_by_technology(hosts: dict[str, Host]) -> dict[str, list[str]]:
    tech_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            for tech in svc.technologies[:1]:
                tech_map[tech.name].append(host.domain)
    return {k: v for k, v in tech_map.items() if len(v) > 1}


def _cluster_by_certificate(hosts: dict[str, Host]) -> dict[str, list[str]]:
    cert_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        if host.tls and host.tls.sans:
            key = "|".join(sorted(host.tls.sans[:3]))
            cert_map[key].append(host.domain)
    return {k: v for k, v in cert_map.items() if len(v) > 1}


def _cluster_by_body_hash(hosts: dict[str, Host]) -> dict[str, list[str]]:
    hash_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            if svc.body_hash:
                hash_map[svc.body_hash].append(host.domain)
    return {k: v for k, v in hash_map.items() if len(v) > 1}


def _cluster_by_redirect(hosts: dict[str, Host]) -> dict[str, list[str]]:
    chain_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            if svc.redirect_chain:
                key = " -> ".join(svc.redirect_chain)
                chain_map[key].append(host.domain)
    return {k: v for k, v in chain_map.items() if len(v) > 1}


def _cluster_by_webserver(hosts: dict[str, Host]) -> dict[str, list[str]]:
    server_map: dict[str, list[str]] = defaultdict(list)
    for host in hosts.values():
        for svc in host.http_services:
            if svc.webserver:
                server_map[svc.webserver].append(host.domain)
    return {k: v for k, v in server_map.items() if len(v) > 1}


# Backward compatibility
def apply_clusters(hosts: dict[str, Host]) -> dict[str, dict[str, list[str]]]:
    clusters = compute_clusters(hosts)
    result: dict[str, dict[str, list[str]]] = defaultdict(dict)
    for cluster in clusters:
        result[cluster.cluster_type][cluster.signal] = cluster.members
    return dict(result)
