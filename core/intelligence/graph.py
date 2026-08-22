"""Infrastructure relationship graph builder."""

from __future__ import annotations

from core.assets import GraphEdge, GraphNode, Host, InfrastructureCluster, InfrastructureGraph
from core.intel.correlate import band_score
from core.intel.model import ConfidenceBand


def build_infrastructure_graph(
    hosts: dict[str, Host],
    clusters: list[InfrastructureCluster],
) -> InfrastructureGraph:
    """Build queryable graph: Host → IP → ASN → CDN → Technology → Cluster."""
    graph = InfrastructureGraph()

    for domain, host in hosts.items():
        host_node = GraphNode(
            node_id=f"host:{domain}",
            node_type="host",
            label=domain,
            metadata={"risk_score": host.risk_score, "confidence": host.confidence_score},
        )
        graph.add_node(host_node)

        for ip in host.ips:
            ip_id = f"ip:{ip}"
            if ip_id not in graph.nodes:
                graph.add_node(GraphNode(node_id=ip_id, node_type="ip", label=ip))
            graph.add_edge(
                GraphEdge(
                    host_node.node_id,
                    ip_id,
                    "resolves_to",
                    confidence=band_score(ConfidenceBand.HIGH),
                    confidence_label=ConfidenceBand.HIGH.value,
                )
            )

        if host.asn:
            asn_id = f"asn:{host.asn}"
            if asn_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        node_id=asn_id,
                        node_type="asn",
                        label=host.asn,
                        metadata={"org": host.asn_org or ""},
                    )
                )
            for ip in host.ips:
                graph.add_edge(
                    GraphEdge(
                        f"ip:{ip}",
                        asn_id,
                        "belongs_to",
                        confidence=band_score(ConfidenceBand.HIGH),
                        confidence_label=ConfidenceBand.HIGH.value,
                    )
                )

        if host.cdn_provider:
            cdn_id = f"cdn:{host.cdn_provider}"
            if cdn_id not in graph.nodes:
                graph.add_node(GraphNode(node_id=cdn_id, node_type="cdn", label=host.cdn_provider))
            graph.add_edge(
                GraphEdge(
                    host_node.node_id,
                    cdn_id,
                    "served_by",
                    confidence=band_score(ConfidenceBand.HIGH),
                    confidence_label=ConfidenceBand.HIGH.value,
                )
            )

        if host.provider:
            prov_id = f"provider:{host.provider}"
            if prov_id not in graph.nodes:
                graph.add_node(
                    GraphNode(node_id=prov_id, node_type="provider", label=host.provider)
                )
            graph.add_edge(
                GraphEdge(
                    host_node.node_id,
                    prov_id,
                    "hosted_on",
                    confidence=band_score(ConfidenceBand.MEDIUM),
                    confidence_label=ConfidenceBand.MEDIUM.value,
                )
            )

        for svc in host.http_services:
            for tech in svc.technologies[:3]:
                tech_id = f"tech:{tech.name}"
                if tech_id not in graph.nodes:
                    graph.add_node(
                        GraphNode(node_id=tech_id, node_type="technology", label=tech.name)
                    )
                graph.add_edge(
                    GraphEdge(
                        host_node.node_id,
                        tech_id,
                        "runs",
                        confidence=tech.confidence,
                    )
                )

        # Certificate nodes are identified by leaf SHA-256 fingerprint only.
        # Do not hash SAN slices — that is not a certificate identity.
        if host.tls and host.tls.fingerprint_sha256:
            cert_id = f"cert:{host.tls.fingerprint_sha256}"
            if cert_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        node_id=cert_id,
                        node_type="cert",
                        label=host.tls.subject or host.tls.fingerprint_sha256[:16],
                        metadata={
                            "fingerprint_sha256": host.tls.fingerprint_sha256,
                            "sans": host.tls.sans,
                        },
                    )
                )
            graph.add_edge(
                GraphEdge(
                    host_node.node_id,
                    cert_id,
                    "PRESENTS_CERTIFICATE",
                    confidence=band_score(ConfidenceBand.VERY_HIGH),
                    confidence_label=ConfidenceBand.VERY_HIGH.value,
                )
            )

        for related in host.profile.related_hosts if host.profile else []:
            rel_id = f"host:{related}"
            if rel_id in graph.nodes or related in hosts:
                graph.add_edge(
                    GraphEdge(
                        host_node.node_id,
                        rel_id,
                        "related_to",
                        confidence=band_score(ConfidenceBand.MEDIUM),
                        confidence_label=ConfidenceBand.MEDIUM.value,
                    )
                )

    for cluster in clusters:
        if len(cluster.members) < 2:
            continue
        cluster_node = GraphNode(
            node_id=f"cluster:{cluster.cluster_id}",
            node_type="cluster",
            label=f"{cluster.cluster_type}: {cluster.signal[:30]}",
            metadata={"member_count": len(cluster.members), "type": cluster.cluster_type},
        )
        graph.add_node(cluster_node)
        for member in cluster.members[:50]:
            member_id = f"host:{member}"
            if member_id in graph.nodes:
                graph.add_edge(
                    GraphEdge(
                        member_id, cluster_node.node_id, "member_of", confidence=cluster.confidence
                    )
                )

    return graph
