"""Infrastructure relationship graph builder."""

from __future__ import annotations

from core.assets import GraphEdge, GraphNode, Host, InfrastructureCluster, InfrastructureGraph


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
            graph.add_edge(GraphEdge(host_node.node_id, ip_id, "resolves_to", confidence=90))

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
                graph.add_edge(GraphEdge(f"ip:{ip}", asn_id, "belongs_to", confidence=85))

        if host.cdn_provider:
            cdn_id = f"cdn:{host.cdn_provider}"
            if cdn_id not in graph.nodes:
                graph.add_node(GraphNode(node_id=cdn_id, node_type="cdn", label=host.cdn_provider))
            graph.add_edge(GraphEdge(host_node.node_id, cdn_id, "served_by", confidence=85))

        if host.provider:
            prov_id = f"provider:{host.provider}"
            if prov_id not in graph.nodes:
                graph.add_node(
                    GraphNode(node_id=prov_id, node_type="provider", label=host.provider)
                )
            graph.add_edge(GraphEdge(host_node.node_id, prov_id, "hosted_on", confidence=80))

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

        # Was nested inside the http_services loop, adding one duplicate
        # "secured_by" edge per HTTP service instead of once per host.
        if host.tls and host.tls.sans:
            cert_key = "|".join(sorted(host.tls.sans[:2]))
            cert_id = f"cert:{hash(cert_key) & 0xFFFFFFFF:08x}"
            if cert_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        node_id=cert_id,
                        node_type="cert",
                        label=host.tls.subject or cert_key[:40],
                        metadata={"sans": host.tls.sans[:5]},
                    )
                )
            graph.add_edge(GraphEdge(host_node.node_id, cert_id, "secured_by", confidence=90))

        for related in host.profile.related_hosts if host.profile else []:
            rel_id = f"host:{related}"
            if rel_id in graph.nodes or related in hosts:
                graph.add_edge(GraphEdge(host_node.node_id, rel_id, "related_to", confidence=70))

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
