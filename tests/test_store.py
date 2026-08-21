"""Tests for SQLite asset store."""

from __future__ import annotations

from core.assets import (
    URL,
    Confidence,
    GraphEdge,
    GraphNode,
    Host,
    HostCategory,
    HostProfile,
    HttpService,
    InfrastructureCluster,
    InfrastructureGraph,
    RiskLevel,
    ScanRun,
    TechnologyFinding,
)
from core.store import AssetStore


class TestAssetStore:
    def test_create_and_query_run(self, tmp_path) -> None:
        db = tmp_path / "test.db"
        store = AssetStore(db)
        store.create_run(
            ScanRun(run_id="run1", started_at="2026-01-01T00:00:00Z", targets=["example.com"])
        )

        host = Host(
            domain="api.example.com",
            dns_resolved=True,
            confidence=Confidence.MEDIUM,
            confidence_score=80,
            risk_level=RiskLevel.HIGH,
            risk_score=30,
        )
        host.profile = HostProfile(category=HostCategory.API, summary="API host")
        host.http_services.append(
            HttpService(
                url="https://api.example.com",
                host="api.example.com",
                status_code=200,
                technologies=[TechnologyFinding(name="nginx", source="httpx", confidence=95)],
                tls_version="tls1.3",
                response_size=1234,
            )
        )
        host.cloud_provider = "AWS"
        host.city = "Seattle"
        host.urls.append(
            URL(
                url="https://api.example.com/v1/users?id=1",
                host="api.example.com",
                source="katana",
                endpoint_type="api",
                parameters=["id"],
            )
        )
        store.upsert_host("run1", host)
        store.finish_run("run1", host_count=1, alive_count=1, warnings=[], errors=[])

        hosts = store.get_hosts("run1")
        assert len(hosts) == 1
        assert hosts[0].domain == "api.example.com"
        assert len(hosts[0].http_services) == 1
        assert hosts[0].http_services[0].technologies[0].name == "nginx"
        assert hosts[0].http_services[0].tls_version == "tls1.3"
        assert hosts[0].cloud_provider == "AWS"
        assert hosts[0].urls[0].endpoint_type == "api"

        export = store.export_run_json("run1")
        assert export["run_id"] == "run1"
        assert len(export["hosts"]) == 1

    def test_persist_registry_with_graph(self, tmp_path) -> None:
        db = tmp_path / "test.db"
        store = AssetStore(db)
        store.create_run(ScanRun(run_id="run2", started_at="2026-01-01T00:00:00Z"))

        hosts = {
            "a.example.com": Host(domain="a.example.com", ips=["1.2.3.4"], risk_score=10),
            "b.example.com": Host(domain="b.example.com", ips=["1.2.3.4"], risk_score=10),
        }
        clusters = [
            InfrastructureCluster(
                cluster_id="ip_0",
                cluster_type="ip",
                signal="1.2.3.4",
                members=["a.example.com", "b.example.com"],
            ),
        ]
        graph = InfrastructureGraph()
        graph.add_node(
            GraphNode(node_id="host:a.example.com", node_type="host", label="a.example.com")
        )
        graph.add_edge(GraphEdge("host:a.example.com", "ip:1.2.3.4", "resolves_to"))

        store.persist_registry("run2", hosts, clusters=clusters, graph=graph)
        assert store.get_host_count("run2") == 2
        assert len(store.get_clusters("run2")) == 1
        assert len(store.get_graph("run2").nodes) >= 1
