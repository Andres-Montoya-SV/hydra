"""In-memory host registry — intelligence hub during pipeline execution."""

from __future__ import annotations

from pathlib import Path

from core.assets import AssetCollection, Host, InfrastructureCluster, InfrastructureGraph
from core.intelligence.engine import IntelligenceEngine
from core.parsers.registry import parse_tool_output


class HostRegistry(AssetCollection):
    """Central registry: merge tool output, run intelligence, export to store."""

    def __init__(self, run_id: str, output_dir: Path) -> None:
        super().__init__()
        self.run_id = run_id
        self.output_dir = output_dir
        self.clusters: list[InfrastructureCluster] = []
        self.graph: InfrastructureGraph = InfrastructureGraph()
        self.warnings: list[str] = []
        self.source_counts: dict[str, int] = {}
        self.correlated_hosts: dict[str, list[str]] = {}
        self._engine = IntelligenceEngine()

    def ingest(self, tool: str, *, artifact: Path | None = None) -> int:
        """Parse tool output and merge into registry. Returns hosts touched."""
        partials, warnings = parse_tool_output(
            tool,
            self.output_dir,
            artifact=artifact,
            run_id=self.run_id,
        )
        self.warnings.extend(warnings)
        for partial in partials:
            self.merge(partial)
        self._refresh_source_correlation()
        return len(partials)

    def ingest_all(self, tools: list[str]) -> None:
        for tool in tools:
            self.ingest(tool)

    def finalize(self) -> dict[str, Host]:
        """Run intelligence pipeline on all hosts."""
        hosts = self.to_dict()
        self._refresh_source_correlation()
        result = self._engine.process(hosts)
        self.clusters = result.clusters
        self.graph = result.graph
        self.warnings.extend(result.warnings)
        return hosts

    def alive_count(self) -> int:
        return sum(1 for h in self.values() if h.http_services)

    def sorted_by_risk(self) -> list[Host]:
        return sorted(self.values(), key=lambda h: h.risk_score, reverse=True)

    def _refresh_source_correlation(self) -> None:
        """Summarize cross-tool discovery overlap for reporting and scoring."""
        source_counts: dict[str, int] = {}
        correlated: dict[str, list[str]] = {}
        for host in self.values():
            sources = sorted(set(host.discovery_sources))
            for source in sources:
                source_counts[source] = source_counts.get(source, 0) + 1
            discovery_sources = [
                source for source in sources if source in {"subfinder", "assetfinder", "amass"}
            ]
            if len(discovery_sources) > 1:
                correlated[host.domain] = discovery_sources
        self.source_counts = source_counts
        self.correlated_hosts = correlated
