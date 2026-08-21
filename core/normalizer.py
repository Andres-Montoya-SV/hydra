"""Normalize tool outputs into canonical Host objects via parser registry."""

from __future__ import annotations

from pathlib import Path

from core.assets import Host
from core.registry import HostRegistry
from utils.files import read_jsonl


def build_registry_from_artifacts(
    *,
    run_id: str,
    output_dir: Path,
    tools: list[str] | None = None,
) -> HostRegistry:
    """Build and finalize host registry from all tool artifacts in output directory."""
    registry = HostRegistry(run_id, output_dir)
    tool_list = tools or [
        "subfinder",
        "assetfinder",
        "dnsx",
        "httpx",
        "naabu",
        "nuclei",
        "gau",
        "waybackurls",
        "katana",
        "hakrawler",
    ]
    registry.ingest_all(tool_list)
    registry.finalize()
    return registry


def load_httpx_results(path: Path) -> list[dict]:
    """Load httpx results from JSON or JSONL file (legacy helper for reporter)."""
    if not path.exists():
        return []
    import json

    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return []
    if content.startswith("["):
        try:
            data = json.loads(content)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            pass
    return read_jsonl(path)


# Backward compatibility wrapper
def build_host_inventory(
    *,
    subdomains: list[str],
    resolved: list[str],
    httpx_results: list[dict],
    naabu_path: Path | None,
    discovery_sources: dict[str, str] | None = None,
) -> tuple[dict[str, Host], list[str]]:
    """Legacy batch normalizer — prefer HostRegistry for new code."""
    from core.intelligence.engine import IntelligenceEngine
    from core.parsers.registry import parse_tool_output

    output_dir = naabu_path.parent if naabu_path else Path(".")
    registry = HostRegistry("legacy", output_dir)

    for domain in subdomains:
        h = Host(domain=domain)
        h.add_source("subfinder")
        if discovery_sources and domain in discovery_sources:
            h.add_source(discovery_sources[domain])
        registry.merge(h)

    resolved_set = set(resolved)
    for domain in resolved_set:
        h = Host(domain=domain)
        h.dns_resolved = True
        h.add_source("dnsx")
        registry.merge(h)

    if httpx_results:
        import json

        from core.parsers.registry import HttpxParser

        tmp = output_dir / "httpx.json"
        if not tmp.exists():
            tmp.write_text("\n".join(json.dumps(r) for r in httpx_results), encoding="utf-8")
        partials, w = HttpxParser().parse(output_dir)
        for p in partials:
            registry.merge(p)

    if naabu_path and naabu_path.exists():
        partials, w = parse_tool_output("naabu", output_dir)
        for p in partials:
            registry.merge(p)

    result = IntelligenceEngine().process(registry.to_dict())
    return result.hosts, result.warnings
