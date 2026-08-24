"""Report generation for reconnaissance runs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.intel.correlate import score_to_band
from core.models import PipelineContext, RunSummary
from utils.files import safe_write_text, write_json
from utils.security import escape_html

if TYPE_CHECKING:
    from config.settings import Settings
    from core.store import AssetStore


class ReportGenerator:
    """Generates summary reports in multiple formats."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build_summary(self, context: PipelineContext) -> RunSummary:
        """Build a run summary from pipeline context.

        Args:
            context: Completed or partial pipeline context.

        Returns:
            Aggregated RunSummary.
        """
        tools_run = []
        tools_failed = []
        tools_skipped = []

        for _name, info in context.tool_states.items():
            status = info.status.value
            if status == "completed":
                tools_run.append(info.name)
            elif status == "failed":
                tools_failed.append(info.name)
            elif status in ("skipped", "missing"):
                tools_skipped.append(info.name)

        return RunSummary(
            targets_count=len(context.targets),
            subdomains_count=len(context.subdomains),
            resolved_count=len(context.resolved),
            alive_count=len(context.alive_urls),
            duration_seconds=context.duration_seconds,
            tools_run=tools_run,
            tools_failed=tools_failed,
            tools_skipped=tools_skipped,
            errors=context.errors,
            warnings=context.warnings,
            output_dir=self._relative_output_dir(context.output_dir),
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    def _relative_output_dir(self, output_dir: Path) -> str:
        """Return output_dir relative to project_root to avoid embedding the
        analyst's home directory / username in shareable reports."""
        try:
            return str(output_dir.resolve().relative_to(self.settings.project_root.resolve()))
        except ValueError:
            return output_dir.name

    def generate(self, context: PipelineContext, store: AssetStore | None = None) -> RunSummary:
        """Generate all report artifacts from SQLite intelligence store."""
        summary = self.build_summary(context)
        base = context.output_dir
        summary_data = summary.to_dict()

        if store and context.run_id:
            export = store.export_run_json(context.run_id)
            write_json(base / "assets.json", export, base_dir=base)
            hosts = store.get_hosts(context.run_id, limit=500)
            summary_data["high_priority"] = [
                h.to_dict() for h in hosts if h.risk_level.value in ("critical", "high")
            ][:25]
            summary_data["low_confidence_hosts"] = [
                h.domain for h in hosts if h.confidence_score < 50
            ][:50]
            summary_data["cluster_count"] = len(store.get_clusters(context.run_id))
            graph = store.get_graph(context.run_id)
            summary_data["graph_nodes"] = len(graph.nodes)
            summary_data["graph_edges"] = len(graph.edges)

            tarpit_hosts = [h for h in hosts if h.tarpit_suspected]
            if tarpit_hosts:
                summary_data["tarpit_suspected_hosts"] = [
                    {
                        "domain": h.domain,
                        "canary_ports": h.tarpit_canary_ports,
                        "message": (
                            "Port scan results unreliable — target responds 'open' to "
                            "canary ports; likely tarpit/portspoof defense. Not reporting "
                            "individual ports as findings."
                        ),
                    }
                    for h in tarpit_hosts
                ]

            wildcard_hosts = [
                h
                for h in hosts
                if h.dns_wildcard and (not h.subdomain or h.domain == h.root_domain)
            ]
            # Prefer roots that carry the wildcard-dns-detected finding
            wildcard_roots = [
                h.domain
                for h in hosts
                if any(f.template_id == "wildcard-dns-detected" for f in h.findings)
            ] or [h.domain for h in wildcard_hosts]
            if wildcard_roots:
                summary_data["wildcard_dns_detected"] = True
                summary_data["wildcard_dns_roots"] = wildcard_roots

            soft404_hosts = [h for h in hosts if h.soft_404_detected]
            if soft404_hosts:
                summary_data["soft_404_detected_hosts"] = [
                    {
                        "domain": h.domain,
                        "message": (
                            "Soft-404 / catch-all detected — HTTP 200 for nonexistent "
                            "paths; URL existence inferred from status codes is unreliable."
                        ),
                    }
                    for h in soft404_hosts
                ]

        invalid_param_hosts = context.metadata.get("param_fuzz_baseline_invalid_hosts") or []
        if invalid_param_hosts:
            summary_data["param_fuzz_baseline_invalid_hosts"] = invalid_param_hosts

        write_json(base / "summary.json", summary_data, base_dir=base)
        write_json(
            self.settings.project_root / self.settings.reports_directory / "statistics.json",
            summary_data,
        )
        self._write_markdown_overview(context, summary, store=store)
        self._write_html_summary(context, summary, store=store)
        return summary

    def _write_markdown_overview(
        self,
        context: PipelineContext,
        summary: RunSummary,
        store: AssetStore | None = None,
    ) -> None:
        lines = [
            "# Hydra Intelligence Report",
            "",
            f"**Generated:** {summary.timestamp}",
            "",
        ]

        if self.settings.program_name:
            lines.extend(
                [
                    f"**Program:** {self.settings.program_name}",
                    f"**Platform:** {self.settings.program_platform or 'N/A'}",
                    "",
                ]
            )

        lines.extend(["## Targets", ""])
        for target in context.targets:
            lines.append(f"- `{target.domain}` (source: {target.source})")

        lines.extend(
            [
                "",
                "## Statistics",
                "",
                "| Metric | Count |",
                "|--------|-------|",
                f"| Subdomains | {summary.subdomains_count} |",
                f"| Resolved | {summary.resolved_count} |",
                f"| Alive HTTP | {summary.alive_count} |",
                f"| Duration | {summary.duration_seconds:.1f}s |",
                "",
                "## Tools",
                "",
                f"- **Completed:** {', '.join(summary.tools_run) or 'None'}",
                f"- **Failed:** {', '.join(summary.tools_failed) or 'None'}",
                f"- **Skipped:** {', '.join(summary.tools_skipped) or 'None'}",
                "",
            ]
        )

        if store and context.run_id:
            hosts = store.query_hosts_by_risk(context.run_id, min_score=10)
            if hosts:
                lines.extend(
                    [
                        "## High-Priority Infrastructure",
                        "",
                        "| Host | Risk | Confidence | Category | Why |",
                        "|------|------|------------|----------|-----|",
                    ]
                )
                for h in hosts[:30]:
                    cat = h.profile.category.value if h.profile else "unknown"
                    why = "; ".join(h.risk_reasons[:2]) if h.risk_reasons else "—"
                    lines.append(
                        f"| `{h.domain}` | {h.risk_score} | {h.confidence_score}% | {cat} | {why} |"
                    )
                lines.append("")

            lines.extend(self._intel_relationship_lines(store, context.run_id))

            clusters = store.get_clusters(context.run_id)
            app_clusters = [
                c for c in clusters if c.cluster_type in ("title", "body_hash", "favicon")
            ]
            if app_clusters:
                lines.extend(
                    [
                        "## Host Projection — Application Clusters",
                        "",
                        "Host clusters are a reporting projection of collected HTTP/TLS "
                        "fields. Correlation confidence comes from `intel_*` relationships "
                        "above, not from cluster size.",
                        "",
                    ]
                )
                for cluster in sorted(app_clusters, key=lambda c: -len(c.members))[:10]:
                    lines.append(f"- {_format_cluster(cluster)}")
                lines.append("")

            infra_clusters = [
                c for c in clusters if c.cluster_type in ("ip", "cdn", "certificate", "asn")
            ]
            if infra_clusters:
                lines.extend(
                    [
                        "## Host Projection — Infrastructure Clusters",
                        "",
                        "These groupings are Host-view projections. They must not override "
                        "intel relationship confidence (for example a shared GCP address is "
                        "MEDIUM tenancy, not ownership).",
                        "",
                    ]
                )
                for cluster in sorted(infra_clusters, key=lambda c: -len(c.members))[:10]:
                    lines.append(f"- {_format_cluster(cluster)}")
                lines.append("")

            # Query all hosts (not just risk_score-filtered ones): tarpit
            # detection deliberately excludes port signal from risk scoring,
            # so a host whose only would-be signal was fabricated open ports
            # can have a risk_score of 0 and be absent from `hosts` above.
            all_hosts = store.get_hosts(context.run_id, limit=500)
            tarpit_hosts = [h for h in all_hosts if h.tarpit_suspected]
            if tarpit_hosts:
                lines.extend(
                    [
                        "## ⚠ Tarpit/Portspoof Suspected",
                        "",
                        "Port scan results unreliable — these hosts respond 'open' to canary "
                        "ports with no standard service association, indicating an anti-"
                        "reconnaissance tarpit/portspoof defense. Individual open ports are "
                        "**not** listed as findings for these hosts; raw naabu/port_verify "
                        "data is preserved in `assets.json` for audit only.",
                        "",
                    ]
                )
                for h in tarpit_hosts:
                    ports = ", ".join(str(p) for p in h.tarpit_canary_ports)
                    lines.append(f"- `{h.domain}` (canary ports probed: {ports})")
                lines.append("")

            wildcard_roots = [
                h
                for h in all_hosts
                if any(f.template_id == "wildcard-dns-detected" for f in h.findings)
            ]
            if wildcard_roots:
                lines.extend(
                    [
                        "## ⚠ Wildcard DNS Detected",
                        "",
                        "These root domains resolve improbable canary subdomains — passive "
                        "enumeration results under them are not independently confirmed and "
                        "have demoted confidence until corroborated (e.g. by Certificate "
                        "Transparency or a live HTTP service).",
                        "",
                    ]
                )
                for h in wildcard_roots:
                    lines.append(f"- `{h.domain}`")
                lines.append("")

            soft404_hosts = [h for h in all_hosts if h.soft_404_detected]
            if soft404_hosts:
                lines.extend(
                    [
                        "## ⚠ Soft-404 / Catch-All Detected",
                        "",
                        "These hosts return HTTP 200 for nonexistent paths with a body "
                        "matching the site root. URL existence inferred from status codes "
                        "alone is unreliable on these hosts.",
                        "",
                    ]
                )
                for h in soft404_hosts:
                    lines.append(f"- `{h.domain}`")
                lines.append("")

        elif context.httpx_results:
            lines.extend(
                [
                    "## Top Live Services",
                    "",
                    "| URL | Status | Title | Tech |",
                    "|-----|--------|-------|------|",
                ]
            )
            for rec in context.httpx_results[:50]:
                url = str(rec.get("url", "")).replace("|", "/")
                status = rec.get("status_code", "")
                title = str(rec.get("title", ""))[:40].replace("|", "/")
                tech_list = rec.get("tech", [])
                tech = ", ".join(tech_list[:3]) if isinstance(tech_list, list) else ""
                lines.append(f"| {url} | {status} | {title} | {tech} |")

        invalid_param_hosts = context.metadata.get("param_fuzz_baseline_invalid_hosts") or []
        if invalid_param_hosts:
            lines.extend(
                [
                    "## ⚠ Parameter Discovery Skipped (Baseline Blocked)",
                    "",
                    "Parameter discovery skipped for these hosts — baseline request was "
                    "blocked/rate-limited, results would be unreliable. This is **not** "
                    "the same as probing successfully and finding zero influential "
                    "parameters.",
                    "",
                ]
            )
            for row in invalid_param_hosts:
                host = row.get("host") or row.get("domain") or "?"
                status = row.get("baseline_status")
                reason = row.get("reason") or ""
                lines.append(f"- `{host}` (baseline HTTP {status}): {reason}")
            lines.append("")

        if summary.errors:
            lines.extend(["", "## Errors", ""])
            for err in summary.errors:
                lines.append(f"- {err}")

        if summary.warnings:
            lines.extend(["", "## Warnings", ""])
            for warn in summary.warnings:
                lines.append(f"- {warn}")

        overview_path = self.settings.project_root / self.settings.reports_directory / "overview.md"
        safe_write_text(overview_path, "\n".join(lines) + "\n", base_dir=self.settings.project_root)

    def _write_html_summary(
        self,
        context: PipelineContext,
        summary: RunSummary,
        store: AssetStore | None = None,
    ) -> None:
        graph_nodes = graph_edges = 0
        if store and context.run_id:
            graph = store.get_graph(context.run_id)
            graph_nodes = len(graph.nodes)
            graph_edges = len(graph.edges)

        html_parts = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="UTF-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
            "  <title>Recon Summary</title>",
            "  <style>",
            "    :root { color-scheme: dark light; --bg:#0f1419; --panel:#17202a; --text:#d7dee8; --muted:#8fa1b3; --line:#2d3a47; --accent:#4fb3ff; --risk:#ffb86b; }",
            "    [data-theme='light'] { --bg:#f7f9fb; --panel:#ffffff; --text:#18212b; --muted:#5b6b7b; --line:#d7e0ea; --accent:#0969da; --risk:#9a4d00; }",
            "    body { font-family: system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--text); }",
            "    main { max-width: 1180px; margin: 0 auto; padding: 1.5rem; }",
            "    header { display:flex; align-items:center; justify-content:space-between; gap:1rem; margin-bottom:1rem; }",
            "    h1, h2 { color: var(--accent); margin-bottom: .5rem; }",
            "    button, input, select { background: var(--panel); color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: .55rem .7rem; }",
            "    .toolbar { display:flex; flex-wrap:wrap; gap:.6rem; margin:1rem 0; }",
            "    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); gap: .75rem; }",
            "    .stat { background: var(--panel); padding: .9rem; border-radius: 8px; border: 1px solid var(--line); }",
            "    .stat .value { font-size: 1.7rem; font-weight: 700; color: var(--risk); }",
            "    table { border-collapse: collapse; width: 100%; margin-top: 1rem; background: var(--panel); }",
            "    th, td { border-bottom: 1px solid var(--line); padding: 0.55rem; text-align: left; vertical-align: top; }",
            "    th { color: var(--muted); font-size: .85rem; }",
            "    tr[data-risk='critical'], tr[data-risk='high'] { box-shadow: inset 3px 0 0 var(--risk); }",
            "    .muted { color: var(--muted); }",
            "    .error { color: #f85149; }",
            "    .exec { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 1rem; margin: 1rem 0; }",
            "    details.evidence { margin-top: .4rem; }",
            "    details.evidence pre { white-space: pre-wrap; font-size: .8rem; max-height: 240px; overflow: auto; }",
            "  </style>",
            "</head>",
            "<body data-theme='dark'>",
            "<main>",
            "  <header>",
            "    <div>",
            "      <h1>Hydra Intelligence Report</h1>",
            f"      <p class='muted'>Generated: {escape_html(summary.timestamp)}</p>",
            "    </div>",
            "    <button type='button' onclick=\"toggleTheme()\">Toggle Theme</button>",
            "  </header>",
            '  <div class="stats">',
            f'    <div class="stat"><div class="value">{summary.targets_count}</div>Targets</div>',
            f'    <div class="stat"><div class="value">{summary.subdomains_count}</div>Subdomains</div>',
            f'    <div class="stat"><div class="value">{summary.resolved_count}</div>Resolved</div>',
            f'    <div class="stat"><div class="value">{summary.alive_count}</div>Alive</div>',
            f'    <div class="stat"><div class="value">{graph_nodes}</div>Graph Nodes</div>',
            f'    <div class="stat"><div class="value">{graph_edges}</div>Graph Edges</div>',
            f'    <div class="stat"><div class="value">{summary.duration_seconds:.0f}s</div>Duration</div>',
            "  </div>",
        ]
        html_parts.extend(self._executive_summary_html(context, summary, store))
        html_parts.extend(self._intel_correlation_html(context, store))
        html_parts.extend(self._host_projection_clusters_html(context, store))
        html_parts.extend(
            [
                "  <h2>Assets</h2>",
                "  <div class='toolbar'>",
                "    <input id='search' placeholder='Search hosts, titles, technologies' oninput='filterRows()'>",
                "    <select id='riskFilter' onchange='filterRows()'><option value=''>All risk</option><option value='critical'>Critical</option><option value='high'>High</option><option value='medium'>Medium+</option></select>",
                "  </div>",
                "  <table id='assets'>",
                "    <tr><th>Host / URL</th><th>Risk</th><th>Category</th><th>Title</th><th>Server</th><th>Tech</th></tr>",
            ]
        )

        if store and context.run_id:
            for h in store.query_hosts_by_risk(context.run_id, min_score=5)[:100]:
                svc = h.http_services[0] if h.http_services else None
                cat = h.profile.category.value if h.profile else "unknown"
                tech = ", ".join(svc.tech_names()[:4]) if svc else ""
                html_parts.append(
                    f"    <tr data-risk='{escape_html(h.risk_level.value)}'>"
                    f"<td>{escape_html(svc.url if svc and svc.url else h.domain)}</td>"
                    f"<td>{escape_html(h.risk_level.value)} {h.risk_score}</td>"
                    f"<td>{escape_html(cat)}</td>"
                    f"<td>{escape_html(svc.title if svc else '')}</td>"
                    f"<td>{escape_html(svc.webserver if svc else '')}</td>"
                    f"<td>{escape_html(tech)}</td>"
                    "</tr>"
                )
        else:
            for rec in context.httpx_results[:100]:
                html_parts.append(
                    "    <tr data-risk='info'>"
                    f"<td>{escape_html(rec.get('url', ''))}</td>"
                    f"<td>{escape_html(rec.get('status_code', ''))}</td>"
                    "<td>unknown</td>"
                    f"<td>{escape_html(str(rec.get('title', ''))[:60])}</td>"
                    f"<td>{escape_html(rec.get('webserver', ''))}</td>"
                    f"<td>{escape_html(', '.join(rec.get('tech', [])[:4]) if isinstance(rec.get('tech'), list) else '')}</td>"
                    "</tr>"
                )

        html_parts.append("  </table>")
        html_parts.extend(self._findings_explained_html(context, store))

        if store and context.run_id:
            all_hosts_html = store.get_hosts(context.run_id, limit=500)
            tarpit_hosts = [h for h in all_hosts_html if h.tarpit_suspected]
            if tarpit_hosts:
                html_parts.append(
                    "  <h2>⚠ Tarpit/Portspoof Suspected</h2>"
                    "  <p class='muted'>Port scan results unreliable — these hosts respond "
                    "'open' to canary ports with no standard service association. "
                    "Individual open ports are not listed as findings for these hosts.</p>"
                    "  <ul>"
                )
                for h in tarpit_hosts:
                    ports = ", ".join(str(p) for p in h.tarpit_canary_ports)
                    html_parts.append(
                        f"    <li>{escape_html(h.domain)} "
                        f"<span class='muted'>(canary ports probed: {escape_html(ports)})</span></li>"
                    )
                html_parts.append("  </ul>")

            wildcard_roots = [
                h
                for h in all_hosts_html
                if any(f.template_id == "wildcard-dns-detected" for f in h.findings)
            ]
            if wildcard_roots:
                html_parts.append(
                    "  <h2>⚠ Wildcard DNS Detected</h2>"
                    "  <p class='muted'>These roots resolve improbable canary subdomains. "
                    "Passively enumerated children without independent confirmation have "
                    "demoted confidence.</p><ul>"
                )
                for h in wildcard_roots:
                    html_parts.append(f"    <li>{escape_html(h.domain)}</li>")
                html_parts.append("  </ul>")

            soft404_hosts = [h for h in all_hosts_html if h.soft_404_detected]
            if soft404_hosts:
                html_parts.append(
                    "  <h2>⚠ Soft-404 / Catch-All Detected</h2>"
                    "  <p class='muted'>These hosts return HTTP 200 for nonexistent paths "
                    "with a body matching the site root. Status-code existence is "
                    "unreliable.</p><ul>"
                )
                for h in soft404_hosts:
                    html_parts.append(f"    <li>{escape_html(h.domain)}</li>")
                html_parts.append("  </ul>")

        invalid_param_hosts = context.metadata.get("param_fuzz_baseline_invalid_hosts") or []
        if invalid_param_hosts:
            html_parts.append(
                "  <h2>⚠ Parameter Discovery Skipped (Baseline Blocked)</h2>"
                "  <p class='muted'>Parameter discovery skipped for these hosts — "
                "baseline request was blocked/rate-limited, results would be "
                "unreliable. This is not the same as probing successfully and "
                "finding zero influential parameters.</p><ul>"
            )
            for row in invalid_param_hosts:
                host = escape_html(str(row.get("host") or row.get("domain") or "?"))
                status = escape_html(str(row.get("baseline_status")))
                reason = escape_html(str(row.get("reason") or ""))
                html_parts.append(
                    f"    <li>{host} "
                    f"<span class='muted'>(baseline HTTP {status}: {reason})</span></li>"
                )
            html_parts.append("  </ul>")

        if summary.errors:
            html_parts.append('  <h2 class="error">Errors</h2><ul>')
            for err in summary.errors:
                html_parts.append(f'    <li class="error">{escape_html(err)}</li>')
            html_parts.append("  </ul>")

        if summary.warnings:
            html_parts.append("  <h2>Warnings</h2><ul>")
            for warn in summary.warnings:
                html_parts.append(f'    <li class="muted">{escape_html(warn)}</li>')
            html_parts.append("  </ul>")

        html_parts.extend(
            [
                "  <script type='text/javascript'>",
                "    function toggleTheme(){document.body.dataset.theme=document.body.dataset.theme==='dark'?'light':'dark'}",
                "    function filterRows(){",
                "      const q=document.getElementById('search').value.toLowerCase();",
                "      const risk=document.getElementById('riskFilter').value;",
                "      document.querySelectorAll('#assets tr[data-risk]').forEach(row=>{",
                "        const text=row.innerText.toLowerCase(); const r=row.dataset.risk;",
                "        const riskOk=!risk || r===risk || (risk==='medium' && ['critical','high','medium'].includes(r));",
                "        row.style.display=text.includes(q)&&riskOk?'':'none';",
                "      });",
                "    }",
                "  </script>",
                "</main>",
                "</body>",
                "</html>",
            ]
        )
        safe_write_text(
            context.output_dir / "summary.html",
            "\n".join(html_parts) + "\n",
            base_dir=context.output_dir,
        )

    def _executive_summary_html(
        self,
        context: PipelineContext,
        summary: RunSummary,
        store: AssetStore | None,
    ) -> list[str]:
        from collections import Counter

        from core.finding_glossary import explain_template

        hosts = store.get_hosts(context.run_id, limit=500) if store and context.run_id else []
        findings = [f for h in hosts for f in h.findings]
        by_sev = Counter(f.severity.lower() for f in findings)
        lines = [
            f"Se encontraron {len(hosts) or summary.alive_count} host(s) con datos en esta corrida. "
            f"{len(findings)} finding(s) "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, info={by_sev.get('info', 0)})."
        ]
        notable = next(
            (f for f in findings if f.severity.lower() in {"critical", "high"}),
            None,
        )
        if notable:
            lines.append(f"1 finding de alta severidad requiere atención: {notable.name}.")
        elif findings:
            sample = findings[0]
            expl = explain_template(sample.template_id)
            lines.append(expl["what"])
        else:
            lines.append(
                "No se registraron findings de seguridad más allá del inventario de superficie."
            )
        return [
            "  <section class='exec' id='executive-summary'>",
            "    <h2>Resumen ejecutivo</h2>",
            f"    <p>{escape_html(' '.join(lines))}</p>",
            "  </section>",
        ]

    def _findings_explained_html(
        self,
        context: PipelineContext,
        store: AssetStore | None,
    ) -> list[str]:
        from core.finding_glossary import explain_template

        if not store or not context.run_id:
            return []
        hosts = store.get_hosts(context.run_id, limit=500)
        findings = [(h, f) for h in hosts for f in h.findings]
        if not findings:
            return []
        parts = ["  <h2>Findings (explained)</h2>", "  <ul class='findings'>"]
        raw_index = self._raw_artifact_index(context.output_dir)
        for host, finding in findings[:80]:
            expl = explain_template(finding.template_id)
            parts.append("    <li>")
            parts.append(
                f"      <strong>{escape_html(finding.name)}</strong> "
                f"<span class='muted'>({escape_html(finding.severity)} · "
                f"{escape_html(host.domain)} · {escape_html(finding.template_id)})</span>"
            )
            parts.append(f"      <p>{escape_html(expl['what'])}</p>")
            parts.append(
                f"      <p class='muted'><em>Por qué importa:</em> {escape_html(expl['why'])}</p>"
            )
            if finding.description:
                parts.append(f"      <p class='muted'>{escape_html(finding.description[:400])}</p>")
            rel = raw_index.get(f"{host.domain}:{finding.template_id}") or raw_index.get(
                finding.template_id
            )
            if rel:
                body = self._read_relative_artifact(context.output_dir, rel)
                if body:
                    parts.append(
                        "      <details class='evidence'><summary>Evidencia cruda</summary>"
                    )
                    parts.append(f"        <pre>{escape_html(body[:4000])}</pre>")
                    parts.append("      </details>")
            parts.append("    </li>")
        parts.append("  </ul>")
        return parts

    def _raw_artifact_index(self, output_dir: Path) -> dict[str, str]:
        """Map template_id (and host+template) to relative raw_artifact paths."""
        from utils.files import read_jsonl

        index: dict[str, str] = {}
        mapping = (
            ("tarpit_check.jsonl", "tarpit-detected"),
            ("wildcard_check.jsonl", "wildcard-dns-detected"),
            ("soft404_check.jsonl", "soft-404-detected"),
            ("param_fuzz.jsonl", "param-reflected"),
            ("vuln_match.jsonl", "vuln-match"),
            ("security_headers.jsonl", "missing-security-header"),
            ("cloud_bucket_enum.jsonl", "cloud-bucket-public-listable"),
        )
        for filename, template_id in mapping:
            path = output_dir / filename
            if not path.exists():
                continue
            for record in read_jsonl(path):
                rel = record.get("raw_artifact")
                if not rel:
                    continue
                index[template_id] = str(rel)
                host = str(record.get("host") or record.get("root_domain") or "")
                if host:
                    index[f"{host}:{template_id}"] = str(rel)
        return index

    def _read_relative_artifact(self, output_dir: Path, relative: str) -> str:
        from utils.security import resolve_raw_artifact

        try:
            path = resolve_raw_artifact(output_dir, relative)
        except Exception:
            return ""
        if path is None or not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def collect_metadata(
        self,
        context: PipelineContext,
        store: AssetStore | None = None,
    ) -> dict[str, Any]:
        """Aggregate metadata from SQLite store when available."""
        metadata: dict[str, Any] = {
            "targets": [t.domain for t in context.targets],
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        status_codes: dict[str, int] = {}
        technologies: dict[str, int] = {}
        servers: dict[str, int] = {}

        if store and context.run_id:
            for h in store.get_hosts(context.run_id, limit=1000):
                for svc in h.http_services:
                    code = str(svc.status_code or "unknown")
                    status_codes[code] = status_codes.get(code, 0) + 1
                    for tech in svc.technologies:
                        technologies[tech.name] = technologies.get(tech.name, 0) + 1
                    if svc.webserver:
                        servers[svc.webserver] = servers.get(svc.webserver, 0) + 1
        else:
            for rec in context.httpx_results:
                code = str(rec.get("status_code", "unknown"))
                status_codes[code] = status_codes.get(code, 0) + 1
                tech_field = rec.get("tech", [])
                if isinstance(tech_field, list):
                    for tech in tech_field:
                        technologies[str(tech)] = technologies.get(str(tech), 0) + 1
                server = rec.get("webserver", "")
                if server:
                    servers[str(server)] = servers.get(str(server), 0) + 1

        metadata.update(
            {
                "status_codes": status_codes,
                "technologies": dict(sorted(technologies.items(), key=lambda x: -x[1])[:20]),
                "web_servers": dict(sorted(servers.items(), key=lambda x: -x[1])[:20]),
                **context.metadata,
            }
        )

        context.metadata = metadata
        write_json(context.output_dir / "metadata.json", metadata, base_dir=context.output_dir)
        return metadata

    def _intel_relationship_lines(self, store: AssetStore, run_id: str) -> list[str]:
        from core.intel.query import IntelQuery
        from core.intel.serialize import serialize_relationship

        conn = store.intel_connection()
        try:
            query = IntelQuery(conn, run_id)
            rows = query.relationships_for_run(limit=80)
        finally:
            conn.close()
        if not rows:
            return []
        lines = [
            "## Intelligence Relationships",
            "",
            "Discovery of an indicator does not imply authorization to probe it. "
            "Out-of-scope names may be observed; they are never active collection targets. "
            "Correlation is infrastructure evidence, not actor or owner attribution.",
            "",
        ]
        for row in rows[:40]:
            payload = serialize_relationship(row, run_id=run_id)
            lines.append(
                f"- `{payload.get('source_entity')}` — {payload.get('relationship_type')} → "
                f"`{payload.get('target_entity')}` ({payload.get('confidence_band')}, "
                f"{payload.get('strength')})"
            )
            if payload.get("explanation"):
                first = str(payload["explanation"]).splitlines()[0]
                if first:
                    lines.append(f"  {first}")
        lines.append("")
        return lines

    def _intel_correlation_html(
        self, context: PipelineContext, store: AssetStore | None
    ) -> list[str]:
        if not (store and context.run_id):
            return []
        getter = getattr(store, "intel_connection", None)
        if not callable(getter):
            return []
        from core.intel.query import IntelQuery
        from core.intel.serialize import serialize_relationship

        conn = store.intel_connection()
        try:
            query = IntelQuery(conn, context.run_id)
            rows = query.relationships_for_run(limit=80)
            entities = {
                row["entity_id"]: dict(row)
                for row in conn.execute(
                    "SELECT entity_id, key, entity_type, scope_status, collection_status "
                    "FROM intel_entities WHERE run_id=?",
                    (context.run_id,),
                ).fetchall()
            }
        finally:
            conn.close()
        parts = [
            "  <h2>Intelligence Correlation</h2>",
            "  <p class='muted'>Discovery of an indicator does not imply authorization "
            "to probe it. Observed names may be out of scope. Confidence bands match "
            "SQLite <code>intel_relationships</code> and the investigate CLI. "
            "Hydra correlates infrastructure; it is not an attribution engine.</p>",
        ]
        if not rows:
            return parts
        parts.append("  <ul>")
        for row in rows[:40]:
            payload = serialize_relationship(
                row,
                source_entity=entities.get(row.get("source_entity") or ""),
                target_entity=entities.get(row.get("target_entity") or ""),
                run_id=context.run_id,
            )
            rel_type = escape_html(str(payload.get("relationship_type") or ""))
            confidence = escape_html(str(payload.get("confidence_band") or ""))
            src_ent = entities.get(payload.get("source_entity") or "") or {}
            dst_ent = entities.get(payload.get("target_entity") or "") or {}
            src_label = escape_html(str(src_ent.get("key") or payload.get("source_entity") or ""))
            dst_label = escape_html(str(dst_ent.get("key") or payload.get("target_entity") or ""))
            src_scope = escape_html(str(src_ent.get("scope_status") or ""))
            dst_scope = escape_html(str(dst_ent.get("scope_status") or ""))
            src_coll = escape_html(str(src_ent.get("collection_status") or ""))
            dst_coll = escape_html(str(dst_ent.get("collection_status") or ""))
            evidence_bits: list[str] = []
            for key, value in (
                ("fingerprint", payload.get("certificate_fingerprint")),
                ("serial", payload.get("certificate_serial")),
                ("san_cardinality", payload.get("san_cardinality")),
                ("ip", payload.get("shared_ip")),
            ):
                if value not in (None, "", []):
                    evidence_bits.append(f"{key}={value}")
            evidence_html = escape_html("; ".join(str(bit) for bit in evidence_bits[:4]))
            evidence_suffix = (
                f'<br><span class="muted">{evidence_html}</span>' if evidence_html else ""
            )
            parts.append(
                "    <li>"
                f"<code>{src_label}</code> [{src_scope}/{src_coll}] "
                f"— <strong>{rel_type}</strong> [{confidence}] → "
                f"<code>{dst_label}</code> [{dst_scope}/{dst_coll}]"
                f"{evidence_suffix}"
                "</li>"
            )
        parts.append("  </ul>")
        return parts

    def _host_projection_clusters_html(
        self, context: PipelineContext, store: AssetStore | None
    ) -> list[str]:
        if not (store and context.run_id):
            return []
        getter = getattr(store, "get_clusters", None)
        if not callable(getter):
            return []
        clusters = getter(context.run_id)
        if not clusters:
            return []
        parts = [
            "  <h2>Host Projection Clusters</h2>",
            "  <p class='muted'>Host clusters are a reporting projection of collected "
            "HTTP/port/TLS fields. They are not the correlation source of truth and "
            "must not override intel confidence (shared cloud addresses are tenancy, "
            "not ownership).</p>",
            "  <ul>",
        ]
        for cluster in sorted(clusters, key=lambda c: -len(c.members))[:15]:
            parts.append(f"    <li>{escape_html(_format_cluster(cluster))}</li>")
        parts.append("  </ul>")
        return parts


def _format_cluster(cluster: Any) -> str:
    band = score_to_band(int(cluster.confidence))
    description = str(cluster.description or "")
    tenancy = ""
    if "shared_cloud_tenancy" in description or cluster.cluster_type in {"cdn", "ip"}:
        if "shared_cloud_tenancy" in description:
            tenancy = "; shared cloud tenancy, not ownership"
    return (
        f"{cluster.cluster_type}: {str(cluster.signal)[:60]} — "
        f"{len(cluster.members)} hosts ({band.value}, {cluster.confidence}%{tenancy})"
    )
