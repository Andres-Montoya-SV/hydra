"""Renders the consolidated findings into the client-facing Markdown
document (docs/CLIENT_REPORT.md). Markdown, not .docx — see that doc for
the reasoning; the short version is that the operator reviews and edits
this before sending, and Markdown is the easiest format to review, diff,
and convert (a single `pandoc report.md -o report.docx`, or a direct
paste into Google Docs) without adding a new binary-document dependency
to the project.

All fixed wording comes from `core.client_report.i18n` — this module only
decides document STRUCTURE (section order, what's a heading vs a bullet)
and never embeds a literal sentence in any language itself.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.client_report.collect import RunReportData
from core.client_report.i18n import DEFAULT_LANGUAGE, not_covered_items, t
from core.client_report.model import ConsolidatedFinding, FindingCategory


def render_markdown(
    data: RunReportData,
    consolidated: list[ConsolidatedFinding],
    language: str = DEFAULT_LANGUAGE,
) -> str:
    lines: list[str] = []
    target = ", ".join(data.targets) if data.targets else data.run_id
    lines.append(t(language, "report_title", target=target))
    lines.append("")
    lines.append(_summary_line(data, language))
    lines.append("")

    vulns = [f for f in consolidated if f.category is FindingCategory.VULNERABILIDAD_CONFIRMADA]
    indicios = [f for f in consolidated if f.category is FindingCategory.INDICIO]
    mejoras = [f for f in consolidated if f.category is FindingCategory.AREA_MEJORA]

    lines.extend(_render_tldr(vulns, indicios, language))

    lines.append(f"## {t(language, 'executive_summary_heading')}")
    lines.append("")
    lines.append(
        f"- **{t(language, 'confirmed_vulns_label')}:** {len(vulns)}\n"
        f"- **{t(language, 'indicios_to_review_label')}:** {len(indicios)}\n"
        f"- **{t(language, 'mejoras_recommended_label')}:** {len(mejoras)}"
    )
    lines.append("")

    lines.append(f"## {t(language, 'vulns_heading')}")
    lines.append("")
    if vulns:
        lines.append(t(language, "vulns_intro"))
        lines.append("")
        for item in vulns:
            lines.extend(_render_item(item, language))
    else:
        lines.append(t(language, "vulns_empty"))
        lines.append("")

    lines.append(f"## {t(language, 'indicios_heading')}")
    lines.append("")
    if indicios:
        lines.append(t(language, "indicios_intro"))
        lines.append("")
        for item in indicios:
            lines.extend(_render_item(item, language))
    else:
        lines.append(t(language, "indicios_empty"))
        lines.append("")

    lines.append(f"## {t(language, 'mejoras_heading')}")
    lines.append("")
    if mejoras:
        lines.append(t(language, "mejoras_intro"))
        lines.append("")
        for item in mejoras:
            lines.extend(_render_item(item, language))
    else:
        lines.append(t(language, "mejoras_empty"))
        lines.append("")

    lines.extend(_render_limitations(data, language))
    lines.append(_render_not_covered(language))

    return "\n".join(lines).rstrip() + "\n"


def _render_tldr(
    vulns: list[ConsolidatedFinding], indicios: list[ConsolidatedFinding], language: str
) -> list[str]:
    """Task 2: "Lo que necesitas saber" / "What You Need to Know" — the
    first section after the title, readable entirely on its own. Always
    exactly 3-5 lines: a vulns line, an optional indicios line, the
    always-present scope-limit line, and a closing pointer to the rest of
    the document."""
    lines = [f"## {t(language, 'tldr_heading')}", ""]
    body: list[str] = []

    vuln_count = len(vulns)
    if vuln_count == 0:
        body.append(t(language, "tldr_zero_vulns"))
    else:
        key = "tldr_vulns_singular" if vuln_count == 1 else "tldr_vulns_plural"
        body.append(t(language, key, count=vuln_count))

    indicio_count = len(indicios)
    if indicio_count > 0:
        key = "tldr_indicios_singular" if indicio_count == 1 else "tldr_indicios_plural"
        body.append(t(language, key, count=indicio_count))

    body.append(t(language, "tldr_scope_line"))
    body.append(t(language, "tldr_closing_line"))

    lines.append(" ".join(body))
    lines.append("")
    return lines


def _summary_line(data: RunReportData, language: str) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if data.duration_seconds is not None:
        minutes = data.duration_seconds / 60
        duration = t(language, "duration_known", minutes=minutes, seconds=data.duration_seconds)
    else:
        duration = t(language, "duration_unknown")
    return t(language, "generated_line", date=generated, duration=duration)


def _render_item(item: ConsolidatedFinding, language: str) -> list[str]:
    # Every finding gets the exact same structure — qué se encontró, cómo
    # se encontró, ubicación, limitación específica de la prueba (si
    # aplica), y una recomendación calibrada por severidad — regardless
    # of category or severity (docs/CLIENT_REPORT.md: uniform depth;
    # severity changes tone/urgency, never how much is explained).
    lines = [f"### {item.title}", ""]
    lines.append(f"**{t(language, 'what_it_means_label')}:** {item.explanation}")
    lines.append("")
    lines.append(f"**{t(language, 'how_found_label')}:** {item.methodology}")
    lines.append("")
    lines.append(f"- **{t(language, 'location_label')}:** {item.host}")
    if item.affected_urls:
        urls = ", ".join(item.affected_urls[:5])
        lines.append(f"- **{t(language, 'affected_pages_label')}:** {urls}")
    lines.append(f"- **{t(language, 'severity_label')}:** {item.severity}")
    lines.append("")
    if item.caveat:
        lines.append(f"*{t(language, 'test_limitation_label')}: {item.caveat}*")
        lines.append("")
    lines.append(f"**{t(language, 'recommendation_label')}:** {item.recommendation}")
    lines.append("")
    return lines


def _render_limitations(data: RunReportData, language: str) -> list[str]:
    lines = [f"## {t(language, 'known_limitations_heading')}", ""]
    notes: list[str] = []

    for item in data.vuln_check_failed:
        tech = item.get("technology", "?")
        version = item.get("version", "?")
        source = item.get("source", "?")
        reason = item.get("reason", t(language, "reason_unspecified"))
        notes.append(
            t(
                language,
                "limitation_vuln_check_failed",
                tech=tech,
                version=version,
                source=source,
                reason=reason,
            )
        )

    if data.wildcard_dns_detected:
        roots = ", ".join(data.wildcard_dns_roots) or t(language, "default_wildcard_roots")
        notes.append(t(language, "limitation_wildcard_dns", roots=roots))

    if data.soft_404_hosts:
        hosts = ", ".join(data.soft_404_hosts)
        notes.append(t(language, "limitation_soft_404", hosts=hosts))

    if data.param_fuzz_baseline_invalid_hosts:
        hosts = ", ".join(
            sorted({str(h.get("host")) for h in data.param_fuzz_baseline_invalid_hosts})
        )
        notes.append(t(language, "limitation_param_fuzz_baseline", hosts=hosts))

    if not notes:
        lines.append(t(language, "no_specific_limitations"))
    else:
        lines.extend(f"- {note}" for note in notes)
    lines.append("")
    return lines


def _render_not_covered(language: str) -> str:
    heading = f"## {t(language, 'not_covered_heading')}"
    items = "\n".join(f"- {item}" for item in not_covered_items(language))
    return f"{heading}\n\n{items}\n"
