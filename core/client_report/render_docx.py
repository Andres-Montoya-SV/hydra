"""Renders the SAME consolidated findings (docs/CLIENT_REPORT.md) into a
professional `.docx` document — the exact same intermediate data
`core.client_report.render.render_markdown` consumes, so neither
renderer computes or duplicates any content decision (methodology,
caveats, recommendations, dedup, categorization all happen once,
upstream, in `core.client_report.dedup`/`explain`). This module owns
visual presentation only: cover page, colored severity badges, and the
closing scope summary table.

All fixed wording comes from `core.client_report.i18n`, same as
`render.py` — never a literal sentence embedded here in any language.

`python-docx` is an optional dependency (requirements-optional.txt),
lazily imported here so importing this module — or any other module in
this package — never requires it unless `--format docx` is actually
used.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from core.client_report.i18n import (
    DEFAULT_LANGUAGE,
    docx_scope_headers,
    docx_severity_label,
    not_covered_items,
    t,
)
from core.client_report.model import FindingCategory

if TYPE_CHECKING:
    from core.client_report.collect import RunReportData
    from core.client_report.model import ConsolidatedFinding


class DocxRenderError(Exception):
    """Raised when python-docx is not installed, or rendering otherwise
    fails — the CLI layer catches this one type instead of importing
    python-docx's own exception hierarchy."""


# (fill color, is_dark_fill) — dark fills get white text for contrast,
# light fills (low/unknown) get black text. Colors are not translatable
# content, so this stays outside core.client_report.i18n.
_SEVERITY_STYLE: dict[str, tuple[str, bool]] = {
    "critical": ("C00000", True),
    "high": ("E81123", True),
    "medium": ("ED7D31", True),
    "low": ("FFC000", False),
    "info": ("8497B0", True),
}
_DEFAULT_SEVERITY_STYLE = ("A6A6A6", True)

_CATEGORY_HEADING_KEY = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: "vulns_heading",
    FindingCategory.INDICIO: "indicios_heading",
    FindingCategory.AREA_MEJORA: "mejoras_heading",
}
_CATEGORY_INTRO_KEY = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: "vulns_intro",
    FindingCategory.INDICIO: "indicios_intro",
    FindingCategory.AREA_MEJORA: "mejoras_intro",
}
_CATEGORY_EMPTY_KEY = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: "vulns_empty",
    FindingCategory.INDICIO: "indicios_empty",
    FindingCategory.AREA_MEJORA: "mejoras_empty",
}


def render_docx(
    data: RunReportData,
    consolidated: list[ConsolidatedFinding],
    language: str = DEFAULT_LANGUAGE,
) -> bytes:
    """Returns the finished .docx file as bytes — the caller decides
    where (or whether) to write it to disk."""
    try:
        import docx
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt, RGBColor
    except ImportError as exc:
        raise DocxRenderError(
            "python-docx is not installed. It is an optional dependency — install "
            "it with: pip install -r requirements-optional.txt"
        ) from exc

    document = docx.Document()
    _add_cover_page(document, data, language, WD_ALIGN_PARAGRAPH, Pt, RGBColor)
    document.add_page_break()

    vulns = [f for f in consolidated if f.category is FindingCategory.VULNERABILIDAD_CONFIRMADA]
    indicios = [f for f in consolidated if f.category is FindingCategory.INDICIO]
    mejoras = [f for f in consolidated if f.category is FindingCategory.AREA_MEJORA]

    _add_tldr(document, vulns, indicios, language)
    _add_executive_summary(document, vulns, indicios, mejoras, language)

    for category, items in (
        (FindingCategory.VULNERABILIDAD_CONFIRMADA, vulns),
        (FindingCategory.INDICIO, indicios),
        (FindingCategory.AREA_MEJORA, mejoras),
    ):
        document.add_heading(t(language, _CATEGORY_HEADING_KEY[category]), level=1)
        if items:
            document.add_paragraph(t(language, _CATEGORY_INTRO_KEY[category]))
            for item in items:
                _add_finding(document, item, language, WD_ALIGN_PARAGRAPH, Pt, RGBColor)
        else:
            document.add_paragraph(t(language, _CATEGORY_EMPTY_KEY[category]))

    _add_limitations(document, data, language)
    _add_not_covered(document, language)
    _add_scope_summary_table(document, data, vulns, indicios, mejoras, language)

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def _add_cover_page(document, data: RunReportData, language: str, align, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    target = ", ".join(data.targets) if data.targets else data.run_id

    title = document.add_paragraph()
    title.alignment = align.CENTER
    title.paragraph_format.space_before = pt(120)
    run = title.add_run(t(language, "docx_cover_title"))
    run.bold = True
    run.font.size = pt(28)

    subtitle = document.add_paragraph()
    subtitle.alignment = align.CENTER
    subtitle.paragraph_format.space_before = pt(24)
    run = subtitle.add_run(target)
    run.font.size = pt(18)
    run.font.color.rgb = rgb(0x40, 0x40, 0x40)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    duration = _format_duration(data.duration_seconds, language)
    meta = document.add_paragraph()
    meta.alignment = align.CENTER
    meta.paragraph_format.space_before = pt(48)
    meta_run = meta.add_run(
        t(language, "docx_report_date_label", date=generated)
        + "\n"
        + t(language, "docx_run_duration_label", duration=duration)
    )
    meta_run.font.size = pt(12)
    meta_run.font.color.rgb = rgb(0x60, 0x60, 0x60)

    disclaimer = document.add_paragraph()
    disclaimer.alignment = align.CENTER
    disclaimer.paragraph_format.space_before = pt(200)
    disc_run = disclaimer.add_run(t(language, "docx_draft_disclaimer"))
    disc_run.italic = True
    disc_run.font.size = pt(10)
    disc_run.font.color.rgb = rgb(0x90, 0x00, 0x00)


def _format_duration(duration_seconds: float | None, language: str) -> str:
    if duration_seconds is None:
        return t(language, "duration_unknown")
    minutes = duration_seconds / 60
    return t(language, "duration_known", minutes=minutes, seconds=duration_seconds)


def _add_tldr(
    document,  # type: ignore[no-untyped-def]
    vulns: list,
    indicios: list,
    language: str,
) -> None:
    """Task 2: same "Lo que necesitas saber" content as the Markdown
    renderer's `_render_tldr`, as its own page-one section — readable on
    its own, before the executive summary."""
    document.add_heading(t(language, "tldr_heading"), level=1)
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
    document.add_paragraph(" ".join(body))


def _add_executive_summary(
    document,  # type: ignore[no-untyped-def]
    vulns: list,
    indicios: list,
    mejoras: list,
    language: str,
) -> None:
    document.add_heading(t(language, "executive_summary_heading"), level=1)
    document.add_paragraph(
        f"{t(language, 'confirmed_vulns_label')}: {len(vulns)}", style="List Bullet"
    )
    document.add_paragraph(
        f"{t(language, 'indicios_to_review_label')}: {len(indicios)}", style="List Bullet"
    )
    document.add_paragraph(
        f"{t(language, 'mejoras_recommended_label')}: {len(mejoras)}", style="List Bullet"
    )


def _add_finding(document, item: ConsolidatedFinding, language: str, align, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    document.add_heading(item.title, level=2)
    _add_severity_badge(document, item.severity, language, pt, rgb)

    p = document.add_paragraph()
    p.add_run(f"{t(language, 'what_it_means_label')}: ").bold = True
    p.add_run(item.explanation)

    p = document.add_paragraph()
    p.add_run(f"{t(language, 'how_found_label')}: ").bold = True
    p.add_run(item.methodology)

    document.add_paragraph(f"{t(language, 'location_label')}: {item.host}", style="List Bullet")
    if item.affected_urls:
        urls = ", ".join(item.affected_urls[:5])
        document.add_paragraph(
            f"{t(language, 'affected_pages_label')}: {urls}", style="List Bullet"
        )

    if item.caveat:
        p = document.add_paragraph()
        run = p.add_run(f"{t(language, 'test_limitation_label')}: {item.caveat}")
        run.italic = True

    p = document.add_paragraph()
    p.add_run(f"{t(language, 'recommendation_label')}: ").bold = True
    p.add_run(item.recommendation)


def _add_severity_badge(document, severity: str, language: str, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    """A colored 1x1 table cell right under the finding's heading — a
    real visual indicator, not just a text label (docs/CLIENT_REPORT.md
    Task 4: 'indicadores de severidad visuales, no solo texto')."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    fill_hex, dark = _SEVERITY_STYLE.get(severity.strip().lower(), _DEFAULT_SEVERITY_STYLE)
    label = docx_severity_label(language, severity)

    table = document.add_table(rows=1, cols=1)
    table.autofit = False
    cell = table.cell(0, 0)
    cell.width = pt(90)
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill_hex)
    tc_pr.append(shd)

    cell.text = ""
    p = cell.paragraphs[0]
    run = p.add_run(t(language, "docx_severity_prefix", label=label))
    run.bold = True
    run.font.size = pt(9)
    run.font.color.rgb = rgb(0xFF, 0xFF, 0xFF) if dark else rgb(0x00, 0x00, 0x00)


def _add_limitations(document, data: RunReportData, language: str) -> None:  # type: ignore[no-untyped-def]
    document.add_heading(t(language, "known_limitations_heading"), level=1)
    notes: list[str] = []

    for item in data.vuln_check_failed:
        tech = item.get("technology", "?")
        version = item.get("version", "?")
        source = item.get("source", "?")
        reason = item.get("reason", t(language, "reason_unspecified"))
        # Shares its wording with render.py's Markdown version of this
        # same note (core.client_report.i18n) rather than duplicating the
        # sentence — that template has **bold** markers for Markdown; a
        # docx paragraph has no markdown syntax, so strip the literal
        # asterisks rather than storing a second, separate plain-text copy.
        notes.append(
            t(
                language,
                "limitation_vuln_check_failed",
                tech=tech,
                version=version,
                source=source,
                reason=reason,
            ).replace("**", "")
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
        document.add_paragraph(t(language, "no_specific_limitations"))
    else:
        for note in notes:
            document.add_paragraph(note, style="List Bullet")


def _add_not_covered(document, language: str) -> None:  # type: ignore[no-untyped-def]
    document.add_heading(t(language, "not_covered_heading"), level=1)
    for line in not_covered_items(language):
        document.add_paragraph(line, style="List Bullet")


def _add_scope_summary_table(
    document,  # type: ignore[no-untyped-def]
    data: RunReportData,
    vulns: list,
    indicios: list,
    mejoras: list,
    language: str,
) -> None:
    document.add_heading(t(language, "docx_scope_heading"), level=1)
    table = document.add_table(rows=2, cols=5)
    table.style = "Table Grid"
    headers = docx_scope_headers(language)
    for idx, text in enumerate(headers):
        cell = table.cell(0, idx)
        cell.text = text
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
    values = [
        ", ".join(data.targets) if data.targets else data.run_id,
        _format_duration(data.duration_seconds, language),
        str(len(vulns)),
        str(len(indicios)),
        str(len(mejoras)),
    ]
    for idx, text in enumerate(values):
        table.cell(1, idx).text = text
