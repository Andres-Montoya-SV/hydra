"""Renders the SAME consolidated findings (docs/CLIENT_REPORT.md) into a
professional `.docx` document — the exact same intermediate data
`core.client_report.render.render_markdown` consumes, so neither
renderer computes or duplicates any content decision (methodology,
caveats, recommendations, dedup, categorization all happen once,
upstream, in `core.client_report.dedup`/`explain`). This module owns
visual presentation only: cover page, colored severity badges, and the
closing scope summary table.

`python-docx` is an optional dependency (requirements-optional.txt),
lazily imported here so importing this module — or any other module in
this package — never requires it unless `--format docx` is actually
used.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from core.client_report.model import FindingCategory

if TYPE_CHECKING:
    from core.client_report.collect import RunReportData
    from core.client_report.model import ConsolidatedFinding


class DocxRenderError(Exception):
    """Raised when python-docx is not installed, or rendering otherwise
    fails — the CLI layer catches this one type instead of importing
    python-docx's own exception hierarchy."""


# (fill color, is_dark_fill) — dark fills get white text for contrast,
# light fills (low/unknown) get black text.
_SEVERITY_STYLE: dict[str, tuple[str, bool]] = {
    "critical": ("C00000", True),
    "high": ("E81123", True),
    "medium": ("ED7D31", True),
    "low": ("FFC000", False),
    "info": ("8497B0", True),
}
_DEFAULT_SEVERITY_STYLE = ("A6A6A6", True)

_SEVERITY_LABEL_ES: dict[str, str] = {
    "critical": "CRÍTICA",
    "high": "ALTA",
    "medium": "MEDIA",
    "low": "BAJA",
    "info": "INFORMATIVA",
}

_CATEGORY_HEADING = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: "Vulnerabilidades confirmadas",
    FindingCategory.INDICIO: "Indicios",
    FindingCategory.AREA_MEJORA: "Áreas de mejora",
}
_CATEGORY_INTRO = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: (
        "Evidencia real de impacto — se recomienda atender estos puntos con prioridad."
    ),
    FindingCategory.INDICIO: (
        "Detectados sin evidencia concluyente de explotabilidad — requieren revisión "
        "manual antes de considerarse un problema confirmado."
    ),
    FindingCategory.AREA_MEJORA: (
        "Recomendaciones de endurecimiento — no son vulnerabilidades por sí solas."
    ),
}
_CATEGORY_EMPTY = {
    FindingCategory.VULNERABILIDAD_CONFIRMADA: (
        "No se confirmó ninguna vulnerabilidad con evidencia concluyente de impacto."
    ),
    FindingCategory.INDICIO: "No se registraron indicios adicionales en esta corrida.",
    FindingCategory.AREA_MEJORA: "No se identificaron áreas de mejora adicionales en esta corrida.",
}

_WHAT_THIS_DOES_NOT_COVER = [
    "No se realizaron pruebas de intrusión activa ni se explotó ninguna condición "
    "para confirmar impacto más allá de lo descrito en cada hallazgo.",
    "No se probó con credenciales — todo lo aquí descrito es visible desde fuera, "
    "sin haber iniciado sesión.",
    "No se realizó ingeniería social ni pruebas de phishing.",
    "Los indicios (a diferencia de las vulnerabilidades confirmadas) se probaron "
    "únicamente con valores de texto plano, nunca con payloads de inyección reales "
    "— una prueba más profunda podría confirmar o descartar cada uno.",
    "Este análisis refleja el estado del sitio en el momento de la corrida; un "
    "cambio posterior en el sitio no queda reflejado aquí.",
    "La cobertura de vulnerabilidades públicas depende de que el componente y su "
    "versión estén correctamente identificados y catalogados en las fuentes "
    "consultadas — un componente sin coincidencias no implica que esté libre de "
    "vulnerabilidades, solo que ninguna coincidencia pública fue encontrada con la "
    "información disponible.",
]


def render_docx(data: RunReportData, consolidated: list[ConsolidatedFinding]) -> bytes:
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
    _add_cover_page(document, data, WD_ALIGN_PARAGRAPH, Pt, RGBColor)
    document.add_page_break()
    _add_executive_summary(document, data, consolidated)

    vulns = [f for f in consolidated if f.category is FindingCategory.VULNERABILIDAD_CONFIRMADA]
    indicios = [f for f in consolidated if f.category is FindingCategory.INDICIO]
    mejoras = [f for f in consolidated if f.category is FindingCategory.AREA_MEJORA]
    for category, items in (
        (FindingCategory.VULNERABILIDAD_CONFIRMADA, vulns),
        (FindingCategory.INDICIO, indicios),
        (FindingCategory.AREA_MEJORA, mejoras),
    ):
        document.add_heading(_CATEGORY_HEADING[category], level=1)
        if items:
            document.add_paragraph(_CATEGORY_INTRO[category])
            for item in items:
                _add_finding(document, item, WD_ALIGN_PARAGRAPH, Pt, RGBColor)
        else:
            document.add_paragraph(_CATEGORY_EMPTY[category])

    _add_limitations(document, data)
    _add_not_covered(document)
    _add_scope_summary_table(document, data, vulns, indicios, mejoras)

    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def _add_cover_page(document, data: RunReportData, align, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    target = ", ".join(data.targets) if data.targets else data.run_id

    title = document.add_paragraph()
    title.alignment = align.CENTER
    title.paragraph_format.space_before = pt(120)
    run = title.add_run("Informe de Seguridad")
    run.bold = True
    run.font.size = pt(28)

    subtitle = document.add_paragraph()
    subtitle.alignment = align.CENTER
    subtitle.paragraph_format.space_before = pt(24)
    run = subtitle.add_run(target)
    run.font.size = pt(18)
    run.font.color.rgb = rgb(0x40, 0x40, 0x40)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    duration = _format_duration(data.duration_seconds)
    meta = document.add_paragraph()
    meta.alignment = align.CENTER
    meta.paragraph_format.space_before = pt(48)
    meta_run = meta.add_run(f"Fecha del informe: {generated}\nDuración de la corrida: {duration}")
    meta_run.font.size = pt(12)
    meta_run.font.color.rgb = rgb(0x60, 0x60, 0x60)

    disclaimer = document.add_paragraph()
    disclaimer.alignment = align.CENTER
    disclaimer.paragraph_format.space_before = pt(200)
    disc_run = disclaimer.add_run(
        "BORRADOR — para revisión interna antes de compartirse con el cliente."
    )
    disc_run.italic = True
    disc_run.font.size = pt(10)
    disc_run.font.color.rgb = rgb(0x90, 0x00, 0x00)


def _format_duration(duration_seconds: float | None) -> str:
    if duration_seconds is None:
        return "no disponible"
    minutes = duration_seconds / 60
    return f"{minutes:.1f} minutos ({duration_seconds:.0f} segundos)"


def _add_executive_summary(document, data: RunReportData, consolidated: list) -> None:  # type: ignore[no-untyped-def]
    document.add_heading("Resumen ejecutivo", level=1)
    vulns = sum(1 for f in consolidated if f.category is FindingCategory.VULNERABILIDAD_CONFIRMADA)
    indicios = sum(1 for f in consolidated if f.category is FindingCategory.INDICIO)
    mejoras = sum(1 for f in consolidated if f.category is FindingCategory.AREA_MEJORA)
    document.add_paragraph(f"Vulnerabilidades confirmadas: {vulns}", style="List Bullet")
    document.add_paragraph(f"Indicios a revisar: {indicios}", style="List Bullet")
    document.add_paragraph(f"Áreas de mejora recomendadas: {mejoras}", style="List Bullet")


def _add_finding(document, item: ConsolidatedFinding, align, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    document.add_heading(item.title, level=2)
    _add_severity_badge(document, item.severity, pt, rgb)

    p = document.add_paragraph()
    p.add_run("Qué significa: ").bold = True
    p.add_run(item.explanation)

    p = document.add_paragraph()
    p.add_run("Cómo se encontró: ").bold = True
    p.add_run(item.methodology)

    document.add_paragraph(f"Ubicación: {item.host}", style="List Bullet")
    if item.affected_urls:
        urls = ", ".join(item.affected_urls[:5])
        document.add_paragraph(f"Página(s) afectada(s): {urls}", style="List Bullet")

    if item.caveat:
        p = document.add_paragraph()
        run = p.add_run(f"Limitación de esta prueba: {item.caveat}")
        run.italic = True

    p = document.add_paragraph()
    p.add_run("Recomendación: ").bold = True
    p.add_run(item.recommendation)


def _add_severity_badge(document, severity: str, pt, rgb) -> None:  # type: ignore[no-untyped-def]
    """A colored 1x1 table cell right under the finding's heading — a
    real visual indicator, not just a text label (docs/CLIENT_REPORT.md
    Task 4: 'indicadores de severidad visuales, no solo texto')."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    fill_hex, dark = _SEVERITY_STYLE.get(severity.strip().lower(), _DEFAULT_SEVERITY_STYLE)
    label = _SEVERITY_LABEL_ES.get(severity.strip().lower(), severity.upper())

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
    run = p.add_run(f"SEVERIDAD: {label}")
    run.bold = True
    run.font.size = pt(9)
    run.font.color.rgb = rgb(0xFF, 0xFF, 0xFF) if dark else rgb(0x00, 0x00, 0x00)


def _add_limitations(document, data: RunReportData) -> None:  # type: ignore[no-untyped-def]
    document.add_heading("Limitaciones conocidas de esta corrida", level=1)
    notes: list[str] = []

    for item in data.vuln_check_failed:
        tech = item.get("technology", "?")
        version = item.get("version", "?")
        source = item.get("source", "?")
        reason = item.get("reason", "razón no especificada")
        notes.append(
            f"No se pudo verificar {tech} {version} contra la fuente de "
            f"vulnerabilidades correspondiente ({source}: {reason}). Esta tecnología "
            "fue detectada pero su estado de vulnerabilidad permanece sin confirmar "
            "— no debe interpretarse como libre de vulnerabilidades."
        )

    if data.wildcard_dns_detected:
        roots = ", ".join(data.wildcard_dns_roots) or "el dominio analizado"
        notes.append(
            f"Se detectó configuración DNS comodín en {roots} — algunos subdominios "
            "listados en fuentes pasivas podrían no corresponder a servicios reales."
        )

    if data.soft_404_hosts:
        hosts = ", ".join(data.soft_404_hosts)
        notes.append(
            f"{hosts} responde con éxito (HTTP 200) incluso para rutas inexistentes "
            "— la existencia de una URL específica no puede confirmarse únicamente "
            "por su código de respuesta en este sitio."
        )

    if data.param_fuzz_baseline_invalid_hosts:
        hosts = ", ".join(
            sorted({str(h.get("host")) for h in data.param_fuzz_baseline_invalid_hosts})
        )
        notes.append(
            f"La revisión de parámetros no pudo completarse de forma confiable en "
            f"{hosts} — la solicitud de referencia fue bloqueada o limitada por el "
            "propio sitio. Esto no equivale a 'sin hallazgos', sino a que la prueba "
            "no pudo ejecutarse con confianza."
        )

    if not notes:
        document.add_paragraph(
            "No se identificaron limitaciones específicas más allá de las generales."
        )
    else:
        for note in notes:
            document.add_paragraph(note, style="List Bullet")


def _add_not_covered(document) -> None:  # type: ignore[no-untyped-def]
    document.add_heading("Qué NO cubre este análisis", level=1)
    for line in _WHAT_THIS_DOES_NOT_COVER:
        document.add_paragraph(line, style="List Bullet")


def _add_scope_summary_table(
    document,  # type: ignore[no-untyped-def]
    data: RunReportData,
    vulns: list,
    indicios: list,
    mejoras: list,
) -> None:
    document.add_heading("Resumen de alcance", level=1)
    table = document.add_table(rows=2, cols=5)
    table.style = "Table Grid"
    headers = [
        "Objetivo(s)",
        "Duración",
        "Vulnerabilidades confirmadas",
        "Indicios",
        "Áreas de mejora",
    ]
    for idx, text in enumerate(headers):
        cell = table.cell(0, idx)
        cell.text = text
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = True
    values = [
        ", ".join(data.targets) if data.targets else data.run_id,
        _format_duration(data.duration_seconds),
        str(len(vulns)),
        str(len(indicios)),
        str(len(mejoras)),
    ]
    for idx, text in enumerate(values):
        table.cell(1, idx).text = text
