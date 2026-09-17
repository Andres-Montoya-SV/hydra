"""Renders the consolidated findings into the client-facing Markdown
document (docs/CLIENT_REPORT.md). Markdown, not .docx — see that doc for
the reasoning; the short version is that the operator reviews and edits
this before sending, and Markdown is the easiest format to review, diff,
and convert (a single `pandoc report.md -o report.docx`, or a direct
paste into Google Docs) without adding a new binary-document dependency
to the project.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.client_report.collect import RunReportData
from core.client_report.model import ConsolidatedFinding, FindingCategory

_WHAT_THIS_DOES_NOT_COVER = """\
## Qué NO cubre este análisis

- No se realizaron pruebas de intrusión activa ni se explotó ninguna \
condición para confirmar impacto más allá de lo descrito en cada hallazgo.
- No se probó con credenciales — todo lo aquí descrito es visible desde \
fuera, sin haber iniciado sesión.
- No se realizó ingeniería social ni pruebas de phishing.
- Los indicios (a diferencia de las vulnerabilidades confirmadas) se \
probaron únicamente con valores de texto plano, nunca con payloads de \
inyección reales — una prueba más profunda podría confirmar o descartar \
cada uno.
- Este análisis refleja el estado del sitio en el momento de la corrida; \
un cambio posterior en el sitio no queda reflejado aquí.
- La cobertura de vulnerabilidades públicas depende de que el componente \
y su versión estén correctamente identificados y catalogados en las \
fuentes consultadas — un componente sin coincidencias no implica que \
esté libre de vulnerabilidades, solo que ninguna coincidencia pública \
fue encontrada con la información disponible.
"""


def render_markdown(data: RunReportData, consolidated: list[ConsolidatedFinding]) -> str:
    lines: list[str] = []
    target = ", ".join(data.targets) if data.targets else data.run_id
    lines.append(f"# Informe de seguridad — {target}")
    lines.append("")
    lines.append(_summary_line(data))
    lines.append("")

    vulns = [f for f in consolidated if f.category is FindingCategory.VULNERABILIDAD_CONFIRMADA]
    indicios = [f for f in consolidated if f.category is FindingCategory.INDICIO]
    mejoras = [f for f in consolidated if f.category is FindingCategory.AREA_MEJORA]

    lines.append("## Resumen ejecutivo")
    lines.append("")
    lines.append(
        f"- **Vulnerabilidades confirmadas:** {len(vulns)}\n"
        f"- **Indicios a revisar:** {len(indicios)}\n"
        f"- **Áreas de mejora recomendadas:** {len(mejoras)}"
    )
    lines.append("")

    lines.append("## Vulnerabilidades confirmadas")
    lines.append("")
    if vulns:
        lines.append(
            "Evidencia real de impacto — se recomienda atender estos puntos con prioridad."
        )
        lines.append("")
        for item in vulns:
            lines.extend(_render_item(item))
    else:
        lines.append("No se confirmó ninguna vulnerabilidad con evidencia concluyente de impacto.")
        lines.append("")

    lines.append("## Indicios")
    lines.append("")
    if indicios:
        lines.append(
            "Detectados sin evidencia concluyente de explotabilidad — requieren revisión "
            "manual antes de considerarse un problema confirmado."
        )
        lines.append("")
        for item in indicios:
            lines.extend(_render_item(item))
    else:
        lines.append("No se registraron indicios adicionales en esta corrida.")
        lines.append("")

    lines.append("## Áreas de mejora")
    lines.append("")
    if mejoras:
        lines.append("Recomendaciones de endurecimiento — no son vulnerabilidades por sí solas.")
        lines.append("")
        for item in mejoras:
            lines.extend(_render_item(item))
    else:
        lines.append("No se identificaron áreas de mejora adicionales en esta corrida.")
        lines.append("")

    lines.extend(_render_limitations(data))
    lines.append(_WHAT_THIS_DOES_NOT_COVER)

    return "\n".join(lines).rstrip() + "\n"


def _summary_line(data: RunReportData) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if data.duration_seconds is not None:
        minutes = data.duration_seconds / 60
        duration = f"{minutes:.1f} minutos ({data.duration_seconds:.0f} segundos)"
    else:
        duration = "no disponible"
    return f"*Generado: {generated} · Duración de la corrida: {duration}*"


def _render_item(item: ConsolidatedFinding) -> list[str]:
    lines = [f"### {item.title}", ""]
    lines.append(item.explanation)
    lines.append("")
    lines.append(f"- **Ubicación:** {item.host}")
    if item.affected_urls:
        urls = ", ".join(item.affected_urls[:5])
        lines.append(f"- **Página(s) afectada(s):** {urls}")
    lines.append(f"- **Severidad reportada:** {item.severity}")
    lines.append("")
    return lines


def _render_limitations(data: RunReportData) -> list[str]:
    lines = ["## Limitaciones conocidas de esta corrida", ""]
    notes: list[str] = []

    for item in data.vuln_check_failed:
        tech = item.get("technology", "?")
        version = item.get("version", "?")
        source = item.get("source", "?")
        reason = item.get("reason", "razón no especificada")
        notes.append(
            f"No se pudo verificar **{tech} {version}** contra la fuente de "
            f"vulnerabilidades correspondiente ({source}: {reason}). Esta tecnología "
            "fue detectada pero su estado de vulnerabilidad permanece **sin confirmar** "
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
            f"{hosts} responde con éxito (HTTP 200) incluso para rutas inexistentes — "
            "la existencia de una URL específica no puede confirmarse únicamente por "
            "su código de respuesta en este sitio."
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
        lines.append("No se identificaron limitaciones específicas más allá de las generales.")
    else:
        lines.extend(f"- {note}" for note in notes)
    lines.append("")
    return lines
