"""Plain-Spanish, tool-name-free explanations for the client report
(docs/CLIENT_REPORT.md requirement 1: never mention a tool/binary name;
requirement 4: every finding explains what it means and why it matters,
in plain language). Deliberately separate from `core.finding_glossary`,
which is short, English, and written for an analyst reading Hydra's own
internal report — this module writes for a client with no security
background, and folds the grouped labels (requirement 3) into the
narrative itself rather than leaving them as an unexplained list.

Four independent content pieces per template_id, deliberately kept as
separate functions/maps rather than blended into one paragraph (each can
be reviewed and corrected on its own, and a renderer picks which pieces
to show):

- `explain_consolidated` — what was found and why it matters (unchanged
  from the previous round).
- `explain_methodology` — HOW it was found, in plain terms, never naming
  a specific tool/binary.
- `explain_caveat` — the specific limitation of THIS test, if any (never
  the general "qué NO cubre" disclaimers, which apply to the whole
  report, not to one finding type).
- `severity_recommendation` — a closing recommendation calibrated to the
  finding's real severity, applied uniformly (including to a template_id
  this module has never seen before, e.g. a future nuclei match) so tone
  never depends on whether a specific template happened to get hand-tuned
  prose.
"""

from __future__ import annotations


def explain_consolidated(template_id: str, labels: list[str]) -> tuple[str, str]:
    """Returns (title, explanation) for one already-grouped finding. Never
    names the underlying tool — describes the activity in plain terms."""
    if template_id == "vuln-match":
        names = ", ".join(sorted(labels))
        title = (
            f"Componente con una vulnerabilidad pública conocida: {names}"
            if names
            else "Componente con una vulnerabilidad pública conocida"
        )
        lead = f"Se identificó lo siguiente: {names}. " if names else ""
        return (
            title,
            f"{lead}Esto significa que existe información pública documentada sobre "
            "cómo podría explotarse esta vulnerabilidad — se recomienda actualizar el "
            "componente a la versión más reciente lo antes posible.",
        )
    if template_id == "cloud-bucket-public-listable":
        return (
            "Almacenamiento en la nube con listado público habilitado",
            "Se encontró un espacio de almacenamiento en la nube asociado a la "
            "organización cuyo contenido puede listarse públicamente sin "
            "autenticación. Dependiendo de qué archivos contenga, esto puede exponer "
            "información sensible a cualquier persona en internet.",
        )
    if template_id == "urlhaus-known-malicious":
        return (
            "Infraestructura catalogada como maliciosa por una base de datos pública",
            "Una dirección asociada al sitio aparece en una base de datos pública de "
            "amenazas como distribuidora de contenido malicioso. Esto puede indicar "
            "un compromiso previo o infraestructura compartida con actividad "
            "maliciosa — se recomienda investigar el origen de esta asociación.",
        )
    if template_id == "cloud-bucket-exists-private":
        return (
            "Almacenamiento en la nube identificado (no público)",
            "Se identificó un espacio de almacenamiento en la nube asociado a la "
            "organización. Su contenido no es listable públicamente en este momento, "
            "por lo que no representa una exposición confirmada — se documenta como "
            "referencia de inventario.",
        )
    if template_id in {"param-reflected", "param-influences-response"}:
        count = len(labels)
        plural = "s" if count != 1 else ""
        article = "los parámetros" if count != 1 else "el parámetro"
        names = ", ".join(sorted(labels))
        strength = (
            "el sitio devuelve ese mismo valor dentro de la respuesta"
            if template_id == "param-reflected"
            else "el sitio responde de forma distinta según el valor enviado"
        )
        return (
            f"{count} parámetro{plural} de la página de inicio responde{'n' if count != 1 else ''} "
            "a valores enviados en la URL",
            f"Al enviar un valor de prueba (texto plano, sin caracteres especiales) en "
            f"{article} {names} de la página de inicio, {strength}. Esto "
            "confirma que el sitio procesa esa entrada, pero NO se probó con "
            "caracteres de inyección reales — esta prueba por sí sola no demuestra "
            "que el sitio sea vulnerable a un ataque, solo que ese parámetro es una "
            "entrada activa que merece revisión adicional con autorización explícita.",
        )
    if template_id == "missing-security-header":
        count = len(labels)
        names = ", ".join(sorted(labels))
        return (
            f"{count} cabecera{'s' if count != 1 else ''} de seguridad HTTP recomendada{'s' if count != 1 else ''} ausente{'s' if count != 1 else ''}",
            f"El sitio no está enviando la{'s' if count != 1 else ''} siguiente{'s' if count != 1 else ''} "
            f"cabecera{'s' if count != 1 else ''} de seguridad recomendada{'s' if count != 1 else ''} en sus "
            f"respuestas HTTP: {names}. Estas cabeceras son instrucciones que el "
            "servidor le da al navegador del visitante para reducir el riesgo de "
            "ciertos ataques (por ejemplo, que el sitio se cargue dentro de otro "
            "sitio, o que el navegador adivine el tipo de un archivo). No es una "
            "vulnerabilidad explotable por sí sola — es una mejora de "
            "endurecimiento recomendada.",
        )
    if template_id == "cloaking-detected":
        return (
            "Comportamiento distinto entre una revisión automática y un navegador real",
            "Al comparar cómo respondió el sitio a una revisión automática frente a "
            "un navegador real, el destino final fue diferente. Esto puede deberse a "
            "una redirección normal según el tipo de visitante, o —con menor "
            "probabilidad— a que el sitio muestra contenido distinto a "
            "herramientas automatizadas que a personas reales. Se recomienda "
            "verificación manual antes de sacar conclusiones.",
        )
    # Unrecognized template_id (most commonly an arbitrary nuclei
    # template match) — present its own name/severity honestly rather
    # than inventing a plain-language gloss that might misrepresent it.
    return (
        f"Hallazgo detectado: {template_id}",
        "Este hallazgo fue detectado durante el análisis automatizado. Revisar la "
        "evidencia técnica adjunta para más contexto.",
    )


# "Cómo lo encontramos" — the technique in plain terms, never a tool or
# binary name. Kept as its own map (not blended into
# `explain_consolidated`'s explanation paragraph) so methodology text can
# be reviewed and corrected independently of the "qué significa" text —
# a report renderer decides how to combine them.
_METHODOLOGY: dict[str, str] = {
    "vuln-match": (
        "Se identificó la tecnología y versión exacta en uso, y se comparó contra "
        "bases de datos públicas de vulnerabilidades documentadas para ese "
        "componente."
    ),
    "cloud-bucket-public-listable": (
        "Se generaron nombres probables de almacenamiento en la nube a partir del "
        "nombre de la organización y su dominio, y se verificó cuáles existen y si "
        "su contenido puede listarse sin autenticación."
    ),
    "cloud-bucket-exists-private": (
        "Se generaron nombres probables de almacenamiento en la nube a partir del "
        "nombre de la organización y su dominio, y se verificó cuáles existen."
    ),
    "urlhaus-known-malicious": (
        "Se consultó una base de datos pública de amenazas para verificar si alguna "
        "dirección asociada al sitio ha sido reportada distribuyendo contenido "
        "malicioso."
    ),
    "param-reflected": (
        "Se probó agregando un valor de identificación única en cada parámetro de "
        "la URL, y se comparó la respuesta del sitio para ver si ese valor aparecía "
        "reflejado de vuelta."
    ),
    "param-influences-response": (
        "Se probó agregando un valor de identificación única en cada parámetro de "
        "la URL, y se comparó la respuesta del sitio para ver si cambiaba según el "
        "valor enviado."
    ),
    "missing-security-header": (
        "Se inspeccionaron las cabeceras HTTP que el servidor envía en cada "
        "respuesta, comparándolas contra el conjunto de cabeceras de seguridad "
        "recomendadas por los estándares actuales de la industria."
    ),
    "cloaking-detected": (
        "Se cargó cada página tanto con una solicitud directa como con un "
        "navegador real, y se compararon los resultados finales para detectar "
        "diferencias."
    ),
    "vuln-check-failed": (
        "Se intentó comparar la tecnología detectada contra la fuente de "
        "vulnerabilidades correspondiente, pero la consulta no pudo completarse."
    ),
}
_DEFAULT_METHODOLOGY = (
    "Este hallazgo fue producido por una verificación automatizada diseñada "
    "específicamente para detectar este tipo de patrón."
)


def explain_methodology(template_id: str) -> str:
    """Never returns an empty string — every finding type, known or not,
    gets a methodology sentence (docs/CLIENT_REPORT.md: uniform depth
    regardless of severity or type)."""
    return _METHODOLOGY.get(template_id, _DEFAULT_METHODOLOGY)


# The specific limitation of THIS test — distinct from the report-wide
# "Qué NO cubre este análisis" section (which applies to everything).
# None means this particular test genuinely has nothing specific beyond
# the general disclaimers worth calling out.
_CAVEATS: dict[str, str] = {
    "param-reflected": (
        "Esta prueba usó únicamente un valor de texto plano como marcador — no se "
        "intentó ningún payload de inyección real (SQL, scripts, etc.), por lo que "
        "no confirma ni descarta una vulnerabilidad explotable."
    ),
    "param-influences-response": (
        "Esta prueba usó únicamente un valor de texto plano como marcador — no se "
        "intentó ningún payload de inyección real, por lo que no confirma ni "
        "descarta una vulnerabilidad explotable."
    ),
    "missing-security-header": (
        "Esta verificación revisa únicamente la presencia de la cabecera en la "
        "respuesta HTTP, no la configuración interna de la aplicación — algunas de "
        "estas protecciones podrían implementarse de otras formas no visibles aquí."
    ),
    "cloaking-detected": (
        "Esta comparación se hizo con una única carga de cada página; un "
        "comportamiento intermitente o dependiente de otros factores (ubicación, "
        "dispositivo, cookies previas) podría no quedar reflejado aquí."
    ),
    "vuln-match": (
        "La coincidencia se basa en el número de versión que el propio sitio "
        "reporta — si esa versión fue parchada manualmente o mal identificada, la "
        "vulnerabilidad documentada podría no aplicar exactamente como se describe."
    ),
    "cloud-bucket-public-listable": (
        "La verificación se limitó a nombres derivados del dominio y la "
        "organización — pueden existir otros espacios de almacenamiento con "
        "nombres no relacionados que no formaron parte de esta revisión."
    ),
    "cloud-bucket-exists-private": (
        "La verificación se limitó a nombres derivados del dominio y la "
        "organización — pueden existir otros espacios de almacenamiento con "
        "nombres no relacionados que no formaron parte de esta revisión."
    ),
    "urlhaus-known-malicious": (
        "La coincidencia depende de que la base de datos pública consultada tenga "
        "la dirección registrada en el momento de la revisión; la asociación puede "
        "ser reciente, histórica, o ya resuelta."
    ),
}


def explain_caveat(template_id: str) -> str | None:
    return _CAVEATS.get(template_id)


# A closing recommendation calibrated to the finding's REAL severity —
# applied uniformly to every finding, known template_id or not, so tone
# never depends on whether a specific type happened to get hand-tuned
# prose (docs/CLIENT_REPORT.md: never alarmist for low-impact findings,
# never dismissive of a real one).
_SEVERITY_RECOMMENDATION: dict[str, str] = {
    "critical": (
        "Se recomienda atender esto de forma inmediata — el riesgo real es alto y "
        "puede tener un impacto directo si no se corrige."
    ),
    "high": ("Se recomienda atender esto con prioridad — el riesgo real es " "significativo."),
    "medium": ("Se recomienda revisar y atender este punto en un plazo razonable."),
    "low": ("Se recomienda considerar este punto como parte de mejoras futuras."),
    "info": (
        "Se recomienda tenerlo en cuenta como referencia — no representa una " "urgencia inmediata."
    ),
}
_DEFAULT_SEVERITY_RECOMMENDATION = (
    "Se recomienda revisarlo con el equipo técnico para decidir la prioridad " "adecuada."
)


def severity_recommendation(severity: str) -> str:
    return _SEVERITY_RECOMMENDATION.get(severity.strip().lower(), _DEFAULT_SEVERITY_RECOMMENDATION)
