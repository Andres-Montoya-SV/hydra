"""Plain-Spanish, tool-name-free explanations for the client report
(docs/CLIENT_REPORT.md requirement 1: never mention a tool/binary name;
requirement 4: every finding explains what it means and why it matters,
in plain language). Deliberately separate from `core.finding_glossary`,
which is short, English, and written for an analyst reading Hydra's own
internal report — this module writes for a client with no security
background, and folds the grouped labels (requirement 3) into the
narrative itself rather than leaving them as an unexplained list.
"""

from __future__ import annotations


def explain_consolidated(template_id: str, labels: list[str]) -> tuple[str, str]:
    """Returns (title, explanation) for one already-grouped finding. Never
    names the underlying tool — describes the activity in plain terms."""
    if template_id == "vuln-match":
        return (
            "Componente con una vulnerabilidad pública conocida",
            "Se identificó un componente del sitio cuya versión coincide con una "
            "vulnerabilidad ya documentada públicamente. Esto significa que existe "
            "información pública sobre cómo podría explotarse — se recomienda "
            "actualizar el componente a la versión más reciente lo antes posible.",
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
