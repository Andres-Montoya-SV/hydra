"""All fixed (template) text for the client report, in every supported
language — the only place that text lives. `render.py`, `render_docx.py`,
`explain.py`, and `dedup.py` never embed a literal Spanish or English
sentence themselves; they call `t()`/`explain_text()`/etc. with a
`language` code and let this module decide the wording. Adding a third
language later means adding one more dict below (`_FR = {...}`,
`TRANSLATIONS["fr"] = _FR`) — no change to any document-assembly logic in
this package. Do not add a third language speculatively: only English and
Spanish are needed today (docs/CLIENT_REPORT.md).

Dynamic content (real domains, hosts, parameter names, counts) is NEVER
part of this module — it is always passed in as a `.format()` keyword
argument by the caller and interpolated into the (translated) template
string, never translated itself.

A handful of phrases are grammatically sensitive to count (1 vs N) in a
way `.format()` alone can't express correctly in either language — those
are stored as an explicit `_singular`/`_plural` pair of keys rather than
as code that pluralizes a word at runtime. The caller picks which key to
use based on nothing more than "is count == 1", which is not itself
language-specific logic.
"""

from __future__ import annotations

from typing import cast

SUPPORTED_LANGUAGES = ("en", "es")
DEFAULT_LANGUAGE = "es"


_ES: dict[str, object] = {
    # --- Markdown/docx shared structure ---
    "report_title": "Informe de seguridad — {target}",
    "report_prepared_by_label": "Preparado por",
    "generated_line": "*Generado: {date} · Duración de la corrida: {duration}*",
    "duration_known": "{minutes:.1f} minutos ({seconds:.0f} segundos)",
    "duration_unknown": "no disponible",
    "executive_summary_heading": "Resumen ejecutivo",
    "confirmed_vulns_label": "Vulnerabilidades confirmadas",
    "indicios_to_review_label": "Indicios a revisar",
    "mejoras_recommended_label": "Áreas de mejora recomendadas",
    "vulns_heading": "Vulnerabilidades confirmadas",
    "vulns_intro": (
        "Evidencia real de impacto — se recomienda atender estos puntos con prioridad."
    ),
    "vulns_empty": "No se confirmó ninguna vulnerabilidad con evidencia concluyente de impacto.",
    "indicios_heading": "Indicios",
    "indicios_intro": (
        "Detectados sin evidencia concluyente de explotabilidad — requieren revisión "
        "manual antes de considerarse un problema confirmado."
    ),
    "indicios_empty": "No se registraron indicios adicionales en esta corrida.",
    "mejoras_heading": "Áreas de mejora",
    "mejoras_intro": "Recomendaciones de endurecimiento — no son vulnerabilidades por sí solas.",
    "mejoras_empty": "No se identificaron áreas de mejora adicionales en esta corrida.",
    "what_it_means_label": "Qué significa",
    "how_found_label": "Cómo se encontró",
    "location_label": "Ubicación",
    "affected_pages_label": "Página(s) afectada(s)",
    "severity_label": "Severidad reportada",
    "test_limitation_label": "Limitación de esta prueba",
    "recommendation_label": "Recomendación",
    "known_limitations_heading": "Limitaciones conocidas de esta corrida",
    "no_specific_limitations": (
        "No se identificaron limitaciones específicas más allá de las generales."
    ),
    "limitation_vuln_check_failed": (
        "No se pudo verificar **{tech} {version}** contra la fuente de vulnerabilidades "
        "correspondiente ({source}: {reason}). Esta tecnología fue detectada pero su "
        "estado de vulnerabilidad permanece **sin confirmar** — no debe interpretarse "
        "como libre de vulnerabilidades."
    ),
    "limitation_wildcard_dns": (
        "Se detectó configuración DNS comodín en {roots} — algunos subdominios listados "
        "en fuentes pasivas podrían no corresponder a servicios reales."
    ),
    "limitation_soft_404": (
        "{hosts} responde con éxito (HTTP 200) incluso para rutas inexistentes — la "
        "existencia de una URL específica no puede confirmarse únicamente por su código "
        "de respuesta en este sitio."
    ),
    "limitation_param_fuzz_baseline": (
        "La revisión de parámetros no pudo completarse de forma confiable en {hosts} — "
        "la solicitud de referencia fue bloqueada o limitada por el propio sitio. Esto "
        "no equivale a 'sin hallazgos', sino a que la prueba no pudo ejecutarse con "
        "confianza."
    ),
    "reason_unspecified": "razón no especificada",
    "default_wildcard_roots": "el dominio analizado",
    "not_covered_heading": "Qué NO cubre este análisis",
    "not_covered_items": [
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
    ],
    # --- "Lo que necesitas saber" (Task 2: read-alone TL;DR) ---
    "tldr_heading": "Lo que necesitas saber",
    "tldr_zero_vulns": (
        "No se confirmó ninguna vulnerabilidad con evidencia real de impacto en esta revisión."
    ),
    "tldr_vulns_singular": (
        "Se confirmó {count} vulnerabilidad con evidencia real de impacto en esta "
        "revisión — ver el detalle completo más abajo."
    ),
    "tldr_vulns_plural": (
        "Se confirmaron {count} vulnerabilidades con evidencia real de impacto en esta "
        "revisión — ver el detalle completo más abajo."
    ),
    "tldr_indicios_singular": (
        "También se detectó {count} indicio que conviene revisar manualmente antes de "
        "confirmarlo como vulnerabilidad."
    ),
    "tldr_indicios_plural": (
        "También se detectaron {count} indicios que conviene revisar manualmente antes "
        "de confirmarlos como vulnerabilidades."
    ),
    "tldr_scope_line": (
        "Este análisis no incluye pruebas de intrusión activa ni acceso con "
        "credenciales — es un reconocimiento externo, no una prueba de penetración "
        "completa."
    ),
    "tldr_closing_line": (
        "El detalle completo de cada punto está en las páginas siguientes — si algo no "
        "queda claro, no dudes en preguntar."
    ),
    # --- explain.py: per-template_id title/explanation ---
    "explain": {
        "vuln_match_title_with_names": "Componente con una vulnerabilidad pública conocida: {names}",
        "vuln_match_title_no_names": "Componente con una vulnerabilidad pública conocida",
        "vuln_match_lead": "Se identificó lo siguiente: {names}. ",
        "vuln_match_body": (
            "Esto significa que existe información pública documentada sobre cómo "
            "podría explotarse esta vulnerabilidad — se recomienda actualizar el "
            "componente a la versión más reciente lo antes posible."
        ),
        "cloud_bucket_public_title": "Almacenamiento en la nube con listado público habilitado",
        "cloud_bucket_public_explanation": (
            "Se encontró un espacio de almacenamiento en la nube asociado a la "
            "organización cuyo contenido puede listarse públicamente sin "
            "autenticación. Dependiendo de qué archivos contenga, esto puede exponer "
            "información sensible a cualquier persona en internet."
        ),
        "urlhaus_title": "Infraestructura catalogada como maliciosa por una base de datos pública",
        "urlhaus_explanation": (
            "Una dirección asociada al sitio aparece en una base de datos pública de "
            "amenazas como distribuidora de contenido malicioso. Esto puede indicar "
            "un compromiso previo o infraestructura compartida con actividad "
            "maliciosa — se recomienda investigar el origen de esta asociación."
        ),
        "cloud_bucket_private_title": "Almacenamiento en la nube identificado (no público)",
        "cloud_bucket_private_explanation": (
            "Se identificó un espacio de almacenamiento en la nube asociado a la "
            "organización. Su contenido no es listable públicamente en este momento, "
            "por lo que no representa una exposición confirmada — se documenta como "
            "referencia de inventario."
        ),
        "param_title_singular": (
            "{count} parámetro de la página de inicio responde a valores enviados en la URL"
        ),
        "param_title_plural": (
            "{count} parámetros de la página de inicio responden a valores enviados en la URL"
        ),
        "param_explanation_singular": (
            "Al enviar un valor de prueba (texto plano, sin caracteres especiales) en "
            "el parámetro {names} de la página de inicio, {strength}. Esto confirma "
            "que el sitio procesa esa entrada, pero NO se probó con caracteres de "
            "inyección reales — esta prueba por sí sola no demuestra que el sitio sea "
            "vulnerable a un ataque, solo que ese parámetro es una entrada activa que "
            "merece revisión adicional con autorización explícita."
        ),
        "param_explanation_plural": (
            "Al enviar un valor de prueba (texto plano, sin caracteres especiales) en "
            "los parámetros {names} de la página de inicio, {strength}. Esto confirma "
            "que el sitio procesa esa entrada, pero NO se probó con caracteres de "
            "inyección reales — esta prueba por sí sola no demuestra que el sitio sea "
            "vulnerable a un ataque, solo que esos parámetros son una entrada activa "
            "que merece revisión adicional con autorización explícita."
        ),
        "param_strength_reflected": "el sitio devuelve ese mismo valor dentro de la respuesta",
        "param_strength_influences": ("el sitio responde de forma distinta según el valor enviado"),
        "header_title_singular": ("{count} cabecera de seguridad HTTP recomendada ausente"),
        "header_title_plural": ("{count} cabeceras de seguridad HTTP recomendadas ausentes"),
        "header_explanation_singular": (
            "El sitio no está enviando la siguiente cabecera de seguridad recomendada "
            "en sus respuestas HTTP: {names}. Estas cabeceras son instrucciones que el "
            "servidor le da al navegador del visitante para reducir el riesgo de "
            "ciertos ataques (por ejemplo, que el sitio se cargue dentro de otro "
            "sitio, o que el navegador adivine el tipo de un archivo). No es una "
            "vulnerabilidad explotable por sí sola — es una mejora de endurecimiento "
            "recomendada."
        ),
        "header_explanation_plural": (
            "El sitio no está enviando las siguientes cabeceras de seguridad "
            "recomendadas en sus respuestas HTTP: {names}. Estas cabeceras son "
            "instrucciones que el servidor le da al navegador del visitante para "
            "reducir el riesgo de ciertos ataques (por ejemplo, que el sitio se cargue "
            "dentro de otro sitio, o que el navegador adivine el tipo de un archivo). "
            "No es una vulnerabilidad explotable por sí sola — es una mejora de "
            "endurecimiento recomendada."
        ),
        "cloaking_title": (
            "Comportamiento distinto entre una revisión automática y un navegador real"
        ),
        "cloaking_explanation": (
            "Al comparar cómo respondió el sitio a una revisión automática frente a un "
            "navegador real, el destino final fue diferente. Esto puede deberse a una "
            "redirección normal según el tipo de visitante, o —con menor "
            "probabilidad— a que el sitio muestra contenido distinto a herramientas "
            "automatizadas que a personas reales. Se recomienda verificación manual "
            "antes de sacar conclusiones."
        ),
        "unrecognized_title": "Hallazgo detectado: {template_id}",
        "unrecognized_explanation": (
            "Este hallazgo fue detectado durante el análisis automatizado. Revisar la "
            "evidencia técnica adjunta para más contexto."
        ),
    },
    "methodology": {
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
            "Se consultó una base de datos pública de amenazas para verificar si "
            "alguna dirección asociada al sitio ha sido reportada distribuyendo "
            "contenido malicioso."
        ),
        "param-reflected": (
            "Se probó agregando un valor de identificación única en cada parámetro de "
            "la URL, y se comparó la respuesta del sitio para ver si ese valor "
            "aparecía reflejado de vuelta."
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
    },
    "default_methodology": (
        "Este hallazgo fue producido por una verificación automatizada diseñada "
        "específicamente para detectar este tipo de patrón."
    ),
    "caveats": {
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
            "vulnerabilidad documentada podría no aplicar exactamente como se "
            "describe."
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
            "la dirección registrada en el momento de la revisión; la asociación "
            "puede ser reciente, histórica, o ya resuelta."
        ),
    },
    "severity_recommendation": {
        "critical": (
            "Se recomienda atender esto de forma inmediata — el riesgo real es alto y "
            "puede tener un impacto directo si no se corrige."
        ),
        "high": "Se recomienda atender esto con prioridad — el riesgo real es significativo.",
        "medium": "Se recomienda revisar y atender este punto en un plazo razonable.",
        "low": "Se recomienda considerar este punto como parte de mejoras futuras.",
        "info": (
            "Se recomienda tenerlo en cuenta como referencia — no representa una "
            "urgencia inmediata."
        ),
    },
    "default_severity_recommendation": (
        "Se recomienda revisarlo con el equipo técnico para decidir la prioridad adecuada."
    ),
    # --- docx-only presentation strings ---
    "docx_cover_title": "Informe de Seguridad",
    "docx_report_date_label": "Fecha del informe: {date}",
    "docx_run_duration_label": "Duración de la corrida: {duration}",
    "docx_draft_disclaimer": (
        "BORRADOR — para revisión interna antes de compartirse con el cliente."
    ),
    "docx_severity_labels": {
        "critical": "CRÍTICA",
        "high": "ALTA",
        "medium": "MEDIA",
        "low": "BAJA",
        "info": "INFORMATIVA",
    },
    "docx_severity_prefix": "SEVERIDAD: {label}",
    "docx_scope_heading": "Resumen de alcance",
    "docx_scope_headers": [
        "Objetivo(s)",
        "Duración",
        "Vulnerabilidades confirmadas",
        "Indicios",
        "Áreas de mejora",
    ],
    # --- CLI's own console status output (core.client_report.cli) ---
    # Unlike every other command's CLI output, this one's operator sees
    # it right after choosing --language for the document itself, so it
    # follows the same choice rather than the CLI-wide English default.
    "cli_report_written_to": "Reporte de cliente escrito en: {dest}",
    "cli_summary_line": (
        "{vulns} vulnerabilidad(es) confirmada(s), {indicios} indicio(s), "
        "{mejoras} área(s) de mejora."
    ),
    "cli_vuln_check_failed_warning": (
        "⚠ {count} verificación(es) de vulnerabilidad no se pudieron completar en esta "
        "corrida — documentado en la sección {heading!r} del reporte."
    ),
    "cli_conversion_hint_pandoc": " (por ejemplo: pandoc client_report.md -o client_report.docx)",
    "cli_draft_reminder": (
        "\nEsto es un BORRADOR. Revísalo y edítalo{conversion_hint} antes de compartirlo "
        "con el cliente. Hydra nunca envía este documento automáticamente."
    ),
}


_EN: dict[str, object] = {
    "report_title": "Security Report — {target}",
    "report_prepared_by_label": "Prepared by",
    "generated_line": "*Generated: {date} · Run duration: {duration}*",
    "duration_known": "{minutes:.1f} minutes ({seconds:.0f} seconds)",
    "duration_unknown": "not available",
    "executive_summary_heading": "Executive Summary",
    "confirmed_vulns_label": "Confirmed vulnerabilities",
    "indicios_to_review_label": "Leads to review",
    "mejoras_recommended_label": "Recommended hardening areas",
    "vulns_heading": "Confirmed Vulnerabilities",
    "vulns_intro": ("Real evidence of impact — these points should be addressed as a priority."),
    "vulns_empty": "No vulnerability was confirmed with conclusive evidence of impact.",
    "indicios_heading": "Leads",
    "indicios_intro": (
        "Detected without conclusive evidence of exploitability — these require "
        "manual review before being considered a confirmed issue."
    ),
    "indicios_empty": "No additional leads were recorded in this run.",
    "mejoras_heading": "Areas for Improvement",
    "mejoras_intro": "Hardening recommendations — these are not vulnerabilities on their own.",
    "mejoras_empty": "No additional hardening opportunities were identified in this run.",
    "what_it_means_label": "What it means",
    "how_found_label": "How it was found",
    "location_label": "Location",
    "affected_pages_label": "Affected page(s)",
    "severity_label": "Reported severity",
    "test_limitation_label": "Limitation of this test",
    "recommendation_label": "Recommendation",
    "known_limitations_heading": "Known Limitations of This Run",
    "no_specific_limitations": "No specific limitations were identified beyond the general ones.",
    "limitation_vuln_check_failed": (
        "**{tech} {version}** could not be checked against the corresponding "
        "vulnerability source ({source}: {reason}). This technology was detected but "
        "its vulnerability status remains **unconfirmed** — this should not be read "
        "as meaning it is free of vulnerabilities."
    ),
    "limitation_wildcard_dns": (
        "Wildcard DNS was detected on {roots} — some subdomains listed by passive "
        "sources may not correspond to real services."
    ),
    "limitation_soft_404": (
        "{hosts} responds successfully (HTTP 200) even for nonexistent paths — a "
        "specific URL's existence can't be confirmed from its response code alone on "
        "this site."
    ),
    "limitation_param_fuzz_baseline": (
        "Parameter review could not be completed reliably on {hosts} — the baseline "
        "request was blocked or rate-limited by the site itself. This does not mean "
        "'no findings' — it means the test could not run with confidence."
    ),
    "reason_unspecified": "reason not specified",
    "default_wildcard_roots": "the analyzed domain",
    "not_covered_heading": "What This Analysis Does NOT Cover",
    "not_covered_items": [
        "No active intrusion testing was performed, nor was any condition exploited "
        "to confirm impact beyond what is described in each finding.",
        "No credentials were used in testing — everything described here is visible "
        "from the outside, without having logged in.",
        "No social engineering or phishing testing was performed.",
        "Leads (unlike confirmed vulnerabilities) were only tested with plain-text "
        "values, never with real injection payloads — deeper testing could confirm "
        "or rule out each one.",
        "This analysis reflects the state of the site at the time of the run; a "
        "later change to the site is not reflected here.",
        "Coverage of public vulnerabilities depends on the component and its version "
        "being correctly identified and cataloged in the sources consulted — a "
        "component with no matches does not mean it is free of vulnerabilities, only "
        "that no public match was found with the information available.",
    ],
    "tldr_heading": "What You Need to Know",
    "tldr_zero_vulns": (
        "No vulnerability was confirmed with real evidence of impact in this review."
    ),
    "tldr_vulns_singular": (
        "{count} vulnerability was confirmed with real evidence of impact in this "
        "review — see the full detail further below."
    ),
    "tldr_vulns_plural": (
        "{count} vulnerabilities were confirmed with real evidence of impact in this "
        "review — see the full detail further below."
    ),
    "tldr_indicios_singular": (
        "{count} additional lead was also found that should be manually reviewed "
        "before it is treated as a confirmed vulnerability."
    ),
    "tldr_indicios_plural": (
        "{count} additional leads were also found that should be manually reviewed "
        "before they are treated as confirmed vulnerabilities."
    ),
    "tldr_scope_line": (
        "This analysis does not include active intrusion testing or credentialed "
        "access — it is external reconnaissance, not a full penetration test."
    ),
    "tldr_closing_line": (
        "The full detail for each point is in the following pages — if anything is "
        "unclear, please don't hesitate to ask."
    ),
    "explain": {
        "vuln_match_title_with_names": "Component with a known public vulnerability: {names}",
        "vuln_match_title_no_names": "Component with a known public vulnerability",
        "vuln_match_lead": "The following was identified: {names}. ",
        "vuln_match_body": (
            "This means publicly documented information exists on how this "
            "vulnerability could be exploited — updating the component to its latest "
            "version is recommended as soon as possible."
        ),
        "cloud_bucket_public_title": "Cloud storage with public listing enabled",
        "cloud_bucket_public_explanation": (
            "A cloud storage space associated with the organization was found whose "
            "contents can be listed publicly without authentication. Depending on "
            "what files it contains, this could expose sensitive information to "
            "anyone on the internet."
        ),
        "urlhaus_title": "Infrastructure flagged as malicious by a public database",
        "urlhaus_explanation": (
            "An address associated with the site appears in a public threat database "
            "as a distributor of malicious content. This may indicate a prior "
            "compromise or shared infrastructure with malicious activity — "
            "investigating the origin of this association is recommended."
        ),
        "cloud_bucket_private_title": "Cloud storage identified (not public)",
        "cloud_bucket_private_explanation": (
            "A cloud storage space associated with the organization was identified. "
            "Its contents are not publicly listable at this time, so it does not "
            "represent a confirmed exposure — it is documented here for inventory "
            "reference."
        ),
        "param_title_singular": (
            "{count} parameter on the homepage responds to values sent in the URL"
        ),
        "param_title_plural": (
            "{count} parameters on the homepage respond to values sent in the URL"
        ),
        "param_explanation_singular": (
            "Sending a test value (plain text, no special characters) in the {names} "
            "parameter on the homepage, {strength}. This confirms the site processes "
            "that input, but real injection characters were NOT tried — this test "
            "alone does not prove the site is vulnerable to an attack, only that this "
            "parameter is an active input that deserves further review with explicit "
            "authorization."
        ),
        "param_explanation_plural": (
            "Sending a test value (plain text, no special characters) in the {names} "
            "parameters on the homepage, {strength}. This confirms the site "
            "processes that input, but real injection characters were NOT tried — "
            "this test alone does not prove the site is vulnerable to an attack, only "
            "that these parameters are active inputs that deserve further review "
            "with explicit authorization."
        ),
        "param_strength_reflected": "the site returns that same value back in the response",
        "param_strength_influences": "the site responds differently depending on the value sent",
        "header_title_singular": "{count} recommended HTTP security header missing",
        "header_title_plural": "{count} recommended HTTP security headers missing",
        "header_explanation_singular": (
            "The site is not sending the following recommended security header in "
            "its HTTP responses: {names}. These headers are instructions the server "
            "gives the visitor's browser to reduce the risk of certain attacks (for "
            "example, the site being loaded inside another site, or the browser "
            "guessing a file's type). This is not an exploitable vulnerability on "
            "its own — it is a recommended hardening improvement."
        ),
        "header_explanation_plural": (
            "The site is not sending the following recommended security headers in "
            "its HTTP responses: {names}. These headers are instructions the server "
            "gives the visitor's browser to reduce the risk of certain attacks (for "
            "example, the site being loaded inside another site, or the browser "
            "guessing a file's type). This is not an exploitable vulnerability on "
            "its own — it is a recommended hardening improvement."
        ),
        "cloaking_title": "Different behavior between an automated check and a real browser",
        "cloaking_explanation": (
            "Comparing how the site responded to an automated check versus a real "
            "browser, the final destination was different. This could be a normal "
            "redirect based on visitor type, or — less likely — the site showing "
            "different content to automated tools than to real people. Manual "
            "verification is recommended before drawing conclusions."
        ),
        "unrecognized_title": "Finding detected: {template_id}",
        "unrecognized_explanation": (
            "This finding was detected during the automated analysis. Review the "
            "attached technical evidence for more context."
        ),
    },
    "methodology": {
        "vuln-match": (
            "The exact technology and version in use was identified, and checked "
            "against public databases of documented vulnerabilities for that "
            "component."
        ),
        "cloud-bucket-public-listable": (
            "Likely cloud storage names were generated from the organization's name "
            "and domain, and checked for which ones exist and whether their contents "
            "can be listed without authentication."
        ),
        "cloud-bucket-exists-private": (
            "Likely cloud storage names were generated from the organization's name "
            "and domain, and checked for which ones exist."
        ),
        "urlhaus-known-malicious": (
            "A public threat database was queried to check whether any address "
            "associated with the site has been reported distributing malicious "
            "content."
        ),
        "param-reflected": (
            "A unique identifying value was added to each URL parameter, and the "
            "site's response was compared to see whether that value came back "
            "reflected."
        ),
        "param-influences-response": (
            "A unique identifying value was added to each URL parameter, and the "
            "site's response was compared to see whether it changed depending on the "
            "value sent."
        ),
        "missing-security-header": (
            "The HTTP headers the server sends in each response were inspected and "
            "compared against the set of security headers recommended by current "
            "industry standards."
        ),
        "cloaking-detected": (
            "Each page was loaded both with a direct request and with a real "
            "browser, and the final results were compared to detect differences."
        ),
        "vuln-check-failed": (
            "An attempt was made to compare the detected technology against the "
            "corresponding vulnerability source, but the query could not be "
            "completed."
        ),
    },
    "default_methodology": (
        "This finding was produced by an automated check specifically designed to "
        "detect this kind of pattern."
    ),
    "caveats": {
        "param-reflected": (
            "This test used only a plain-text marker value — no real injection "
            "payload (SQL, scripts, etc.) was attempted, so it neither confirms nor "
            "rules out an exploitable vulnerability."
        ),
        "param-influences-response": (
            "This test used only a plain-text marker value — no real injection "
            "payload was attempted, so it neither confirms nor rules out an "
            "exploitable vulnerability."
        ),
        "missing-security-header": (
            "This check only reviews whether the header is present in the HTTP "
            "response, not the application's internal configuration — some of these "
            "protections could be implemented in other ways not visible here."
        ),
        "cloaking-detected": (
            "This comparison was made with a single load of each page; intermittent "
            "behavior or behavior dependent on other factors (location, device, "
            "prior cookies) might not be reflected here."
        ),
        "vuln-match": (
            "The match is based on the version number the site itself reports — if "
            "that version was manually patched or misidentified, the documented "
            "vulnerability might not apply exactly as described."
        ),
        "cloud-bucket-public-listable": (
            "The check was limited to names derived from the domain and organization "
            "— other storage spaces with unrelated names may exist that were not "
            "part of this review."
        ),
        "cloud-bucket-exists-private": (
            "The check was limited to names derived from the domain and organization "
            "— other storage spaces with unrelated names may exist that were not "
            "part of this review."
        ),
        "urlhaus-known-malicious": (
            "The match depends on the public database queried having the address on "
            "record at the time of the check; the association could be recent, "
            "historical, or already resolved."
        ),
    },
    "severity_recommendation": {
        "critical": (
            "Addressing this immediately is recommended — the real risk is high and "
            "could have a direct impact if not fixed."
        ),
        "high": "Addressing this as a priority is recommended — the real risk is significant.",
        "medium": "Reviewing and addressing this within a reasonable timeframe is recommended.",
        "low": "Considering this as part of future improvements is recommended.",
        "info": (
            "Keeping this in mind for reference is recommended — it does not "
            "represent an immediate urgency."
        ),
    },
    "default_severity_recommendation": (
        "Reviewing this with the technical team to decide the appropriate priority "
        "is recommended."
    ),
    "docx_cover_title": "Security Report",
    "docx_report_date_label": "Report date: {date}",
    "docx_run_duration_label": "Run duration: {duration}",
    "docx_draft_disclaimer": "DRAFT — for internal review before being shared with the client.",
    "docx_severity_labels": {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    },
    "docx_severity_prefix": "SEVERITY: {label}",
    "docx_scope_heading": "Scope Summary",
    "docx_scope_headers": [
        "Target(s)",
        "Duration",
        "Confirmed Vulnerabilities",
        "Leads",
        "Areas for Improvement",
    ],
    "cli_report_written_to": "Client report written to: {dest}",
    "cli_summary_line": (
        "{vulns} confirmed vulnerability(ies), {indicios} unconfirmed lead(s), "
        "{mejoras} improvement area(s)."
    ),
    "cli_vuln_check_failed_warning": (
        "⚠ {count} vulnerability check(s) could not be completed this run — documented "
        "under the report's {heading!r} section."
    ),
    "cli_conversion_hint_pandoc": " (e.g.: pandoc client_report.md -o client_report.docx)",
    "cli_draft_reminder": (
        "\nThis is a DRAFT. Review and edit it{conversion_hint} before sharing it with "
        "the client. Hydra never sends this document automatically."
    ),
}


TRANSLATIONS: dict[str, dict[str, object]] = {"es": _ES, "en": _EN}


def t(language: str, key: str, **kwargs: object) -> str:
    """Look up a flat translation string and interpolate dynamic content.
    Dynamic values arrive only via `**kwargs` — never embedded in the
    template itself — so translated text and real target data can never
    be confused with each other."""
    value = cast(str, TRANSLATIONS[language][key])
    return value.format(**kwargs) if kwargs else value


def not_covered_items(language: str) -> list[str]:
    return cast(list, TRANSLATIONS[language]["not_covered_items"])


def docx_scope_headers(language: str) -> list[str]:
    return cast(list, TRANSLATIONS[language]["docx_scope_headers"])


def docx_severity_label(language: str, severity: str) -> str:
    labels = cast(dict, TRANSLATIONS[language]["docx_severity_labels"])
    return labels.get(severity.strip().lower(), severity.upper())


def explain_text(language: str, key: str, **kwargs: object) -> str:
    table = cast(dict, TRANSLATIONS[language]["explain"])
    value = cast(str, table[key])
    return value.format(**kwargs) if kwargs else value


def methodology_text(language: str, template_id: str) -> str:
    table = cast(dict, TRANSLATIONS[language]["methodology"])
    return table.get(template_id, TRANSLATIONS[language]["default_methodology"])


def caveat_text(language: str, template_id: str) -> str | None:
    table = cast(dict, TRANSLATIONS[language]["caveats"])
    return table.get(template_id)


def severity_recommendation_text(language: str, severity: str) -> str:
    table = cast(dict, TRANSLATIONS[language]["severity_recommendation"])
    return table.get(
        severity.strip().lower(), TRANSLATIONS[language]["default_severity_recommendation"]
    )
