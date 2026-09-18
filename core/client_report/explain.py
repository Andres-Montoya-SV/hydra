"""Plain-language, tool-name-free explanations for the client report
(docs/CLIENT_REPORT.md requirement 1: never mention a tool/binary name;
requirement 4: every finding explains what it means and why it matters,
in plain language). Deliberately separate from `core.finding_glossary`,
which is short, English, and written for an analyst reading Hydra's own
internal report — this module writes for a client with no security
background, and folds the grouped labels (requirement 3) into the
narrative itself rather than leaving them as an unexplained list.

All actual wording lives in `core.client_report.i18n` — this module only
decides WHICH template applies to a given template_id/count/labels
combination and which dynamic values get interpolated into it; it never
embeds a literal sentence in any language itself (Task 1: bilingual
support designed so adding a third language later is a new dictionary in
i18n.py, never a change here).

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

from core.client_report.i18n import (
    DEFAULT_LANGUAGE,
    caveat_text,
    explain_text,
    methodology_text,
    severity_recommendation_text,
)


def explain_consolidated(
    template_id: str, labels: list[str], language: str = DEFAULT_LANGUAGE
) -> tuple[str, str]:
    """Returns (title, explanation) for one already-grouped finding. Never
    names the underlying tool — describes the activity in plain terms."""
    if template_id == "vuln-match":
        names = ", ".join(sorted(labels))
        title = (
            explain_text(language, "vuln_match_title_with_names", names=names)
            if names
            else explain_text(language, "vuln_match_title_no_names")
        )
        lead = explain_text(language, "vuln_match_lead", names=names) if names else ""
        return (title, f"{lead}{explain_text(language, 'vuln_match_body')}")
    if template_id == "cloud-bucket-public-listable":
        return (
            explain_text(language, "cloud_bucket_public_title"),
            explain_text(language, "cloud_bucket_public_explanation"),
        )
    if template_id == "urlhaus-known-malicious":
        return (
            explain_text(language, "urlhaus_title"),
            explain_text(language, "urlhaus_explanation"),
        )
    if template_id == "cloud-bucket-exists-private":
        return (
            explain_text(language, "cloud_bucket_private_title"),
            explain_text(language, "cloud_bucket_private_explanation"),
        )
    if template_id in {"param-reflected", "param-influences-response"}:
        count = len(labels)
        names = ", ".join(sorted(labels))
        strength_key = (
            "param_strength_reflected"
            if template_id == "param-reflected"
            else "param_strength_influences"
        )
        strength = explain_text(language, strength_key)
        suffix = "singular" if count == 1 else "plural"
        return (
            explain_text(language, f"param_title_{suffix}", count=count),
            explain_text(language, f"param_explanation_{suffix}", names=names, strength=strength),
        )
    if template_id == "missing-security-header":
        count = len(labels)
        names = ", ".join(sorted(labels))
        suffix = "singular" if count == 1 else "plural"
        return (
            explain_text(language, f"header_title_{suffix}", count=count),
            explain_text(language, f"header_explanation_{suffix}", names=names),
        )
    if template_id == "cloaking-detected":
        return (
            explain_text(language, "cloaking_title"),
            explain_text(language, "cloaking_explanation"),
        )
    # Unrecognized template_id (most commonly an arbitrary nuclei
    # template match) — present its own name/severity honestly rather
    # than inventing a plain-language gloss that might misrepresent it.
    return (
        explain_text(language, "unrecognized_title", template_id=template_id),
        explain_text(language, "unrecognized_explanation"),
    )


def explain_methodology(template_id: str, language: str = DEFAULT_LANGUAGE) -> str:
    """Never returns an empty string — every finding type, known or not,
    gets a methodology sentence (docs/CLIENT_REPORT.md: uniform depth
    regardless of severity or type)."""
    return methodology_text(language, template_id)


def explain_caveat(template_id: str, language: str = DEFAULT_LANGUAGE) -> str | None:
    """The specific limitation of THIS test — distinct from the report-wide
    "Qué NO cubre este análisis" section (which applies to everything).
    None means this particular test genuinely has nothing specific beyond
    the general disclaimers worth calling out."""
    return caveat_text(language, template_id)


def severity_recommendation(severity: str, language: str = DEFAULT_LANGUAGE) -> str:
    """A closing recommendation calibrated to the finding's REAL severity —
    applied uniformly to every finding, known template_id or not, so tone
    never depends on whether a specific type happened to get hand-tuned
    prose (docs/CLIENT_REPORT.md: never alarmist for low-impact findings,
    never dismissive of a real one)."""
    return severity_recommendation_text(language, severity)
