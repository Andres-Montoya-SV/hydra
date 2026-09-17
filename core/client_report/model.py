"""Data model for the client report — deliberately separate from
`core.assets.Finding` (the raw, one-row-per-probe shape): a
`ConsolidatedFinding` is a PRESENTATION-level object, already deduplicated
and grouped, that never names a tool and always carries a plain-language
explanation (docs/CLIENT_REPORT.md requirements 1-5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingCategory(str, Enum):
    """The three buckets the client report keeps strictly separate
    (requirement 2: 'Indicios' and 'Vulnerabilidades confirmadas' are
    never mixed in one list) plus two housekeeping categories that never
    appear as ordinary findings at all:

    VULNERABILIDAD_CONFIRMADA: real evidence of impact (a published CVE
    match, a publicly-listable cloud bucket, a host cataloged as
    malicious) — not merely detected, demonstrated.
    INDICIO: detected without conclusive evidence of exploitability
    (a reflected parameter with no real injection payload tried, a
    behavioral difference that needs manual confirmation, an existing but
    non-public cloud bucket).
    AREA_MEJORA: a hardening recommendation, not a vulnerability — e.g. a
    missing security header. Shown in its own section, never counted
    alongside vulnerabilities or indicios.
    LIMITACION: this run could not actually verify something (requirement
    8) — surfaced only in the 'known limitations of this run' section,
    never presented as if it were a finding about the target.
    """

    VULNERABILIDAD_CONFIRMADA = "vulnerabilidad_confirmada"
    INDICIO = "indicio"
    AREA_MEJORA = "area_mejora"
    LIMITACION = "limitacion"


@dataclass
class ConsolidatedFinding:
    """One client-report-ready item — already deduplicated across URL
    variants of the same page and, where the underlying issue is the same
    pattern repeated under different labels (several reflected parameters,
    several missing headers), already grouped into one entry listing the
    distinct labels rather than one entry per raw row.

    Every field here is populated once, in `core.client_report.dedup`, so
    both the Markdown and the Word renderers read the exact same content
    — neither renderer computes or duplicates any of this on its own
    (methodology, caveat, and recommendation text all come from
    `core.client_report.explain`, applied uniformly regardless of
    severity or how well-known the finding's template_id is).
    """

    category: FindingCategory
    title: str
    explanation: str
    methodology: str
    recommendation: str
    host: str
    severity: str
    occurrences: int
    affected_urls: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    caveat: str | None = None
    limitation_note: str | None = None
