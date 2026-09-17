"""Deduplication and grouping for the client report (docs/CLIENT_REPORT.md
requirement 3: 'no asumas que cada fila de findings es un hallazgo
distinto para efectos de presentación'). Pure functions, no I/O — operate
on `core.assets.Finding` objects already parsed from a run's per-tool
artifacts.

Two axes are collapsed, deliberately kept separate:

1. URL-variant dedup: the SAME page probed with and without a trailing
   slash (or under its bare-domain vs www alias) is one page, not two —
   applied unconditionally to every finding regardless of template.
2. Label grouping: several distinct raw findings that are really the SAME
   underlying pattern repeated under different labels on the same page
   (eight different query parameters all reflecting input, five different
   missing security headers) become ONE entry listing the distinct labels
   — applied only for the template_ids where that framing is honest (a
   single CVE identifier is never merged with a different CVE just
   because both hit the same host).
"""

from __future__ import annotations

import re
from typing import cast
from urllib.parse import urlsplit

from core.assets import Finding
from core.client_report.model import ConsolidatedFinding, FindingCategory

# Scan-quality/reliability caveats about the COLLECTION itself, not about
# the target — never client-facing findings. Surfaced (if at all) via the
# run's own warnings, not as report items.
_EXCLUDED_TEMPLATE_IDS = frozenset(
    {"tarpit-detected", "wildcard-dns-detected", "soft-404-detected"}
)

_VULNERABILIDAD_CONFIRMADA_TEMPLATE_IDS = frozenset(
    {"vuln-match", "cloud-bucket-public-listable", "urlhaus-known-malicious"}
)
_AREA_MEJORA_TEMPLATE_IDS = frozenset({"missing-security-header"})
_LIMITACION_TEMPLATE_IDS = frozenset({"vuln-check-failed"})

# template_ids where several distinct labels (parameter names, header
# names) on the same host collapse into ONE entry listing every label —
# every other template_id groups per-label instead (a CVE identifier, a
# specific nuclei template match, a specific malicious host are never
# merged with a different one just for sharing a host).
_MERGE_LABELS_TEMPLATE_IDS = frozenset(
    {"param-reflected", "param-influences-response", "missing-security-header", "cloaking-detected"}
)

_PARAM_NAME_RE = re.compile(r"Parameter '([^']+)'")
_HEADER_NAME_RE = re.compile(r"Missing security header: (.+)$")


def normalize_host_for_grouping(host: str) -> str:
    """Strip a leading 'www.' for GROUPING purposes only — the bare domain
    and its www alias are overwhelmingly the same site (this run's own
    evidence: a browser-behavior finding recorded under both). Never used
    for display; the real host(s) involved are still shown to the reader.
    """
    h = host.strip().lower()
    return h[4:] if h.startswith("www.") else h


def normalize_page_url(url: str | None) -> str:
    """Collapse a page's URL down to (scheme, host, path) with a trailing
    slash stripped — query strings are dropped because grouping happens
    at the PAGE level (a parameter-fuzzing probe's own injected query
    string is exactly what should NOT distinguish two occurrences of the
    same underlying page)."""
    if not url:
        return ""
    parsed = urlsplit(url)
    if not parsed.netloc:
        # No real host component (e.g. "about:blank", a browser's own
        # blank-page placeholder) — nothing meaningful to normalize;
        # return it verbatim rather than constructing a malformed
        # "scheme://path" string.
        return url
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"


def categorize_template(template_id: str, severity: str) -> FindingCategory | None:
    """Returns None for a template_id that never belongs in a client
    report at all (a scan-quality caveat, not a target-facing item)."""
    if template_id in _EXCLUDED_TEMPLATE_IDS:
        return None
    if template_id in _LIMITACION_TEMPLATE_IDS:
        return FindingCategory.LIMITACION
    if template_id in _VULNERABILIDAD_CONFIRMADA_TEMPLATE_IDS:
        return FindingCategory.VULNERABILIDAD_CONFIRMADA
    if template_id in _AREA_MEJORA_TEMPLATE_IDS:
        return FindingCategory.AREA_MEJORA
    if template_id in {
        "param-reflected",
        "param-influences-response",
        "cloaking-detected",
        "cloud-bucket-exists-private",
    }:
        return FindingCategory.INDICIO
    # An unrecognized template_id (most commonly an arbitrary nuclei
    # template-id) falls back to its own reported severity: a template
    # that actually fired with a real severity is a concrete match, not
    # merely a lead — info/unknown severity stays an indicio pending
    # manual review, same conservative default as everywhere else in
    # this project.
    if severity in {"critical", "high", "medium"}:
        return FindingCategory.VULNERABILIDAD_CONFIRMADA
    return FindingCategory.INDICIO


def _extract_label(finding: Finding) -> str:
    """The specific instance within a merge-labels group (a parameter
    name, a header name) — falls back to the finding's own name when no
    template-specific extraction applies, so an unrecognized shape still
    groups sanely (by its literal name) rather than crashing."""
    if finding.template_id in {"param-reflected", "param-influences-response"}:
        match = _PARAM_NAME_RE.search(finding.name)
        if match:
            return match.group(1)
    if finding.template_id == "missing-security-header":
        match = _HEADER_NAME_RE.search(finding.name)
        if match:
            return match.group(1)
    if finding.template_id == "cloaking-detected":
        return finding.host
    return finding.name


def consolidate(findings: list[Finding]) -> list[ConsolidatedFinding]:
    """The full consolidation pass: categorize, drop scan-quality
    caveats, collapse URL-variant duplicates, then group merge-labels
    template_ids by label into one entry each. Order is stable
    (first-seen) so output is deterministic given the same input.
    """
    # group_key -> accumulator
    groups: dict[tuple[str, str, str, str], dict[str, object]] = {}
    order: list[tuple[str, str, str, str]] = []

    for finding in findings:
        category = categorize_template(finding.template_id, finding.severity)
        if category is None:
            continue
        host_group = normalize_host_for_grouping(finding.host)
        page_url = normalize_page_url(finding.url)
        label = _extract_label(finding)
        merge_labels = finding.template_id in _MERGE_LABELS_TEMPLATE_IDS
        # merge_labels groups ignore both page_url and label in the key
        # (every distinct label on the host collapses into one entry);
        # everything else keys on page_url + label so distinct pages or
        # distinct identifiers (a different CVE, a different bucket) stay
        # separate entries.
        if merge_labels:
            key = (host_group, category.value, finding.template_id, "")
        else:
            key = (host_group, category.value, finding.template_id, f"{page_url}\0{label}")

        if key not in groups:
            groups[key] = {
                "category": category,
                "template_id": finding.template_id,
                "host": finding.host,
                "hosts": {finding.host},
                "severity": finding.severity,
                "occurrences": 0,
                "urls": [],
                "labels": [],
                "descriptions": [],
                "limitation_note": None,
            }
            order.append(key)

        acc = groups[key]
        acc["occurrences"] = int(acc["occurrences"]) + 1
        acc["hosts"].add(finding.host)  # type: ignore[union-attr]
        if page_url and page_url not in acc["urls"]:
            acc["urls"].append(page_url)  # type: ignore[union-attr]
        if label not in acc["labels"]:
            acc["labels"].append(label)  # type: ignore[union-attr]
        if finding.description and finding.description not in acc["descriptions"]:
            acc["descriptions"].append(finding.description)  # type: ignore[union-attr]
        if category is FindingCategory.LIMITACION and not acc["limitation_note"]:
            acc["limitation_note"] = finding.description

    return [_build_consolidated(groups[key]) for key in order]


def _build_consolidated(acc: dict[str, object]) -> ConsolidatedFinding:
    from core.client_report.explain import explain_consolidated

    category = cast(FindingCategory, acc["category"])
    template_id = str(acc["template_id"])
    hosts = sorted(acc["hosts"])  # type: ignore[arg-type]
    labels = list(acc["labels"])  # type: ignore[arg-type]
    title, explanation = explain_consolidated(template_id, labels)
    return ConsolidatedFinding(
        category=category,
        title=title,
        explanation=explanation,
        host=" / ".join(hosts),
        severity=str(acc["severity"]),
        occurrences=int(acc["occurrences"]),
        affected_urls=list(acc["urls"]),  # type: ignore[arg-type]
        labels=labels,
        limitation_note=(
            str(acc["limitation_note"]) if acc["limitation_note"] is not None else None
        ),
    )
