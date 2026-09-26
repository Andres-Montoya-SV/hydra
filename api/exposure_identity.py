"""Fase 08 — deterministic Exposure identity derived from verified run findings.

A Finding is run-scoped evidence that one detector reported something.
An Exposure is the durable EASM identity of a security-relevant condition
observed on one durable Asset across runs.

This module is intentionally pure: no database, clock, network, LLM, or fuzzy
matching. Exact inputs always produce the same exposure identity fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

EXPOSURE_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
EXPOSURE_STATUS_OPEN = "open"
EXPOSURE_STATUS_RESOLVED = "resolved"


@dataclass(frozen=True)
class ExposureDraft:
    asset_id: str
    source: str
    template_id: str
    location: str
    severity: str
    title: str
    description: str
    confidence_score: int | None


def normalize_exposure_location(url: object, host: object) -> str:
    """Stable endpoint location used in exposure identity.

    Query and fragment are deliberately removed: a detector observing the same
    vulnerable endpoint with a different tracking/query value must not mint a
    second durable Exposure. Host-only findings fall back to the normalized
    hostname.
    """
    raw_url = str(url or "").strip()
    if raw_url:
        try:
            parsed = urlparse(raw_url)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            if hostname and parsed.scheme.lower() in {"http", "https"}:
                scheme = parsed.scheme.lower()
                try:
                    port = parsed.port
                except ValueError:
                    port = None
                default = 443 if scheme == "https" else 80
                netloc = hostname
                if port and port != default:
                    netloc = f"{hostname}:{port}"
                path = parsed.path or "/"
                if path != "/":
                    path = path.rstrip("/")
                return urlunparse((scheme, netloc, path, "", "", ""))
        except (TypeError, ValueError):
            pass
    return str(host or "").strip().lower().rstrip(".")


def exposure_from_finding(
    finding: dict[str, object],
    *,
    asset_id: str,
) -> ExposureDraft | None:
    """Promote one security-relevant finding into a durable Exposure draft.

    Informational findings remain findings/observations. They are useful
    diagnostics, but treating every informational detector result as an open
    security problem would make the EASM exposure inventory noisy by design.
    """
    severity = str(finding.get("severity") or "").strip().lower()
    if severity not in EXPOSURE_SEVERITIES:
        return None

    source = str(finding.get("source") or "").strip().lower()
    template_id = str(finding.get("template_id") or "").strip()
    host = str(finding.get("host") or "").strip().lower().rstrip(".")
    if not asset_id or not source or not template_id or not host:
        return None

    confidence_raw = finding.get("confidence_score")
    confidence_score: int | None
    if confidence_raw is None:
        confidence_score = None
    else:
        try:
            confidence_score = max(0, min(100, int(confidence_raw)))
        except (TypeError, ValueError):
            confidence_score = None

    return ExposureDraft(
        asset_id=asset_id,
        source=source,
        template_id=template_id,
        location=normalize_exposure_location(finding.get("url"), host),
        severity=severity,
        title=str(finding.get("name") or template_id).strip() or template_id,
        description=str(finding.get("description") or "").strip(),
        confidence_score=confidence_score,
    )
