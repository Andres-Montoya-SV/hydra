"""Confidence scoring for reconnaissance findings."""

from __future__ import annotations

from core.assets import CONFIDENCE_SCORE, Confidence, Host, HttpService, Port

# Passive enumeration sources alone do not prove a subdomain is real when the
# root zone has wildcard DNS — they can invent names that still resolve.
_PASSIVE_DISCOVERY_SOURCES = frozenset({"subfinder", "assetfinder", "amass"})
# Independent confirmation that a name is not a wildcard artifact.
_INDEPENDENT_CONFIRMATION_SOURCES = frozenset({"ctlogs", "httpx"})


def score_subdomain(host: Host) -> tuple[Confidence, int]:
    """Score subdomain confidence based on validation chain."""
    sources = set(host.discovery_sources)
    independently_confirmed = bool(
        sources & _INDEPENDENT_CONFIRMATION_SOURCES or host.http_services
    )

    # Wildcard DNS: a canary probe already proved the root resolves arbitrary
    # names. Passive passively discovered subdomain with no independent
    # confirmation (CT logs, live HTTP) is a likely false positive — demote
    # hard but do not discard (still useful as a lead to verify manually).
    if host.dns_wildcard and not independently_confirmed:
        warning = (
            "Possible wildcard DNS false positive — discovered only by passive "
            "enumeration under a wildcard root; not independently confirmed"
        )
        if warning not in host.warnings:
            host.warnings.append(warning)
        return Confidence.UNKNOWN, 15

    if host.dns_resolved and host.http_services:
        return Confidence.HIGH, 100
    if host.dns_resolved:
        return Confidence.MEDIUM, 80
    if sources & _PASSIVE_DISCOVERY_SOURCES:
        return Confidence.LOW, 50
    return Confidence.UNKNOWN, 25


def score_http(service: HttpService, host: Host | None = None) -> tuple[Confidence, int]:
    """Score HTTP service confidence."""
    if host is not None and host.soft_404_detected:
        # Status codes cannot be trusted as existence proof on a soft-404 host.
        return Confidence.LOW, 40
    if service.status_code and 100 <= service.status_code < 600:
        if service.cdn or service.waf:
            return Confidence.MEDIUM, 80
        return Confidence.HIGH, 95
    return Confidence.LOW, 50


def score_port(port: Port, host: Host) -> tuple[Confidence, int]:
    """Score port finding confidence."""
    # A canary probe already showed this host fabricates "open" responses
    # for ports with no possible real service — nmap completing a TCP
    # handshake ("verified_open") proves nothing here, since the same
    # tarpit/portspoof defense that fools naabu also fools nmap's connect
    # probe. Never let port data from a tarpit-suspected host reach HIGH
    # confidence, regardless of verification_state.
    if host.tarpit_suspected:
        return Confidence.UNKNOWN, 5
    if port.verification_state in {"filtered", "closed"}:
        return Confidence.UNKNOWN, 10
    if port.verification_state == "verified_open":
        return Confidence.HIGH, 100
    if port.validated:
        return Confidence.HIGH, 100
    if host.is_cdn or host.cdn_provider:
        return Confidence.LOW, 25
    if port.port in {80, 443, 8080, 8443}:
        return Confidence.MEDIUM, 50
    return Confidence.LOW, 25


def update_host_confidence(host: Host) -> None:
    """Recompute aggregate host confidence from child findings and provenance."""
    scores: list[int] = []

    _, sub_score = score_subdomain(host)
    scores.append(sub_score)

    for svc in host.http_services:
        _, http_score = score_http(svc, host)
        svc.confidence_score = http_score
        svc.confidence = _score_to_level(http_score)
        scores.append(http_score)

    for port in host.ports:
        _, port_score = score_port(port, host)
        port.confidence_score = port_score
        port.confidence = _score_to_level(port_score)
        scores.append(port_score)

    for rec in host.provenance:
        scores.append(rec.confidence)

    if scores:
        host.confidence_score = max(scores)
        host.confidence = _score_to_level(host.confidence_score)
    else:
        host.confidence = Confidence.UNKNOWN
        host.confidence_score = CONFIDENCE_SCORE[Confidence.UNKNOWN]


def _score_to_level(score: int) -> Confidence:
    if score >= 90:
        return Confidence.HIGH
    if score >= 70:
        return Confidence.MEDIUM
    if score >= 40:
        return Confidence.LOW
    return Confidence.UNKNOWN
