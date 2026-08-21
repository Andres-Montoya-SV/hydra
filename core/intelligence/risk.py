"""Host risk prioritization engine with category classification."""

from __future__ import annotations

from core.assets import Host, HostCategory, RiskLevel

CATEGORY_WEIGHTS: dict[HostCategory, int] = {
    HostCategory.PAYMENTS: 45,
    HostCategory.AUTHENTICATION: 40,
    HostCategory.CHECKOUT: 40,
    HostCategory.IDENTITY: 35,
    HostCategory.ADMIN: 35,
    HostCategory.API: 30,
    HostCategory.SELLER: 25,
    HostCategory.PARTNER: 20,
    HostCategory.INTERNAL: 20,
    HostCategory.STORAGE: 15,
    HostCategory.SUPPORT: 10,
    HostCategory.MARKETING: 5,
    HostCategory.MEDIA: 3,
    HostCategory.CDN: 0,
    HostCategory.UNKNOWN: 5,
}


def score_host(host: Host) -> None:
    """Compute risk score and level with explanatory reasons."""
    score = 0
    reasons: list[str] = []

    if host.profile:
        cat = host.profile.category
        weight = CATEGORY_WEIGHTS.get(cat, 5)
        if weight > 0:
            score += weight
            reasons.append(f"Category: {cat.value} (+{weight})")

        if host.profile.has_authentication:
            score += 15
            reasons.append("Authentication surface detected (+15)")
        if host.profile.has_api:
            score += 10
            reasons.append("API endpoint detected (+10)")
        if host.profile.has_graphql:
            score += 8
            reasons.append("GraphQL detected (+8)")

    if host.http_services:
        score += 5
        reasons.append("Live HTTP service confirmed (+5)")
        missing_security_headers = 0
        weak_tls = False
        exposed_adminish = False
        for svc in host.http_services:
            missing_security_headers += len(
                {
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                }
                - set(svc.security_headers)
            )
            if svc.tls_version and svc.tls_version.lower() in {
                "tls10",
                "tls1.0",
                "tls11",
                "tls1.1",
            }:
                weak_tls = True
            title_blob = f"{svc.title or ''} {' '.join(svc.tech_names())}".lower()
            if any(
                token in title_blob
                for token in ("admin", "swagger", "graphql", "jenkins", "grafana")
            ):
                exposed_adminish = True
        if missing_security_headers:
            delta = min(8, missing_security_headers)
            score += delta
            reasons.append(f"Missing security headers (+{delta})")
        if weak_tls:
            score += 10
            reasons.append("Legacy TLS detected (+10)")
        if exposed_adminish:
            score += 12
            reasons.append("Sensitive app surface fingerprinted (+12)")

    if host.dns_resolved:
        score += 3
        reasons.append("DNS resolution confirmed (+3)")

    if host.tarpit_suspected:
        # A canary probe confirmed this host fabricates "open" responses to
        # arbitrary unassigned ports (tarpit/portspoof defense). Every port
        # naabu/nmap reported is therefore unreliable noise, not signal —
        # scoring it as a real "sensitive port" or "broad exposed surface"
        # would inflate risk based on data we already know is fake.
        reasons.append(
            "Port scan results unreliable (tarpit/portspoof suspected) — excluded from risk score"
        )
    else:
        interesting_ports = {
            22: 4,
            80: 2,
            443: 2,
            445: 10,
            3389: 12,
            5432: 10,
            6379: 12,
            9200: 12,
            27017: 12,
        }
        for port in host.ports[:20]:
            delta = interesting_ports.get(port.port, 1)
            score += delta
            if delta >= 10:
                reasons.append(f"Sensitive port {port.port}/{port.protocol} (+{delta})")
        if len(host.ports) > 10:
            score += 5
            reasons.append("Broad exposed port surface (+5)")

    api_urls = sum(1 for url in host.urls if url.endpoint_type in {"api", "graphql"})
    if api_urls:
        delta = min(10, api_urls * 2)
        score += delta
        reasons.append(f"Crawled API endpoints (+{delta})")

    if any(url.secrets or url.jwts for url in host.urls):
        score += 15
        reasons.append("Crawler observed token-like material (+15)")

    if host.findings:
        critical = sum(1 for f in host.findings if f.severity in ("critical", "high"))
        medium = sum(1 for f in host.findings if f.severity == "medium")
        if critical:
            score += min(20, critical * 10)
            reasons.append(
                f"Security findings: {critical} high/critical (+{min(20, critical * 10)})"
            )
        if medium:
            score += min(10, medium * 4)
            reasons.append(f"Medium findings: {medium} (+{min(10, medium * 4)})")

    if host.cloud_provider:
        score += 2
        reasons.append(f"Cloud deployment: {host.cloud_provider} (+2)")

    if host.confidence_score < 50:
        score = max(0, score - 10)
        reasons.append("Low confidence penalty (-10)")

    if host.is_cdn and not host.http_services:
        score = max(0, score - 5)

    host.risk_score = max(0, min(100, score))
    host.risk_reasons = reasons[:8]

    if score >= 40:
        host.risk_level = RiskLevel.CRITICAL
    elif score >= 25:
        host.risk_level = RiskLevel.HIGH
    elif score >= 10:
        host.risk_level = RiskLevel.MEDIUM
    elif score > 0:
        host.risk_level = RiskLevel.LOW
    else:
        host.risk_level = RiskLevel.INFO


def score_all(hosts: dict[str, Host]) -> list[Host]:
    """Score all hosts and return sorted by risk (descending)."""
    for host in hosts.values():
        score_host(host)
    return sorted(hosts.values(), key=lambda h: h.risk_score, reverse=True)
