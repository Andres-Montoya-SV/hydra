"""Automatic host profiling from normalized intelligence."""

from __future__ import annotations

import re

from core.assets import Host, HostCategory, HostProfile, RiskLevel

_AUTH_PATTERNS = re.compile(r"login|signin|sign-in|auth|oauth|sso|session|account", re.I)
_PAYMENT_PATTERNS = re.compile(r"payment|checkout|wallet|billing|pay\.|cash", re.I)
_API_PATTERNS = re.compile(r"api|graphql|gateway|webhook|rest|grpc", re.I)
_ADMIN_PATTERNS = re.compile(r"admin|manage|console|dashboard|portal|internal", re.I)
_PARTNER_PATTERNS = re.compile(r"partner|supplier|vendor|seller|merchant", re.I)
_SUPPORT_PATTERNS = re.compile(r"support|help|ticket|service", re.I)
_MEDIA_PATTERNS = re.compile(r"media|cdn|static|assets|images|video", re.I)
_STORAGE_PATTERNS = re.compile(r"storage|s3|blob|upload|files", re.I)
_MARKETING_PATTERNS = re.compile(r"marketing|landing|promo|campaign|www", re.I)

_CLOUD_SIGNALS: dict[str, re.Pattern[str]] = {
    "AWS": re.compile(r"amazonaws|cloudfront|aws", re.I),
    "GCP": re.compile(r"googleusercontent|googleapis|gcp", re.I),
    "Azure": re.compile(r"azure|windows\.net|blob\.core", re.I),
    "Akamai": re.compile(r"akamai|akamaized", re.I),
    "Cloudflare": re.compile(r"cloudflare", re.I),
}


def profile_host(host: Host, all_hosts: dict[str, Host] | None = None) -> HostProfile:
    """Generate automatic infrastructure profile for a host."""
    domain = host.domain
    labels = domain.replace(".", " ").lower()
    profile = HostProfile()

    profile.has_authentication = bool(_AUTH_PATTERNS.search(labels))
    profile.has_api = bool(_API_PATTERNS.search(labels))
    profile.has_graphql = "graphql" in labels

    for svc in host.http_services:
        title = (svc.title or "").lower()
        tech_names = " ".join(svc.tech_names()).lower()
        combined = f"{labels} {title} {tech_names}"
        if _AUTH_PATTERNS.search(combined):
            profile.has_authentication = True
        if _API_PATTERNS.search(combined):
            profile.has_api = True
        if "graphql" in combined:
            profile.has_graphql = True

    profile.category = _classify_category(domain, profile)
    profile.cloud_provider = _detect_cloud(host)
    profile.certificate_type = _cert_type(host)
    profile.related_hosts = _find_related(domain, all_hosts or {})
    profile.priority = _map_priority(profile.category, host)
    profile.confidence_score = min(100, host.confidence_score + (10 if host.http_services else 0))
    profile.summary = _build_summary(host, profile)
    return profile


def _classify_category(domain: str, profile: HostProfile) -> HostCategory:
    d = domain.lower()
    if _PAYMENT_PATTERNS.search(d):
        return HostCategory.PAYMENTS
    if profile.has_authentication or _AUTH_PATTERNS.search(d):
        return HostCategory.AUTHENTICATION
    if profile.has_api or _API_PATTERNS.search(d):
        return HostCategory.API
    if _ADMIN_PATTERNS.search(d):
        return HostCategory.ADMIN
    if _PARTNER_PATTERNS.search(d):
        return HostCategory.PARTNER
    if _STORAGE_PATTERNS.search(d):
        return HostCategory.STORAGE
    if _SUPPORT_PATTERNS.search(d):
        return HostCategory.SUPPORT
    if _MEDIA_PATTERNS.search(d):
        return HostCategory.MEDIA
    if _MARKETING_PATTERNS.search(d):
        return HostCategory.MARKETING
    return HostCategory.UNKNOWN


def _detect_cloud(host: Host) -> str | None:
    if host.cloud_provider:
        return host.cloud_provider
    signals = " ".join(
        [
            host.cdn_provider or "",
            host.provider or "",
            host.asn_org or "",
            " ".join(host.ips),
        ]
    )
    for name, pattern in _CLOUD_SIGNALS.items():
        if pattern.search(signals):
            return name
    if host.is_cdn and host.cdn_provider:
        return host.cdn_provider
    return None


def _cert_type(host: Host) -> str | None:
    if not host.tls:
        return None
    if host.tls.is_wildcard:
        return "Wildcard"
    if len(host.tls.sans) > 5:
        return "Multi-SAN"
    return "Standard"


def _find_related(domain: str, all_hosts: dict[str, Host]) -> list[str]:
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    root = ".".join(parts[-2:])
    prefix = parts[0] if len(parts) > 2 else ""
    related: list[str] = []
    for other in all_hosts:
        if other == domain:
            continue
        if other.endswith(root) and other != domain:
            other_prefix = other.split(".")[0]
            if prefix and _share_stem(prefix, other_prefix):
                related.append(other)
    return sorted(related)[:10]


def _share_stem(a: str, b: str) -> bool:
    if len(a) >= 3 and len(b) >= 3 and (a in b or b in a):
        return True
    return a[:4] == b[:4] if len(a) >= 4 and len(b) >= 4 else False


def _map_priority(category: HostCategory, host: Host) -> RiskLevel:
    critical = {HostCategory.PAYMENTS, HostCategory.AUTHENTICATION, HostCategory.ADMIN}
    high = {HostCategory.API, HostCategory.IDENTITY, HostCategory.CHECKOUT, HostCategory.SELLER}
    if category in critical:
        return RiskLevel.CRITICAL
    if category in high:
        return RiskLevel.HIGH
    if host.http_services:
        return RiskLevel.MEDIUM
    return RiskLevel.INFO


def _build_summary(host: Host, profile: HostProfile) -> str:
    parts = [host.domain]
    if profile.category != HostCategory.UNKNOWN:
        parts.append(f"Category: {profile.category.value}")
    if profile.cloud_provider:
        parts.append(f"Cloud: {profile.cloud_provider}")
    if host.cdn_provider:
        parts.append(f"CDN: {host.cdn_provider}")
    techs = []
    for svc in host.http_services:
        techs.extend(svc.tech_names()[:3])
    if techs:
        parts.append(f"Tech: {', '.join(list(dict.fromkeys(techs))[:3])}")
    if profile.has_authentication:
        parts.append("Auth: Yes")
    if profile.has_api:
        parts.append("API: Yes")
    if profile.has_graphql:
        parts.append("GraphQL: Yes")
    parts.append(f"Confidence: {profile.confidence_score}%")
    return " | ".join(parts)
