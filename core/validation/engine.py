"""Validation engine for reconnaissance findings."""

from __future__ import annotations

import re
from collections import Counter

from core.assets import Confidence, DnsRecord, Host, Port

# Known CDN/WAF indicators in headers and server fields
CDN_WAF_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "akamai": ["akamai", "akamaighost", "x-akamai"],
    "cloudfront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "fastly": ["fastly", "x-served-by", "x-cache"],
    "aws_waf": ["awselb", "x-amzn-requestid"],
    "incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "sucuri": ["sucuri", "x-sucuri-id"],
}

SUSPICIOUS_NAABU_THRESHOLD = 50  # ports per host
SUSPICIOUS_TOTAL_NAABU = 500


def detect_cdn_waf(
    headers: dict[str, str], server: str | None = None
) -> tuple[str | None, str | None]:
    """Detect CDN and WAF from response headers."""
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    if server:
        blob += " " + server.lower()

    cdn = waf = None
    for provider, sigs in CDN_WAF_SIGNATURES.items():
        if any(sig in blob for sig in sigs):
            if provider in {"cloudflare", "akamai", "cloudfront", "fastly"}:
                cdn = provider
            else:
                waf = provider
    return cdn, waf


def validate_naabu_ports(host: Host, ports: list[Port]) -> list[str]:
    """Validate naabu output and return warnings."""
    warnings: list[str] = []
    by_host: Counter[str] = Counter()

    for port in ports:
        by_host[port.host] += 1

    total = len(ports)
    if total > SUSPICIOUS_TOTAL_NAABU:
        warnings.append(
            f"Naabu reported {total} open ports total — likely CDN/anycast false positives. "
            "Confidence lowered. Manual validation recommended."
        )

    for hostname, count in by_host.items():
        if count > SUSPICIOUS_NAABU_THRESHOLD:
            warnings.append(
                f"{hostname}: {count} open ports — suspicious. Likely CDN edge or scan artifact."
            )
            for port in ports:
                if port.host == hostname:
                    port.confidence = Confidence.LOW
                    port.warnings.append("High port count — unvalidated")

    return warnings


def validate_dns_resolution(
    subdomains: list[str],
    resolved: list[str],
) -> tuple[list[str], float]:
    """Validate DNS resolution rate and return warnings + ratio."""
    warnings: list[str] = []
    if not subdomains:
        return warnings, 0.0

    ratio = len(resolved) / len(subdomains)
    if ratio < 0.5:
        warnings.append(
            f"Only {len(resolved)}/{len(subdomains)} ({ratio:.0%}) subdomains resolved. "
            "Unresolved hosts will NOT be probed."
        )
    return warnings, ratio


def apply_host_warnings(host: Host) -> None:
    """Apply validation warnings to a host based on its state."""
    if host.is_cdn or host.cdn_provider:
        host.warnings.append(
            f"CDN detected ({host.cdn_provider}) — edge responses may differ from origin"
        )
    if host.waf_provider:
        host.warnings.append(
            f"WAF detected ({host.waf_provider}) — scans may be blocked or rate-limited"
        )
    if host.dns_wildcard:
        host.warnings.append(
            "Wildcard DNS detected — subdomain enumeration may include false positives"
        )
        host.confidence = Confidence.LOW
    if host.tarpit_suspected:
        host.warnings.append(
            "Port scan results unreliable — target responds 'open' to canary ports; "
            "likely tarpit/portspoof defense. Not reporting individual ports as findings."
        )
    if host.soft_404_detected:
        warning = (
            "Soft-404 / catch-all detected — HTTP 200 for nonexistent paths; "
            "URL existence inferred from status codes is unreliable on this host."
        )
        if warning not in host.warnings:
            host.warnings.append(warning)
    for warning in validate_dns_records(host.dns_records):
        if warning not in host.warnings:
            host.warnings.append(warning)


def annotate_dns_record(record: DnsRecord) -> DnsRecord:
    """Attach security-relevant tags to a DNS record."""
    value = record.value.lower()
    tags: list[str] = []
    if record.record_type == "TXT":
        if "v=spf1" in value:
            tags.append("spf")
            if "+all" in value or " all" in value and "-all" not in value and "~all" not in value:
                tags.append("weak-spf")
        if "v=dmarc1" in value:
            tags.append("dmarc")
            if "p=none" in value:
                tags.append("monitoring-only-dmarc")
        if any(
            token in value
            for token in (
                "google-site-verification",
                "amazonses",
                "ms=",
                "atlassian-domain-verification",
            )
        ):
            tags.append("domain-verification")
    elif record.record_type == "CAA":
        tags.append("certificate-authority-policy")
    elif record.record_type == "MX":
        tags.append("mail-surface")
    elif record.record_type == "SRV":
        tags.append("service-discovery")
    elif record.record_type == "CNAME":
        if any(
            token in value
            for token in ("s3.amazonaws.com", "github.io", "herokuapp.com", "azurewebsites.net")
        ):
            tags.append("takeover-watch")
    record.security_tags = list(dict.fromkeys([*record.security_tags, *tags]))
    return record


def validate_dns_records(records: list[DnsRecord]) -> list[str]:
    """Return DNS security notes for a host."""
    warnings: list[str] = []
    types = {record.record_type for record in records}
    tags = {tag for record in records for tag in record.security_tags}
    if "MX" in types and "spf" not in tags:
        warnings.append("Mail exchanger found without SPF TXT record observed")
    if "weak-spf" in tags:
        warnings.append("Weak SPF policy observed")
    if "monitoring-only-dmarc" in tags:
        warnings.append("DMARC policy is monitoring-only")
    if "takeover-watch" in tags:
        warnings.append(
            "CNAME points at a provider commonly associated with dangling-host takeovers"
        )
    return warnings


def parse_naabu_line(line: str) -> Port | None:
    """Parse a naabu output line into a Port object."""
    line = line.strip()
    if not line:
        return None
    # host:port or ip:port
    match = re.match(r"^([\w.\-]+):(\d+)$", line)
    if not match:
        return None
    host, port_str = match.groups()
    return Port(host=host, port=int(port_str), source="naabu", confidence=Confidence.UNKNOWN)
