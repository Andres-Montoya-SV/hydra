"""Canonical normalized asset model for reconnaissance intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.domain import parse_hostname
from core.provenance import ProvenanceRecord, utc_now_iso


class Confidence(str, Enum):
    """Finding confidence level."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Host risk priority."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HostCategory(str, Enum):
    """Infrastructure role classification."""

    AUTHENTICATION = "authentication"
    PAYMENTS = "payments"
    CHECKOUT = "checkout"
    IDENTITY = "identity"
    API = "api"
    ADMIN = "admin"
    SELLER = "seller"
    PARTNER = "partner"
    MARKETING = "marketing"
    SUPPORT = "support"
    MEDIA = "media"
    STORAGE = "storage"
    CDN = "cdn"
    INTERNAL = "internal"
    SCAREWARE = "scareware"
    PHISHING_KIT = "phishing_kit"
    CLOAKING_LAYER = "cloaking_layer"
    AD_REDIRECTOR = "ad_redirector"
    UNKNOWN = "unknown"


CONFIDENCE_SCORE: dict[Confidence, int] = {
    Confidence.HIGH: 100,
    Confidence.MEDIUM: 80,
    Confidence.LOW: 50,
    Confidence.UNKNOWN: 25,
}


def normalize_domain(domain: str) -> str:
    """Return the canonical key used for host-level deduplication."""
    return domain.strip().lower().rstrip(".")


def normalize_http_url(url: str) -> str:
    """Canonical HTTP(S) URL: lowercase host, drop default ports and fragments."""
    from urllib.parse import urlparse, urlunparse

    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    scheme = (parsed.scheme or "https").lower()
    if scheme not in {"http", "https"}:
        scheme = "https"
    host = normalize_domain(parsed.hostname or "")
    if not host:
        return raw.split("#", 1)[0]
    try:
        port = parsed.port
    except ValueError:
        port = None
    default = 443 if scheme == "https" else 80
    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host
    if port and port != default:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


@dataclass
class TechnologyFinding:
    """Technology stack entry with provenance."""

    name: str
    source: str
    confidence: int
    verified_by: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=utc_now_iso)
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "confidence": self.confidence,
            "verified_by": self.verified_by,
            "discovered_at": self.discovered_at,
            "version": self.version,
        }


@dataclass
class Port:
    """Network port finding."""

    host: str
    port: int
    protocol: str = "tcp"
    banner: str | None = None
    source: str = "naabu"
    confidence: Confidence = Confidence.UNKNOWN
    confidence_score: int = 50
    validated: bool = False
    verification_state: str = "unverified"
    service: str | None = None
    version: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class HttpService:
    """HTTP/HTTPS service metadata."""

    url: str
    host: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: list[TechnologyFinding] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    content_length: int | None = None
    favicon_hash: str | None = None
    body_hash: str | None = None
    response_fingerprint: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    response_size: int | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    cdn: str | None = None
    waf: str | None = None
    source: str = "httpx"
    confidence: Confidence = Confidence.UNKNOWN
    confidence_score: int = 80
    screenshot_path: str | None = None

    def tech_names(self) -> list[str]:
        return [t.name for t in self.technologies]


@dataclass
class DnsRecord:
    """DNS record for a host."""

    host: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    security_tags: list[str] = field(default_factory=list)
    source: str = "dnsx"
    confidence_score: int = 80


@dataclass
class TlsCertificate:
    """TLS certificate metadata.

    Identity for intelligence correlation is ``fingerprint_sha256`` (leaf
    SHA-256). SAN lists are observations on the certificate, never its id.
    """

    host: str
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = field(default_factory=list)
    not_after: str | None = None
    not_before: str | None = None
    fingerprint_sha256: str | None = None
    is_wildcard: bool = False
    source: str = "httpx"
    confidence_score: int = 90


@dataclass
class URL:
    """Discovered URL (crawl, archive, or endpoint)."""

    url: str
    host: str
    source: str
    discovered_at: str = field(default_factory=utc_now_iso)
    confidence_score: int = 60
    path: str = ""
    parameters: list[str] = field(default_factory=list)
    endpoint_type: str = "page"
    secrets: list[str] = field(default_factory=list)
    jwts: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Security finding (e.g. nuclei template match)."""

    host: str
    template_id: str
    severity: str
    name: str
    source: str = "nuclei"
    url: str | None = None
    description: str = ""
    confidence_score: int = 80
    discovered_at: str = field(default_factory=utc_now_iso)


@dataclass
class HostProfile:
    """Automatic infrastructure profile for a host."""

    category: HostCategory = HostCategory.UNKNOWN
    priority: RiskLevel = RiskLevel.INFO
    has_authentication: bool = False
    has_api: bool = False
    has_graphql: bool = False
    cloud_provider: str | None = None
    certificate_type: str | None = None
    related_hosts: list[str] = field(default_factory=list)
    summary: str = ""
    confidence_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "priority": self.priority.value,
            "has_authentication": self.has_authentication,
            "has_api": self.has_api,
            "has_graphql": self.has_graphql,
            "cloud_provider": self.cloud_provider,
            "certificate_type": self.certificate_type,
            "related_hosts": self.related_hosts,
            "summary": self.summary,
            "confidence_score": self.confidence_score,
        }


@dataclass
class Host:
    """Canonical host object — single source of truth per domain."""

    domain: str
    hostname: str = ""
    root_domain: str = ""
    subdomain: str = ""
    ips: list[str] = field(default_factory=list)
    asn: str | None = None
    asn_org: str | None = None
    cidr: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str | None = None
    cloud_provider: str | None = None
    cloud_region: str | None = None
    registrar: str | None = None
    registration_created_at: str | None = None
    registration_expires_at: str | None = None
    nameservers: list[str] = field(default_factory=list)
    is_cdn: bool = False
    is_waf: bool = False
    cdn_provider: str | None = None
    waf_provider: str | None = None
    dns_resolved: bool = False
    dns_wildcard: bool = False
    # True when a pre-scan canary probe (arbitrary high ports with no
    # standard/real-world service association) came back "open", indicating
    # the host sits behind a tarpit/portspoof anti-reconnaissance defense
    # that fabricates open-port responses. When set, naabu/port_verify port
    # data for this host is preserved (not discarded) but must never be
    # treated as a reliable security finding — see core/confidence.py and
    # core/intelligence/risk.py, which both discount port signal for
    # tarpit-suspected hosts.
    tarpit_suspected: bool = False
    tarpit_canary_ports: list[int] = field(default_factory=list)
    # True when a random nonexistent path returned HTTP 200 with a body
    # substantially identical to the site root — the server does not
    # distinguish valid from invalid routes (soft-404 / catch-all). URL
    # "existence" inferred from status codes alone is then unreliable.
    soft_404_detected: bool = False
    security_headers_score: int | None = None
    ports: list[Port] = field(default_factory=list)
    http_services: list[HttpService] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)
    tls: TlsCertificate | None = None
    urls: list[URL] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovery_sources: list[str] = field(default_factory=list)
    provenance: list[ProvenanceRecord] = field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    confidence_score: int = 25
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    cluster_ids: dict[str, str] = field(default_factory=dict)
    profile: HostProfile | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    scan_timestamp: str | None = None

    def __post_init__(self) -> None:
        self.domain = normalize_domain(self.domain)
        if not self.hostname:
            self.hostname, self.subdomain, self.root_domain = parse_hostname(self.domain)
        if not self.scan_timestamp:
            self.scan_timestamp = utc_now_iso()
        if not self.first_seen:
            self.first_seen = self.scan_timestamp
        if not self.last_seen:
            self.last_seen = self.scan_timestamp

    def add_source(self, source: str) -> None:
        if source and source not in self.discovery_sources:
            self.discovery_sources.append(source)

    def add_provenance(self, record: ProvenanceRecord) -> None:
        self.provenance.append(record)
        self.add_source(record.tool)
        if record.confidence > self.confidence_score:
            self.confidence_score = record.confidence

    def merge_from(self, other: Host) -> None:
        """Merge another partial Host into this one (idempotent)."""
        now = utc_now_iso()
        self.last_seen = now

        for src in other.discovery_sources:
            self.add_source(src)
        # Dedup on (tool, field, value) rather than full-object equality —
        # ProvenanceRecord carries a microsecond-precision discovered_at
        # timestamp, so two records built from the exact same observation
        # would never compare equal and would accumulate unbounded.
        existing_keys = {(rec.tool, rec.field, rec.value) for rec in self.provenance}
        for rec in other.provenance:
            key = (rec.tool, rec.field, rec.value)
            if key not in existing_keys:
                self.provenance.append(rec)
                existing_keys.add(key)

        for ip in other.ips:
            if ip not in self.ips:
                self.ips.append(ip)

        if other.asn:
            self.asn = other.asn
        if other.asn_org:
            self.asn_org = other.asn_org
        if other.cidr:
            self.cidr = other.cidr
        if other.country:
            self.country = other.country
        if other.provider:
            self.provider = other.provider
        if other.registrar:
            self.registrar = other.registrar
        if other.registration_created_at:
            self.registration_created_at = other.registration_created_at
        if other.registration_expires_at:
            self.registration_expires_at = other.registration_expires_at
        for nameserver in other.nameservers:
            if nameserver not in self.nameservers:
                self.nameservers.append(nameserver)

        if other.is_cdn:
            self.is_cdn = True
            self.cdn_provider = other.cdn_provider or self.cdn_provider
        if other.is_waf:
            self.is_waf = True
            self.waf_provider = other.waf_provider or self.waf_provider

        if other.dns_resolved:
            self.dns_resolved = True
        if other.dns_wildcard:
            self.dns_wildcard = True
        if other.tarpit_suspected:
            self.tarpit_suspected = True
        for port in other.tarpit_canary_ports:
            if port not in self.tarpit_canary_ports:
                self.tarpit_canary_ports.append(port)
        if other.soft_404_detected:
            self.soft_404_detected = True
        if other.security_headers_score is not None:
            self.security_headers_score = other.security_headers_score

        self._merge_ports(other.ports)
        self._merge_http(other.http_services)
        self._merge_dns(other.dns_records)
        self._merge_urls(other.urls)
        self._merge_findings(other.findings)

        if other.tls:
            self.tls = other.tls

        for w in other.warnings:
            if w not in self.warnings:
                self.warnings.append(w)

        if other.confidence_score > self.confidence_score:
            self.confidence_score = other.confidence_score

    def _merge_ports(self, ports: list[Port]) -> None:
        existing = {(p.host, p.port, p.protocol): p for p in self.ports}
        for port in ports:
            key = (port.host, port.port, port.protocol)
            current = existing.get(key)
            if current is None:
                self.ports.append(port)
                existing[key] = port
                continue
            if port.verification_state != "unverified":
                current.verification_state = port.verification_state
                current.validated = port.validated
                current.service = port.service or current.service
                current.version = port.version or current.version
                current.banner = port.banner or current.banner
                current.confidence = port.confidence
                current.confidence_score = port.confidence_score
                current.source = port.source
            for warning in port.warnings:
                if warning not in current.warnings:
                    current.warnings.append(warning)

    def _merge_http(self, services: list[HttpService]) -> None:
        existing = {s.url for s in self.http_services}
        for svc in services:
            if svc.url not in existing:
                self.http_services.append(svc)
                existing.add(svc.url)

    def _merge_dns(self, records: list[DnsRecord]) -> None:
        existing = {(r.record_type, r.value) for r in self.dns_records}
        for rec in records:
            key = (rec.record_type, rec.value)
            if key not in existing:
                self.dns_records.append(rec)
                existing.add(key)

    def _merge_urls(self, urls: list[URL]) -> None:
        existing = {u.url for u in self.urls}
        for url in urls:
            if url.url not in existing:
                self.urls.append(url)
                existing.add(url.url)

    def _merge_findings(self, findings: list[Finding]) -> None:
        existing = {(f.template_id, f.url) for f in self.findings}
        for finding in findings:
            key = (finding.template_id, finding.url)
            if key not in existing:
                self.findings.append(finding)
                existing.add(key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "hostname": self.hostname,
            "root_domain": self.root_domain,
            "subdomain": self.subdomain,
            "ips": self.ips,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "cidr": self.cidr,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "provider": self.provider,
            "cloud_provider": self.cloud_provider,
            "cloud_region": self.cloud_region,
            "registrar": self.registrar,
            "registration_created_at": self.registration_created_at,
            "registration_expires_at": self.registration_expires_at,
            "nameservers": self.nameservers,
            "is_cdn": self.is_cdn,
            "cdn_provider": self.cdn_provider,
            "waf_provider": self.waf_provider,
            "dns_resolved": self.dns_resolved,
            "dns_wildcard": self.dns_wildcard,
            "tarpit_suspected": self.tarpit_suspected,
            "tarpit_canary_ports": self.tarpit_canary_ports,
            "soft_404_detected": self.soft_404_detected,
            "security_headers_score": self.security_headers_score,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "risk_reasons": self.risk_reasons,
            "discovery_sources": self.discovery_sources,
            "warnings": self.warnings,
            "cluster_ids": self.cluster_ids,
            "profile": self.profile.to_dict() if self.profile else None,
            "http_count": len(self.http_services),
            "port_count": len(self.ports),
            "url_count": len(self.urls),
            "finding_count": len(self.findings),
            "findings": [
                {
                    "template_id": f.template_id,
                    "severity": f.severity,
                    "name": f.name,
                    "source": f.source,
                    "url": f.url,
                    "description": f.description,
                    "confidence_score": f.confidence_score,
                }
                for f in self.findings[:50]
            ],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scan_timestamp": self.scan_timestamp,
            "http_services": [
                {
                    "url": s.url,
                    "status_code": s.status_code,
                    "title": s.title,
                    "technologies": [t.to_dict() for t in s.technologies],
                    "cdn": s.cdn,
                    "waf": s.waf,
                    "favicon_hash": s.favicon_hash,
                    "content_length": s.content_length,
                    "response_size": s.response_size,
                    "tls_version": s.tls_version,
                    "tls_cipher": s.tls_cipher,
                    "security_headers": s.security_headers,
                    "confidence_score": s.confidence_score,
                }
                for s in self.http_services
            ],
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "source": p.source,
                    "confidence_score": p.confidence_score,
                    "verification_state": p.verification_state,
                    "service": p.service,
                    "version": p.version,
                }
                for p in self.ports[:50]
            ],
        }


@dataclass
class ScanRun:
    """Metadata for a single reconnaissance run."""

    run_id: str
    started_at: str
    finished_at: str | None = None
    targets: list[str] = field(default_factory=list)
    program_name: str = ""
    host_count: int = 0
    alive_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class InfrastructureCluster:
    """Group of related hosts sharing an infrastructure signal."""

    cluster_id: str
    cluster_type: str
    signal: str
    members: list[str] = field(default_factory=list)
    confidence: int = 80
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_type": self.cluster_type,
            "signal": self.signal,
            "members": self.members,
            "member_count": len(self.members),
            "confidence": self.confidence,
            "description": self.description,
        }


@dataclass
class GraphNode:
    """Node in the infrastructure relationship graph."""

    node_id: str
    node_type: str  # host, ip, asn, cdn, cert, technology, cluster
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Directed relationship between graph nodes."""

    source_id: str
    target_id: str
    relation: str
    confidence: int = 80
    evidence_id: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    confidence_label: str | None = None


@dataclass
class InfrastructureGraph:
    """Queryable infrastructure relationship graph."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def neighbors(self, node_id: str, relation: str | None = None) -> list[str]:
        result = []
        for edge in self.edges:
            if edge.source_id == node_id and (relation is None or edge.relation == relation):
                result.append(edge.target_id)
            elif edge.target_id == node_id and (relation is None or edge.relation == relation):
                result.append(edge.source_id)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [vars(n) for n in self.nodes.values()],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relation": e.relation,
                    "confidence": e.confidence,
                    "confidence_label": e.confidence_label,
                    "evidence_id": e.evidence_id,
                    "first_seen": e.first_seen,
                    "last_seen": e.last_seen,
                }
                for e in self.edges
            ],
        }


class AssetCollection:
    """In-memory collection of canonical Host objects."""

    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}

    def __len__(self) -> int:
        return len(self._hosts)

    def __iter__(self):
        return iter(self._hosts.values())

    def values(self) -> list[Host]:
        return list(self._hosts.values())

    def items(self):
        return self._hosts.items()

    def get(self, domain: str) -> Host | None:
        return self._hosts.get(normalize_domain(domain))

    def get_or_create(self, domain: str) -> Host:
        domain = normalize_domain(domain)
        if domain not in self._hosts:
            self._hosts[domain] = Host(domain=domain)
        return self._hosts[domain]

    def merge(self, partial: Host) -> Host:
        host = self.get_or_create(partial.domain)
        host.merge_from(partial)
        return host

    def to_dict(self) -> dict[str, Host]:
        return self._hosts
