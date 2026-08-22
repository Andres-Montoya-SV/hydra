"""Per-tool output parsers — normalize raw artifacts into canonical Host objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from core.assets import (
    URL,
    Confidence,
    DnsRecord,
    Finding,
    Host,
    HttpService,
    Port,
    TechnologyFinding,
    TlsCertificate,
    normalize_domain,
    normalize_http_url,
)
from core.parsers.crawlers import parse_crawler_output
from core.provenance import record_observation
from core.validation.engine import annotate_dns_record, detect_cdn_waf, parse_naabu_line
from utils.files import read_jsonl, read_lines

_SECURITY_HEADER_KEYS = frozenset(
    {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "permissions-policy",
        "referrer-policy",
    }
)

# Response headers that can carry session/credential material reflected by the
# target. These are never persisted to the intelligence store or reports —
# capturing them would create a local artifact that itself becomes sensitive
# (and a potential deanonymization/credential-leak vector if the run output is
# ever shared, synced, or exfiltrated).
_SENSITIVE_RESPONSE_HEADER_KEYS = frozenset(
    {
        "set-cookie",
        "set-cookie2",
        "authorization",
        "proxy-authorization",
    }
)


def _redact_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k not in _SENSITIVE_RESPONSE_HEADER_KEYS}


def _host_from_domain(domain: str, tool: str, artifact: str | None = None) -> Host:
    host = Host(domain=normalize_domain(domain))
    host.add_provenance(
        record_observation(
            tool=tool,
            field="hostname",
            value=host.domain,
            confidence=80 if tool in {"subfinder", "assetfinder"} else 90,
            artifact_path=artifact,
        )
    )
    return host


def _extract_domain(value: str) -> str:
    value = value.strip().lower().strip("[]")
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    hostname = parsed.hostname or value.split()[0].split(":")[0]
    return normalize_domain(hostname)


class ToolParser(ABC):
    tool_name: str

    @abstractmethod
    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]: ...


class SubdomainParser(ToolParser):
    tool_name = "subfinder"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "subfinder.txt"
        if path.name == "subdomains.txt" and (output_dir / "subfinder.txt").exists():
            path = output_dir / "subfinder.txt"
        if not path.exists() and artifact is None:
            path = output_dir / "subdomains.txt"
        if not path.exists():
            return [], []
        tool = self.tool_name
        artifact_str = str(path)
        return (
            _dedupe_hosts(_host_from_domain(line, tool, artifact_str) for line in read_lines(path)),
            [],
        )


class AssetfinderParser(SubdomainParser):
    tool_name = "assetfinder"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "assetfinder.txt"
        if path.name == "subdomains.txt" and (output_dir / "assetfinder.txt").exists():
            path = output_dir / "assetfinder.txt"
        if not path.exists() and artifact is None:
            path = output_dir / "subdomains.txt"
        if not path.exists():
            return [], []
        return (
            _dedupe_hosts(
                _host_from_domain(line, "assetfinder", str(path)) for line in read_lines(path)
            ),
            [],
        )


class AmassParser(SubdomainParser):
    """Parser for amass passive subdomain enumeration output."""

    tool_name = "amass"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "amass.txt"
        if path.name == "subdomains.txt" and (output_dir / "amass.txt").exists():
            path = output_dir / "amass.txt"
        if not path.exists():
            return [], []
        return (
            _dedupe_hosts(_host_from_domain(line, "amass", str(path)) for line in read_lines(path)),
            [],
        )


class DnsxParser(ToolParser):
    tool_name = "dnsx"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        # Prefer the full JSONL record dump if present
        jsonl_path = output_dir / "dnsx_records.jsonl"
        plain_path = artifact or output_dir / "resolved.txt"

        if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
            return self._parse_jsonl(jsonl_path)
        if plain_path.exists():
            return self._parse_plain(plain_path)
        return [], []

    def _parse_jsonl(self, path: Path) -> tuple[list[Host], list[str]]:
        import json

        by_host: dict[str, Host] = {}
        artifact_str = str(path)

        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain = rec.get("host", "").strip().rstrip(".")
            if not domain:
                continue

            host = by_host.setdefault(domain, Host(domain=domain))
            host.dns_resolved = True
            host.add_provenance(
                record_observation(
                    tool="dnsx",
                    field="dns_resolved",
                    value="true",
                    confidence=90,
                    verified_by=["dnsx"],
                    artifact_path=artifact_str,
                )
            )

            # A records
            ttl = _parse_ttl(rec)
            for ip in rec.get("a", []) or []:
                ip = str(ip).strip()
                if ip and ip not in host.ips:
                    host.ips.append(ip)
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="A",
                            value=ip,
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # AAAA
            for ip in rec.get("aaaa", []) or []:
                ip = str(ip).strip()
                if ip and ip not in host.ips:
                    host.ips.append(ip)
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="AAAA",
                            value=ip,
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # CNAME
            for cname in rec.get("cname", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="CNAME",
                            value=str(cname).rstrip("."),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # MX
            for mx in rec.get("mx", []) or []:
                priority, value = _parse_priority_value(mx)
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="MX",
                            value=value.rstrip("."),
                            ttl=ttl,
                            priority=priority,
                            source="dnsx",
                        )
                    )
                )

            # TXT
            for txt in rec.get("txt", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="TXT",
                            value=str(txt),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # NS
            for ns in rec.get("ns", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="NS",
                            value=str(ns).rstrip("."),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # SOA
            for soa in rec.get("soa", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="SOA",
                            value=str(soa),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            # CAA
            for caa in rec.get("caa", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="CAA",
                            value=str(caa),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

            for srv in rec.get("srv", []) or []:
                priority, value = _parse_priority_value(srv)
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="SRV",
                            value=value.rstrip("."),
                            ttl=ttl,
                            priority=priority,
                            source="dnsx",
                        )
                    )
                )

            for ptr in rec.get("ptr", []) or []:
                host.dns_records.append(
                    annotate_dns_record(
                        DnsRecord(
                            host=domain,
                            record_type="PTR",
                            value=str(ptr).rstrip("."),
                            ttl=ttl,
                            source="dnsx",
                        )
                    )
                )

        return list(by_host.values()), []

    def _parse_plain(self, path: Path) -> tuple[list[Host], list[str]]:
        """Fallback parser for plain-text resolved.txt (hostname [IP] format)."""
        artifact_str = str(path)
        hosts: list[Host] = []
        for line in read_lines(path):
            domain = _extract_domain(line)
            if not domain:
                continue
            host = Host(domain=domain)
            host.dns_resolved = True
            host.add_provenance(
                record_observation(
                    tool="dnsx",
                    field="dns_resolved",
                    value="true",
                    confidence=90,
                    verified_by=["dnsx"],
                    artifact_path=artifact_str,
                )
            )
            parts = line.split()
            if len(parts) > 1:
                for token in parts[1:]:
                    token = token.strip("[]")
                    if _looks_like_ip(token):
                        host.ips.append(token)
                        host.dns_records.append(
                            annotate_dns_record(
                                DnsRecord(
                                    host=domain,
                                    record_type="A",
                                    value=token,
                                    source="dnsx",
                                )
                            )
                        )
            hosts.append(host)
        return hosts, []


class HttpxParser(ToolParser):
    tool_name = "httpx"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "httpx.json"
        if not path.exists():
            return [], []
        artifact_str = str(path)
        hosts: list[Host] = []
        for record in read_jsonl(path):
            domain = _extract_domain(record.get("input", record.get("host", record.get("url", ""))))
            if not domain:
                continue
            host = Host(domain=domain)
            host.dns_resolved = True
            host.add_provenance(
                record_observation(
                    tool="httpx",
                    field="http_alive",
                    value=record.get("url", domain),
                    confidence=95,
                    verified_by=["status_code", "headers"],
                    artifact_path=artifact_str,
                )
            )

            headers = record.get("header", {}) or {}
            flat = (
                {str(k).lower(): str(v) for k, v in headers.items()}
                if isinstance(headers, dict)
                else {}
            )
            flat = _redact_sensitive_headers(flat)
            server = record.get("webserver")
            cdn, waf = detect_cdn_waf(flat, server)

            if cdn:
                host.is_cdn = True
                host.cdn_provider = cdn
            if waf:
                host.is_waf = True
                host.waf_provider = waf

            for ip in record.get("a", []) or []:
                if ip and str(ip) not in host.ips:
                    host.ips.append(str(ip))
            ip_value = record.get("ip")
            if ip_value and str(ip_value) not in host.ips:
                host.ips.append(str(ip_value))

            # Intentionally NOT setting host.asn/asn_org/cidr/country from
            # httpx's JSON here: asn_lookup (Team Cymru) is the dedicated,
            # authoritative source for these fields and is ingested before
            # httpx in _finalize_to_store's ingest_tools order. Host.merge_from
            # does "last write wins" with no confidence comparison, so letting
            # httpx also populate these would silently degrade accuracy if a
            # future httpx version/flag starts emitting an "asn" field.

            tech_raw = record.get("tech", [])
            technologies = []
            if isinstance(tech_raw, list):
                for t in tech_raw:
                    from modules.vuln_match import parse_tech_name_version

                    name, version = parse_tech_name_version(str(t))
                    technologies.append(
                        TechnologyFinding(
                            name=name,
                            source="httpx",
                            confidence=95,
                            verified_by=["headers", "response"],
                            version=version,
                        )
                    )

            security_headers = {k: v for k, v in flat.items() if k in _SECURITY_HEADER_KEYS}

            redirect_chain = record.get("chain", []) or record.get("redirect_chain", [])
            if isinstance(redirect_chain, list):
                chain = [str(u) for u in redirect_chain]
            else:
                chain = []

            svc = HttpService(
                url=normalize_http_url(str(record.get("url") or "")) or str(record.get("url") or ""),
                host=domain,
                status_code=record.get("status_code"),
                title=record.get("title"),
                webserver=server,
                technologies=technologies,
                headers=flat,
                security_headers=security_headers,
                content_length=record.get("content_length"),
                favicon_hash=str(record.get("favicon", "")) or None,
                body_hash=str(record.get("body_hash", record.get("hash", ""))) or None,
                response_fingerprint=str(record.get("hash", "")) or None,
                redirect_chain=chain,
                response_size=_parse_int(
                    record.get("response_size") or record.get("content_length")
                ),
                tls_version=_extract_tls_value(record, "version"),
                tls_cipher=_extract_tls_value(record, "cipher"),
                cdn=cdn,
                waf=waf,
                confidence_score=95,
            )
            host.http_services.append(svc)

            cert = _parse_tls(record, domain)
            if cert:
                host.tls = cert

            hosts.append(host)
        return hosts, []


class NaabuParser(ToolParser):
    tool_name = "naabu"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "naabu.txt"
        if not path.exists():
            return [], []
        artifact_str = str(path)
        by_host: dict[str, Host] = {}
        for line in read_lines(path):
            port = parse_naabu_line(line)
            if not port:
                continue
            port.confidence_score = 50
            host = by_host.setdefault(port.host, Host(domain=port.host))
            host.ports.append(port)
            host.add_provenance(
                record_observation(
                    tool="naabu",
                    field="port",
                    value=f"{port.port}/{port.protocol}",
                    confidence=50,
                    artifact_path=artifact_str,
                )
            )
        return list(by_host.values()), []


class NucleiParser(ToolParser):
    tool_name = "nuclei"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "nuclei.json"
        if not path.exists():
            return [], []
        artifact_str = str(path)
        by_host: dict[str, Host] = {}
        for record in read_jsonl(path):
            domain = _extract_domain(record.get("host", record.get("url", "")))
            if not domain:
                continue
            host = by_host.setdefault(domain, Host(domain=domain))
            info = record.get("info", {}) or {}
            finding = Finding(
                host=domain,
                template_id=str(record.get("template-id", record.get("templateID", ""))),
                severity=str(info.get("severity", record.get("severity", "unknown"))),
                name=str(info.get("name", record.get("template-id", ""))),
                url=record.get("matched-at", record.get("url")),
                confidence_score=80,
            )
            host.findings.append(finding)
            host.add_provenance(
                record_observation(
                    tool="nuclei",
                    field="finding",
                    value=finding.template_id,
                    confidence=80,
                    artifact_path=artifact_str,
                )
            )
        return list(by_host.values()), []


class UrlListParser(ToolParser):
    """Parser for line-based URL discovery tools."""

    tool_name = "gau"
    url_source = "gau"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / f"{self.url_source}.txt"
        if not path.exists():
            return [], []
        artifact_str = str(path)
        by_host: dict[str, Host] = {}
        for line in read_lines(path):
            domain = _extract_domain(line)
            if not domain:
                continue
            host = by_host.setdefault(domain, Host(domain=domain))
            canonical = normalize_http_url(line) or line
            if any(existing.url == canonical for existing in host.urls):
                continue
            host.urls.append(
                URL(url=canonical, host=domain, source=self.url_source, confidence_score=60)
            )
            host.add_provenance(
                record_observation(
                    tool=self.url_source,
                    field="url",
                    value=line[:200],
                    confidence=60,
                    artifact_path=artifact_str,
                )
            )
        return list(by_host.values()), []


class GauParser(UrlListParser):
    tool_name = "gau"
    url_source = "gau"


class WaybackurlsParser(UrlListParser):
    tool_name = "waybackurls"
    url_source = "waybackurls"


class KatanaParser(UrlListParser):
    tool_name = "katana"
    url_source = "katana"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "katana.jsonl"
        if not path.exists() and artifact is None:
            path = output_dir / "katana.txt"
        return parse_crawler_output(path, source=self.url_source)


class HakrawlerParser(UrlListParser):
    tool_name = "hakrawler"
    url_source = "hakrawler"

    def parse(
        self, output_dir: Path, *, artifact: Path | None = None, run_id: str = ""
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "hakrawler.jsonl"
        if not path.exists() and artifact is None:
            path = output_dir / "hakrawler.txt"
        return parse_crawler_output(path, source=self.url_source)


class WhoisParser(ToolParser):
    """Normalize parsed WHOIS registration metadata."""

    tool_name = "whois"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "whois.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("domain", "")))
            if not domain:
                continue
            host = Host(
                domain=domain,
                registrar=_optional_str(record.get("registrar")),
                registration_created_at=_optional_str(record.get("created_at")),
                registration_expires_at=_optional_str(record.get("expires_at")),
                nameservers=[
                    normalize_domain(str(value)) for value in record.get("nameservers", []) if value
                ],
            )
            host.add_provenance(
                record_observation(
                    tool="whois",
                    field="registration",
                    value=host.registrar or domain,
                    confidence=90,
                    verified_by=["registry_whois"],
                    artifact_path=str(path),
                )
            )
            hosts.append(host)
        return hosts, []


class PortVerifyParser(ToolParser):
    """Merge nmap service evidence into Naabu port observations."""

    tool_name = "port_verify"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "port_verify.jsonl"
        by_host: dict[str, Host] = {}
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("host", "")))
            port_number = _parse_int(record.get("port"))
            if not domain or port_number is None:
                continue

            state = str(record.get("nmap_state", "unknown"))
            verified = state == "open"
            confidence_score = 100 if verified else 10 if state in {"filtered", "closed"} else 25
            service = _optional_str(record.get("service"))
            version = _optional_str(record.get("version"))
            warning = (
                [] if verified else [f"Naabu reported open; nmap classified this port as {state}"]
            )
            port = Port(
                host=domain,
                port=port_number,
                protocol=str(record.get("protocol", "tcp")),
                banner=" ".join(value for value in (service, version) if value) or None,
                source="naabu+nmap",
                confidence=Confidence.HIGH if verified else Confidence.UNKNOWN,
                confidence_score=confidence_score,
                validated=verified,
                verification_state="verified_open" if verified else state,
                service=service,
                version=version,
                warnings=warning,
            )
            host = by_host.setdefault(domain, Host(domain=domain))
            host.ports.append(port)
            host.add_provenance(
                record_observation(
                    tool="port_verify",
                    field="port_verification",
                    value=f"{port_number}/{port.protocol}:{state}",
                    confidence=confidence_score,
                    verified_by=["nmap_service_detection"],
                    artifact_path=str(path),
                )
            )
        return list(by_host.values()), []


class ThreatIntelParser(ToolParser):
    """Turn URLhaus confirmations into high-severity canonical findings."""

    tool_name = "threat_intel"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "threat_intel.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            if record.get("query_status") != "ok":
                continue
            urls = record.get("urls")
            online = (
                [
                    item
                    for item in urls
                    if isinstance(item, dict) and item.get("url_status") == "online"
                ]
                if isinstance(urls, list)
                else []
            )
            domain = normalize_domain(str(record.get("query_host", "")))
            if not domain or not online:
                continue

            threats = sorted(
                {str(item.get("threat", "")).strip() for item in online if item.get("threat")}
            )
            tags = sorted(
                {
                    str(tag)
                    for item in online
                    for tag in (item.get("tags") or [])
                    if isinstance(item.get("tags"), list)
                }
            )
            details = [f"{len(online)} online malicious URL(s) confirmed by URLhaus"]
            if threats:
                details.append("threats: " + ", ".join(threats))
            if tags:
                details.append("tags: " + ", ".join(tags))

            host = Host(domain=domain)
            finding = Finding(
                host=domain,
                template_id="urlhaus-known-malicious",
                severity="high",
                name="Host has online URLs catalogued as malicious by URLhaus",
                source="threat_intel",
                url=_optional_str(online[0].get("url")),
                description="; ".join(details),
                confidence_score=95,
            )
            host.findings.append(finding)
            host.add_provenance(
                record_observation(
                    tool="threat_intel",
                    field="finding",
                    value=finding.template_id,
                    confidence=95,
                    verified_by=["urlhaus"],
                    artifact_path=str(path),
                )
            )
            hosts.append(host)
        return hosts, []


class BrowserProbeParser(ToolParser):
    """Create a finding when browser and httpx destinations disagree."""

    tool_name = "browser_probe"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "browser_probe.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            if not record.get("cloaking_suspected"):
                continue
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            httpx_url = str(record.get("httpx_final_url", ""))
            browser_url = str(record.get("browser_final_url", ""))
            host = Host(domain=domain)
            finding = Finding(
                host=domain,
                template_id="cloaking-detected",
                severity="medium",
                name="Browser destination differs from HTTP probe",
                source="browser_probe",
                url=browser_url or None,
                description=(
                    f"httpx ended at {httpx_url}; mobile WebKit ended at {browser_url}. "
                    "Different destination hosts can indicate cloaking, conditional "
                    "redirects, or ordinary client-specific routing; verify manually."
                ),
                confidence_score=75,
            )
            host.findings.append(finding)
            host.add_provenance(
                record_observation(
                    tool="browser_probe",
                    field="finding",
                    value=finding.template_id,
                    confidence=75,
                    verified_by=["webkit", "httpx_comparison"],
                    artifact_path=str(path),
                )
            )
            hosts.append(host)
        return hosts, []


class CtlogsParser(ToolParser):
    """Normalize Certificate Transparency hostnames."""

    tool_name = "ctlogs"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "ctlogs_domains.txt"
        if path.name == "ctlogs.jsonl":
            path = output_dir / "ctlogs_domains.txt"
        if not path.exists():
            return [], []
        hosts: list[Host] = []
        for domain in read_lines(path):
            host = Host(domain=domain)
            host.add_provenance(
                record_observation(
                    tool="ctlogs",
                    field="hostname",
                    value=host.domain,
                    confidence=70,
                    verified_by=["certificate_transparency"],
                    artifact_path=str(path),
                )
            )
            hosts.append(host)
        return hosts, []


class WildcardCheckParser(ToolParser):
    """Attach wildcard-DNS canary results and an informational finding."""

    tool_name = "wildcard_check"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "wildcard_check.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("root_domain", "")))
            if not domain:
                continue
            detected = bool(record.get("wildcard_dns_detected"))
            canaries = [str(h) for h in (record.get("canary_hosts") or []) if h]
            resolved = [str(h) for h in (record.get("canary_resolved") or []) if h]
            host = Host(domain=domain, dns_wildcard=detected)
            if detected:
                finding = Finding(
                    host=domain,
                    template_id="wildcard-dns-detected",
                    severity="info",
                    name="Root domain resolves improbable canary subdomains (wildcard DNS)",
                    source="wildcard_check",
                    description=(
                        f"{len(resolved)}/{len(canaries)} random canary subdomain(s) "
                        f"resolved under {domain} "
                        f"({', '.join(resolved) or 'n/a'}). Passively discovered "
                        "subdomains under this root that lack independent confirmation "
                        "(e.g. Certificate Transparency or a live HTTP service) are "
                        "likely wildcard false positives — confidence is demoted, not "
                        "discarded."
                    ),
                    confidence_score=90,
                )
                host.findings.append(finding)
                host.warnings.append(
                    "Wildcard DNS detected — passively enumerated subdomains may be "
                    "false positives until independently confirmed"
                )
                host.add_provenance(
                    record_observation(
                        tool="wildcard_check",
                        field="finding",
                        value=finding.template_id,
                        confidence=90,
                        verified_by=["canary_subdomains"],
                        artifact_path=str(path),
                    )
                )
            else:
                host.add_provenance(
                    record_observation(
                        tool="wildcard_check",
                        field="dns_wildcard",
                        value="false",
                        confidence=90,
                        artifact_path=str(path),
                    )
                )
            hosts.append(host)
        return hosts, []


class Soft404CheckParser(ToolParser):
    """Attach soft-404 canary results and an informational finding."""

    tool_name = "soft404_check"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "soft404_check.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            detected = bool(record.get("soft_404_detected"))
            host = Host(domain=domain, soft_404_detected=detected)
            if detected:
                canary_url = _optional_str(record.get("canary_url"))
                finding = Finding(
                    host=domain,
                    template_id="soft-404-detected",
                    severity="info",
                    name="Host returns HTTP 200 for nonexistent paths (soft-404 / catch-all)",
                    source="soft404_check",
                    url=canary_url,
                    description=(
                        f"Random nonexistent path {canary_url or '(canary)'} returned "
                        f"HTTP {record.get('canary_status')} with a body matching the "
                        f"site root (hash={record.get('canary_body_hash', '')[:16]}…). "
                        "URL existence inferred from status codes alone is unreliable "
                        "on this host."
                    ),
                    confidence_score=85,
                )
                host.findings.append(finding)
                host.warnings.append(
                    "Soft-404 / catch-all detected — HTTP 200 does not confirm a real path"
                )
                host.add_provenance(
                    record_observation(
                        tool="soft404_check",
                        field="finding",
                        value=finding.template_id,
                        confidence=85,
                        verified_by=["canary_path"],
                        artifact_path=str(path),
                    )
                )
            else:
                host.add_provenance(
                    record_observation(
                        tool="soft404_check",
                        field="soft_404_detected",
                        value="false",
                        confidence=85,
                        artifact_path=str(path),
                    )
                )
            hosts.append(host)
        return hosts, []


class TarpitCheckParser(ToolParser):
    """Attach tarpit/portspoof canary results and an informational finding."""

    tool_name = "tarpit_check"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "tarpit_check.jsonl"
        hosts: list[Host] = []
        warnings: list[str] = []
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            # A failed probe is NOT evidence that the host is clean — do not
            # attach tarpit_suspected=false provenance for probe_error rows.
            if record.get("probe_error"):
                warnings.append(
                    f"{domain}: tarpit canary probe failed — "
                    f"{record['probe_error']}; check inconclusive"
                )
                continue
            suspected = bool(record.get("tarpit_suspected"))
            canary_ports = [
                port for port in (record.get("canary_ports") or []) if isinstance(port, int)
            ]
            host = Host(
                domain=domain,
                tarpit_suspected=suspected,
                tarpit_canary_ports=canary_ports,
            )
            if suspected:
                opened = [
                    port
                    for port in (record.get("canary_open_ports") or [])
                    if isinstance(port, int)
                ]
                technique = str(record.get("probe_technique") or "nmap -sV")
                finding = Finding(
                    host=domain,
                    template_id="tarpit-detected",
                    severity="info",
                    name="Host responds 'open' to arbitrary canary ports (tarpit/portspoof suspected)",
                    source="tarpit_check",
                    description=(
                        f"{len(opened)}/{len(canary_ports)} canary ports with no standard "
                        f"service association ({', '.join(str(p) for p in canary_ports)}) "
                        f"responded 'open' under {technique}. This host likely runs an "
                        "anti-reconnaissance tarpit/portspoof defense that fabricates "
                        "open-port responses. naabu/port_verify data for this host is "
                        "preserved for audit but must not be treated as a reliable "
                        "security finding unless corroborated by an out-of-band "
                        "service banner."
                    ),
                    confidence_score=90,
                )
                host.findings.append(finding)
                host.add_provenance(
                    record_observation(
                        tool="tarpit_check",
                        field="finding",
                        value=finding.template_id,
                        confidence=90,
                        verified_by=["nmap_sV_canary_ports"],
                        artifact_path=str(path),
                    )
                )
            else:
                host.add_provenance(
                    record_observation(
                        tool="tarpit_check",
                        field="tarpit_suspected",
                        value="false",
                        confidence=90,
                        artifact_path=str(path),
                    )
                )
            hosts.append(host)
        return hosts, warnings


class ASNParser(ToolParser):
    """Apply Team Cymru ownership data to hosts sharing each IP."""

    tool_name = "asn_lookup"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "asn.jsonl"
        ownership = {
            str(record.get("ip", "")): record for record in read_jsonl(path) if record.get("ip")
        }
        if not ownership:
            return [], []

        dns_hosts, _ = DnsxParser().parse(output_dir)
        http_hosts, _ = HttpxParser().parse(output_dir)
        by_domain: dict[str, Host] = {}
        for source_host in [*dns_hosts, *http_hosts]:
            matches = [ownership[ip] for ip in source_host.ips if ip in ownership]
            if not matches:
                continue
            record = matches[0]
            host = by_domain.setdefault(source_host.domain, Host(domain=source_host.domain))
            host.ips = list(dict.fromkeys([*host.ips, *source_host.ips]))
            host.asn = _optional_str(record.get("asn"))
            host.asn_org = _optional_str(record.get("as_name"))
            host.cidr = _optional_str(record.get("bgp_prefix"))
            host.country = _optional_str(record.get("country"))
            host.provider = host.asn_org
            host.add_provenance(
                record_observation(
                    tool="asn_lookup",
                    field="asn",
                    value=host.asn or "",
                    confidence=90,
                    verified_by=["team_cymru"],
                    artifact_path=str(path),
                )
            )
        return list(by_domain.values()), []


class ParamFuzzParser(ToolParser):
    """Create findings for parameters that influence responses / reflect canaries."""

    tool_name = "param_fuzz"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "param_fuzz.jsonl"
        by_host: dict[str, Host] = {}
        for record in read_jsonl(path):
            if record.get("baseline_invalid"):
                continue
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            influences = bool(record.get("parameter_influences_response"))
            reflected = bool(record.get("reflected"))
            if not influences and not reflected:
                continue
            host = by_host.setdefault(domain, Host(domain=domain))
            param = str(record.get("parameter") or "")
            url = _optional_str(record.get("probe_url") or record.get("url"))
            if reflected:
                severity = "medium"
                template_id = "param-reflected"
                name = f"Parameter '{param}' reflects input in response body"
            else:
                severity = "info"
                template_id = "param-influences-response"
                name = f"Parameter '{param}' influences HTTP response"
            finding = Finding(
                host=domain,
                template_id=template_id,
                severity=severity,
                name=name,
                source="param_fuzz",
                url=url,
                description=(
                    f"Probe {url or '(url)'} with {param}=reconprobe123 "
                    f"(baseline status={record.get('baseline_status')}, "
                    f"probe status={record.get('probe_status')}, "
                    f"reflected={reflected}). Existence/behavior only — not exploited."
                ),
                confidence_score=75 if reflected else 65,
            )
            host.findings.append(finding)
            host.add_provenance(
                record_observation(
                    tool="param_fuzz",
                    field="finding",
                    value=template_id,
                    confidence=finding.confidence_score,
                    verified_by=["response_diff"],
                    artifact_path=str(path),
                )
            )
        return list(by_host.values()), []


class CloudBucketEnumParser(ToolParser):
    """Findings for existing cloud buckets (private = info, listable = high)."""

    tool_name = "cloud_bucket_enum"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "cloud_bucket_enum.jsonl"
        hosts: list[Host] = []
        for record in read_jsonl(path):
            bucket = str(record.get("bucket") or "").strip()
            if not bucket:
                continue
            provider = str(record.get("provider") or "cloud")
            url = _optional_str(record.get("url"))
            public = bool(record.get("public_listable"))
            domain = normalize_domain(bucket) or bucket
            host = Host(domain=domain)
            if public:
                severity = "high"
                template_id = "cloud-bucket-public-listable"
                name = f"Publicly listable {provider.upper()} bucket: {bucket}"
                description = (
                    f"{url or bucket} returned a public object listing "
                    f"(classification={record.get('classification')})."
                )
            else:
                severity = "info"
                template_id = "cloud-bucket-exists-private"
                name = f"Existing private {provider.upper()} bucket: {bucket}"
                description = (
                    f"{url or bucket} exists but is not publicly listable "
                    f"(classification={record.get('classification')})."
                )
            finding = Finding(
                host=domain,
                template_id=template_id,
                severity=severity,
                name=name,
                source="cloud_bucket_enum",
                url=url,
                description=description,
                confidence_score=85 if public else 70,
            )
            host.findings.append(finding)
            host.add_provenance(
                record_observation(
                    tool="cloud_bucket_enum",
                    field="finding",
                    value=template_id,
                    confidence=finding.confidence_score,
                    verified_by=[provider],
                    artifact_path=str(path),
                )
            )
            hosts.append(host)
        return hosts, []

        return hosts, []


class VulnMatchParser(ToolParser):
    """CVE/GHSA findings from OSV.dev / WPScan correlation."""

    tool_name = "vuln_match"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "vuln_match.jsonl"
        by_host: dict[str, Host] = {}
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            ident = str(record.get("identifier") or "")
            if not ident:
                continue
            host = by_host.setdefault(domain, Host(domain=domain))
            tech = str(record.get("technology") or "")
            version = str(record.get("version") or "")
            finding = Finding(
                host=domain,
                template_id="vuln-match",
                severity=str(record.get("severity") or "info"),
                name=f"{ident} in {tech} {version}".strip(),
                source="vuln_match",
                url=_optional_str(record.get("url") or record.get("source_url")),
                description=(
                    f"{ident} reported by {record.get('source')} for {tech} {version}. "
                    f"{record.get('summary') or ''} "
                    f"Source: {record.get('source_url') or ''}"
                ).strip(),
                confidence_score=80,
            )
            host.findings.append(finding)
        return list(by_host.values()), []


class SecurityHeadersParser(ToolParser):
    """Informational findings for missing HTTP security headers."""

    tool_name = "security_headers"

    def parse(
        self,
        output_dir: Path,
        *,
        artifact: Path | None = None,
        run_id: str = "",
    ) -> tuple[list[Host], list[str]]:
        path = artifact or output_dir / "security_headers.jsonl"
        by_host: dict[str, Host] = {}
        for record in read_jsonl(path):
            domain = normalize_domain(str(record.get("host", "")))
            if not domain:
                continue
            host = by_host.setdefault(domain, Host(domain=domain))
            score = record.get("security_headers_score")
            if isinstance(score, int):
                host.security_headers_score = score
            if not record.get("missing"):
                continue
            header = str(record.get("header") or record.get("header_key") or "")
            finding = Finding(
                host=domain,
                template_id="missing-security-header",
                severity="info",
                name=f"Missing security header: {header}",
                source="security_headers",
                url=_optional_str(record.get("url")),
                description=f"{header} is not present on {record.get('url')}.",
                confidence_score=70,
            )
            host.findings.append(finding)
        return list(by_host.values()), []


PARSER_REGISTRY: dict[str, ToolParser] = {
    p.tool_name: p
    for p in [
        SubdomainParser(),
        AssetfinderParser(),
        AmassParser(),
        DnsxParser(),
        HttpxParser(),
        NaabuParser(),
        NucleiParser(),
        GauParser(),
        WaybackurlsParser(),
        KatanaParser(),
        HakrawlerParser(),
        WhoisParser(),
        CtlogsParser(),
        ASNParser(),
        PortVerifyParser(),
        ThreatIntelParser(),
        BrowserProbeParser(),
        TarpitCheckParser(),
        WildcardCheckParser(),
        Soft404CheckParser(),
        ParamFuzzParser(),
        CloudBucketEnumParser(),
        VulnMatchParser(),
        SecurityHeadersParser(),
    ]
}


def parse_tool_output(
    tool: str,
    output_dir: Path,
    *,
    artifact: Path | None = None,
    run_id: str = "",
) -> tuple[list[Host], list[str]]:
    parser = PARSER_REGISTRY.get(tool)
    if not parser:
        return [], []
    hosts, warnings = parser.parse(output_dir, artifact=artifact, run_id=run_id)
    return _dedupe_hosts(hosts), warnings


def _dedupe_hosts(hosts) -> list[Host]:
    by_domain: dict[str, Host] = {}
    for host in hosts:
        if not host.domain:
            continue
        key = normalize_domain(host.domain)
        if key in by_domain:
            by_domain[key].merge_from(host)
        else:
            by_domain[key] = host
    return list(by_domain.values())


def _looks_like_ip(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _parse_ttl(record: dict) -> int | None:
    ttl = record.get("ttl")
    if isinstance(ttl, list):
        ttl = ttl[0] if ttl else None
    try:
        return int(ttl) if ttl is not None and str(ttl).strip() else None
    except (TypeError, ValueError):
        return None


def _parse_priority_value(raw: object) -> tuple[int | None, str]:
    if isinstance(raw, dict):
        priority = raw.get("priority") or raw.get("preference")
        value = (
            raw.get("host") or raw.get("target") or raw.get("exchange") or raw.get("value") or ""
        )
        try:
            parsed_priority = int(priority) if priority is not None else None
        except (TypeError, ValueError):
            parsed_priority = None
        return parsed_priority, str(value)
    parts = str(raw).split()
    if len(parts) > 1 and parts[0].isdigit():
        return int(parts[0]), " ".join(parts[1:])
    return None, str(raw)


def _parse_int(raw: object) -> int | None:
    try:
        return int(raw) if raw is not None and str(raw).strip() else None
    except (TypeError, ValueError):
        return None


def _optional_str(raw: object) -> str | None:
    value = str(raw).strip() if raw is not None else ""
    return value or None


def _extract_tls_value(record: dict, key: str) -> str | None:
    tls = record.get("tls") or record.get("certificate") or {}
    if isinstance(tls, dict):
        value = tls.get(key) or tls.get(f"tls_{key}")
        if value:
            return str(value)
    direct = record.get(f"tls_{key}") or record.get(key if key.startswith("tls") else f"tls-{key}")
    return str(direct) if direct else None


def _parse_tls(record: dict, domain: str) -> TlsCertificate | None:
    tls = record.get("tls") or record.get("certificate")
    if not tls or not isinstance(tls, dict):
        return None
    subject = tls.get("subject_cn") or tls.get("subject")
    sans = tls.get("subject_an", tls.get("sans", [])) or []
    if isinstance(sans, str):
        sans = [sans]
    is_wildcard = any(str(s).startswith("*.") for s in sans)
    from core.intel.tls import extract_sans, extract_tls_fingerprint

    fingerprint = extract_tls_fingerprint(tls)
    san_names = extract_sans(sans)
    return TlsCertificate(
        host=domain,
        issuer=str(tls.get("issuer_cn", tls.get("issuer", ""))) or None,
        subject=str(subject) if subject else None,
        sans=san_names,
        not_after=str(tls.get("not_after", "")) or None,
        not_before=str(tls.get("not_before", "")) or None,
        fingerprint_sha256=fingerprint or None,
        is_wildcard=is_wildcard,
        source="httpx",
        confidence_score=90,
    )
