"""Crawler output normalization and lightweight secret/endpoint detection."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from core.assets import URL, Finding, Host, normalize_domain, normalize_http_url
from core.provenance import record_observation
from utils.files import read_jsonl, read_lines

_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b")
_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|access[_-]?key|client[_-]?secret|authorization)"
    r"[^=&\s]{0,20}[=:][^&\s]{6,}"
)
_API_PATH_RE = re.compile(r"(?i)(/api/|/graphql|/v\d+/|/rest/|/oauth|/webhook)")


def parse_crawler_output(
    path: Path,
    *,
    source: str,
) -> tuple[list[Host], list[str]]:
    """Parse JSONL or plain crawler output into Host objects."""
    if not path.exists():
        return [], []
    records = _load_records(path)
    by_host: dict[str, Host] = {}
    artifact = str(path)

    for record in records:
        raw_url = str(
            record.get("url") or record.get("request") or record.get("endpoint") or ""
        ).strip()
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        domain = normalize_domain(parsed.hostname or "")
        if not domain:
            continue
        canonical = normalize_http_url(raw_url) or raw_url

        host = by_host.setdefault(domain, Host(domain=domain))
        if any(existing.url == canonical for existing in host.urls):
            continue
        params = sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)})
        secrets = _SECRET_RE.findall(raw_url)
        jwt_matches = _JWT_RE.findall(raw_url)
        endpoint_type = _classify_endpoint(parsed.path)

        host.urls.append(
            URL(
                url=canonical,
                host=domain,
                source=source,
                confidence_score=70 if endpoint_type != "page" else 60,
                path=parsed.path,
                parameters=params,
                endpoint_type=endpoint_type,
                secrets=list(dict.fromkeys(secrets)),
                jwts=list(dict.fromkeys(jwt_matches)),
            )
        )
        host.add_provenance(
            record_observation(
                tool=source,
                field="url",
                value=raw_url[:200],
                confidence=70,
                artifact_path=artifact,
            )
        )

        if secrets:
            host.findings.append(
                Finding(
                    host=domain,
                    template_id=f"{source}-secret-in-url",
                    severity="medium",
                    name="Potential secret material in crawled URL",
                    source=source,
                    url=raw_url,
                    confidence_score=60,
                )
            )
        if jwt_matches:
            host.findings.append(
                Finding(
                    host=domain,
                    template_id=f"{source}-jwt-in-url",
                    severity="low",
                    name="JWT observed in crawled URL",
                    source=source,
                    url=raw_url,
                    confidence_score=60,
                )
            )

    return list(by_host.values()), []


def _load_records(path: Path) -> list[dict[str, object]]:
    if path.suffix in {".jsonl", ".json"}:
        records = read_jsonl(path)
        if records:
            return records
    return [{"url": line} for line in read_lines(path)]


def _classify_endpoint(path: str) -> str:
    lower = path.lower()
    if "graphql" in lower:
        return "graphql"
    if _API_PATH_RE.search(path):
        return "api"
    if lower.endswith((".js", ".json", ".xml")):
        return "asset"
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css")):
        return "static"
    return "page"
