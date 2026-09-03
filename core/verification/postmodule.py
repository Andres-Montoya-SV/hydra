"""Wires the B.2 pure detectors (core/verification/detectors.py) to the
real artifacts a run actually produces — "after each plugin, before
persisting to SQLite" (design Part B.2), read from `output_dir` once,
right before `core/runner.py`'s final `store.persist_registry(...)` call.

Each `_check_*` function below is independent and skips cleanly (returns
`[]`) when its plugin didn't run or produced no artifact — enabling one
detector never depends on another having run.
"""

from __future__ import annotations

from pathlib import Path

from core.verification.detectors import (
    detect_dnsx_nodata_as_resolved,
    detect_naabu_nmap_port_disagreement,
    detect_security_headers_key_mismatch,
    detect_whois_block_specificity,
)
from core.verification.model import VerificationFinding
from utils.files import read_jsonl, read_lines


def _check_dnsx(output_dir: Path) -> list[VerificationFinding]:
    records_path = output_dir / "dnsx_records.jsonl"
    resolved_path = output_dir / "resolved.txt"
    if not records_path.exists():
        return []
    resolved_hosts = set(read_lines(resolved_path)) if resolved_path.exists() else set()
    findings: list[VerificationFinding] = []
    for record in read_jsonl(records_path):
        host = str(record.get("host") or "").strip().rstrip(".")
        finding = detect_dnsx_nodata_as_resolved(
            record,
            was_counted_resolved=host in resolved_hosts,
            raw_artifact="dnsx_records.jsonl",
        )
        if finding:
            findings.append(finding)
    return findings


def _check_security_headers(output_dir: Path) -> list[VerificationFinding]:
    sh_path = output_dir / "security_headers.jsonl"
    httpx_path = output_dir / "httpx.json"
    if not sh_path.exists() or not httpx_path.exists():
        return []

    raw_headers_by_host: dict[str, dict] = {}
    for record in read_jsonl(httpx_path):
        host = str(record.get("host") or record.get("input") or "").strip().rstrip(".")
        headers = record.get("header") or record.get("headers") or {}
        if host and isinstance(headers, dict):
            raw_headers_by_host[host] = headers

    missing_by_host: dict[str, list[str]] = {}
    artifact_by_host: dict[str, str | None] = {}
    for row in read_jsonl(sh_path):
        host = str(row.get("host") or "").strip().rstrip(".")
        if not host:
            continue
        artifact_by_host.setdefault(host, row.get("raw_artifact"))
        if row.get("missing") and row.get("header_key"):
            missing_by_host.setdefault(host, []).append(str(row["header_key"]))

    findings: list[VerificationFinding] = []
    for host, missing_list in missing_by_host.items():
        raw_headers = raw_headers_by_host.get(host)
        if raw_headers is None:
            continue
        finding = detect_security_headers_key_mismatch(
            raw_headers,
            missing_list,
            host=host,
            raw_artifact=artifact_by_host.get(host),
        )
        if finding:
            findings.append(finding)
    return findings


def _extract_domain_whois_section(raw_text: str, domain: str) -> str:
    """`whois_raw.txt` concatenates every queried domain's raw response
    under a `===== domain =====` marker (`modules/whois.py`) — slice out
    just this domain's section so a referral chain's "last Domain Name:"
    anchor never crosses into a different domain's own text.
    """
    marker = f"===== {domain} ====="
    start = raw_text.find(marker)
    if start == -1:
        return raw_text
    start += len(marker)
    next_marker = raw_text.find("\n===== ", start)
    return raw_text[start:next_marker] if next_marker != -1 else raw_text[start:]


def _check_whois(output_dir: Path) -> list[VerificationFinding]:
    whois_path = output_dir / "whois.jsonl"
    if not whois_path.exists():
        return []
    findings: list[VerificationFinding] = []
    for record in read_jsonl(whois_path):
        domain = str(record.get("domain") or "")
        created_at = record.get("created_at")
        raw_artifact = record.get("raw_artifact")
        if not domain or not created_at or not raw_artifact:
            continue
        raw_file = output_dir / str(raw_artifact)
        if not raw_file.is_file():
            continue
        try:
            raw_text = raw_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        section = _extract_domain_whois_section(raw_text, domain)
        finding = detect_whois_block_specificity(
            section, str(created_at), host=domain, raw_artifact=str(raw_artifact)
        )
        if finding:
            findings.append(finding)
    return findings


def _check_port_verify(output_dir: Path) -> list[VerificationFinding]:
    path = output_dir / "port_verify.jsonl"
    if not path.exists():
        return []
    findings: list[VerificationFinding] = []
    for record in read_jsonl(path):
        finding = detect_naabu_nmap_port_disagreement(
            str(record.get("naabu_state") or ""),
            str(record.get("nmap_state") or ""),
            host=record.get("host"),
            port=record.get("port"),
            raw_artifact=record.get("raw_artifact") or "port_verify.jsonl",
        )
        if finding:
            findings.append(finding)
    return findings


def run_post_module_checks(output_dir: Path) -> list[VerificationFinding]:
    """Every B.2 detector this run's artifacts make possible, run once,
    right before persistence — see this module's docstring.
    """
    findings: list[VerificationFinding] = []
    findings.extend(_check_dnsx(output_dir))
    findings.extend(_check_security_headers(output_dir))
    findings.extend(_check_whois(output_dir))
    findings.extend(_check_port_verify(output_dir))
    return findings
