"""Immutable seed/follow-up artifacts and deterministic authorized union.

Canonical files (resolved.txt, alive.txt, dnsx_records.jsonl, httpx.json) are
projections. Seed snapshots and per-pass sidecars are the durable collection
record. If follow-up crashes or returns nothing, seed snapshots remain intact.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.intel.authorize import authorize_active_indicator
from core.intel.scope import CollectionScope, filter_authorized_indicators
from utils.files import read_jsonl, read_lines, write_jsonl, write_lines

SEED_RESOLVED = "resolved_seed.txt"
SEED_DNSX_RECORDS = "dnsx_records_seed.jsonl"
SEED_ALIVE = "alive_seed.txt"
SEED_HTTPX = "httpx_seed.json"
AUTHORIZED_ALIVE = "authorized_alive.txt"


def followup_resolved_name(pass_no: int) -> str:
    return f"resolved_followup_{pass_no}.txt"


def followup_dnsx_records_name(pass_no: int) -> str:
    return f"dnsx_records_followup_{pass_no}.jsonl"


def followup_alive_name(pass_no: int) -> str:
    return f"alive_followup_{pass_no}.txt"


def followup_httpx_name(pass_no: int) -> str:
    return f"httpx_followup_{pass_no}.json"


def followup_suffix(pass_no: int) -> str:
    return f"_followup_{pass_no}"


def _copy_if_present(source: Path, dest: Path) -> None:
    if not source.exists() or dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)


def snapshot_seed_dns(output_dir: Path) -> None:
    """Freeze seed DNS artifacts once. Never overwrite an existing snapshot."""
    _copy_if_present(output_dir / "resolved.txt", output_dir / SEED_RESOLVED)
    _copy_if_present(output_dir / "dnsx_records.jsonl", output_dir / SEED_DNSX_RECORDS)


def snapshot_seed_http(output_dir: Path) -> None:
    """Freeze seed HTTP artifacts once. Never overwrite an existing snapshot."""
    _copy_if_present(output_dir / "alive.txt", output_dir / SEED_ALIVE)
    _copy_if_present(output_dir / "httpx.json", output_dir / SEED_HTTPX)


def _ordered_existing(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.exists()]


def authorized_union_lines(
    paths: list[Path],
    scope: CollectionScope,
    *,
    operation: str,
) -> list[str]:
    """Deterministic, idempotent union. First-write-wins. Unauthorized dropped."""
    seen: set[str] = set()
    out: list[str] = []
    for path in _ordered_existing(paths):
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line in seen:
                continue
            decision = authorize_active_indicator(line, scope, operation, "authorized_union")
            if not decision.allowed:
                continue
            seen.add(line)
            out.append(line)
    return out


def authorized_union_jsonl(paths: list[Path], identity_fn) -> list[dict]:
    """First-write-wins JSONL union. Identity function must be deterministic."""
    merged: list[dict] = []
    seen: set[str] = set()
    for path in _ordered_existing(paths):
        for record in read_jsonl(path):
            if not isinstance(record, dict):
                continue
            key = identity_fn(record)
            if key in seen:
                continue
            seen.add(key)
            merged.append(record)
    return merged


def write_canonical_lines(dest: Path, lines: list[str], *, base_dir: Path) -> None:
    write_lines(dest, lines, base_dir=base_dir)


def write_canonical_jsonl(dest: Path, records: list[dict], *, base_dir: Path) -> None:
    write_jsonl(dest, records, base_dir=base_dir)


def write_authorized_alive(output_dir: Path, scope: CollectionScope) -> Path:
    """Centrally authorized view consumed by crawlers/scanners."""
    alive = output_dir / "alive.txt"
    dest = output_dir / AUTHORIZED_ALIVE
    kept = filter_authorized_indicators(read_lines(alive) if alive.exists() else [], scope)
    write_lines(dest, kept, base_dir=output_dir)
    return dest


def dns_union_paths(output_dir: Path, pass_no: int) -> list[Path]:
    paths = [output_dir / SEED_RESOLVED, output_dir / "resolved.txt"]
    for index in range(1, pass_no + 1):
        paths.append(output_dir / followup_resolved_name(index))
        # Legacy sidecar from earlier builds.
        if index == 1:
            paths.append(output_dir / "resolved_followup.txt")
    return paths


def dns_record_union_paths(output_dir: Path, pass_no: int) -> list[Path]:
    paths = [output_dir / SEED_DNSX_RECORDS, output_dir / "dnsx_records.jsonl"]
    for index in range(1, pass_no + 1):
        paths.append(output_dir / followup_dnsx_records_name(index))
        if index == 1:
            paths.append(output_dir / "dnsx_records_followup.jsonl")
    return paths


def alive_union_paths(output_dir: Path, pass_no: int) -> list[Path]:
    paths = [output_dir / SEED_ALIVE]
    for index in range(1, pass_no + 1):
        paths.append(output_dir / followup_alive_name(index))
        if index == 1:
            paths.append(output_dir / "alive_followup.txt")
    return paths


def httpx_union_paths(output_dir: Path, pass_no: int) -> list[Path]:
    paths = [output_dir / SEED_HTTPX]
    for index in range(1, pass_no + 1):
        paths.append(output_dir / followup_httpx_name(index))
        if index == 1:
            paths.append(output_dir / "httpx_followup.json")
    return paths


def successful_followup_hosts(output_dir: Path, pass_no: int) -> set[str]:
    """Hosts actually written by this follow-up DNS pass (not merely scheduled)."""
    from core.assets import normalize_domain

    hosts: set[str] = set()
    for path in (
        output_dir / followup_resolved_name(pass_no),
        output_dir / "resolved_followup.txt" if pass_no == 1 else None,
    ):
        if path is None or not path.exists():
            continue
        for line in read_lines(path):
            name = normalize_domain(line) or indicator_hostname_safe(line)
            if name:
                hosts.add(name)
    return hosts


def successful_followup_http_hosts(output_dir: Path, pass_no: int) -> set[str]:
    from core.assets import normalize_domain
    from core.intel.scope import indicator_hostname

    hosts: set[str] = set()
    for path in (
        output_dir / followup_alive_name(pass_no),
        output_dir / "alive_followup.txt" if pass_no == 1 else None,
        output_dir / followup_httpx_name(pass_no),
    ):
        if path is None or not path.exists():
            continue
        if path.suffix in {".json", ".jsonl"} or path.name.endswith(".json"):
            for record in read_jsonl(path):
                if not isinstance(record, dict):
                    continue
                raw = str(record.get("input") or record.get("host") or record.get("url") or "")
                name = normalize_domain(raw) or indicator_hostname(raw)
                if name:
                    hosts.add(name)
            continue
        for line in read_lines(path):
            name = normalize_domain(line) or indicator_hostname(line)
            if name:
                hosts.add(name)
    return hosts


def indicator_hostname_safe(raw: str) -> str:
    from core.intel.scope import indicator_hostname

    return indicator_hostname(raw)
