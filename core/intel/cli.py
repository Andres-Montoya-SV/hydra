"""CLI helpers for querying persisted intelligence without rescanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.intel.query import IntelQuery
from core.store import AssetStore


def default_db(project_root: Path, output_directory: Path) -> Path:
    return project_root / output_directory / "recon.db"


def print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str, sort_keys=True))


def open_query(
    db_path: Path, run_id: str | None, *, domain: str | None = None
) -> tuple[AssetStore, IntelQuery, str | None]:
    store = AssetStore(db_path)
    resolved = run_id or store.find_latest_finished_run(domain=domain)
    conn = store.intel_connection()
    return store, IntelQuery(conn, resolved), resolved


def cmd_investigate(db_path: Path, domain: str, run_id: str | None, entity: str | None) -> int:
    store, query, resolved = open_query(db_path, run_id, domain=domain)
    _ = store
    if entity:
        payload = query.investigate(entity)
        payload["requested_entity"] = entity
    else:
        payload = query.investigate(domain)
    payload["run_id"] = resolved
    print_json(payload)
    query.conn.close()
    return 0 if payload.get("entity") or payload.get("observations") else 1


def cmd_graph(db_path: Path, domain: str, run_id: str | None) -> int:
    _, query, resolved = open_query(db_path, run_id, domain=domain)
    payload = query.graph_neighborhood(domain)
    payload["run_id"] = resolved
    print_json(payload)
    query.conn.close()
    return 0


def cmd_relationships(db_path: Path, domain: str, run_id: str | None) -> int:
    from core.intel.query import domain_entity_id

    _, query, resolved = open_query(db_path, run_id, domain=domain)
    payload = {"run_id": resolved, "relationships": query.relationships(domain_entity_id(domain))}
    print_json(payload)
    query.conn.close()
    return 0


def cmd_evidence(db_path: Path, target: str, run_id: str | None) -> int:
    from core.intel.query import domain_entity_id

    looks_like_id = len(target) == 32 and all(ch in "0123456789abcdef" for ch in target.lower())
    domain = "" if looks_like_id else target
    _, query, resolved = open_query(db_path, run_id, domain=domain or None)
    if looks_like_id:
        payload = query.evidence_by_relationship(target.lower())
        payload["run_id"] = resolved
        print_json(payload)
        query.conn.close()
        return 0 if payload.get("relationship") else 1
    payload = {"run_id": resolved, "evidence": query.evidence_for(domain_entity_id(target))}
    print_json(payload)
    query.conn.close()
    return 0


def cmd_certificates(db_path: Path, domain: str, run_id: str | None) -> int:
    _, query, resolved = open_query(db_path, run_id, domain=domain)
    payload = {"run_id": resolved, "certificates": query.certificates(domain)}
    print_json(payload)
    query.conn.close()
    return 0


def cmd_indicators(db_path: Path, domain: str, run_id: str | None) -> int:
    _, query, resolved = open_query(db_path, run_id, domain=domain)
    payload = {"run_id": resolved, "indicators": query.indicators(domain)}
    print_json(payload)
    query.conn.close()
    return 0


def cmd_diff_runs(db_path: Path, run_a: str, run_b: str | None = None) -> int:
    from core.diff import diff_runs

    store = AssetStore(db_path)
    if run_b:
        diff = diff_runs(store, run_b, run_a)
        if not diff:
            print_json({"error": "unable to compare runs", "run_a": run_a, "run_b": run_b})
            return 1
        print_json(diff.to_dict())
        return 0
    domain = run_a
    current = store.find_latest_finished_run(domain=domain)
    if not current:
        print_json({"error": "no finished run for domain", "domain": domain})
        return 1
    previous = store.find_previous_run(current)
    diff = diff_runs(store, current, previous)
    if not diff:
        print_json(
            {
                "error": "no previous finished overlapping run",
                "domain": domain,
                "current_run_id": current,
            }
        )
        return 1
    print_json(diff.to_dict())
    return 0
