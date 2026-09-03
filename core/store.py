"""SQLite persistence layer — single source of truth for infrastructure intelligence."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.assets import (
    URL,
    Confidence,
    DnsRecord,
    Finding,
    Host,
    HttpService,
    InfrastructureCluster,
    InfrastructureGraph,
    Port,
    RiskLevel,
    ScanRun,
    TlsCertificate,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    targets_json TEXT,
    program_name TEXT,
    host_count INTEGER DEFAULT 0,
    alive_count INTEGER DEFAULT 0,
    warnings_json TEXT,
    errors_json TEXT,
    intel_truncated INTEGER DEFAULT 0,
    intel_truncation_reason TEXT,
    scope_file_hash TEXT,
    attribution_fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    hostname TEXT,
    root_domain TEXT,
    subdomain TEXT,
    ips_json TEXT,
    asn TEXT,
    asn_org TEXT,
    cidr TEXT,
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    provider TEXT,
    cloud_provider TEXT,
    cloud_region TEXT,
    registrar TEXT,
    registration_created_at TEXT,
    registration_expires_at TEXT,
    nameservers_json TEXT,
    is_cdn INTEGER DEFAULT 0,
    cdn_provider TEXT,
    waf_provider TEXT,
    dns_resolved INTEGER DEFAULT 0,
    dns_wildcard INTEGER DEFAULT 0,
    tarpit_suspected INTEGER DEFAULT 0,
    tarpit_canary_ports_json TEXT,
    soft_404_detected INTEGER DEFAULT 0,
    confidence TEXT,
    confidence_score INTEGER DEFAULT 25,
    risk_level TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_reasons_json TEXT,
    discovery_sources_json TEXT,
    warnings_json TEXT,
    cluster_ids_json TEXT,
    profile_json TEXT,
    first_seen TEXT,
    last_seen TEXT,
    scan_timestamp TEXT,
    UNIQUE(run_id, domain),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS http_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    webserver TEXT,
    technologies_json TEXT,
    headers_json TEXT,
    security_headers_json TEXT,
    cdn TEXT,
    waf TEXT,
    confidence TEXT,
    confidence_score INTEGER DEFAULT 80,
    body_hash TEXT,
    favicon_hash TEXT,
    content_length INTEGER,
    response_size INTEGER,
    tls_version TEXT,
    tls_cipher TEXT,
    response_fingerprint TEXT,
    redirect_chain_json TEXT,
    UNIQUE(run_id, host, url),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    banner TEXT,
    source TEXT,
    confidence TEXT,
    confidence_score INTEGER DEFAULT 50,
    validated INTEGER DEFAULT 0,
    verification_state TEXT DEFAULT 'unverified',
    service TEXT,
    version TEXT,
    warnings_json TEXT,
    UNIQUE(run_id, host, port, protocol),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    priority INTEGER,
    security_tags_json TEXT,
    source TEXT,
    confidence_score INTEGER DEFAULT 80,
    UNIQUE(run_id, host, record_type, value),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    issuer TEXT,
    subject TEXT,
    sans_json TEXT,
    not_after TEXT,
    not_before TEXT,
    fingerprint_sha256 TEXT,
    is_wildcard INTEGER DEFAULT 0,
    source TEXT,
    confidence_score INTEGER DEFAULT 90,
    UNIQUE(run_id, host),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT,
    discovered_at TEXT,
    confidence_score INTEGER DEFAULT 60,
    path TEXT,
    parameters_json TEXT,
    endpoint_type TEXT,
    secrets_json TEXT,
    jwts_json TEXT,
    UNIQUE(run_id, url),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT,
    name TEXT,
    source TEXT,
    url TEXT,
    description TEXT,
    confidence_score INTEGER DEFAULT 80,
    discovered_at TEXT,
    UNIQUE(run_id, host, template_id, url),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS provenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    tool TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT,
    confidence INTEGER DEFAULT 25,
    discovered_at TEXT,
    verified_by_json TEXT,
    artifact_path TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

-- Verification agent (docs/VERIFICATION_AGENT_DESIGN.md): a contradiction
-- between an interpreted claim and the raw evidence that backs or
-- contradicts it. Deliberately its own table, not folded into `findings`
-- (a claim about the target) or `provenance` (a single tool observation) —
-- see the design doc Part C for why each was reviewed and rejected.
-- related_table/related_id are a loose, non-FK pointer on purpose: a flag
-- can point at a row in findings/hosts/intel_relationships, or nothing at
-- all (an UNRESOLVED, run-level flag with no single row to blame).
CREATE TABLE IF NOT EXISTS verification_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT,
    detector TEXT NOT NULL,
    claim TEXT NOT NULL,
    evidence TEXT NOT NULL,
    raw_artifact TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CONFIRMED',
    related_table TEXT,
    related_id TEXT,
    metadata_json TEXT,
    discovered_at TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE INDEX IF NOT EXISTS idx_verification_flags_run ON verification_flags(run_id);
CREATE INDEX IF NOT EXISTS idx_verification_flags_related ON verification_flags(related_table, related_id);

CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    cluster_type TEXT NOT NULL,
    signal TEXT,
    members_json TEXT,
    confidence INTEGER DEFAULT 80,
    description TEXT,
    UNIQUE(run_id, cluster_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    label TEXT,
    metadata_json TEXT,
    UNIQUE(run_id, node_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    confidence INTEGER DEFAULT 80,
    evidence_id TEXT,
    first_seen TEXT,
    last_seen TEXT,
    confidence_label TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_hosts_run ON hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_hosts_domain ON hosts(domain);
CREATE INDEX IF NOT EXISTS idx_hosts_risk ON hosts(run_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_http_run ON http_services(run_id);
CREATE INDEX IF NOT EXISTS idx_ports_run ON ports(run_id);
CREATE INDEX IF NOT EXISTS idx_provenance_run ON provenance(run_id, host);
CREATE INDEX IF NOT EXISTS idx_clusters_run ON clusters(run_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_run ON graph_nodes(run_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_run ON graph_edges(run_id);

CREATE TABLE IF NOT EXISTS intel_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    key TEXT NOT NULL,
    data_json TEXT,
    scope_status TEXT,
    collection_status TEXT,
    is_seed INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(run_id, entity_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS intel_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    source TEXT,
    collector TEXT,
    observed_at TEXT,
    data_json TEXT,
    scope_status TEXT,
    UNIQUE(run_id, observation_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id),
    FOREIGN KEY(run_id, entity_id) REFERENCES intel_entities(run_id, entity_id)
);

CREATE TABLE IF NOT EXISTS intel_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    source TEXT,
    collector TEXT,
    observation_id TEXT,
    reason TEXT,
    metadata_json TEXT,
    observed_at TEXT,
    UNIQUE(run_id, evidence_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id),
    FOREIGN KEY(run_id, observation_id) REFERENCES intel_observations(run_id, observation_id)
);

CREATE TABLE IF NOT EXISTS intel_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    relationship_id TEXT NOT NULL,
    source_entity TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    confidence TEXT,
    strength TEXT,
    first_seen TEXT,
    last_seen TEXT,
    evidence_id TEXT,
    data_json TEXT,
    UNIQUE(run_id, relationship_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id),
    FOREIGN KEY(run_id, source_entity) REFERENCES intel_entities(run_id, entity_id),
    FOREIGN KEY(run_id, target_entity) REFERENCES intel_entities(run_id, entity_id),
    FOREIGN KEY(run_id, evidence_id) REFERENCES intel_evidence(run_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS intel_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    indicator_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    depth INTEGER DEFAULT 0,
    parent_id TEXT,
    reason TEXT,
    scope_status TEXT,
    collection_status TEXT,
    evidence_id TEXT,
    priority INTEGER DEFAULT 100,
    discovered_from TEXT,
    authorization_status TEXT,
    created_at TEXT,
    claimed_at TEXT,
    completed_at TEXT,
    failure_reason TEXT,
    collector TEXT,
    UNIQUE(run_id, indicator_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS intel_hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    relationship_id TEXT,
    target_value TEXT NOT NULL,
    evidence_id TEXT,
    confidence_band TEXT,
    status TEXT,
    rationale TEXT,
    depth INTEGER DEFAULT 1,
    kind TEXT,
    UNIQUE(run_id, hypothesis_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS intel_collection_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    indicator_id TEXT,
    value TEXT NOT NULL,
    capability TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    collector TEXT,
    observed_at TEXT,
    artifact TEXT,
    UNIQUE(run_id, attempt_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

-- Per-destination network authorization audit trail — finer-grained than
-- intel_collection_attempts (one row per plugin capability attempt): one row
-- per concrete network decision the crawler-confinement proxy or httpx's
-- redirect-hop resolver actually made, ALLOW and DENY alike. Answers "was
-- this host actually contacted, under which authorization, why" from SQLite
-- alone, without re-reading warnings text.
CREATE TABLE IF NOT EXISTS intel_network_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    capability TEXT,
    method TEXT,
    url TEXT NOT NULL,
    normalized_hostname TEXT,
    resolved_ip TEXT,
    port INTEGER,
    redirect_hop INTEGER DEFAULT 0,
    decision TEXT NOT NULL,
    reason TEXT,
    network_attempted INTEGER NOT NULL DEFAULT 0,
    network_completed INTEGER NOT NULL DEFAULT 0,
    response_status INTEGER,
    response_location TEXT,
    parent_request_id TEXT,
    observed_at TEXT,
    UNIQUE(run_id, request_id),
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_intel_network_requests_run ON intel_network_requests(run_id, decision);
CREATE INDEX IF NOT EXISTS idx_intel_network_requests_host ON intel_network_requests(run_id, normalized_hostname);

CREATE INDEX IF NOT EXISTS idx_intel_entities_run ON intel_entities(run_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_intel_entities_key ON intel_entities(run_id, key);
CREATE INDEX IF NOT EXISTS idx_intel_obs_entity ON intel_observations(run_id, entity_id);
CREATE INDEX IF NOT EXISTS idx_intel_rel_src ON intel_relationships(run_id, source_entity);
CREATE INDEX IF NOT EXISTS idx_intel_rel_dst ON intel_relationships(run_id, target_entity);
CREATE INDEX IF NOT EXISTS idx_intel_rel_type ON intel_relationships(run_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_intel_ind_value ON intel_indicators(run_id, value);
CREATE INDEX IF NOT EXISTS idx_runs_finished_started ON runs(finished_at, started_at DESC);

CREATE TABLE IF NOT EXISTS result_cache (
    cache_key TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    lines_produced INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def configure_sqlite(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Apply the single store/intel/CLI connection configuration."""
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def connect_sqlite(db_path: Path, *, timeout: float = 30) -> sqlite3.Connection:
    """Open a SQLite connection with WAL and foreign keys enabled."""
    return configure_sqlite(sqlite3.connect(db_path, timeout=timeout))


def _normalize_run_target(value: object) -> str:
    return str(value).lower().rstrip(".")


class AssetStore:
    """SQLite-backed intelligence store."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._restrict_database_permissions()

    def _restrict_database_permissions(self) -> None:
        """Keep intelligence databases and SQLite sidecars owner-readable only."""
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{self.db_path}{suffix}")
            if path.exists():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate_schema(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Add columns introduced after initial schema without breaking existing DBs."""
        table_migrations: dict[str, dict[str, str]] = {
            "hosts": {
                "hostname": "ALTER TABLE hosts ADD COLUMN hostname TEXT",
                "root_domain": "ALTER TABLE hosts ADD COLUMN root_domain TEXT",
                "subdomain": "ALTER TABLE hosts ADD COLUMN subdomain TEXT",
                "city": "ALTER TABLE hosts ADD COLUMN city TEXT",
                "latitude": "ALTER TABLE hosts ADD COLUMN latitude REAL",
                "longitude": "ALTER TABLE hosts ADD COLUMN longitude REAL",
                "provider": "ALTER TABLE hosts ADD COLUMN provider TEXT",
                "cloud_provider": "ALTER TABLE hosts ADD COLUMN cloud_provider TEXT",
                "cloud_region": "ALTER TABLE hosts ADD COLUMN cloud_region TEXT",
                "registrar": "ALTER TABLE hosts ADD COLUMN registrar TEXT",
                "registration_created_at": "ALTER TABLE hosts ADD COLUMN registration_created_at TEXT",
                "registration_expires_at": "ALTER TABLE hosts ADD COLUMN registration_expires_at TEXT",
                "nameservers_json": "ALTER TABLE hosts ADD COLUMN nameservers_json TEXT",
                "confidence_score": "ALTER TABLE hosts ADD COLUMN confidence_score INTEGER DEFAULT 25",
                "profile_json": "ALTER TABLE hosts ADD COLUMN profile_json TEXT",
                "first_seen": "ALTER TABLE hosts ADD COLUMN first_seen TEXT",
                "last_seen": "ALTER TABLE hosts ADD COLUMN last_seen TEXT",
                "scan_timestamp": "ALTER TABLE hosts ADD COLUMN scan_timestamp TEXT",
                "tarpit_suspected": "ALTER TABLE hosts ADD COLUMN tarpit_suspected INTEGER DEFAULT 0",
                "tarpit_canary_ports_json": "ALTER TABLE hosts ADD COLUMN tarpit_canary_ports_json TEXT",
                "soft_404_detected": "ALTER TABLE hosts ADD COLUMN soft_404_detected INTEGER DEFAULT 0",
            },
            "tls_certificates": {
                "not_before": "ALTER TABLE tls_certificates ADD COLUMN not_before TEXT",
                "fingerprint_sha256": "ALTER TABLE tls_certificates ADD COLUMN fingerprint_sha256 TEXT",
            },
            "graph_edges": {
                "evidence_id": "ALTER TABLE graph_edges ADD COLUMN evidence_id TEXT",
                "first_seen": "ALTER TABLE graph_edges ADD COLUMN first_seen TEXT",
                "last_seen": "ALTER TABLE graph_edges ADD COLUMN last_seen TEXT",
                "confidence_label": "ALTER TABLE graph_edges ADD COLUMN confidence_label TEXT",
            },
            "ports": {
                "confidence_score": "ALTER TABLE ports ADD COLUMN confidence_score INTEGER DEFAULT 50",
                "verification_state": "ALTER TABLE ports ADD COLUMN verification_state TEXT DEFAULT 'unverified'",
                "service": "ALTER TABLE ports ADD COLUMN service TEXT",
                "version": "ALTER TABLE ports ADD COLUMN version TEXT",
            },
            "findings": {
                "description": "ALTER TABLE findings ADD COLUMN description TEXT",
            },
            "http_services": {
                "confidence_score": "ALTER TABLE http_services ADD COLUMN confidence_score INTEGER DEFAULT 80",
                "security_headers_json": "ALTER TABLE http_services ADD COLUMN security_headers_json TEXT",
                "content_length": "ALTER TABLE http_services ADD COLUMN content_length INTEGER",
                "response_size": "ALTER TABLE http_services ADD COLUMN response_size INTEGER",
                "tls_version": "ALTER TABLE http_services ADD COLUMN tls_version TEXT",
                "tls_cipher": "ALTER TABLE http_services ADD COLUMN tls_cipher TEXT",
                "response_fingerprint": "ALTER TABLE http_services ADD COLUMN response_fingerprint TEXT",
                "redirect_chain_json": "ALTER TABLE http_services ADD COLUMN redirect_chain_json TEXT",
            },
            "dns_records": {
                "priority": "ALTER TABLE dns_records ADD COLUMN priority INTEGER",
                "security_tags_json": "ALTER TABLE dns_records ADD COLUMN security_tags_json TEXT",
            },
            "urls": {
                "path": "ALTER TABLE urls ADD COLUMN path TEXT",
                "parameters_json": "ALTER TABLE urls ADD COLUMN parameters_json TEXT",
                "endpoint_type": "ALTER TABLE urls ADD COLUMN endpoint_type TEXT",
                "secrets_json": "ALTER TABLE urls ADD COLUMN secrets_json TEXT",
                "jwts_json": "ALTER TABLE urls ADD COLUMN jwts_json TEXT",
            },
            "runs": {
                "intel_truncated": "ALTER TABLE runs ADD COLUMN intel_truncated INTEGER DEFAULT 0",
                "intel_truncation_reason": "ALTER TABLE runs ADD COLUMN intel_truncation_reason TEXT",
                "scope_file_hash": "ALTER TABLE runs ADD COLUMN scope_file_hash TEXT",
                "attribution_fingerprint": "ALTER TABLE runs ADD COLUMN attribution_fingerprint TEXT",
            },
            "intel_indicators": {
                "authorization_status": "ALTER TABLE intel_indicators ADD COLUMN authorization_status TEXT",
                "created_at": "ALTER TABLE intel_indicators ADD COLUMN created_at TEXT",
                "claimed_at": "ALTER TABLE intel_indicators ADD COLUMN claimed_at TEXT",
                "completed_at": "ALTER TABLE intel_indicators ADD COLUMN completed_at TEXT",
                "failure_reason": "ALTER TABLE intel_indicators ADD COLUMN failure_reason TEXT",
                "collector": "ALTER TABLE intel_indicators ADD COLUMN collector TEXT",
            },
            "intel_network_requests": {
                "resolved_ip": "ALTER TABLE intel_network_requests ADD COLUMN resolved_ip TEXT",
            },
        }
        for table, migrations in table_migrations.items():
            existing = {
                row[1]
                for row in conn.execute(
                    f"PRAGMA table_info({table})"  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
                ).fetchall()
            }
            if not existing:
                continue
            for col, sql in migrations.items():
                if col not in existing:
                    conn.execute(sql)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = connect_sqlite(self.db_path)
        self._restrict_database_permissions()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_run(self, run: ScanRun) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO runs
                   (run_id, started_at, finished_at, targets_json, program_name,
                    host_count, alive_count, warnings_json, errors_json,
                    scope_file_hash, attribution_fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run.run_id,
                    run.started_at,
                    run.finished_at,
                    json.dumps(run.targets),
                    run.program_name,
                    run.host_count,
                    run.alive_count,
                    json.dumps(run.warnings),
                    json.dumps(run.errors),
                    run.scope_file_hash,
                    run.attribution_fingerprint,
                ),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        host_count: int,
        alive_count: int,
        warnings: list[str],
        errors: list[str],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE runs SET finished_at=?, host_count=?, alive_count=?,
                   warnings_json=?, errors_json=? WHERE run_id=?""",
                (
                    datetime.now(timezone.utc).isoformat(),
                    host_count,
                    alive_count,
                    json.dumps(warnings),
                    json.dumps(errors),
                    run_id,
                ),
            )

    def clear_run_data(self, run_id: str) -> None:
        """Remove all child data for a run (idempotent re-finalize)."""
        tables = (
            "provenance",
            "findings",
            "urls",
            "tls_certificates",
            "dns_records",
            "ports",
            "http_services",
            "hosts",
            "clusters",
            "graph_edges",
            "graph_nodes",
            "intel_collection_attempts",
            "intel_network_requests",
            "intel_hypotheses",
            "intel_indicators",
            "intel_relationships",
            "intel_evidence",
            "intel_observations",
            "intel_entities",
        )
        with self._connect() as conn:
            for table in tables:
                conn.execute(
                    f"DELETE FROM {table} WHERE run_id=?",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
                    (run_id,),
                )

    def persist_registry(
        self, run_id: str, hosts: dict[str, Host], *, clusters=None, graph=None, intel=None
    ) -> None:
        """Persist full intelligence snapshot (replace child data for run)."""
        prior_indicators = self.get_intel_indicators(run_id) if intel is not None else []
        if intel is not None and prior_indicators:
            _apply_prior_indicator_lifecycle(intel, prior_indicators)
        self.clear_run_data(run_id)
        with self._connect() as conn:
            for host in hosts.values():
                self._insert_host(conn, run_id, host)
            if clusters:
                for cluster in clusters:
                    conn.execute(
                        """INSERT INTO clusters
                           (run_id, cluster_id, cluster_type, signal, members_json, confidence, description)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            run_id,
                            cluster.cluster_id,
                            cluster.cluster_type,
                            cluster.signal,
                            json.dumps(cluster.members),
                            cluster.confidence,
                            cluster.description,
                        ),
                    )
            if graph:
                for node in graph.nodes.values():
                    conn.execute(
                        """INSERT INTO graph_nodes (run_id, node_id, node_type, label, metadata_json)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            run_id,
                            node.node_id,
                            node.node_type,
                            node.label,
                            json.dumps(node.metadata),
                        ),
                    )
                for edge in graph.edges:
                    conn.execute(
                        """INSERT INTO graph_edges
                           (run_id, source_id, target_id, relation, confidence,
                            evidence_id, first_seen, last_seen, confidence_label)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            run_id,
                            edge.source_id,
                            edge.target_id,
                            edge.relation,
                            edge.confidence,
                            getattr(edge, "evidence_id", None),
                            getattr(edge, "first_seen", None),
                            getattr(edge, "last_seen", None),
                            getattr(edge, "confidence_label", None),
                        ),
                    )
            if intel is not None:
                self._insert_intel(conn, run_id, intel)
                conn.execute(
                    """UPDATE runs SET intel_truncated=?, intel_truncation_reason=?
                       WHERE run_id=?""",
                    (
                        int(bool(getattr(intel, "truncated", False))),
                        getattr(intel, "truncation_reason", None),
                        run_id,
                    ),
                )

    def get_intel_indicators(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    "SELECT * FROM intel_indicators WHERE run_id=?",
                    (run_id,),
                ).fetchall()
            except sqlite3.OperationalError:
                return []
        return [dict(row) for row in rows]

    def upsert_intel_indicators(self, run_id: str, indicators) -> None:
        """Persist indicator lifecycle without wiping the rest of the run."""
        if not indicators:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_indicators
                   (run_id, indicator_id, kind, value, depth, parent_id, reason,
                    scope_status, collection_status, evidence_id, priority, discovered_from,
                    authorization_status, created_at, claimed_at, completed_at,
                    failure_reason, collector)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        i.indicator_id,
                        i.kind.value,
                        i.value,
                        i.depth,
                        i.parent_id,
                        i.reason.value,
                        i.scope_status.value,
                        i.collection_status.value,
                        i.evidence_id,
                        i.priority,
                        i.discovered_from,
                        getattr(i, "authorization_status", "") or "",
                        getattr(i, "created_at", "") or "",
                        getattr(i, "claimed_at", "") or "",
                        getattr(i, "completed_at", "") or "",
                        getattr(i, "failure_reason", "") or "",
                        getattr(i, "collector", "") or "",
                    )
                    for i in indicators
                ],
            )

    def upsert_intel_attempts(self, run_id: str, attempts) -> None:
        """Persist collection attempts without wiping the rest of the run."""
        if not attempts:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_collection_attempts
                   (run_id, attempt_id, indicator_id, value, capability, status,
                    reason, collector, observed_at, artifact)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        a.attempt_id,
                        a.indicator_id,
                        a.value,
                        a.capability,
                        a.status,
                        a.reason,
                        a.collector,
                        a.observed_at,
                        a.artifact,
                    )
                    for a in attempts
                ],
            )

    def record_network_requests(self, run_id: str, requests: list[dict]) -> None:
        """Persist per-destination network authorization decisions.

        `requests` is a list of plain dicts (see `core.collection.audit.
        NetworkRequestRecord.to_dict()`), accumulated in `context.metadata
        ["network_requests"]` by the crawler-confinement proxy and httpx's
        redirect-hop resolver — the two components that make individual,
        per-destination ALLOW/DENY decisions outside the input-file gate.
        `INSERT OR REPLACE` so a retried/partial finalize is idempotent.
        """
        if not requests:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_network_requests
                   (run_id, request_id, collector, capability, method, url,
                    normalized_hostname, resolved_ip, port, redirect_hop, decision, reason,
                    network_attempted, network_completed, response_status,
                    response_location, parent_request_id, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        str(r.get("request_id") or ""),
                        str(r.get("collector") or ""),
                        str(r.get("capability") or ""),
                        str(r.get("method") or ""),
                        str(r.get("url") or ""),
                        str(r.get("normalized_hostname") or ""),
                        str(r.get("resolved_ip") or ""),
                        r.get("port"),
                        int(r.get("redirect_hop") or 0),
                        str(r.get("decision") or ""),
                        str(r.get("reason") or ""),
                        1 if r.get("network_attempted") else 0,
                        1 if r.get("network_completed") else 0,
                        r.get("response_status"),
                        str(r.get("response_location") or ""),
                        str(r.get("parent_request_id") or ""),
                        str(r.get("observed_at") or ""),
                    )
                    for r in requests
                    if r.get("request_id")
                ],
            )

    def get_network_requests(
        self, run_id: str, *, decision: str | None = None
    ) -> list[dict[str, object]]:
        """Read back the network-request audit trail for a run (CLI/debugging)."""
        with self._connect() as conn:
            if decision:
                rows = conn.execute(
                    "SELECT * FROM intel_network_requests WHERE run_id=? AND decision=? "
                    "ORDER BY id",
                    (run_id, decision),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM intel_network_requests WHERE run_id=? ORDER BY id",
                    (run_id,),
                ).fetchall()
        return [dict(row) for row in rows]

    def record_verification_findings(self, run_id: str, findings: list) -> None:
        """Persist verification-agent contradiction flags for a run.

        `findings` is a list of `core.verification.model.VerificationFinding`
        (or anything with the same `.to_dict()` shape). See
        docs/VERIFICATION_AGENT_DESIGN.md Part C for why this is its own
        table rather than folded into `findings` or `provenance`.
        """
        if not findings:
            return
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO verification_flags
                   (run_id, host, detector, claim, evidence, raw_artifact,
                    severity, status, related_table, related_id, metadata_json,
                    discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        f.host,
                        f.detector,
                        f.claim,
                        f.evidence,
                        f.raw_artifact,
                        f.severity.value,
                        f.status.value,
                        f.related_table,
                        f.related_id,
                        json.dumps(f.metadata),
                        datetime.now(timezone.utc).isoformat(),
                    )
                    for f in findings
                ],
            )

    def get_verification_flags(
        self, run_id: str, *, status: str | None = None
    ) -> list[dict[str, object]]:
        """Read back verification flags for a run (CLI/report use)."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM verification_flags WHERE run_id=? AND status=? ORDER BY id",
                    (run_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM verification_flags WHERE run_id=? ORDER BY id",
                    (run_id,),
                ).fetchall()
        return [dict(row) for row in rows]

    def upsert_host(self, run_id: str, host: Host) -> None:
        """Legacy single-host upsert (used by tests)."""
        with self._connect() as conn:
            self._insert_host(conn, run_id, host)

    def save_http_service(self, run_id: str, service: HttpService) -> None:
        with self._connect() as conn:
            self._insert_http(conn, run_id, service)

    def save_port(self, run_id: str, port: Port) -> None:
        with self._connect() as conn:
            self._insert_port(conn, run_id, port)

    def get_hosts(self, run_id: str, *, limit: int = 0, offset: int = 0) -> list[Host]:
        query = "SELECT * FROM hosts WHERE run_id=? ORDER BY risk_score DESC"
        params: list[Any] = [run_id]
        if limit > 0:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            hosts = [self._row_to_host(row) for row in rows]
            if not hosts:
                return []
            domains = [h.domain for h in hosts]
            self._hydrate_hosts(conn, run_id, hosts, domains)
        return hosts

    def get_host_count(self, run_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as c FROM hosts WHERE run_id=?", (run_id,)
            ).fetchone()
        return row["c"] if row else 0

    def get_clusters(self, run_id: str) -> list[InfrastructureCluster]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM clusters WHERE run_id=?", (run_id,)).fetchall()
        return [
            InfrastructureCluster(
                cluster_id=row["cluster_id"],
                cluster_type=row["cluster_type"],
                signal=row["signal"] or "",
                members=json.loads(row["members_json"] or "[]"),
                confidence=row["confidence"] or 80,
                description=row["description"] or "",
            )
            for row in rows
        ]

    def get_graph(self, run_id: str) -> InfrastructureGraph:
        graph = InfrastructureGraph()
        with self._connect() as conn:
            for row in conn.execute("SELECT * FROM graph_nodes WHERE run_id=?", (run_id,)):
                from core.assets import GraphNode

                graph.add_node(
                    GraphNode(
                        node_id=row["node_id"],
                        node_type=row["node_type"],
                        label=row["label"] or "",
                        metadata=json.loads(row["metadata_json"] or "{}"),
                    )
                )
            for row in conn.execute("SELECT * FROM graph_edges WHERE run_id=?", (run_id,)):
                from core.assets import GraphEdge

                graph.add_edge(
                    GraphEdge(
                        source_id=row["source_id"],
                        target_id=row["target_id"],
                        relation=row["relation"],
                        confidence=row["confidence"] or 80,
                        evidence_id=row["evidence_id"] if "evidence_id" in row.keys() else None,
                        first_seen=row["first_seen"] if "first_seen" in row.keys() else None,
                        last_seen=row["last_seen"] if "last_seen" in row.keys() else None,
                        confidence_label=(
                            row["confidence_label"] if "confidence_label" in row.keys() else None
                        ),
                    )
                )
        return graph

    def get_run_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT run_id FROM runs ORDER BY started_at DESC").fetchall()
        return [row["run_id"] for row in rows]

    def export_run_json(self, run_id: str) -> dict[str, Any]:
        hosts = self.get_hosts(run_id)
        payload: dict[str, Any] = {
            "run_id": run_id,
            "host_count": len(hosts),
            "alive_count": sum(1 for h in hosts if h.http_services),
            "hosts": [h.to_dict() for h in hosts],
            "clusters": [c.to_dict() for c in self.get_clusters(run_id)],
            "graph": self.get_graph(run_id).to_dict(),
        }
        try:
            from core.intel.query import IntelQuery
            from core.intel.serialize import serialize_relationships

            conn = self.intel_connection()
            try:
                query = IntelQuery(conn, run_id)
                rels = query.relationships_for_run(limit=500)
                evidence_rows = []
                if rels:
                    ids = [r.get("evidence_id") for r in rels if r.get("evidence_id")]
                    if ids:
                        placeholders = ",".join("?" * len(ids))
                        # placeholders is a fixed count of '?' chars; all values are bound params
                        evidence_rows = [
                            dict(row)
                            for row in conn.execute(
                                f"SELECT * FROM intel_evidence WHERE run_id=? AND evidence_id IN ({placeholders})",  # noqa: S608 # nosec B608
                                [run_id, *ids],
                            ).fetchall()
                        ]
                        for item in evidence_rows:
                            meta = item.get("metadata_json")
                            if meta:
                                try:
                                    item["metadata"] = json.loads(meta)
                                except json.JSONDecodeError:
                                    item["metadata"] = {}
                entities = {
                    row["entity_id"]: dict(row)
                    for row in conn.execute(
                        "SELECT * FROM intel_entities WHERE run_id=?",
                        (run_id,),
                    ).fetchall()
                }
                evidence_by_id = {row.get("evidence_id"): row for row in evidence_rows}
                payload["intelligence"] = {
                    "relationships": serialize_relationships(
                        rels,
                        evidence_by_id=evidence_by_id,
                        entities_by_id=entities,
                        run_id=run_id,
                    )
                }
            finally:
                conn.close()
        except Exception:
            payload["intelligence"] = {"relationships": []}
        return payload

    def query_hosts_by_risk(self, run_id: str, min_score: int = 25) -> list[Host]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM hosts WHERE run_id=? AND risk_score>=? ORDER BY risk_score DESC",
                (run_id, min_score),
            ).fetchall()
            hosts = [self._row_to_host(row) for row in rows]
            if hosts:
                self._hydrate_hosts(conn, run_id, hosts, [h.domain for h in hosts])
        return hosts

    def get_cache_entry(self, cache_key: str) -> dict[str, Any] | None:
        """Return a non-expired cached artifact entry."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM result_cache WHERE cache_key=? AND expires_at>?",
                (cache_key, datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        return dict(row) if row else None

    def set_cache_entry(
        self,
        cache_key: str,
        *,
        tool: str,
        input_hash: str,
        artifact_path: str,
        lines_produced: int,
        ttl_seconds: int,
    ) -> None:
        """Persist a cached artifact reference with TTL."""
        now = datetime.now(timezone.utc)
        expires = datetime.fromtimestamp(now.timestamp() + ttl_seconds, timezone.utc)
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO result_cache
                   (cache_key, tool, input_hash, artifact_path, lines_produced, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    cache_key,
                    tool,
                    input_hash,
                    artifact_path,
                    lines_produced,
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )

    def _insert_host(self, conn: sqlite3.Connection, run_id: str, host: Host) -> None:
        conn.execute(
            """INSERT OR REPLACE INTO hosts
               (run_id, domain, hostname, root_domain, subdomain, ips_json,
                asn, asn_org, cidr, country, city, latitude, longitude, provider,
                cloud_provider, cloud_region, registrar, registration_created_at,
                registration_expires_at, nameservers_json, is_cdn, cdn_provider, waf_provider,
                dns_resolved, dns_wildcard, tarpit_suspected, tarpit_canary_ports_json,
                soft_404_detected, confidence, confidence_score,
                risk_level, risk_score, risk_reasons_json, discovery_sources_json,
                warnings_json, cluster_ids_json, profile_json,
                first_seen, last_seen, scan_timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                host.domain,
                host.hostname,
                host.root_domain,
                host.subdomain,
                json.dumps(host.ips),
                host.asn,
                host.asn_org,
                host.cidr,
                host.country,
                host.city,
                host.latitude,
                host.longitude,
                host.provider,
                host.cloud_provider,
                host.cloud_region,
                host.registrar,
                host.registration_created_at,
                host.registration_expires_at,
                json.dumps(host.nameservers),
                int(host.is_cdn),
                host.cdn_provider,
                host.waf_provider,
                int(host.dns_resolved),
                int(host.dns_wildcard),
                int(host.tarpit_suspected),
                json.dumps(host.tarpit_canary_ports),
                int(host.soft_404_detected),
                host.confidence.value,
                host.confidence_score,
                host.risk_level.value,
                host.risk_score,
                json.dumps(host.risk_reasons),
                json.dumps(host.discovery_sources),
                json.dumps(host.warnings),
                json.dumps(host.cluster_ids),
                json.dumps(host.profile.to_dict()) if host.profile else None,
                host.first_seen,
                host.last_seen,
                host.scan_timestamp,
            ),
        )
        for svc in host.http_services:
            self._insert_http(conn, run_id, svc)
        for port in host.ports:
            self._insert_port(conn, run_id, port)
        for rec in host.dns_records:
            conn.execute(
                """INSERT OR IGNORE INTO dns_records
                   (run_id, host, record_type, value, ttl, priority, security_tags_json, source, confidence_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    rec.host,
                    rec.record_type,
                    rec.value,
                    rec.ttl,
                    rec.priority,
                    json.dumps(rec.security_tags),
                    rec.source,
                    rec.confidence_score,
                ),
            )
        if host.tls:
            t = host.tls
            conn.execute(
                """INSERT OR REPLACE INTO tls_certificates
                   (run_id, host, issuer, subject, sans_json, not_after, not_before,
                    fingerprint_sha256, is_wildcard, source, confidence_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    t.host,
                    t.issuer,
                    t.subject,
                    json.dumps(t.sans),
                    t.not_after,
                    getattr(t, "not_before", None),
                    getattr(t, "fingerprint_sha256", None),
                    int(t.is_wildcard),
                    t.source,
                    t.confidence_score,
                ),
            )
        for url in host.urls:
            conn.execute(
                """INSERT OR IGNORE INTO urls
                   (run_id, host, url, source, discovered_at, confidence_score,
                    path, parameters_json, endpoint_type, secrets_json, jwts_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    url.host,
                    url.url,
                    url.source,
                    url.discovered_at,
                    url.confidence_score,
                    url.path,
                    json.dumps(url.parameters),
                    url.endpoint_type,
                    json.dumps(url.secrets),
                    json.dumps(url.jwts),
                ),
            )
        for finding in host.findings:
            conn.execute(
                """INSERT OR IGNORE INTO findings
                   (run_id, host, template_id, severity, name, source, url, description,
                    confidence_score, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    finding.host,
                    finding.template_id,
                    finding.severity,
                    finding.name,
                    finding.source,
                    finding.url,
                    finding.description,
                    finding.confidence_score,
                    finding.discovered_at,
                ),
            )
        for prov in host.provenance:
            conn.execute(
                """INSERT INTO provenance
                   (run_id, host, tool, field, value, confidence, discovered_at, verified_by_json, artifact_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    host.domain,
                    prov.tool,
                    prov.field,
                    prov.value,
                    prov.confidence,
                    prov.discovered_at,
                    json.dumps(prov.verified_by),
                    prov.artifact_path,
                ),
            )

    def _insert_http(self, conn: sqlite3.Connection, run_id: str, service: HttpService) -> None:
        from core.assets import TechnologyFinding

        tech_data = [
            t.to_dict() if isinstance(t, TechnologyFinding) else t for t in service.technologies
        ]
        conn.execute(
            """INSERT OR REPLACE INTO http_services
               (run_id, host, url, status_code, title, webserver, technologies_json,
                headers_json, security_headers_json, cdn, waf, confidence, confidence_score,
                body_hash, favicon_hash, content_length, response_size, tls_version, tls_cipher,
                response_fingerprint, redirect_chain_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                service.host,
                service.url,
                service.status_code,
                service.title,
                service.webserver,
                json.dumps(tech_data),
                json.dumps(service.headers),
                json.dumps(service.security_headers),
                service.cdn,
                service.waf,
                service.confidence.value,
                service.confidence_score,
                service.body_hash,
                service.favicon_hash,
                service.content_length,
                service.response_size,
                service.tls_version,
                service.tls_cipher,
                service.response_fingerprint,
                json.dumps(service.redirect_chain),
            ),
        )

    def _insert_port(self, conn: sqlite3.Connection, run_id: str, port: Port) -> None:
        conn.execute(
            """INSERT OR REPLACE INTO ports
               (run_id, host, port, protocol, banner, source, confidence, confidence_score,
                validated, verification_state, service, version, warnings_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                port.host,
                port.port,
                port.protocol,
                port.banner,
                port.source,
                port.confidence.value,
                port.confidence_score,
                int(port.validated),
                port.verification_state,
                port.service,
                port.version,
                json.dumps(port.warnings),
            ),
        )

    def _hydrate_hosts(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        hosts: list[Host],
        domains: list[str],
    ) -> None:
        if not domains:
            return
        placeholders = ",".join("?" * len(domains))
        host_map = {h.domain: h for h in hosts}

        for row in conn.execute(
            f"SELECT * FROM http_services WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.http_services.append(self._row_to_http(row))

        for row in conn.execute(
            f"SELECT * FROM ports WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.ports.append(self._row_to_port(row))

        for row in conn.execute(
            f"SELECT * FROM dns_records WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.dns_records.append(
                    DnsRecord(
                        host=row["host"],
                        record_type=row["record_type"],
                        value=row["value"],
                        ttl=row["ttl"],
                        priority=row["priority"] if "priority" in row.keys() else None,
                        security_tags=(
                            json.loads(row["security_tags_json"] or "[]")
                            if "security_tags_json" in row.keys()
                            else []
                        ),
                        source=row["source"] or "dnsx",
                        confidence_score=row["confidence_score"] or 80,
                    )
                )

        for row in conn.execute(
            f"SELECT * FROM urls WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.urls.append(
                    URL(
                        url=row["url"],
                        host=row["host"],
                        source=row["source"] or "crawler",
                        discovered_at=row["discovered_at"],
                        confidence_score=row["confidence_score"] or 60,
                        path=row["path"] or "",
                        parameters=(
                            json.loads(row["parameters_json"] or "[]")
                            if "parameters_json" in row.keys()
                            else []
                        ),
                        endpoint_type=row["endpoint_type"] or "page",
                        secrets=(
                            json.loads(row["secrets_json"] or "[]")
                            if "secrets_json" in row.keys()
                            else []
                        ),
                        jwts=(
                            json.loads(row["jwts_json"] or "[]")
                            if "jwts_json" in row.keys()
                            else []
                        ),
                    )
                )

        for row in conn.execute(
            f"SELECT * FROM tls_certificates WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.tls = TlsCertificate(
                    host=row["host"],
                    issuer=row["issuer"],
                    subject=row["subject"],
                    sans=json.loads(row["sans_json"] or "[]"),
                    not_after=row["not_after"],
                    not_before=row["not_before"] if "not_before" in row.keys() else None,
                    fingerprint_sha256=(
                        row["fingerprint_sha256"] if "fingerprint_sha256" in row.keys() else None
                    ),
                    is_wildcard=bool(row["is_wildcard"]),
                    source=row["source"] or "httpx",
                    confidence_score=row["confidence_score"] or 90,
                )

        for row in conn.execute(
            f"SELECT * FROM findings WHERE run_id=? AND host IN ({placeholders})",  # noqa: S608  # nosec B608  # table names are a hardcoded tuple, values are bound params
            [run_id, *domains],
        ):
            h = host_map.get(row["host"])
            if h:
                h.findings.append(
                    Finding(
                        host=row["host"],
                        template_id=row["template_id"],
                        severity=row["severity"] or "info",
                        name=row["name"] or row["template_id"],
                        source=row["source"] or "nuclei",
                        url=row["url"],
                        description=row["description"] if "description" in row.keys() else "",
                        confidence_score=row["confidence_score"] or 80,
                        discovered_at=row["discovered_at"],
                    )
                )

    def _row_to_host(self, row: sqlite3.Row) -> Host:
        from core.assets import HostCategory, HostProfile

        profile_data = json.loads(row["profile_json"] or "null") if row["profile_json"] else None
        profile = None
        if profile_data:
            try:
                category = HostCategory(profile_data.get("category", "unknown"))
            except ValueError:
                category = HostCategory.UNKNOWN
            try:
                priority = RiskLevel(profile_data.get("priority", "info"))
            except ValueError:
                priority = RiskLevel.INFO
            profile = HostProfile(
                category=category,
                priority=priority,
                summary=profile_data.get("summary", ""),
                confidence_score=profile_data.get("confidence_score", 0),
                has_authentication=profile_data.get("has_authentication", False),
                has_api=profile_data.get("has_api", False),
                has_graphql=profile_data.get("has_graphql", False),
                cloud_provider=profile_data.get("cloud_provider"),
                certificate_type=profile_data.get("certificate_type"),
                related_hosts=profile_data.get("related_hosts", []),
            )
        return Host(
            domain=row["domain"],
            hostname=row["hostname"] or row["domain"],
            root_domain=row["root_domain"] or "",
            subdomain=row["subdomain"] or "",
            ips=json.loads(row["ips_json"] or "[]"),
            asn=row["asn"],
            asn_org=row["asn_org"],
            cidr=row["cidr"],
            country=row["country"],
            city=row["city"] if "city" in row.keys() else None,
            latitude=row["latitude"] if "latitude" in row.keys() else None,
            longitude=row["longitude"] if "longitude" in row.keys() else None,
            provider=row["provider"],
            cloud_provider=row["cloud_provider"] if "cloud_provider" in row.keys() else None,
            cloud_region=row["cloud_region"] if "cloud_region" in row.keys() else None,
            registrar=row["registrar"] if "registrar" in row.keys() else None,
            registration_created_at=(
                row["registration_created_at"] if "registration_created_at" in row.keys() else None
            ),
            registration_expires_at=(
                row["registration_expires_at"] if "registration_expires_at" in row.keys() else None
            ),
            nameservers=(
                json.loads(row["nameservers_json"] or "[]")
                if "nameservers_json" in row.keys()
                else []
            ),
            is_cdn=bool(row["is_cdn"]),
            cdn_provider=row["cdn_provider"],
            waf_provider=row["waf_provider"],
            dns_resolved=bool(row["dns_resolved"]),
            dns_wildcard=bool(row["dns_wildcard"]),
            tarpit_suspected=(
                bool(row["tarpit_suspected"]) if "tarpit_suspected" in row.keys() else False
            ),
            tarpit_canary_ports=(
                json.loads(row["tarpit_canary_ports_json"] or "[]")
                if "tarpit_canary_ports_json" in row.keys()
                else []
            ),
            soft_404_detected=(
                bool(row["soft_404_detected"]) if "soft_404_detected" in row.keys() else False
            ),
            confidence=Confidence(row["confidence"] or "unknown"),
            confidence_score=row["confidence_score"] or 25,
            risk_level=RiskLevel(row["risk_level"] or "info"),
            risk_score=row["risk_score"] or 0,
            risk_reasons=json.loads(row["risk_reasons_json"] or "[]"),
            discovery_sources=json.loads(row["discovery_sources_json"] or "[]"),
            warnings=json.loads(row["warnings_json"] or "[]"),
            cluster_ids=json.loads(row["cluster_ids_json"] or "{}"),
            profile=profile,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            scan_timestamp=row["scan_timestamp"],
        )

    def _row_to_http(self, row: sqlite3.Row) -> HttpService:
        from core.assets import TechnologyFinding

        tech_raw = json.loads(row["technologies_json"] or "[]")
        technologies = []
        for t in tech_raw:
            if isinstance(t, dict):
                technologies.append(
                    TechnologyFinding(
                        name=t.get("name", ""),
                        source=t.get("source", "httpx"),
                        confidence=t.get("confidence", 80),
                        verified_by=t.get("verified_by", []),
                        version=t.get("version"),
                    )
                )
            else:
                technologies.append(TechnologyFinding(name=str(t), source="httpx", confidence=80))
        return HttpService(
            url=row["url"],
            host=row["host"],
            status_code=row["status_code"],
            title=row["title"],
            webserver=row["webserver"],
            technologies=technologies,
            headers=json.loads(row["headers_json"] or "{}"),
            security_headers=json.loads(row["security_headers_json"] or "{}"),
            cdn=row["cdn"],
            waf=row["waf"],
            confidence=Confidence(row["confidence"] or "unknown"),
            confidence_score=row["confidence_score"] or 80,
            body_hash=row["body_hash"],
            favicon_hash=row["favicon_hash"],
            content_length=row["content_length"] if "content_length" in row.keys() else None,
            response_size=row["response_size"] if "response_size" in row.keys() else None,
            tls_version=row["tls_version"] if "tls_version" in row.keys() else None,
            tls_cipher=row["tls_cipher"] if "tls_cipher" in row.keys() else None,
            response_fingerprint=row["response_fingerprint"],
            redirect_chain=json.loads(row["redirect_chain_json"] or "[]"),
        )

    def _row_to_port(self, row: sqlite3.Row) -> Port:
        return Port(
            host=row["host"],
            port=row["port"],
            protocol=row["protocol"] or "tcp",
            banner=row["banner"],
            source=row["source"] or "naabu",
            confidence=Confidence(row["confidence"] or "unknown"),
            confidence_score=row["confidence_score"] or 50,
            validated=bool(row["validated"]),
            verification_state=(
                row["verification_state"] if "verification_state" in row.keys() else "unverified"
            ),
            service=row["service"] if "service" in row.keys() else None,
            version=row["version"] if "version" in row.keys() else None,
            warnings=json.loads(row["warnings_json"] or "[]"),
        )

    def _insert_intel(self, conn: sqlite3.Connection, run_id: str, intel) -> None:
        """Batched insert of the intelligence snapshot."""
        entities = list(intel.entities.values())
        known = {e.entity_id for e in entities}
        observations = [o for o in intel.observations if o.entity_id in known]
        obs_ids = {o.observation_id for o in observations}
        evidence = [
            ev
            for ev in intel.evidence.values()
            if not ev.observation_id or ev.observation_id in obs_ids
        ]
        ev_ids = {ev.evidence_id for ev in evidence}
        relationships = [
            rel
            for rel in intel.relationships.values()
            if rel.source_entity in known
            and rel.target_entity in known
            and (not rel.evidence_id or rel.evidence_id in ev_ids)
        ]
        if entities:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_entities
                   (run_id, entity_id, entity_type, key, data_json, scope_status,
                    collection_status, is_seed, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        e.entity_id,
                        e.entity_type.value,
                        e.key,
                        json.dumps(e.data, sort_keys=True, default=str),
                        e.scope_status.value,
                        e.collection_status.value,
                        int(e.is_seed),
                        e.first_seen,
                        e.last_seen,
                    )
                    for e in entities
                ],
            )
        if observations:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_observations
                   (run_id, observation_id, entity_id, source, collector, observed_at,
                    data_json, scope_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        o.observation_id,
                        o.entity_id,
                        o.source,
                        o.collector,
                        o.observed_at,
                        json.dumps(o.data, sort_keys=True, default=str),
                        o.scope_status.value,
                    )
                    for o in observations
                ],
            )
        if evidence:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_evidence
                   (run_id, evidence_id, source, collector, observation_id, reason,
                    metadata_json, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        ev.evidence_id,
                        ev.source,
                        ev.collector,
                        ev.observation_id or None,
                        ev.reason,
                        json.dumps(ev.metadata, sort_keys=True, default=str),
                        ev.observed_at,
                    )
                    for ev in evidence
                ],
            )
        if relationships:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_relationships
                   (run_id, relationship_id, source_entity, relationship_type, target_entity,
                    confidence, strength, first_seen, last_seen, evidence_id, data_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        r.relationship_id,
                        r.source_entity,
                        r.relationship_type.value,
                        r.target_entity,
                        r.confidence.value,
                        r.strength,
                        r.first_seen,
                        r.last_seen,
                        r.evidence_id or None,
                        json.dumps(r.data, sort_keys=True, default=str),
                    )
                    for r in relationships
                ],
            )
        if intel.indicators:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_indicators
                   (run_id, indicator_id, kind, value, depth, parent_id, reason,
                    scope_status, collection_status, evidence_id, priority, discovered_from,
                    authorization_status, created_at, claimed_at, completed_at,
                    failure_reason, collector)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        i.indicator_id,
                        i.kind.value,
                        i.value,
                        i.depth,
                        i.parent_id,
                        i.reason.value,
                        i.scope_status.value,
                        i.collection_status.value,
                        i.evidence_id,
                        i.priority,
                        i.discovered_from,
                        getattr(i, "authorization_status", "") or "",
                        getattr(i, "created_at", "") or "",
                        getattr(i, "claimed_at", "") or "",
                        getattr(i, "completed_at", "") or "",
                        getattr(i, "failure_reason", "") or "",
                        getattr(i, "collector", "") or "",
                    )
                    for i in intel.indicators
                ],
            )
        hypotheses = getattr(intel, "hypotheses", None) or []
        if isinstance(hypotheses, dict):
            hypotheses = list(hypotheses.values())
        if hypotheses:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_hypotheses
                   (run_id, hypothesis_id, relationship_id, target_value, evidence_id,
                    confidence_band, status, rationale, depth, kind)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        h.hypothesis_id,
                        h.relationship_id,
                        h.target_value,
                        h.evidence_id or None,
                        h.confidence_band,
                        h.status,
                        h.rationale,
                        h.depth,
                        h.kind,
                    )
                    for h in hypotheses
                ],
            )
        attempts = (
            getattr(intel, "collection_attempts", None) or getattr(intel, "attempts", None) or []
        )
        if attempts:
            conn.executemany(
                """INSERT OR REPLACE INTO intel_collection_attempts
                   (run_id, attempt_id, indicator_id, value, capability, status,
                    reason, collector, observed_at, artifact)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_id,
                        a.attempt_id,
                        a.indicator_id,
                        a.value,
                        a.capability,
                        a.status,
                        a.reason,
                        a.collector,
                        a.observed_at,
                        a.artifact,
                    )
                    for a in attempts
                ],
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        return {
            "run_id": row["run_id"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "targets": json.loads(row["targets_json"] or "[]"),
            "program_name": row["program_name"],
            "host_count": row["host_count"],
            "alive_count": row["alive_count"],
            "scope_file_hash": row["scope_file_hash"],
            "attribution_fingerprint": row["attribution_fingerprint"],
        }

    def find_previous_run(self, current_run_id: str) -> str | None:
        """Most recent finished run whose target set overlaps the current run.

        Single bounded query. Never selects an unfinished run. Does not fall
        back to an unrelated latest run.
        """
        with self._connect() as conn:
            current = conn.execute(
                "SELECT targets_json FROM runs WHERE run_id=?", (current_run_id,)
            ).fetchone()
            if not current:
                return None
            targets = {
                _normalize_run_target(item)
                for item in json.loads(current["targets_json"] or "[]")
                if _normalize_run_target(item)
            }
            if not targets:
                return None
            placeholders = ",".join("?" * len(targets))
            row = conn.execute(
                f"""
                SELECT r.run_id
                FROM runs r
                WHERE r.run_id != ?
                  AND r.finished_at IS NOT NULL
                  AND r.finished_at != ''
                  AND EXISTS (
                    SELECT 1 FROM json_each(COALESCE(r.targets_json, '[]')) t
                    WHERE lower(trim(t.value, '.')) IN ({placeholders})
                  )
                ORDER BY r.started_at DESC
                LIMIT 1
                """,  # noqa: S608  # nosec B608  # placeholders are bound '?' only
                (current_run_id, *targets),
            ).fetchone()
        return row["run_id"] if row else None

    def find_latest_finished_run(self, *, domain: str | None = None) -> str | None:
        """Latest finished run, preferring one that observed or targeted domain."""
        host = _normalize_run_target(domain) if domain else ""
        with self._connect() as conn:
            if host:
                row = conn.execute(
                    """
                    SELECT r.run_id
                    FROM runs r
                    JOIN intel_entities e ON e.run_id = r.run_id
                    WHERE r.finished_at IS NOT NULL
                      AND r.finished_at != ''
                      AND e.entity_type = 'DOMAIN'
                      AND e.key = ?
                    ORDER BY r.started_at DESC
                    LIMIT 1
                    """,
                    (host,),
                ).fetchone()
                if row:
                    return row["run_id"]
                row = conn.execute(
                    """
                    SELECT r.run_id
                    FROM runs r
                    WHERE r.finished_at IS NOT NULL
                      AND r.finished_at != ''
                      AND EXISTS (
                        SELECT 1 FROM json_each(COALESCE(r.targets_json, '[]')) t
                        WHERE lower(trim(t.value, '.')) = ?
                      )
                    ORDER BY r.started_at DESC
                    LIMIT 1
                    """,
                    (host,),
                ).fetchone()
                if row:
                    return row["run_id"]
            row = conn.execute(
                """
                SELECT run_id FROM runs
                WHERE finished_at IS NOT NULL AND finished_at != ''
                ORDER BY started_at DESC
                LIMIT 1
                """
            ).fetchone()
        return row["run_id"] if row else None

    def find_latest_finished_run_for_program(self, program_name: str) -> str | None:
        """Latest finished run declared under the same PROGRAM_NAME.

        Verification-agent pre-flight (docs/VERIFICATION_AGENT_DESIGN.md
        B.1): unlike `find_previous_run`, this needs no existing `runs` row
        for the current run — it runs *before* `PipelineRunner.run()`,
        before the current run has been created at all. Unlike
        `find_latest_finished_run(domain=...)`, matching is by declared
        program identity, not by target overlap — two runs can share a
        program name across different target sets (a multi-target bug
        bounty program), and target overlap alone would miss that.
        """
        name = (program_name or "").strip()
        if not name:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT run_id FROM runs
                WHERE program_name = ?
                  AND finished_at IS NOT NULL AND finished_at != ''
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (name,),
            ).fetchone()
        return row["run_id"] if row else None

    def intel_connection(self) -> sqlite3.Connection:
        """Read connection used by intelligence query CLI. Same PRAGMAs as store."""
        return connect_sqlite(self.db_path)

    def intel_integrity(self, run_id: str | None = None) -> dict[str, Any]:
        """SQLite + application-level referential checks for intelligence tables."""
        with self._connect() as conn:
            fk_on = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
            orphans = self._intel_orphans(conn, run_id)
        fk_violations = [
            {"table": row[0], "rowid": row[1], "parent": row[2], "fkid": row[3]} for row in fk_rows
        ]
        return {
            "foreign_keys": int(fk_on),
            "integrity_check": integrity,
            "foreign_key_violations": fk_violations,
            "orphans": orphans,
            "ok": integrity == "ok" and not fk_violations and not any(orphans.values()),
        }

    def _intel_orphans(self, conn: sqlite3.Connection, run_id: str | None) -> dict[str, list[str]]:
        run_clause = {
            "observations": " AND o.run_id=?" if run_id else "",
            "relationships": " AND r.run_id=?" if run_id else "",
            "evidence": " AND ev.run_id=?" if run_id else "",
        }
        params: tuple[Any, ...] = (run_id,) if run_id else ()
        observations = [
            row["observation_id"]
            for row in conn.execute(
                f"""
                SELECT o.observation_id FROM intel_observations o
                WHERE NOT EXISTS (
                    SELECT 1 FROM intel_entities e
                    WHERE e.run_id=o.run_id AND e.entity_id=o.entity_id
                ){run_clause["observations"]}
                """,  # noqa: S608  # nosec B608
                params,
            )
        ]
        relationships = [
            row["relationship_id"]
            for row in conn.execute(
                f"""
                SELECT r.relationship_id FROM intel_relationships r
                WHERE (
                    NOT EXISTS (
                        SELECT 1 FROM intel_entities e
                        WHERE e.run_id=r.run_id AND e.entity_id=r.source_entity
                    )
                    OR NOT EXISTS (
                        SELECT 1 FROM intel_entities e
                        WHERE e.run_id=r.run_id AND e.entity_id=r.target_entity
                    )
                ){run_clause["relationships"]}
                """,  # noqa: S608  # nosec B608
                params,
            )
        ]
        evidence = [
            row["evidence_id"]
            for row in conn.execute(
                f"""
                SELECT ev.evidence_id FROM intel_evidence ev
                WHERE ev.observation_id IS NOT NULL
                  AND ev.observation_id != ''
                  AND NOT EXISTS (
                    SELECT 1 FROM intel_observations o
                    WHERE o.run_id=ev.run_id AND o.observation_id=ev.observation_id
                ){run_clause["evidence"]}
                """,  # noqa: S608  # nosec B608
                params,
            )
        ]
        return {
            "observations": observations,
            "relationships": relationships,
            "evidence": evidence,
        }


def _apply_prior_indicator_lifecycle(intel, prior_rows: list[dict[str, Any]]) -> None:
    """Preserve FAILED / interrupted IN_FLIGHT across finalize. Never invent COLLECTED."""
    from core.intel.model import CollectionStatus

    by_id = {str(row.get("indicator_id") or ""): row for row in prior_rows}
    by_value = {str(row.get("value") or "").lower(): row for row in prior_rows}
    for indicator in getattr(intel, "indicators", []) or []:
        row = by_id.get(indicator.indicator_id) or by_value.get(str(indicator.value).lower())
        if not row:
            continue
        try:
            prior = CollectionStatus(str(row.get("collection_status") or ""))
        except ValueError:
            continue
        if prior is CollectionStatus.IN_FLIGHT:
            if indicator.collection_status is not CollectionStatus.COLLECTED:
                indicator.collection_status = CollectionStatus.FAILED
                indicator.failure_reason = (
                    getattr(indicator, "failure_reason", "") or "interrupted_in_flight"
                )
        elif prior is CollectionStatus.FAILED:
            if indicator.collection_status is not CollectionStatus.COLLECTED:
                indicator.collection_status = CollectionStatus.FAILED
                indicator.failure_reason = str(
                    row.get("failure_reason")
                    or getattr(indicator, "failure_reason", "")
                    or "failed"
                )
        if row.get("claimed_at"):
            indicator.claimed_at = str(row.get("claimed_at"))
        if row.get("created_at") and not getattr(indicator, "created_at", ""):
            indicator.created_at = str(row.get("created_at"))
        if row.get("collector") and not getattr(indicator, "collector", ""):
            indicator.collector = str(row.get("collector"))
