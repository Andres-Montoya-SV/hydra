"""Intelligence engine: entities, observations, evidence, bounded indicators."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.assets import (
    GraphEdge,
    GraphNode,
    Host,
    InfrastructureGraph,
    normalize_domain,
    normalize_http_url,
)
from core.intel.bounds import DiscoveryBounds
from core.intel.cloud import cloud_provider_for_ip, is_ipv4, is_ipv6
from core.intel.correlate import (
    band_score,
    bounded_pairs,
    ipv4_confidence,
    ipv6_confidence,
    registrable_domain,
    shares_certificate_confidence,
)
from core.intel.model import (
    AttemptStatus,
    CollectionAttempt,
    CollectionCapability,
    CollectionStatus,
    CollectReason,
    ConfidenceBand,
    EntityType,
    Evidence,
    Hypothesis,
    HypothesisStatus,
    Indicator,
    IndicatorKind,
    IntelEntity,
    Observation,
    Relationship,
    RelationshipType,
    ScopeStatus,
    certificate_entity_id,
    dump_json,
    entity_id,
    normalize_fingerprint,
    stable_id,
)
from core.intel.plugin import StructuredEmission, validate_emitted_relationship
from core.intel.queue import IndicatorQueue
from core.intel.scope import (
    CollectionScope,
    allows_active_collection,
    classify_scope,
    scope_status_allows_collection,
)
from core.intel.tls import extract_certificate_names, extract_sans, extract_tls_fingerprint
from core.provenance import utc_now_iso
from utils.files import read_jsonl


@dataclass
class IntelRunConfig:
    run_id: str
    seed_domains: list[str]
    scope_patterns: list[str] = field(default_factory=list)
    bounds: DiscoveryBounds = field(default_factory=DiscoveryBounds)
    collected_domains: set[str] = field(default_factory=set)
    emissions: list[dict[str, Any]] = field(default_factory=list)
    observed_at: str = ""
    cloud_collection_allowed: bool = False

    def collection_scope(self) -> CollectionScope:
        return CollectionScope(
            seed_domains=tuple(
                normalize_domain(s) for s in self.seed_domains if normalize_domain(s)
            ),
            scope_patterns=tuple(self.scope_patterns),
            cloud_collection_allowed=self.cloud_collection_allowed,
        )


@dataclass
class IntelSnapshot:
    run_id: str
    entities: dict[str, IntelEntity]
    observations: list[Observation]
    evidence: dict[str, Evidence]
    relationships: dict[str, Relationship]
    indicators: list[Indicator]
    hypotheses: list[Hypothesis] = field(default_factory=list)
    collection_attempts: list[CollectionAttempt] = field(default_factory=list)
    truncated: bool = False
    truncation_reason: str | None = None

    def domains(self) -> list[IntelEntity]:
        return [e for e in self.entities.values() if e.entity_type is EntityType.DOMAIN]

    def certificates(self) -> list[IntelEntity]:
        return [e for e in self.entities.values() if e.entity_type is EntityType.CERTIFICATE]


class IntelEngine:
    """Normalize recon artifacts into an evidence-backed intelligence graph."""

    def __init__(self, config: IntelRunConfig) -> None:
        self.config = config
        self.bounds = config.bounds
        self.observed_at = config.observed_at or utc_now_iso()
        self.entities: dict[str, IntelEntity] = {}
        self.observations: list[Observation] = []
        self.evidence: dict[str, Evidence] = {}
        self.relationships: dict[str, Relationship] = {}
        self.queue = IndicatorQueue(config.bounds)
        self.hypotheses: dict[str, Hypothesis] = {}
        self.attempts: list[CollectionAttempt] = []
        self._truncated = False
        self._truncation_reason: str | None = None
        seeds = [normalize_domain(s) for s in config.seed_domains if normalize_domain(s)]
        self.seeds = seeds
        self.scope = config.collection_scope()
        for seed in seeds:
            self._domain_entity(seed, is_seed=True)
            self.queue.add(
                kind=IndicatorKind.DOMAIN,
                value=seed,
                depth=0,
                parent_id=None,
                reason=CollectReason.SEED,
                scope_status=ScopeStatus.IN_SCOPE,
                evidence_id="",
                discovered_from="cli",
                collected=seed in {normalize_domain(c) for c in config.collected_domains},
                is_seed=True,
                priority=0,
            )

    def snapshot(self) -> IntelSnapshot:
        self._drop_orphans()
        return IntelSnapshot(
            run_id=self.config.run_id,
            entities=self.entities,
            observations=list(self.observations),
            evidence=self.evidence,
            relationships=self.relationships,
            indicators=self.queue.values(),
            hypotheses=list(self.hypotheses.values()),
            collection_attempts=list(self.attempts),
            truncated=self._truncated,
            truncation_reason=self._truncation_reason,
        )

    def _mark_truncated(self, reason: str) -> None:
        self._truncated = True
        if not self._truncation_reason:
            self._truncation_reason = reason

    def _put_entity(self, entity: IntelEntity) -> IntelEntity | None:
        existing = self.entities.get(entity.entity_id)
        if existing:
            return existing
        if (
            entity.entity_type is EntityType.CERTIFICATE
            and self._count_type(EntityType.CERTIFICATE) >= self.bounds.max_certificates
        ):
            self._mark_truncated("certificate_limit")
            return None
        if (
            entity.entity_type is EntityType.IP_ADDRESS
            and self._count_type(EntityType.IP_ADDRESS) >= self.bounds.max_ips
        ):
            self._mark_truncated("ip_limit")
            return None
        if (
            entity.entity_type is EntityType.URL
            and self._count_type(EntityType.URL) >= self.bounds.max_url_entities
        ):
            self._mark_truncated("entity_limit")
            return None
        if (
            entity.entity_type is EntityType.TECHNOLOGY
            and self._count_type(EntityType.TECHNOLOGY) >= self.bounds.max_technology_entities
        ):
            self._mark_truncated("entity_limit")
            return None
        if len(self.entities) >= self.bounds.max_entities:
            if entity.is_seed:
                victim = next(
                    (
                        eid
                        for eid, item in reversed(list(self.entities.items()))
                        if not item.is_seed and item.entity_type is EntityType.DOMAIN
                    ),
                    None,
                )
                if victim:
                    del self.entities[victim]
                    self._mark_truncated("entity_limit")
                else:
                    self._mark_truncated("entity_limit")
                    return None
            else:
                self._mark_truncated("entity_limit")
                return None
        self.entities[entity.entity_id] = entity
        return entity

    def _count_type(self, entity_type: EntityType) -> int:
        return sum(1 for item in self.entities.values() if item.entity_type is entity_type)

    def _prioritize_certificate_names(self, names: list[str]) -> list[str]:
        unique = list(
            dict.fromkeys(normalize_domain(name) for name in names if normalize_domain(name))
        )
        seeds = [name for name in unique if name in self.seeds]
        in_scope = [
            name
            for name in unique
            if name not in self.seeds and allows_active_collection(name, self.scope)
        ]
        rest = [name for name in unique if name not in seeds and name not in in_scope]
        return seeds + in_scope + rest

    def _drop_orphans(self) -> None:
        known = set(self.entities)
        self.observations = [obs for obs in self.observations if obs.entity_id in known]
        obs_ids = {obs.observation_id for obs in self.observations}
        self.evidence = {
            eid: ev
            for eid, ev in self.evidence.items()
            if not ev.observation_id or ev.observation_id in obs_ids
        }
        ev_ids = set(self.evidence)
        self.relationships = {
            rid: rel
            for rid, rel in self.relationships.items()
            if rel.source_entity in known
            and rel.target_entity in known
            and (not rel.evidence_id or rel.evidence_id in ev_ids)
        }

    def ingest_hosts(self, hosts: dict[str, Host]) -> None:
        authorized_collected = {
            normalize_domain(c)
            for c in self.config.collected_domains
            if allows_active_collection(c, self.scope)
        }
        for domain, host in hosts.items():
            name = normalize_domain(domain)
            if not name:
                continue
            authorized = allows_active_collection(name, self.scope)
            actively_collected = authorized and (
                name in authorized_collected or bool(host.dns_resolved) or bool(host.http_services)
            )
            entity = self._domain_entity(name, collected=actively_collected)
            if entity is None:
                continue
            if actively_collected:
                self.queue.mark_collected(IndicatorKind.DOMAIN, name)
            self._observe(
                entity.entity_id,
                source="host_registry",
                collector="host_registry",
                data={
                    "dns_resolved": host.dns_resolved,
                    "is_seed": entity.is_seed,
                    "authorized": authorized,
                },
            )
            if authorized:
                for ip in host.ips:
                    self._ingest_resolution(name, str(ip), source="host", collector="dnsx")
                if host.asn:
                    self._ingest_asn(name, str(host.asn), host.asn_org or "")
                for rec in host.dns_records:
                    if rec.record_type == "NS" and rec.value:
                        self._ingest_nameserver(name, rec.value)
                for svc in host.http_services:
                    self._ingest_http_service(name, svc)
            if host.tls:
                self._ingest_tls_from_host(name, host)

    def ingest_artifacts(self, output_dir: Path) -> None:
        ct_path = output_dir / "ctlogs.jsonl"
        if ct_path.exists():
            self.ingest_ct_records(read_jsonl(ct_path))
        httpx_path = output_dir / "httpx.json"
        if httpx_path.exists():
            self.ingest_httpx_records(read_jsonl(httpx_path))
        passive_path = output_dir / "passive_dns.jsonl"
        if passive_path.exists():
            self.ingest_passive_dns_records(read_jsonl(passive_path))

    def ingest_ct_records(self, records: Iterable[dict[str, Any]]) -> None:
        for record in records:
            if not isinstance(record, dict):
                continue
            names = self._prioritize_certificate_names(
                extract_certificate_names(record.get("name_value") or record.get("common_name"))
            )
            if not names:
                continue
            fingerprint = extract_tls_fingerprint(record) or normalize_fingerprint(
                str(record.get("fingerprint_sha256") or "")
            )
            cert_id_raw = str(record.get("id") or "")
            serial = str(record.get("serial_number") or "")
            issuer = str(record.get("issuer_name") or record.get("issuer") or "")
            not_before = str(record.get("not_before") or "") or None
            not_after = str(record.get("not_after") or "") or None
            if fingerprint:
                cert_key = fingerprint
                identity_kind = "sha256"
            elif serial and issuer:
                cert_key = f"serial:{stable_id(issuer, serial, not_before or '', not_after or '')}"
                identity_kind = "serial_issuer"
            else:
                # crt.sh id / SAN tuples are not cryptographic identity.
                cert_key = f"unidentified:{stable_id(dump_json(record))}"
                identity_kind = "unidentified"
            observed_names = names[: self.bounds.max_ct_names_per_certificate]
            if len(names) > len(observed_names):
                self._mark_truncated("ct_names_per_certificate")
            cert = self._certificate_entity(
                cert_key,
                fingerprint_sha256=fingerprint,
                subject=str(record.get("common_name") or names[0]),
                issuer=issuer or None,
                serial=serial or None,
                not_before=not_before,
                not_after=not_after,
                sans=observed_names,
                identity_kind=identity_kind,
            )
            if cert is None:
                continue
            cert.data["san_cardinality"] = len(set(names))
            cert.data["sans_truncated"] = len(names) > len(observed_names)
            obs = self._observe(
                cert.entity_id,
                source="certificate_transparency",
                collector="ctlogs",
                data={
                    "names": observed_names,
                    "san_cardinality": len(set(names)),
                    "crtsh_id": cert_id_raw,
                    "identity_kind": identity_kind,
                    "identified": identity_kind in {"sha256", "serial_issuer"},
                },
            )
            if obs is None:
                continue
            query_domain = normalize_domain(str(record.get("query_domain") or ""))
            parent = self.queue.get(IndicatorKind.DOMAIN, query_domain) if query_domain else None
            parent_id = parent.indicator_id if parent else None
            parent_depth = parent.depth if parent else 0
            for name in observed_names:
                self._observe_san(
                    cert,
                    name,
                    observation=obs,
                    source="certificate_transparency",
                    collector="ctlogs",
                    parent_id=parent_id,
                    parent_depth=parent_depth,
                    reason=CollectReason.CERTIFICATE_SAN,
                )

    def ingest_httpx_records(self, records: Iterable[dict[str, Any]]) -> None:
        for record in records:
            if not isinstance(record, dict):
                continue
            domain = normalize_domain(
                str(record.get("input") or record.get("host") or record.get("url") or "")
            )
            if not domain:
                continue
            authorized = allows_active_collection(domain, self.scope)
            if self._domain_entity(domain, collected=authorized) is None:
                continue
            if authorized:
                self.queue.mark_collected(IndicatorKind.DOMAIN, domain)
            tls = record.get("tls") if isinstance(record.get("tls"), dict) else {}
            fingerprint = extract_tls_fingerprint(tls)
            sans = extract_sans(tls.get("subject_an") or tls.get("sans") if tls else [])
            ips: list[str] = []
            for ip in record.get("a") or []:
                ips.append(str(ip))
            if record.get("ip"):
                ips.append(str(record.get("ip")))
            if authorized:
                for ip in ips:
                    self._ingest_resolution(domain, ip, source="httpx", collector="httpx")
            if fingerprint or sans:
                cert_key = fingerprint or f"opaque:{stable_id(domain, dump_json(sans))}"
                # Prefer fingerprint. Opaque only if httpx omitted the hash entirely.
                identity_kind = "sha256" if fingerprint else "opaque_record"
                if not fingerprint:
                    continue
                cert = self._certificate_entity(
                    cert_key,
                    fingerprint_sha256=fingerprint,
                    subject=str(tls.get("subject_cn") or tls.get("subject") or domain),
                    issuer=str(tls.get("issuer_cn") or tls.get("issuer") or "") or None,
                    not_before=str(tls.get("not_before") or "") or None,
                    not_after=str(tls.get("not_after") or "") or None,
                    sans=sans,
                    identity_kind=identity_kind,
                )
                if cert is None:
                    continue
                obs = self._observe(
                    cert.entity_id,
                    source="tls",
                    collector="httpx",
                    data={"host": domain, "fingerprint_sha256": fingerprint, "sans": sans},
                )
                self._relate(
                    entity_id(EntityType.DOMAIN, domain),
                    RelationshipType.PRESENTS_CERTIFICATE,
                    cert.entity_id,
                    ConfidenceBand.VERY_HIGH,
                    "leaf_certificate_fingerprint",
                    obs,
                    metadata={"fingerprint_sha256": fingerprint},
                )
                parent = self.queue.get(IndicatorKind.DOMAIN, domain)
                for ip in ips:
                    ip_entity = entity_id(EntityType.IP_ADDRESS, ip)
                    if ip_entity in self.entities:
                        self._relate(
                            cert.entity_id,
                            RelationshipType.PRESENTED_AT,
                            ip_entity,
                            ConfidenceBand.HIGH,
                            "tls_handshake_ip",
                            obs,
                            metadata={"ip": ip},
                        )
                for name in sans:
                    self._observe_san(
                        cert,
                        name,
                        observation=obs,
                        source="tls",
                        collector="httpx",
                        parent_id=parent.indicator_id if parent else None,
                        parent_depth=parent.depth if parent else 0,
                        reason=CollectReason.CERTIFICATE_SAN,
                    )

    def ingest_passive_dns_records(self, records: Iterable[dict[str, Any]]) -> None:
        """Ingest passive-DNS artifacts written by production collectors.

        Records resolutions without authorizing active collection.
        """
        for record in records:
            if not isinstance(record, dict):
                continue
            name = normalize_domain(str(record.get("host") or record.get("domain") or ""))
            raw_ips = record.get("ip") or record.get("a") or record.get("addresses") or []
            if isinstance(raw_ips, str):
                raw_ips = [raw_ips]
            collector = str(record.get("collector") or "passive_dns")
            source = str(record.get("source") or "passive_dns")
            if not name:
                continue
            if self._domain_entity(name, collected=False) is None:
                continue
            for ip in raw_ips:
                if ip:
                    self._ingest_resolution(name, str(ip), source=source, collector=collector)

    def ingest_passive_resolutions(
        self, mapping: dict[str, str], *, source: str = "passive", collector: str = "fixture"
    ) -> None:
        """Record DNS observations without marking domains COLLECTED.

        Used for case fixtures and unit tests. Production code writes
        ``passive_dns.jsonl`` and goes through ``ingest_artifacts``.
        """
        for domain, ip in mapping.items():
            name = normalize_domain(domain)
            if not name or not ip:
                continue
            if self._domain_entity(name, collected=False) is None:
                continue
            self._ingest_resolution(name, str(ip), source=source, collector=collector)

    def ingest_emissions(self, emissions: Iterable[dict[str, Any] | StructuredEmission]) -> None:
        for raw in emissions:
            emission = (
                raw if isinstance(raw, StructuredEmission) else StructuredEmission.from_dict(raw)
            )
            for domain in emission.domains:
                name = normalize_domain(domain)
                if name:
                    if self._domain_entity(name) is None:
                        continue
                    self._observe(
                        entity_id(EntityType.DOMAIN, name),
                        source="plugin",
                        collector="plugin",
                        data={"plugin_domain": name},
                    )
            for ip in emission.ip_addresses:
                self._ip_entity(str(ip))
            for cert in emission.certificates:
                fp = normalize_fingerprint(str(cert.get("fingerprint_sha256") or ""))
                if not fp:
                    continue
                names = extract_sans(cert.get("sans") or [])
                entity = self._certificate_entity(
                    fp,
                    fingerprint_sha256=fp,
                    subject=str(cert.get("subject") or ""),
                    issuer=str(cert.get("issuer") or "") or None,
                    not_before=str(cert.get("not_before") or "") or None,
                    not_after=str(cert.get("not_after") or "") or None,
                    sans=names,
                )
                if entity is None:
                    continue
                obs = self._observe(
                    entity.entity_id,
                    source="plugin",
                    collector=str(cert.get("collector") or "plugin"),
                    data={"fingerprint_sha256": fp, "sans": names},
                )
                for name in names:
                    self._observe_san(
                        entity,
                        name,
                        observation=obs,
                        source="plugin",
                        collector=str(cert.get("collector") or "plugin"),
                        parent_id=None,
                        parent_depth=0,
                        reason=CollectReason.PLUGIN,
                    )
            for rel in emission.relationships:
                self._ingest_emitted_relationship(rel)
            self._ingest_emission_followups(emission)

    def _ingest_emission_followups(self, emission: StructuredEmission) -> None:
        """Queue plugin follow-ups. A reason string is never evidence."""
        if not emission.followups:
            return
        for item in emission.followups:
            values = [item.get("value")] if item.get("value") else list(emission.domains)
            claimed_evidence = str(item.get("evidence_id") or "")
            for raw in values:
                name = normalize_domain(str(raw or ""))
                if not name:
                    continue
                entity = self.entities.get(entity_id(EntityType.DOMAIN, name))
                if entity is None:
                    continue
                evidence_id = claimed_evidence if claimed_evidence in self.evidence else ""
                self.queue.add(
                    kind=IndicatorKind.DOMAIN,
                    value=name,
                    depth=1,
                    parent_id=None,
                    reason=CollectReason.PLUGIN,
                    scope_status=entity.scope_status,
                    evidence_id=evidence_id,
                    discovered_from="plugin_followup",
                    collected=entity.collection_status is CollectionStatus.COLLECTED,
                    is_seed=entity.is_seed,
                    source_entity_id=entity.entity_id,
                )

    def correlate(self) -> None:
        self._correlate_shared_certificates()
        self._correlate_shared_ips()
        self._correlate_shared_nameservers()
        self._correlate_shared_asn()
        self._correlate_http_identity()
        self._emit_hypotheses()

    def _emit_hypotheses(self) -> None:
        """Relationships do not authorize collection. They may create hypotheses."""
        collected = {normalize_domain(c) for c in self.config.collected_domains}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.SAN_CONTAINS:
                continue
            domain = rel.target_entity.removeprefix("domain:")
            host = normalize_domain(domain)
            if not host or host in collected:
                continue
            hid = stable_id("hypothesis", rel.relationship_id, host)
            in_scope = allows_active_collection(host, self.scope)
            status = HypothesisStatus.OPEN.value if in_scope else HypothesisStatus.REJECTED.value
            rationale = (
                "Observed SAN relationship; possible related infrastructure. "
                "Not authorization to collect."
                if in_scope
                else "Observed SAN relationship is out of scope; not a collection command."
            )
            self.hypotheses[hid] = Hypothesis(
                hypothesis_id=hid,
                relationship_id=rel.relationship_id,
                target_value=host,
                evidence_id=rel.evidence_id,
                confidence_band=rel.confidence.value,
                status=status,
                rationale=rationale,
                depth=1,
            )

    def record_attempt(
        self,
        value: str,
        *,
        capability: CollectionCapability,
        success: bool,
        collector: str,
        reason: str,
        artifact: str = "",
    ) -> CollectionAttempt:
        item = self.queue.get(IndicatorKind.DOMAIN, value)
        indicator_id = item.indicator_id if item else stable_id("indicator", "DOMAIN", value)
        attempt = CollectionAttempt(
            attempt_id=stable_id("attempt", indicator_id, capability.value, collector, reason),
            indicator_id=indicator_id,
            value=value,
            capability=capability.value,
            status=AttemptStatus.SUCCESS.value if success else AttemptStatus.FAILED.value,
            reason=reason,
            collector=collector,
            observed_at=self.observed_at,
            artifact=artifact,
        )
        self.attempts.append(attempt)
        return attempt

    def authorize_hypothesis(self, hostname: str) -> None:
        host = normalize_domain(hostname)
        for hyp in self.hypotheses.values():
            if hyp.target_value == host and hyp.status == HypothesisStatus.OPEN.value:
                hyp.status = HypothesisStatus.AUTHORIZED_FOR_COLLECTION.value

    def reject_hypothesis(self, hostname: str, *, reason: str = "") -> None:
        host = normalize_domain(hostname)
        for hyp in self.hypotheses.values():
            if hyp.target_value == host and hyp.status == HypothesisStatus.OPEN.value:
                hyp.status = HypothesisStatus.REJECTED.value
                if reason:
                    hyp.rationale = reason

    def eligible_followups(
        self, kind: IndicatorKind | None = IndicatorKind.DOMAIN
    ) -> list[Indicator]:
        return self.queue.eligible_followups(kind)

    def annotate_hosts(self, hosts: dict[str, Host]) -> None:
        """Attach explainable correlation context to Host (reporting view)."""
        cert_members = self._certificate_member_map()
        for domain, host in hosts.items():
            name = normalize_domain(domain)
            extra: list[str] = []
            for members in cert_members.values():
                if name in members and len(members) > 1:
                    others = sorted(m for m in members if m != name)
                    extra.append(
                        f"Certificate shared with {len(others)} additional domain(s) "
                        "(infrastructure correlation, not attribution)"
                    )
                    break
            ip_cloud = [cloud_provider_for_ip(ip) for ip in host.ips]
            if any(ip_cloud) and "shared_cloud_tenancy" not in " ".join(host.risk_reasons):
                provider = next(p for p in ip_cloud if p)
                extra.append(f"Address on {provider} — shared tenancy, not ownership evidence")
            # Do not treat shared cloud IP as critical.
            for reason in extra:
                if reason not in host.risk_reasons:
                    host.risk_reasons.append(reason)

    def to_infrastructure_graph(
        self, host_graph: InfrastructureGraph | None = None
    ) -> InfrastructureGraph:
        graph = InfrastructureGraph()
        if host_graph:
            for node in host_graph.nodes.values():
                if not str(node.node_id).startswith("cert:"):
                    graph.add_node(node)
            for edge in host_graph.edges:
                if not str(edge.source_id).startswith("cert:") and not str(
                    edge.target_id
                ).startswith("cert:"):
                    graph.add_edge(edge)

        for entity in self.entities.values():
            node_id = entity.entity_id
            graph.add_node(
                GraphNode(
                    node_id=node_id,
                    node_type=entity.entity_type.value.lower(),
                    label=str(entity.data.get("label") or entity.key),
                    metadata={
                        "scope_status": entity.scope_status.value,
                        "collection_status": entity.collection_status.value,
                        "is_seed": entity.is_seed,
                        **{
                            k: v
                            for k, v in entity.data.items()
                            if k in {"fingerprint_sha256", "sans", "provider", "cloud_tenancy"}
                        },
                    },
                )
            )
            if entity.entity_type is EntityType.DOMAIN and entity.collection_status is (
                CollectionStatus.COLLECTED
            ):
                host_id = f"host:{entity.key}"
                if host_id in graph.nodes:
                    graph.add_edge(GraphEdge(host_id, node_id, "projects_to", confidence=100))

        for rel in self.relationships.values():
            band = band_score(rel.confidence)
            graph.add_edge(
                GraphEdge(
                    rel.source_entity,
                    rel.target_entity,
                    rel.relationship_type.value,
                    confidence=band,
                    evidence_id=rel.evidence_id,
                    first_seen=rel.first_seen,
                    last_seen=rel.last_seen,
                    confidence_label=rel.confidence.value,
                )
            )
        return graph

    # --- internals ---------------------------------------------------------

    def _scope_of(self, hostname: str) -> ScopeStatus:
        return classify_scope(
            hostname,
            seed_domains=self.seeds,
            scope_patterns=self.config.scope_patterns or None,
        )

    def _domain_entity(
        self, name: str, *, is_seed: bool = False, collected: bool = False
    ) -> IntelEntity | None:
        name = normalize_domain(name)
        eid = entity_id(EntityType.DOMAIN, name)
        existing = self.entities.get(eid)
        scope = ScopeStatus.IN_SCOPE if is_seed or name in self.seeds else self._scope_of(name)
        if existing:
            if is_seed:
                existing.is_seed = True
                existing.scope_status = ScopeStatus.IN_SCOPE
            if collected and scope_status_allows_collection(existing.scope_status):
                existing.collection_status = CollectionStatus.COLLECTED
            return existing
        status = CollectionStatus.NOT_COLLECTED
        if collected and scope_status_allows_collection(scope):
            status = CollectionStatus.COLLECTED
        elif not scope_status_allows_collection(scope):
            status = CollectionStatus.NOT_ALLOWED
        entity = IntelEntity(
            entity_id=eid,
            entity_type=EntityType.DOMAIN,
            key=name,
            data={"label": name},
            scope_status=scope,
            collection_status=status,
            is_seed=is_seed or name in self.seeds,
            first_seen=self.observed_at,
            last_seen=self.observed_at,
        )
        return self._put_entity(entity)

    def _ip_entity(self, ip: str) -> IntelEntity | None:
        ip = ip.strip()
        eid = entity_id(EntityType.IP_ADDRESS, ip)
        existing = self.entities.get(eid)
        if existing:
            return existing
        provider = cloud_provider_for_ip(ip)
        entity = IntelEntity(
            entity_id=eid,
            entity_type=EntityType.IP_ADDRESS,
            key=ip,
            data={
                "label": ip,
                "version": "ipv4" if is_ipv4(ip) else ("ipv6" if is_ipv6(ip) else "unknown"),
                "provider": provider,
                "cloud_tenancy": bool(provider),
            },
            first_seen=self.observed_at,
            last_seen=self.observed_at,
        )
        return self._put_entity(entity)

    def _certificate_entity(
        self,
        cert_key: str,
        *,
        fingerprint_sha256: str = "",
        subject: str = "",
        issuer: str | None = None,
        serial: str | None = None,
        not_before: str | None = None,
        not_after: str | None = None,
        sans: list[str] | None = None,
        identity_kind: str = "sha256",
    ) -> IntelEntity | None:
        fp = normalize_fingerprint(fingerprint_sha256)
        eid = certificate_entity_id(fp or None, fallback=cert_key)
        existing = self.entities.get(eid)
        names = list(sans or [])
        if existing:
            merged = list(dict.fromkeys(list(existing.data.get("sans") or []) + names))
            existing.data["sans"] = merged
            if fp:
                existing.data["fingerprint_sha256"] = fp
                existing.data["identity_kind"] = "sha256"
            if subject:
                existing.data["subject"] = subject
            if issuer:
                existing.data["issuer"] = issuer
            if serial:
                existing.data["serial"] = serial
            if not_before:
                existing.data["not_before"] = not_before
            if not_after:
                existing.data["not_after"] = not_after
            return existing
        entity = IntelEntity(
            entity_id=eid,
            entity_type=EntityType.CERTIFICATE,
            key=fp or cert_key,
            data={
                "label": (fp[:16] + "…") if fp else cert_key,
                "fingerprint_sha256": fp or None,
                "subject": subject,
                "issuer": issuer,
                "serial": serial,
                "not_before": not_before,
                "not_after": not_after,
                "sans": names,
                "identity_kind": identity_kind if not fp else "sha256",
            },
            first_seen=self.observed_at,
            last_seen=self.observed_at,
        )
        return self._put_entity(entity)

    def _observe(
        self,
        entity_eid: str,
        *,
        source: str,
        collector: str,
        data: dict[str, Any],
    ) -> Observation | None:
        entity = self.entities.get(entity_eid)
        if entity is None:
            return None
        scope = entity.scope_status
        obs = Observation(
            observation_id=stable_id(
                "obs", self.config.run_id, entity_eid, source, collector, dump_json(data)
            ),
            entity_id=entity_eid,
            source=source,
            collector=collector,
            run_id=self.config.run_id,
            observed_at=self.observed_at,
            data=data,
            scope_status=scope,
        )
        self.observations.append(obs)
        return obs

    def _evidence_from(
        self, observation: Observation, reason: str, metadata: dict[str, Any]
    ) -> Evidence:
        eid = stable_id("ev", observation.observation_id, reason, dump_json(metadata))
        existing = self.evidence.get(eid)
        if existing:
            return existing
        ev = Evidence(
            evidence_id=eid,
            source=observation.source,
            collector=observation.collector,
            observation_id=observation.observation_id,
            reason=reason,
            metadata=metadata,
            observed_at=observation.observed_at,
        )
        self.evidence[eid] = ev
        return ev

    def _relate(
        self,
        source: str,
        rel_type: RelationshipType,
        target: str,
        confidence: ConfidenceBand,
        strength: str,
        observation: Observation | None,
        metadata: dict[str, Any] | None = None,
    ) -> Relationship | None:
        if observation is None:
            return None
        if source not in self.entities or target not in self.entities:
            return None
        if len(self.relationships) >= self.bounds.max_relationships:
            self._mark_truncated("relationship_limit")
            return None
        metadata = metadata or {}
        evidence = self._evidence_from(observation, strength, metadata)
        identity = (
            str(metadata.get("certificate") or "")
            or str(metadata.get("fingerprint_sha256") or "")
            or str(metadata.get("ip") or "")
            or str(metadata.get("favicon") or metadata.get("favicon_hash") or "")
            or str(metadata.get("body_hash") or "")
            or str(metadata.get("nameserver") or "")
            or str(metadata.get("asn") or "")
        )
        rid = stable_id("rel", source, rel_type.value, target, identity)
        existing = self.relationships.get(rid)
        if existing:
            existing.last_seen = self.observed_at
            existing.evidence_id = evidence.evidence_id
            return existing
        rel = Relationship(
            relationship_id=rid,
            source_entity=source,
            relationship_type=rel_type,
            target_entity=target,
            confidence=confidence,
            strength=strength,
            first_seen=self.observed_at,
            last_seen=self.observed_at,
            evidence_id=evidence.evidence_id,
            data=metadata,
        )
        self.relationships[rid] = rel
        return rel

    def _observe_san(
        self,
        cert: IntelEntity,
        name: str,
        *,
        observation: Observation,
        source: str,
        collector: str,
        parent_id: str | None,
        parent_depth: int,
        reason: CollectReason,
    ) -> None:
        if cert.entity_id not in self.entities:
            return
        domain = self._domain_entity(name)
        if domain is None:
            return
        name_obs = self._observe(
            domain.entity_id,
            source=source,
            collector=collector,
            data={
                "observed_as": "certificate_san",
                "certificate": cert.entity_id,
                "fingerprint_sha256": cert.data.get("fingerprint_sha256"),
            },
        )
        self._relate(
            cert.entity_id,
            RelationshipType.SAN_CONTAINS,
            domain.entity_id,
            ConfidenceBand.VERY_HIGH,
            "certificate_san",
            name_obs,
            metadata={
                "certificate": cert.entity_id,
                "fingerprint_sha256": cert.data.get("fingerprint_sha256"),
                "san": name,
            },
        )
        san_rel = next(
            (
                rel
                for rel in self.relationships.values()
                if rel.relationship_type is RelationshipType.SAN_CONTAINS
                and rel.source_entity == cert.entity_id
                and rel.target_entity == domain.entity_id
            ),
            None,
        )
        collected = domain.collection_status is CollectionStatus.COLLECTED
        self.queue.add(
            kind=IndicatorKind.DOMAIN,
            value=name,
            depth=parent_depth + 1,
            parent_id=parent_id,
            reason=reason,
            scope_status=domain.scope_status,
            evidence_id=san_rel.evidence_id if san_rel else "",
            discovered_from=cert.entity_id,
            collected=collected,
            is_seed=domain.is_seed,
            source_entity_id=cert.entity_id,
            priority=40 if domain.scope_status is ScopeStatus.IN_SCOPE else 90,
        )

    def _ingest_resolution(self, domain: str, ip: str, *, source: str, collector: str) -> None:
        ip = ip.strip()
        if not ip:
            return
        host = self._domain_entity(domain)
        addr = self._ip_entity(ip)
        if host is None or addr is None:
            return
        obs = self._observe(
            host.entity_id,
            source=source,
            collector=collector,
            data={"record": "A" if is_ipv4(ip) else "AAAA", "ip": ip},
        )
        self._relate(
            host.entity_id,
            RelationshipType.RESOLVES_TO,
            addr.entity_id,
            ConfidenceBand.HIGH,
            "dns_resolution",
            obs,
            metadata={"ip": ip},
        )
        parent = self.queue.get(IndicatorKind.DOMAIN, domain)
        self.queue.add(
            kind=IndicatorKind.IP,
            value=ip,
            depth=(parent.depth + 1) if parent else 1,
            parent_id=parent.indicator_id if parent else None,
            reason=CollectReason.DNS_RESOLUTION,
            scope_status=host.scope_status,
            evidence_id=obs.observation_id,
            discovered_from=host.entity_id,
            collected=host.collection_status is CollectionStatus.COLLECTED,
        )

    def _ingest_asn(self, domain: str, asn: str, org: str) -> None:
        host = self._domain_entity(domain)
        if host is None:
            return
        eid = entity_id(EntityType.ASN, asn)
        if eid not in self.entities:
            created = self._put_entity(
                IntelEntity(
                    entity_id=eid,
                    entity_type=EntityType.ASN,
                    key=asn,
                    data={"label": asn, "org": org},
                    first_seen=self.observed_at,
                    last_seen=self.observed_at,
                )
            )
            if created is None:
                return
        obs = self._observe(
            eid, source="asn", collector="asn_lookup", data={"asn": asn, "org": org}
        )
        self._relate(
            host.entity_id,
            RelationshipType.IN_ASN,
            eid,
            ConfidenceBand.MEDIUM,
            "asn_lookup",
            obs,
            metadata={"asn": asn, "org": org},
        )

    def _ingest_nameserver(self, domain: str, nameserver: str) -> None:
        ns = normalize_domain(nameserver)
        if not ns:
            return
        host = self._domain_entity(domain)
        if host is None:
            return
        eid = entity_id(EntityType.NAMESERVER, ns)
        if eid not in self.entities:
            created = self._put_entity(
                IntelEntity(
                    entity_id=eid,
                    entity_type=EntityType.NAMESERVER,
                    key=ns,
                    data={"label": ns},
                    first_seen=self.observed_at,
                    last_seen=self.observed_at,
                )
            )
            if created is None:
                return
        obs = self._observe(eid, source="dns", collector="dnsx", data={"ns": ns})
        self._relate(
            host.entity_id,
            RelationshipType.HAS_NAMESERVER,
            eid,
            ConfidenceBand.MEDIUM,
            "dns_ns",
            obs,
            metadata={"nameserver": ns},
        )

    def _ingest_tls_from_host(self, domain: str, host: Host) -> None:
        tls = host.tls
        if tls is None:
            return
        fp = normalize_fingerprint(getattr(tls, "fingerprint_sha256", None))
        if not fp:
            return
        sans = extract_sans(tls.sans)
        cert = self._certificate_entity(
            fp,
            fingerprint_sha256=fp,
            subject=tls.subject or domain,
            issuer=tls.issuer,
            not_after=tls.not_after,
            sans=sans,
        )
        if cert is None:
            return
        obs = self._observe(
            cert.entity_id,
            source="tls",
            collector=tls.source or "httpx",
            data={"host": domain, "fingerprint_sha256": fp, "sans": sans},
        )
        self._relate(
            entity_id(EntityType.DOMAIN, domain),
            RelationshipType.PRESENTS_CERTIFICATE,
            cert.entity_id,
            ConfidenceBand.VERY_HIGH,
            "leaf_certificate_fingerprint",
            obs,
            metadata={"fingerprint_sha256": fp},
        )
        parent = self.queue.get(IndicatorKind.DOMAIN, domain)
        for name in sans:
            self._observe_san(
                cert,
                name,
                observation=obs,
                source="tls",
                collector=tls.source or "httpx",
                parent_id=parent.indicator_id if parent else None,
                parent_depth=parent.depth if parent else 0,
                reason=CollectReason.CERTIFICATE_SAN,
            )

    def _ingest_http_service(self, domain: str, svc: Any) -> None:
        url = normalize_http_url(getattr(svc, "url", "") or "") or (getattr(svc, "url", "") or "")
        if not url:
            return
        eid = entity_id(EntityType.HTTP_SERVICE, url)
        if eid not in self.entities:
            created = self._put_entity(
                IntelEntity(
                    entity_id=eid,
                    entity_type=EntityType.HTTP_SERVICE,
                    key=url,
                    data={
                        "label": url,
                        "status_code": getattr(svc, "status_code", None),
                        "title": getattr(svc, "title", None),
                        "favicon_hash": getattr(svc, "favicon_hash", None),
                        "body_hash": getattr(svc, "body_hash", None),
                        "tls_version": getattr(svc, "tls_version", None),
                        "tls_cipher": getattr(svc, "tls_cipher", None),
                    },
                    first_seen=self.observed_at,
                    last_seen=self.observed_at,
                )
            )
            if created is None:
                return
        obs = self._observe(eid, source="http", collector="httpx", data={"url": url})
        self._relate(
            entity_id(EntityType.DOMAIN, domain),
            RelationshipType.SERVES_HTTP,
            eid,
            ConfidenceBand.HIGH,
            "http_probe",
            obs,
            metadata={"url": url},
        )
        for tech in getattr(svc, "technologies", []) or []:
            name = getattr(tech, "name", None) or str(tech)
            tid = entity_id(EntityType.TECHNOLOGY, name)
            if tid not in self.entities:
                created = self._put_entity(
                    IntelEntity(
                        entity_id=tid,
                        entity_type=EntityType.TECHNOLOGY,
                        key=name,
                        data={"label": name},
                        first_seen=self.observed_at,
                        last_seen=self.observed_at,
                    )
                )
                if created is None:
                    continue
            self._relate(
                entity_id(EntityType.DOMAIN, domain),
                RelationshipType.RUNS_TECHNOLOGY,
                tid,
                ConfidenceBand.MEDIUM,
                "http_tech",
                obs,
                metadata={"technology": name},
            )

    def _ingest_emitted_relationship(self, raw: dict[str, Any]) -> None:
        parsed = validate_emitted_relationship(raw)
        if parsed is None:
            return
        dummy = self._observe(
            parsed["source_entity"],
            source="plugin",
            collector=parsed["collector"],
            data=raw,
        )
        self._relate(
            parsed["source_entity"],
            parsed["relationship_type"],
            parsed["target_entity"],
            parsed["confidence"],
            parsed["reason"],
            dummy,
            metadata=parsed["metadata"],
        )

    def _pairwise_share(
        self,
        members: list[str],
        rel_type: RelationshipType,
        band: ConfidenceBand,
        reason: str,
        hub_eid: str,
        metadata: dict[str, Any],
        *,
        band_for_pair=None,
    ) -> None:
        """Create bounded domain-domain share edges, or keep hub-only for large sets."""
        unique = sorted(set(members))
        if len(unique) < 2 or hub_eid not in self.entities:
            return
        cap = min(self.bounds.max_relationships_per_signal, 16)
        from core.intel.correlate import bounded_pairs as _bounded

        pairs = _bounded(unique, max_members=cap)
        if not pairs:
            return
        if len(self.relationships) + len(pairs) > self.bounds.max_relationships:
            self._mark_truncated("relationship_limit")
            return
        dummy = self._observe(hub_eid, source="correlation", collector="intel", data=metadata)
        if dummy is None:
            return
        for left, right in pairs:
            pair_band = band_for_pair((left, right), metadata) if band_for_pair else band
            rel_meta = dict(metadata)
            if band_for_pair:
                rel_meta["corroborated"] = pair_band is ConfidenceBand.HIGH
            self._relate(
                entity_id(EntityType.DOMAIN, left),
                rel_type,
                entity_id(EntityType.DOMAIN, right),
                pair_band,
                reason,
                dummy,
                metadata=rel_meta,
            )

    def _certificate_member_map(self) -> dict[str, list[str]]:
        members: dict[str, list[str]] = {}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.SAN_CONTAINS:
                continue
            cert_id = rel.source_entity
            domain = rel.target_entity.removeprefix("domain:")
            members.setdefault(cert_id, []).append(domain)
        return members

    def _correlate_shared_certificates(self) -> None:
        for cert_id, domains in self._certificate_member_map().items():
            cert = self.entities.get(cert_id)
            if not cert or len(set(domains)) < 2:
                continue
            sans = list(cert.data.get("sans") or domains)
            qualified = shares_certificate_confidence(
                sans, identity_kind=str(cert.data.get("identity_kind") or "")
            )
            if qualified is None:
                continue
            band, reason = qualified
            fp = cert.data.get("fingerprint_sha256")
            serial = cert.data.get("serial")
            evidence_meta = {
                "certificate_fingerprint": fp,
                "fingerprint_sha256": fp,
                "certificate_serial": serial,
                "certificate": cert_id,
                "san_cardinality": len(set(sans)),
                "registrable_domain_count": len(
                    {root for item in sans if (root := registrable_domain(item))}
                ),
                "observed_at": self.observed_at,
                "source": "correlation",
            }
            self._pairwise_share(
                domains,
                RelationshipType.SHARES_CERTIFICATE,
                band,
                reason,
                cert_id,
                {**evidence_meta, "members": sorted(set(domains))},
            )

    def _correlate_shared_ips(self) -> None:
        members: dict[str, list[str]] = {}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.RESOLVES_TO:
                continue
            ip = rel.target_entity.removeprefix("ip_address:")
            domain = rel.source_entity.removeprefix("domain:")
            members.setdefault(ip, []).append(domain)
        for ip, domains in members.items():
            if len(set(domains)) < 2:
                continue
            if is_ipv4(ip):
                band, reason = ipv4_confidence(ip)
                rel_type = RelationshipType.SHARES_IPV4
            elif is_ipv6(ip):
                band, reason = ipv6_confidence(ip)
                rel_type = RelationshipType.SHARES_IPV6
            else:
                continue
            provider = cloud_provider_for_ip(ip)
            asn, asn_org = self._asn_for_domains(domains)
            evidence_meta = {
                "ip": ip,
                "source": "correlation",
                "shared_cloud_tenancy": bool(provider),
                "provider": provider,
                "asn": asn,
                "asn_org": asn_org,
                "reason": reason,
                "observed_at": self.observed_at,
            }
            self._pairwise_share(
                domains,
                rel_type,
                band,
                reason,
                entity_id(EntityType.IP_ADDRESS, ip),
                evidence_meta,
            )

    def _asn_for_domains(self, domains: list[str]) -> tuple[str | None, str | None]:
        wanted = {entity_id(EntityType.DOMAIN, name) for name in domains}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.IN_ASN:
                continue
            if rel.source_entity in wanted:
                org = rel.data.get("org")
                return rel.target_entity.removeprefix("asn:"), str(org) if org else None
        return None, None

    def _correlate_shared_nameservers(self) -> None:
        members: dict[str, list[str]] = {}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.HAS_NAMESERVER:
                continue
            ns = rel.target_entity.removeprefix("nameserver:")
            domain = rel.source_entity.removeprefix("domain:")
            members.setdefault(ns, []).append(domain)
        for ns, domains in members.items():
            if len(set(domains)) < 2:
                continue
            self._pairwise_share(
                domains,
                RelationshipType.SHARES_NAMESERVER,
                ConfidenceBand.MEDIUM,
                "shared_nameserver",
                entity_id(EntityType.NAMESERVER, ns),
                {"nameserver": ns},
            )

    def _correlate_shared_asn(self) -> None:
        members: dict[str, list[str]] = {}
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.IN_ASN:
                continue
            asn = rel.target_entity.removeprefix("asn:")
            domain = rel.source_entity.removeprefix("domain:")
            members.setdefault(asn, []).append(domain)
        for asn, domains in members.items():
            if len(set(domains)) < 2:
                continue
            self._pairwise_share(
                domains,
                RelationshipType.SHARES_ASN,
                ConfidenceBand.LOW,
                "shared_asn",
                entity_id(EntityType.ASN, asn),
                {"asn": asn},
            )

    def _correlate_http_identity(self) -> None:
        fav: dict[str, list[str]] = {}
        body: dict[str, list[str]] = {}
        tls_fp: dict[str, list[str]] = {}
        for entity in self.entities.values():
            if entity.entity_type is not EntityType.HTTP_SERVICE:
                continue
            # HTTP service key is URL; recover domain from SERVES_HTTP reverse.
        domain_of_service = {
            rel.target_entity: rel.source_entity.removeprefix("domain:")
            for rel in self.relationships.values()
            if rel.relationship_type is RelationshipType.SERVES_HTTP
        }
        for entity in self.entities.values():
            if entity.entity_type is not EntityType.HTTP_SERVICE:
                continue
            domain = domain_of_service.get(entity.entity_id)
            if not domain:
                continue
            if entity.data.get("favicon_hash"):
                fav.setdefault(str(entity.data["favicon_hash"]), []).append(domain)
            if entity.data.get("body_hash"):
                body.setdefault(str(entity.data["body_hash"]), []).append(domain)
            tls_key = "|".join(str(entity.data.get(k) or "") for k in ("tls_version", "tls_cipher"))
            if entity.data.get("tls_version") and entity.data.get("tls_cipher"):
                tls_fp.setdefault(tls_key, []).append(domain)

        pair_signals: dict[tuple[str, str], set[str]] = {}
        for signal, domains in fav.items():
            for pair in bounded_pairs(domains):
                pair_signals.setdefault(pair, set()).add(f"favicon:{signal}")
        for signal, domains in body.items():
            for pair in bounded_pairs(domains):
                pair_signals.setdefault(pair, set()).add(f"body_hash:{signal}")
        for rel in self.relationships.values():
            if rel.relationship_type is not RelationshipType.SHARES_CERTIFICATE:
                continue
            left = rel.source_entity.removeprefix("domain:")
            right = rel.target_entity.removeprefix("domain:")
            pair = (left, right) if left < right else (right, left)
            pair_signals.setdefault(pair, set()).add("certificate")

        def _http_band(pair: tuple[str, str], kind: str) -> ConfidenceBand:
            kinds = {item.split(":", 1)[0] for item in pair_signals.get(pair, set())}
            corroborated = len(kinds) >= 2
            if kind in {"favicon", "body_hash"}:
                return ConfidenceBand.HIGH if corroborated else ConfidenceBand.LOW
            return ConfidenceBand.LOW

        def _share(
            groups: dict[str, list[str]],
            rel_type: RelationshipType,
            reason: str,
            meta_key: str,
        ) -> None:
            for signal, domains in groups.items():
                unique = sorted(set(domains))
                if len(unique) < 2:
                    continue
                hub = entity_id(EntityType.DOMAIN, unique[0])

                def _band(
                    pair: tuple[str, str], _meta: dict[str, Any], key=meta_key
                ) -> ConfidenceBand:
                    return _http_band(pair, key)

                self._pairwise_share(
                    unique,
                    rel_type,
                    ConfidenceBand.MEDIUM,
                    reason,
                    hub,
                    {
                        meta_key: signal,
                        "source": "correlation",
                        "observed_at": self.observed_at,
                    },
                    band_for_pair=_band,
                )

        _share(fav, RelationshipType.SHARES_FAVICON, "shared_favicon", "favicon")
        _share(body, RelationshipType.SHARES_BODY_HASH, "shared_body_hash", "body_hash")
        _share(
            tls_fp,
            RelationshipType.SHARES_TLS_CHARACTERISTICS,
            "shared_tls_characteristics",
            "tls",
        )


def build_intel(
    config: IntelRunConfig,
    hosts: dict[str, Host],
    output_dir: Path | None = None,
) -> IntelEngine:
    engine = IntelEngine(config)
    engine.ingest_hosts(hosts)
    if output_dir:
        engine.ingest_artifacts(output_dir)
    if config.emissions:
        engine.ingest_emissions(config.emissions)
    engine.correlate()
    engine.annotate_hosts(hosts)
    return engine
