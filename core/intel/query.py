"""Read-only queries against the SQLite intelligence tables."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from core.assets import normalize_domain
from core.intel.model import EntityType, entity_id


def domain_entity_id(domain: str) -> str:
    return entity_id(EntityType.DOMAIN, normalize_domain(domain))


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key in ("data_json", "metadata_json"):
            if key in item and item[key]:
                try:
                    item[key.replace("_json", "")] = json.loads(item[key])
                except json.JSONDecodeError:
                    item[key.replace("_json", "")] = {}
        result.append(item)
    return result


class IntelQuery:
    """Query helpers used by the CLI. SQLite remains the source of truth."""

    def __init__(self, conn: sqlite3.Connection, run_id: str | None = None) -> None:
        self.conn = conn
        self.run_id = run_id

    def entity_by_domain(self, domain: str) -> dict[str, Any] | None:
        eid = domain_entity_id(domain)
        if self.run_id:
            row = self.conn.execute(
                "SELECT * FROM intel_entities WHERE entity_id=? AND run_id=?",
                (eid, self.run_id),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM intel_entities WHERE entity_id=? ORDER BY last_seen DESC LIMIT 1",
                (eid,),
            ).fetchone()
        if not row:
            return None
        return rows_to_dicts([row])[0]

    def entity_by_id(self, entity_id_value: str) -> dict[str, Any] | None:
        if self.run_id:
            row = self.conn.execute(
                "SELECT * FROM intel_entities WHERE entity_id=? AND run_id=?",
                (entity_id_value, self.run_id),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM intel_entities WHERE entity_id=? ORDER BY last_seen DESC LIMIT 1",
                (entity_id_value,),
            ).fetchone()
        if not row:
            return None
        return rows_to_dicts([row])[0]

    def investigate(self, domain: str) -> dict[str, Any]:
        from core.intel.explain import explain_relationship
        from core.intel.serialize import serialize_relationships

        entity = self.entity_by_domain(domain)
        eid = domain_entity_id(domain)
        relationships = self.relationships(eid)
        evidence_rows = self.evidence_for(eid)
        evidence_by_id = {row.get("evidence_id"): row for row in evidence_rows}
        entity_cache: dict[str, dict[str, Any] | None] = {eid: entity}
        explanations = []
        for rel in relationships:
            source_id = str(rel.get("source_entity") or "")
            target_id = str(rel.get("target_entity") or "")
            if source_id not in entity_cache:
                entity_cache[source_id] = self.entity_by_id(source_id)
            if target_id not in entity_cache:
                entity_cache[target_id] = self.entity_by_id(target_id)
            ev = evidence_by_id.get(rel.get("evidence_id"))
            obs_rows: list[dict[str, Any]] = []
            obs_id = (ev or {}).get("observation_id")
            if obs_id:
                obs_rows = self._observations_by_id(str(obs_id))
            explanations.append(
                explain_relationship(
                    rel,
                    ev,
                    source_entity=entity_cache.get(source_id),
                    target_entity=entity_cache.get(target_id),
                    observations=obs_rows,
                )
            )
        return {
            "entity": entity,
            "observations": self.observations(eid),
            # Canonical serializer (core/intel/serialize.py) — same shape as
            # cmd_relationships/reporter.py, so confidence/certificate/SAN
            # fields are never independently reformatted per CLI surface.
            "relationships": serialize_relationships(
                relationships,
                evidence_by_id=evidence_by_id,
                entities_by_id=entity_cache,
                run_id=self.run_id,
            ),
            "evidence": evidence_rows,
            "indicators": self.indicators(domain),
            "certificates": self.certificates(domain),
            "explanations": explanations,
        }

    def _observations_by_id(self, observation_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM intel_observations WHERE observation_id=?"
        params: list[Any] = [observation_id]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        return rows_to_dicts(self.conn.execute(sql, params).fetchall())

    def evidence_by_relationship(self, relationship_id: str) -> dict[str, Any]:
        from core.intel.explain import explain_relationship

        sql = "SELECT * FROM intel_relationships WHERE relationship_id=?"
        params: list[Any] = [relationship_id]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        row = self.conn.execute(sql, params).fetchone()
        if not row:
            return {"relationship": None, "evidence": [], "explanation": None}
        relationship = rows_to_dicts([row])[0]
        evidence_id = relationship.get("evidence_id")
        evidence: list[dict[str, Any]] = []
        if evidence_id:
            ev_sql = "SELECT * FROM intel_evidence WHERE evidence_id=?"
            ev_params: list[Any] = [evidence_id]
            if self.run_id:
                ev_sql += " AND run_id=?"
                ev_params.append(self.run_id)
            evidence = rows_to_dicts(self.conn.execute(ev_sql, ev_params).fetchall())
        explanation = explain_relationship(
            relationship,
            evidence[0] if evidence else None,
            source_entity=self.entity_by_id(str(relationship.get("source_entity") or "")),
            target_entity=self.entity_by_id(str(relationship.get("target_entity") or "")),
        )
        return {
            "relationship": relationship,
            "evidence": evidence,
            "explanation": explanation,
        }

    def observations(self, entity_id_value: str) -> list[dict[str, Any]]:
        if self.run_id:
            rows = self.conn.execute(
                "SELECT * FROM intel_observations WHERE entity_id=? AND run_id=? "
                "ORDER BY observed_at",
                (entity_id_value, self.run_id),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM intel_observations WHERE entity_id=? ORDER BY observed_at",
                (entity_id_value,),
            ).fetchall()
        return rows_to_dicts(rows)

    def relationships(self, entity_id_value: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM intel_relationships " "WHERE source_entity=? OR target_entity=?"
        params: list[Any] = [entity_id_value, entity_id_value]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        rows = self.conn.execute(sql, params).fetchall()
        return rows_to_dicts(rows)

    def evidence_for(self, entity_id_value: str) -> list[dict[str, Any]]:
        rels = self.relationships(entity_id_value)
        ids = [r["evidence_id"] for r in rels if r.get("evidence_id")]
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        params: list[Any] = list(ids)
        sql = f"SELECT * FROM intel_evidence WHERE evidence_id IN ({placeholders})"  # noqa: S608  # nosec B608  # placeholders are bound '?' only
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        return rows_to_dicts(self.conn.execute(sql, params).fetchall())

    def certificates(self, domain: str) -> list[dict[str, Any]]:
        eid = domain_entity_id(domain)
        sql = (
            "SELECT e.* FROM intel_entities e "
            "JOIN intel_relationships r ON r.target_entity=e.entity_id "
            "WHERE r.source_entity=? AND r.relationship_type='PRESENTS_CERTIFICATE'"
        )
        params: list[Any] = [eid]
        if self.run_id:
            sql += " AND e.run_id=? AND r.run_id=?"
            params.extend([self.run_id, self.run_id])
        presented = rows_to_dicts(self.conn.execute(sql, params).fetchall())
        sql2 = (
            "SELECT e.* FROM intel_entities e "
            "JOIN intel_relationships r ON r.source_entity=e.entity_id "
            "WHERE r.target_entity=? AND r.relationship_type='SAN_CONTAINS'"
        )
        params2: list[Any] = [eid]
        if self.run_id:
            sql2 += " AND e.run_id=? AND r.run_id=?"
            params2.extend([self.run_id, self.run_id])
        sans = rows_to_dicts(self.conn.execute(sql2, params2).fetchall())
        seen: set[str] = set()
        merged: list[dict[str, Any]] = []
        for item in presented + sans:
            key = item.get("entity_id") or ""
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    def relationships_for_run(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.run_id:
            return []
        rows = self.conn.execute(
            "SELECT * FROM intel_relationships WHERE run_id=? "
            "ORDER BY relationship_type, source_entity LIMIT ?",
            (self.run_id, limit),
        ).fetchall()
        return rows_to_dicts(rows)

    def indicators(self, domain: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM intel_indicators WHERE value=?"
        params: list[Any] = [normalize_domain(domain)]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        return rows_to_dicts(self.conn.execute(sql, params).fetchall())

    def _indicator_by_identifier(self, identifier: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM intel_indicators WHERE indicator_id=?"
        params: list[Any] = [identifier]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        row = self.conn.execute(sql, params).fetchone()
        if row:
            return rows_to_dicts([row])[0]
        sql2 = "SELECT * FROM intel_indicators WHERE value=?"
        params2: list[Any] = [normalize_domain(identifier) or identifier]
        if self.run_id:
            sql2 += " AND run_id=?"
            params2.append(self.run_id)
        row2 = self.conn.execute(sql2, params2).fetchone()
        return rows_to_dicts([row2])[0] if row2 else None

    def _attempt_by_id(self, attempt_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM intel_collection_attempts WHERE attempt_id=?"
        params: list[Any] = [attempt_id]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        row = self.conn.execute(sql, params).fetchone()
        return rows_to_dicts([row])[0] if row else None

    def _attempts_for_indicator(self, indicator_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM intel_collection_attempts WHERE indicator_id=? ORDER BY id"
        params: list[Any] = [indicator_id]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        return rows_to_dicts(self.conn.execute(sql, params).fetchall())

    def _hypothesis_for_value(self, value: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM intel_hypotheses WHERE target_value=?"
        params: list[Any] = [value]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        row = self.conn.execute(sql, params).fetchone()
        return rows_to_dicts([row])[0] if row else None

    def _network_requests_for_host(self, hostname: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM intel_network_requests WHERE normalized_hostname=? ORDER BY id"
        params: list[Any] = [hostname]
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        return rows_to_dicts(self.conn.execute(sql, params).fetchall())

    def explain_collection(self, identifier: str) -> dict[str, Any]:
        """Reconstruct, from persisted SQLite rows alone, why (or why not) a
        given indicator was collected — no rescan, no re-reading warning text.

        `identifier` may be an `indicator_id`, a raw value (hostname), or a
        `collection_attempt_id`; whichever resolves first is used. Walks the
        same causal chain the mission text specifies: indicator (why
        discovered, its scope/collection status) -> hypothesis (why eligible,
        the authorization decision and rationale) -> relationship/evidence
        (what actually supported it) -> collection attempts (which collector
        ran, whether it succeeded, what artifact resulted) -> network
        requests (was the destination host actually contacted).
        """
        indicator = self._indicator_by_identifier(identifier)
        attempts: list[dict[str, Any]] = []
        value = ""

        if indicator:
            value = str(indicator.get("value") or "")
            attempts = self._attempts_for_indicator(str(indicator["indicator_id"]))
        else:
            attempt = self._attempt_by_id(identifier)
            if attempt:
                attempts = [attempt]
                value = str(attempt.get("value") or "")
                indicator = self._indicator_by_identifier(str(attempt.get("indicator_id") or ""))
            else:
                value = normalize_domain(identifier) or identifier

        hypothesis = self._hypothesis_for_value(value) if value else None
        relationship: dict[str, Any] | None = None
        evidence: dict[str, Any] | None = None
        if hypothesis and hypothesis.get("relationship_id"):
            bundle = self.evidence_by_relationship(str(hypothesis["relationship_id"]))
            relationship = bundle.get("relationship")
            evidence = bundle["evidence"][0] if bundle.get("evidence") else None

        network_requests = self._network_requests_for_host(value) if value else []

        narrative: list[str] = []
        if indicator is None and not attempts:
            narrative.append(f"No indicator, attempt, or network request found for {identifier!r}.")
        if indicator:
            narrative.append(
                f"Discovered as {indicator.get('kind')} via reason={indicator.get('reason')}"
                f" (parent_id={indicator.get('parent_id') or 'none'})."
            )
            narrative.append(
                f"Scope status: {indicator.get('scope_status')}; "
                f"collection status: {indicator.get('collection_status')}."
            )
            if indicator.get("authorization_status"):
                narrative.append(f"Authorization status: {indicator.get('authorization_status')}.")
            if indicator.get("failure_reason"):
                narrative.append(f"Failure reason: {indicator.get('failure_reason')}.")
        if hypothesis:
            narrative.append(
                f"Hypothesis {hypothesis.get('status')}: {hypothesis.get('rationale')}"
            )
        if evidence:
            narrative.append(
                f"Supporting evidence: {evidence.get('evidence_id')} "
                f"(source={evidence.get('source')}, collector={evidence.get('collector')})."
            )
        for attempt in attempts:
            narrative.append(
                f"Attempt via {attempt.get('collector')} "
                f"(capability={attempt.get('capability')}): {attempt.get('status')} — "
                f"{attempt.get('reason')}"
                + (f"; artifact={attempt.get('artifact')}" if attempt.get("artifact") else "")
            )
        for req in network_requests:
            narrative.append(
                f"Network request [{req.get('collector')}] {req.get('decision')} "
                f"({req.get('reason')}); attempted={bool(req.get('network_attempted'))}, "
                f"completed={bool(req.get('network_completed'))}."
            )

        return {
            "identifier": identifier,
            "resolved_value": value,
            "indicator": indicator,
            "hypothesis": hypothesis,
            "relationship": relationship,
            "evidence": evidence,
            "collection_attempts": attempts,
            "network_requests": network_requests,
            "narrative": narrative,
        }

    def graph_neighborhood(self, domain: str) -> dict[str, Any]:
        eid = domain_entity_id(domain)
        rels = self.relationships(eid)
        node_ids = {eid}
        for rel in rels:
            node_ids.add(rel["source_entity"])
            node_ids.add(rel["target_entity"])
        if not node_ids:
            return {"nodes": [], "edges": rels}
        placeholders = ",".join("?" * len(node_ids))
        params: list[Any] = list(node_ids)
        sql = f"SELECT * FROM intel_entities WHERE entity_id IN ({placeholders})"  # noqa: S608  # nosec B608  # placeholders are bound '?' only
        if self.run_id:
            sql += " AND run_id=?"
            params.append(self.run_id)
        nodes = rows_to_dicts(self.conn.execute(sql, params).fetchall())
        return {"nodes": nodes, "edges": rels}
