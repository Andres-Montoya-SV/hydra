"""Persistence operations for Hydra's EASM layer."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from core.easm.model import AssetEventType, AssetType
from core.easm.schema import ensure_easm_schema


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:24]
    return f"{prefix}_{digest}"


class EasmStore:
    """Run-independent organization and asset persistence.

    The class accepts an already-open Hydra SQLite connection so it can coexist
    with ``AssetStore`` during the migration period without introducing a
    second database or bypassing the existing transaction boundary.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        ensure_easm_schema(conn)

    def ensure_organization(
        self,
        *,
        name: str,
        slug: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        slug = slug.strip().lower()
        if not slug:
            raise ValueError("organization slug must not be empty")
        now = utc_now_iso()
        organization_id = _stable_id("org", slug)
        self.conn.execute(
            """
            INSERT INTO easm_organizations(
                organization_id, name, slug, created_at, updated_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
                name=excluded.name,
                updated_at=excluded.updated_at,
                metadata_json=excluded.metadata_json
            """,
            (
                organization_id,
                name.strip() or slug,
                slug,
                now,
                now,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )
        row = self.conn.execute(
            "SELECT organization_id FROM easm_organizations WHERE slug = ?", (slug,)
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to persist organization")
        return str(row[0])

    def upsert_asset(
        self,
        *,
        organization_id: str,
        asset_type: AssetType | str,
        canonical_key: str,
        display_name: str | None = None,
        seen_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, bool]:
        key = canonical_key.strip().lower().rstrip(".")
        if not key:
            raise ValueError("asset canonical_key must not be empty")
        kind = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
        now = seen_at or utc_now_iso()
        asset_id = _stable_id("asset", organization_id, kind, key)

        existing = self.conn.execute(
            """
            SELECT asset_id FROM easm_assets
            WHERE organization_id = ? AND asset_type = ? AND canonical_key = ?
            """,
            (organization_id, kind, key),
        ).fetchone()
        created = existing is None

        self.conn.execute(
            """
            INSERT INTO easm_assets(
                asset_id, organization_id, asset_type, canonical_key,
                display_name, status, first_seen, last_seen, created_at,
                updated_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id, asset_type, canonical_key) DO UPDATE SET
                display_name=COALESCE(excluded.display_name, easm_assets.display_name),
                status='active',
                last_seen=excluded.last_seen,
                updated_at=excluded.updated_at,
                metadata_json=excluded.metadata_json
            """,
            (
                asset_id,
                organization_id,
                kind,
                key,
                display_name,
                now,
                now,
                now,
                now,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )

        if created:
            self.record_event(
                organization_id=organization_id,
                asset_id=asset_id,
                event_type=AssetEventType.NEW_ASSET,
                detected_at=now,
                confidence=100,
                current_state={"asset_type": kind, "canonical_key": key},
            )
        return asset_id, created

    def record_observation(
        self,
        *,
        asset_id: str,
        source: str,
        data: dict[str, Any],
        run_id: str | None = None,
        collector: str | None = None,
        confidence: int = 50,
        observed_at: str | None = None,
        fingerprint: str | None = None,
    ) -> str:
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        observed_at = observed_at or utc_now_iso()
        observation_id = f"obs_{uuid.uuid4().hex}"
        if fingerprint is None:
            fingerprint = hashlib.sha256(
                json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        self.conn.execute(
            """
            INSERT INTO easm_asset_observations(
                observation_id, asset_id, run_id, source, collector,
                observed_at, confidence, fingerprint, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                asset_id,
                run_id,
                source,
                collector,
                observed_at,
                confidence,
                fingerprint,
                json.dumps(data, sort_keys=True),
            ),
        )
        self.conn.execute(
            "UPDATE easm_assets SET last_seen = ?, updated_at = ? WHERE asset_id = ?",
            (observed_at, observed_at, asset_id),
        )
        return observation_id

    def record_event(
        self,
        *,
        organization_id: str,
        asset_id: str,
        event_type: AssetEventType | str,
        detected_at: str | None = None,
        confidence: int = 50,
        severity: str | None = None,
        source_observation_id: str | None = None,
        previous_state: dict[str, Any] | None = None,
        current_state: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        kind = event_type.value if isinstance(event_type, AssetEventType) else str(event_type)
        event_id = f"evt_{uuid.uuid4().hex}"
        self.conn.execute(
            """
            INSERT INTO easm_asset_events(
                event_id, organization_id, asset_id, event_type, severity,
                detected_at, confidence, source_observation_id,
                previous_state_json, current_state_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                organization_id,
                asset_id,
                kind,
                severity,
                detected_at or utc_now_iso(),
                confidence,
                source_observation_id,
                json.dumps(previous_state) if previous_state is not None else None,
                json.dumps(current_state) if current_state is not None else None,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )
        return event_id
