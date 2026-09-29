"""Offline IP geolocation (Network & Geo Intelligence).

Reads a local MaxMind-format database (e.g. GeoLite2-City) with the
`maxminddb` reader: every lookup is a local file read, never a network
request, so no scanned IP is ever sent to a third-party service. That keeps
geo enrichment inside Hydra's confinement/OPSEC posture, the same
"sockets/DNS/local data only, no new networked dependency" rule
`modules/asn_lookup.py` follows.

Optional by design: with no database configured (or the library missing),
`open_geoip` returns `None` and enrichment is simply skipped.

Freshness is recorded with each result. A database older than
`GEOIP_MAX_AGE_DAYS` is degraded evidence, reported as stale rather than
silently trusted. GeoLite2 needs a free MaxMind account and periodic
re-download under its license; see docs/productization/v2_gaps.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("hydra.geoip")

# MaxMind publishes GeoLite2 updates about twice a week; anything older than
# this has missed several releases and is treated as stale.
GEOIP_MAX_AGE_DAYS = 45


@dataclass(frozen=True)
class GeoLocation:
    country: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None


@dataclass(frozen=True)
class GeoDatabaseInfo:
    edition: str
    build_date: datetime

    def age_days(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        return max(0, (now - self.build_date).days)

    def source(self) -> str:
        return f"{self.edition}@{self.build_date.date().isoformat()}"


def _english_name(node: object) -> str | None:
    if not isinstance(node, dict):
        return None
    names = node.get("names")
    if isinstance(names, dict) and isinstance(names.get("en"), str):
        return str(names["en"])
    return None


def _as_float(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def location_from_record(record: dict[str, Any]) -> GeoLocation:
    """Maps one GeoIP2/GeoLite2 City record to the fields Hydra keeps."""
    country = record.get("country")
    iso_code = country.get("iso_code") if isinstance(country, dict) else None
    subdivisions = record.get("subdivisions")
    region = (
        _english_name(subdivisions[0]) if isinstance(subdivisions, list) and subdivisions else None
    )
    location = record.get("location")
    location = location if isinstance(location, dict) else {}
    return GeoLocation(
        country=iso_code if isinstance(iso_code, str) else None,
        region=region,
        city=_english_name(record.get("city")),
        latitude=_as_float(location.get("latitude")),
        longitude=_as_float(location.get("longitude")),
    )


class GeoIPDatabase:
    def __init__(self, path: Path) -> None:
        import maxminddb

        self._reader = maxminddb.open_database(str(path))
        metadata = self._reader.metadata()
        self.info = GeoDatabaseInfo(
            edition=str(metadata.database_type),
            build_date=datetime.fromtimestamp(int(metadata.build_epoch), tz=timezone.utc),
        )

    def lookup(self, ip: str) -> GeoLocation | None:
        try:
            record = self._reader.get(ip)
        except ValueError:  # not a valid IP address
            return None
        return location_from_record(record) if isinstance(record, dict) else None

    def close(self) -> None:
        self._reader.close()


def open_geoip(path: str | Path | None) -> GeoIPDatabase | None:
    """The configured database, or `None` when geo enrichment isn't
    available (no path, missing file, library not installed, unreadable).
    Never raises: geo is an enrichment, never a reason to fail a scan."""
    if not path:
        return None
    db_path = Path(path)
    if not db_path.is_file():
        logger.warning("GeoIP database not found at %s; geo enrichment skipped.", db_path)
        return None
    try:
        return GeoIPDatabase(db_path)
    except ImportError:
        logger.warning("maxminddb is not installed; geo enrichment skipped.")
    except Exception as exc:  # noqa: BLE001 - corrupt/unsupported file: skip enrichment
        logger.warning("GeoIP database at %s could not be opened (%s); skipped.", db_path, exc)
    return None
