"""Streaming CSV / NDJSON export of an organization's assets and exposures,
for risk registers, spreadsheets and SIEM ingestion.

Rows are read in keyset pages (never the whole table at once) and written
as they arrive. CSV cells are neutralized against formula injection
(OWASP "CSV Injection"): data from scanned targets (titles, hostnames,
descriptions) can start with `=`, `+`, `-`, `@`, tab or carriage return,
which a spreadsheet would otherwise evaluate; such cells get a leading `'`.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from dataclasses import asdict
from typing import Any, Literal

from api.control_db import ControlDB

Dataset = Literal["assets", "exposures"]
ExportFormat = Literal["csv", "ndjson"]

PAGE_SIZE = 500

ASSET_FIELDS = (
    "asset_id",
    "asset_type",
    "identity_key",
    "first_seen_at",
    "last_seen_at",
    "last_seen_run_id",
)
EXPOSURE_FIELDS = (
    "exposure_id",
    "asset_id",
    "title",
    "severity",
    "status",
    "location",
    "source",
    "template_id",
    "confidence_score",
    "first_seen_at",
    "last_seen_at",
    "first_seen_run_id",
    "last_seen_run_id",
    "resolved_at",
    "resolution_reason",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def fields_for(dataset: Dataset) -> tuple[str, ...]:
    return ASSET_FIELDS if dataset == "assets" else EXPOSURE_FIELDS


def _page(db: ControlDB, organization_id: str, dataset: Dataset, after: str) -> list[Any]:
    if dataset == "assets":
        return db.export_assets_page(organization_id, after=after, limit=PAGE_SIZE)
    return db.export_exposures_page(organization_id, after=after, limit=PAGE_SIZE)


def _rows(db: ControlDB, organization_id: str, dataset: Dataset) -> Iterator[dict[str, Any]]:
    fields = fields_for(dataset)
    key = fields[0]  # asset_id / exposure_id: the keyset column
    after = ""
    while True:
        page = _page(db, organization_id, dataset, after)
        for record in page:
            row = asdict(record)
            yield {field: row[field] for field in fields}
        if len(page) < PAGE_SIZE:
            return
        after = getattr(page[-1], key)


def stream_csv(db: ControlDB, organization_id: str, dataset: Dataset) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields_for(dataset))
    writer.writeheader()
    for row in _rows(db, organization_id, dataset):
        writer.writerow({field: neutralize_cell(value) for field, value in row.items()})
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
    if buffer.getvalue():
        yield buffer.getvalue()


def stream_ndjson(db: ControlDB, organization_id: str, dataset: Dataset) -> Iterator[str]:
    for row in _rows(db, organization_id, dataset):
        yield json.dumps(row, separators=(",", ":")) + "\n"
