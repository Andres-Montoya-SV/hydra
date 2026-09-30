"""Shared pieces of the integration delivery-log endpoints (webhooks and
ticketing integrations): one paging dependency and one conversion, so the
two logs can't drift apart."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import Query

from api.control_db import DeliveryRecord
from api.schemas import DeliveryResponse


@dataclass(frozen=True)
class Page:
    limit: int
    offset: int


def page(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page:
    return Page(limit=limit, offset=offset)


def delivery_responses(records: Iterable[DeliveryRecord]) -> list[DeliveryResponse]:
    return [DeliveryResponse.model_validate(r, from_attributes=True) for r in records]
