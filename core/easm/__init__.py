"""Persistent EASM domain model and schema primitives.

This package is deliberately additive to the existing run-scoped reconnaissance
model.  The first migration step introduces stable organization/asset identity,
observations, and change events without changing the semantics of existing
``runs``, ``hosts``, or ``intel_*`` tables.
"""

from core.easm.model import (
    AssetCriticality,
    AssetEventType,
    AssetStatus,
    AssetType,
    Environment,
    OwnershipState,
)
from core.easm.schema import EASM_SCHEMA, ensure_easm_schema

__all__ = [
    "AssetCriticality",
    "AssetEventType",
    "AssetStatus",
    "AssetType",
    "Environment",
    "OwnershipState",
    "EASM_SCHEMA",
    "ensure_easm_schema",
]
