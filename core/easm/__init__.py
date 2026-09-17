"""Persistent EASM domain model and schema primitives.

This package is deliberately additive to the existing run-scoped reconnaissance
model. The first migration step introduces stable organization/asset identity,
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
from core.easm.projector import PROJECTOR_VERSION, ProjectionResult, host_state, project_hosts
from core.easm.schema import EASM_SCHEMA, ensure_easm_schema

__all__ = [
    "AssetCriticality",
    "AssetEventType",
    "AssetStatus",
    "AssetType",
    "Environment",
    "OwnershipState",
    "PROJECTOR_VERSION",
    "ProjectionResult",
    "host_state",
    "project_hosts",
    "EASM_SCHEMA",
    "ensure_easm_schema",
]
