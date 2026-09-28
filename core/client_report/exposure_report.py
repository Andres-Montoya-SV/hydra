"""Fase 21 (EASM roadmap): connects client-facing reporting to the EASM
exposure model WITH history, instead of only current-run raw data.

**Verified before building anything** (this phase's own explicit
instruction — "verificar qué infraestructura de reportability/hipótesis
existe realmente" — never assume its shape): neither
`api/reportability_orchestrator.py` (reads `store.get_findings(run_id)`,
one run at a time) nor `api/hypotheses_orchestrator.py`
(`core/hypotheses/evidence.py::gather_run_evidence`, which reads the
legacy `intel_relationships` table scoped to one `run_id`) nor
`core/client_report/collect.py` (builds `RunReportData` from one run's
raw `core.assets.Finding` objects) ever queries the newer `exposures`/
`exposure_history` tables (Fases 08/20) at all. This module is the
missing connection — new and additive, alongside the existing per-run
report pipeline, never a rewrite of `collect.py`/`render.py`'s own,
already-tested rendering logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.risk_scoring import classify_exposure_risk

if TYPE_CHECKING:
    from api.control_db import ControlDB


@dataclass(frozen=True)
class ExposureHistoryEvent:
    event_type: str
    happened_at: str
    run_id: str | None
    reason: str


@dataclass(frozen=True)
class ExposureReportEntry:
    """One exposure, carrying its FULL cross-run history — never just
    the current-run snapshot — plus its Fase 21 risk classification."""

    exposure_id: str
    asset_id: str
    title: str
    severity: str
    status: str
    first_seen_at: str
    last_seen_at: str
    history: tuple[ExposureHistoryEvent, ...]
    risk_level: str
    risk_reasons: tuple[str, ...]


def exposure_history_report_data(
    control_db: ControlDB,
    organization_id: str,
    *,
    status: str | None = None,
    limit: int = 500,
) -> list[ExposureReportEntry]:
    """One entry per exposure the organization has, each carrying its
    complete `exposure_history` (Fase 08) and its deterministic risk
    classification (this phase's own `core/risk_scoring.py`) — this is
    what makes a report built from this data show "5 runs, 1 exposure,
    with its full confirmation/resolution/reappearance trail," rather
    than a fresh-looking "finding" on every run that happens to observe
    it again."""
    entries: list[ExposureReportEntry] = []
    for exposure in control_db.list_exposures_for_organization(
        organization_id, status=status, limit=limit
    ):
        history_rows = control_db.list_exposure_history(organization_id, exposure.exposure_id)
        factors = control_db.risk_factors_for_exposure(organization_id, exposure.exposure_id)
        classification = classify_exposure_risk(factors) if factors is not None else None
        entries.append(
            ExposureReportEntry(
                exposure_id=exposure.exposure_id,
                asset_id=exposure.asset_id,
                title=exposure.title,
                severity=exposure.severity,
                status=exposure.status,
                first_seen_at=exposure.first_seen_at,
                last_seen_at=exposure.last_seen_at,
                history=tuple(
                    ExposureHistoryEvent(
                        event_type=row.event_type,
                        happened_at=row.happened_at,
                        run_id=row.run_id,
                        reason=row.reason,
                    )
                    for row in history_rows
                ),
                risk_level=classification.level.value if classification is not None else "unknown",
                risk_reasons=classification.reasons if classification is not None else (),
            )
        )
    return entries
