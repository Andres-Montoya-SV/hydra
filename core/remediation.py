"""Productization Phase 07: the remediation workflow for one exposure.

Detection truth (the exposure's open/reopened/resolved lifecycle and its
evidence) and human workflow state are kept apart: nothing here changes an
exposure or its evidence. The stored state is only what a person decided;
the *effective* state also accounts for what detection saw since, and is
computed on read, so no background job can drift from it:

- the exposure is resolved                          -> closed
- an accepted risk is past its expiry               -> triage
- claimed fixed, then detected again after that     -> in_progress
  (verification failed: the fix didn't hold)

Stored states and the transitions a person may make:

    triage ─────────► in_progress ─────► fixed_pending_verification
      │  ▲               │  ▲                     │
      │  └───────────────┘  └─────────────────────┘
      ├──► accepted_risk (reason + expiry required) ──► triage | in_progress
      └──► false_positive (reason required) ──────────► triage
    (in_progress may also go to accepted_risk / false_positive)

Closing is the existing explicit exposure resolve: a remediation claim
alone never closes anything, because absence from a scan is not proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, cast

StoredState = Literal[
    "triage", "in_progress", "fixed_pending_verification", "accepted_risk", "false_positive"
]
EffectiveState = Literal[
    "triage",
    "in_progress",
    "fixed_pending_verification",
    "accepted_risk",
    "false_positive",
    "closed",
]

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "triage": frozenset({"in_progress", "accepted_risk", "false_positive"}),
    "in_progress": frozenset(
        {"triage", "fixed_pending_verification", "accepted_risk", "false_positive"}
    ),
    "fixed_pending_verification": frozenset({"in_progress"}),
    "accepted_risk": frozenset({"triage", "in_progress"}),
    "false_positive": frozenset({"triage"}),
}
REASON_REQUIRED = frozenset({"accepted_risk", "false_positive"})
MAX_RISK_ACCEPTANCE_DAYS = 365

# Default remediation SLA by severity, in days from first detection.
SLA_DAYS: dict[str, int] = {"critical": 7, "high": 30, "medium": 90, "low": 180}


class TransitionError(ValueError):
    """A transition request that is invalid (missing reason, bad window)."""


class TransitionConflictError(TransitionError):
    """A transition the workflow doesn't allow from the current state."""


@dataclass(frozen=True)
class RemediationFacts:
    """Everything the effective-state rule needs, DB-free."""

    stored_state: str
    state_changed_at: str | None
    accepted_until: str | None
    exposure_status: str
    exposure_last_seen_at: str
    first_seen_at: str
    severity: str
    due_at: str | None


@dataclass(frozen=True)
class EffectiveRemediation:
    state: EffectiveState
    # Why the effective state differs from the stored one; None if it doesn't.
    derived_reason: str | None
    sla_due_at: str
    due_at: str
    overdue: bool


def check_transition(
    current: str, target: str, *, reason: str | None, accepted_until: str | None, now: datetime
) -> None:
    """Raises TransitionError unless `current -> target` is allowed and
    carries what it requires."""
    if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise TransitionConflictError(f"cannot move from {current} to {target}")
    if target in REASON_REQUIRED and not (reason and reason.strip()):
        raise TransitionError(f"{target} requires a reason")
    if target == "accepted_risk":
        _check_acceptance_window(accepted_until, now)
    elif accepted_until is not None:
        raise TransitionError("accepted_until only applies to accepted_risk")


def check_transitions(
    current: dict[str, str],
    target: str,
    *,
    reason: str | None,
    accepted_until: str | None,
    now: datetime,
) -> None:
    """`check_transition` for several exposures at once (exposure id ->
    current effective state). Collects every failure, naming each exposure;
    if any is a state conflict, the whole request is one."""
    errors: list[TransitionError] = []
    for exposure_id, state in current.items():
        try:
            check_transition(state, target, reason=reason, accepted_until=accepted_until, now=now)
        except TransitionError as exc:
            errors.append(type(exc)(f"{exposure_id}: {exc}"))
    if not errors:
        return
    message = "; ".join(str(e) for e in errors)
    if any(isinstance(e, TransitionConflictError) for e in errors):
        raise TransitionConflictError(message)
    raise TransitionError(message)


def _check_acceptance_window(accepted_until: str | None, now: datetime) -> None:
    if accepted_until is None:
        raise TransitionError("accepted_risk requires accepted_until")
    until = datetime.fromisoformat(to_utc_iso(accepted_until, field="accepted_until"))
    if until <= now:
        raise TransitionError("accepted_until must be in the future")
    if until > now + timedelta(days=MAX_RISK_ACCEPTANCE_DAYS):
        raise TransitionError(f"a risk can be accepted for at most {MAX_RISK_ACCEPTANCE_DAYS} days")


def sla_due_at(first_seen_at: str, severity: str) -> str:
    days = SLA_DAYS.get(severity, SLA_DAYS["low"])
    return (datetime.fromisoformat(first_seen_at) + timedelta(days=days)).isoformat()


def effective_remediation(facts: RemediationFacts, *, now: datetime) -> EffectiveRemediation:
    state, reason = _effective_state(facts, now)
    sla = sla_due_at(facts.first_seen_at, facts.severity)
    due = facts.due_at or sla
    overdue = state in ("triage", "in_progress") and datetime.fromisoformat(due) < now
    return EffectiveRemediation(
        state=state, derived_reason=reason, sla_due_at=sla, due_at=due, overdue=overdue
    )


def _effective_state(facts: RemediationFacts, now: datetime) -> tuple[EffectiveState, str | None]:
    if facts.exposure_status == "resolved":
        return "closed", "exposure resolved"
    if facts.stored_state == "accepted_risk" and facts.accepted_until:
        if datetime.fromisoformat(facts.accepted_until) <= now:
            return "triage", f"risk acceptance expired at {facts.accepted_until}"
    if (
        facts.stored_state == "fixed_pending_verification"
        and facts.state_changed_at
        and datetime.fromisoformat(facts.exposure_last_seen_at)
        > datetime.fromisoformat(facts.state_changed_at)
    ):
        return "in_progress", (
            f"verification failed: detected again at {facts.exposure_last_seen_at} after the "
            f"fix was claimed at {facts.state_changed_at}"
        )
    return cast(EffectiveState, facts.stored_state), None


def to_utc_iso(value: str, *, field: str) -> str:
    """A client-supplied timestamp, which must carry a timezone, as UTC ISO."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TransitionError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise TransitionError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()
