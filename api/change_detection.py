"""Fase 05 (EASM roadmap, docs/easm/00_consolidation_plan.md): asset
lifecycle state and change detection, built on Fase 03's Asset identity
and Fase 04's Observations/Evidence. Pure module — no database access,
no `datetime.now()`, no LLM, no probabilistic/fuzzy anything — by the
phase's own explicit requirement: "debe ser reproducible y explicable en
una frase," and "esto es seguridad, no solo UX."

**The five states, one sentence each** (the phase's own required
documentation, and the literal behavior of `compute_asset_state_transitions`
below):

- **NEW** — the first run that ever observed this asset.
- **UNCHANGED** — this run observed the exact same set of facts (same
  observation types, same evidence content) as the last time this asset
  was observed.
- **CHANGED** — this run observed this asset, but at least one fact
  differs from the last time it was observed (a new/removed observation
  type, or the same type with different evidence content).
- **DISAPPEARED** — this asset was not observed for `missed_run_threshold`
  CONSECUTIVE relevant runs in a row (never a single missed run — see
  below).
- **REAPPEARED** — an asset that was `DISAPPEARED` was observed again;
  the very next observation after that (if unchanged) settles back into
  plain `UNCHANGED`, since `REAPPEARED` marks the one transition, not an
  ongoing status.

**Why a single missed run never means DISAPPEARED — the phase's own
required tolerance rule**: `DEFAULT_MISSED_RUN_THRESHOLD = 2`. A scan
can fail to observe a real, still-existing asset for reasons that have
nothing to do with the asset (a transient DNS resolver hiccup, a
timeout, a rate limit) — the exact case the phase's prompt names
explicitly. Requiring TWO CONSECUTIVE misses before declaring an asset
gone means a single bad run can never hide it, while still catching a
genuine disappearance within one extra cycle — not an unbounded wait.
Callers may override this per organization/asset if a later phase needs
that; the module-level default is the one number every test and the
backfill actually use unless told otherwise.

**Determinism, restated as code, not just prose**:
`compute_asset_state_transitions` is a pure function of its
`run_outcomes` argument (and `missed_run_threshold`) alone — no clock,
no randomness, no I/O. The exact same list of `RunObservationOutcome`
always produces the exact same list of `ChangeEvent`s.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

# A single missed run is explicitly, deliberately NOT enough to declare
# an asset gone (see module docstring) — two consecutive misses is.
DEFAULT_MISSED_RUN_THRESHOLD = 2


class AssetLifecycleState(str, Enum):
    NEW = "new"
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    DISAPPEARED = "disappeared"
    REAPPEARED = "reappeared"


@dataclass(frozen=True)
class RunObservationOutcome:
    """One relevant run's outcome for ONE asset — `observed=False` means
    this run completed but recorded no observation for this asset (a
    real miss, not "this run didn't apply to this asset at all"; the
    caller — `api/change_backfill.py` — is responsible for only
    including runs actually relevant to this asset, via
    `host_for_asset`/`api.domain_verification.domain_is_covered`, before
    building this list)."""

    run_id: str
    observed: bool
    observation_digest: str | None = None


@dataclass(frozen=True)
class ChangeEvent:
    """One recorded STATE TRANSITION — never one per run. A run that
    leaves the state unchanged (still `UNCHANGED`, or a miss that hasn't
    yet crossed `missed_run_threshold`) produces no `ChangeEvent` at
    all; only an actual transition does, per the phase's own "cada
    transición... queda registrada" (a transition, not a heartbeat)."""

    run_id: str
    previous_state: AssetLifecycleState | None
    new_state: AssetLifecycleState
    reason: str
    previous_digest: str | None
    new_digest: str | None


def compute_asset_state_transitions(
    *,
    run_outcomes: list[RunObservationOutcome],
    missed_run_threshold: int = DEFAULT_MISSED_RUN_THRESHOLD,
) -> list[ChangeEvent]:
    """Processes `run_outcomes` in chronological order (the caller's
    responsibility to sort); returns only the runs that actually
    produced a state transition. See the module docstring for the exact
    one-sentence rule per state — this function is that table, as code."""
    events: list[ChangeEvent] = []
    state: AssetLifecycleState | None = None
    last_digest: str | None = None
    consecutive_misses = 0

    for outcome in run_outcomes:
        if outcome.observed:
            if state is None:
                new_state = AssetLifecycleState.NEW
                reason = "first observation of this asset"
            elif state == AssetLifecycleState.DISAPPEARED:
                new_state = AssetLifecycleState.REAPPEARED
                reason = f"observed again after {consecutive_misses} missed run(s)"
            elif outcome.observation_digest != last_digest:
                new_state = AssetLifecycleState.CHANGED
                reason = "observed facts differ from the previous observation"
            else:
                new_state = AssetLifecycleState.UNCHANGED
                reason = ""  # no event emitted for a no-op transition

            if new_state != AssetLifecycleState.UNCHANGED or state is None:
                events.append(
                    ChangeEvent(
                        run_id=outcome.run_id,
                        previous_state=state,
                        new_state=new_state,
                        reason=reason,
                        previous_digest=last_digest,
                        new_digest=outcome.observation_digest,
                    )
                )
            state = new_state
            last_digest = outcome.observation_digest
            consecutive_misses = 0
        else:
            if state is None or state == AssetLifecycleState.DISAPPEARED:
                # Never observed yet, or already known gone — a further
                # miss changes nothing observable.
                continue
            consecutive_misses += 1
            if consecutive_misses >= missed_run_threshold:
                events.append(
                    ChangeEvent(
                        run_id=outcome.run_id,
                        previous_state=state,
                        new_state=AssetLifecycleState.DISAPPEARED,
                        reason=f"missed {consecutive_misses} consecutive relevant run(s)",
                        previous_digest=last_digest,
                        new_digest=None,
                    )
                )
                state = AssetLifecycleState.DISAPPEARED
            # else: tolerated, no event — the exact fail-tolerance rule
            # the phase's own prompt requires.

    return events


def observation_digest(facts: list[tuple[str, str, str, int | None]]) -> str:
    """A stable digest of everything one run observed about one asset —
    `facts` is `(observation_type, evidence.source, evidence.detail,
    evidence.confidence_score)` tuples, already fetched by the caller
    (`api/control_db.py::observation_digest_input_for_run`). Sorted
    before hashing so digest equality never depends on database read
    order — two runs that observed the exact same facts, in any order,
    always produce the exact same digest, which is what makes
    `UNCHANGED` vs `CHANGED` a reliable, deterministic comparison."""
    canonical = "\n".join(
        f"{obs_type}|{source}|{detail}|{confidence}"
        for obs_type, source, detail, confidence in sorted(facts)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def host_for_asset(*, asset_type: str, identity_key: str) -> str:
    """Extracts the underlying hostname an asset belongs to, straight
    from its own `identity_key` format (`api/asset_identity.py` is the
    single source of truth for these formats — this function does not
    invent a new one). Used to decide which scans are actually relevant
    to THIS asset (`api.domain_verification.domain_is_covered`) — never
    every scan in the organization regardless of target, which would
    wrongly count an unrelated domain's scan as a "miss" for this asset
    (a real false-disappearance risk this function exists to avoid)."""
    if asset_type == "domain":
        return identity_key.removeprefix("domain:")
    if asset_type in ("port", "dns_record"):
        # "port:<host>:<port>:<protocol>" / "dns_record:<host>:<type>:<value>"
        # — `host` (via core.assets.normalize_domain) never itself
        # contains ":", so splitting on ":" and taking the second field
        # is safe regardless of what a DNS record's OWN value contains
        # (e.g. an IPv6 address with colons, which only ever appears
        # later in the string).
        return identity_key.split(":")[1]
    if asset_type == "url":
        url = identity_key.removeprefix("url:")
        return urlparse(url).hostname or ""
    raise ValueError(f"unknown asset_type for host extraction: {asset_type!r}")
