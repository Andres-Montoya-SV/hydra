"""Fase 17 (EASM roadmap): deterministic, source-independence-aware
confidence composition — requirement 8's "dos providers que parsean la
misma respuesta HTTP no son evidencia independiente."

`core/confidence.py` already scores individual facts (`score_subdomain`,
`score_http`, `score_port`) and aggregates them for a `Host` via
`update_host_confidence`'s `max(scores)` — a real function, left
untouched here deliberately (it is already tested and used broadly; this
phase's own "no reescribir salvo bug real" discipline applies). What did
not exist anywhere: a function that takes several PROVIDERS' own
confidences about the SAME fact and combines them accounting for which
of those providers are actually independent measurements versus multiple
tools reading the same underlying signal. This module is that function —
new, additive, usable wherever a future caller (Fase 21's risk scoring,
a technology-inventory confidence, an exposure's own confidence) needs
it, without altering `core/confidence.py`'s existing, already-relied-on
behavior.

**Deterministic, explainable, no ML**: a fixed table of which sources are
known to read the same underlying signal (`_CORRELATED_SOURCE_GROUPS`),
and a simple, documented noisy-OR combination across the resulting
independent clusters — never a trained/opaque model, per the roadmap's
own "nada de scores de caja negra" invariant.
"""

from __future__ import annotations

from dataclasses import dataclass

# Sources known to parse the SAME underlying signal, not independent
# measurements of the same fact. httpx and WhatWeb (and the
# security-header extraction that also reads httpx's own response) all
# derive from one HTTP response Hydra fetched once — two of them
# agreeing is not two independent confirmations. A source not listed
# here is treated as its own, independent cluster.
_CORRELATED_SOURCE_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"httpx", "whatweb", "security_headers"}),
)


def _cluster_key(source: str) -> str:
    for group in _CORRELATED_SOURCE_GROUPS:
        if source in group:
            return "+".join(sorted(group))
    return source


@dataclass(frozen=True)
class SourceObservation:
    source: str
    confidence: int  # 0-100, the source's own reported confidence for this one fact


@dataclass(frozen=True)
class ComposedConfidence:
    score: int  # 0-100
    contributing_sources: tuple[str, ...]
    reason: str


def compose_confidence(observations: list[SourceObservation]) -> ComposedConfidence:
    """Deterministic: the same multiset of observations, in any order,
    always produces the same result. Within a correlated group, only the
    single highest confidence counts (agreement inside the group adds
    nothing new). Across genuinely independent clusters, confidences
    combine via noisy-OR (`1 - product(1 - p_i)`) — two weak-but-
    independent signals can together justify more confidence than either
    alone, without ever exceeding what plain probability combination
    allows."""
    if not observations:
        return ComposedConfidence(score=0, contributing_sources=(), reason="no observations")

    clusters: dict[str, list[SourceObservation]] = {}
    for obs in observations:
        clusters.setdefault(_cluster_key(obs.source), []).append(obs)

    best_per_cluster: list[SourceObservation] = [
        max(cluster, key=lambda o: (o.confidence, o.source)) for cluster in clusters.values()
    ]
    best_per_cluster.sort(key=lambda o: o.source)

    probability_all_wrong = 1.0
    for obs in best_per_cluster:
        clamped = max(0, min(100, obs.confidence))
        probability_all_wrong *= 1.0 - (clamped / 100.0)
    composed_score = round((1.0 - probability_all_wrong) * 100)

    contributing = tuple(sorted(obs.source for obs in best_per_cluster))
    reason = (
        f"{len(best_per_cluster)} independent source cluster(s) "
        f"({', '.join(contributing)}) combined via noisy-OR; "
        f"{len(observations) - len(best_per_cluster)} correlated observation(s) "
        f"did not add independent weight"
    )
    return ComposedConfidence(
        score=composed_score, contributing_sources=contributing, reason=reason
    )
