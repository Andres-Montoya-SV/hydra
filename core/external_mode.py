"""Conservative-by-default posture for a run targeting a domain the operator
does not own (a third-party bug-bounty program, most importantly).

Pure classification/formatting logic lives here so it is unit-testable
without a terminal; the actual `input()` confirmation prompt lives in
`app.py`, which is the only place that should be doing interactive I/O.
"""

from __future__ import annotations

from config.settings import Settings
from core.intel.scope import CollectionScope

# Settings flags that require an additional, explicit CLI confirmation
# before running against an external (non-owned) target, even when already
# `true` in .env — these are the modules that send active traffic directly
# at the target itself, not merely observe it.
EXTERNAL_MODE_GATED_FLAGS: tuple[str, ...] = (
    "enable_param_fuzz",
    "enable_cloud_bucket_enum",
    "enable_browser_probe",
)


def _is_owned(domain: str, owned_domains: tuple[str, ...]) -> bool:
    from core.assets import normalize_domain
    from core.domain import parse_hostname

    norm = normalize_domain(domain)
    if not norm:
        return False
    _, _, root = parse_hostname(norm)
    for owned in owned_domains:
        owned_norm = normalize_domain(owned)
        if not owned_norm:
            continue
        _, _, owned_root = parse_hostname(owned_norm)
        if norm == owned_norm or (root and root == owned_root):
            return True
    return False


def classify_run(domains: list[str], settings: Settings) -> bool:
    """True when this run should be treated as targeting an external
    (non-owned) domain, triggering the conservative defaults below.

    Already-forced modes (`--external` / `EXTERNAL_TARGET_MODE=true`) short
    circuit to True. Otherwise: no `OWNED_DOMAINS` declared at all means
    nothing is classified as owned, so every run is external — the point of
    the setting is to name what is exempt, not to assume the opposite by
    default. A run mixing an owned and a non-owned domain is external:
    caution wins over convenience.
    """
    if settings.external_target_mode:
        return True
    if not settings.owned_domains:
        return bool(domains)
    return any(not _is_owned(d, settings.owned_domains) for d in domains)


def format_scope_summary(scope: CollectionScope, settings: Settings) -> str:
    """Human-readable pre-flight summary of exactly what a run is about to
    touch: authorized domains/wildcards, path exclusions (Task 1), and
    whether a researcher attribution header is configured (Task 2) — shown
    before any active collection starts, not after."""
    lines = ["Scope summary:"]
    lines.append("  Seed domains: " + (", ".join(scope.seed_domains) or "(none)"))
    lines.append("  Authorized patterns: " + (", ".join(scope.scope_patterns) or "(seed-only)"))
    if scope.path_exclusions:
        lines.append("  Path exclusions:")
        for domain, path_glob in scope.path_exclusions:
            lines.append(f"    ! {domain}{path_glob}")
    else:
        lines.append("  Path exclusions: (none)")
    headers = settings.merged_headers()
    if headers:
        lines.append(f"  Researcher attribution header: configured ({', '.join(headers)})")
    else:
        lines.append("  Researcher attribution header: NOT configured")
    if settings.external_target_mode:
        lines.append(
            "  External target mode: ON — conservative rate limits applied; "
            "active modules require confirmation"
        )
    return "\n".join(lines)
