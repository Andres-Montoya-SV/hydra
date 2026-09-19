"""Tier/quota/billing-status business logic (docs/PAID_API_DESIGN.md
Part B, Round 3) — pure functions over `ControlDB`/`api/tiers.py`
records, no HTTP concerns. Routers (`api/routers/scans.py`,
`api/routers/domains.py`, `api/routers/reportability.py`,
`api/routers/hypotheses.py`, `api/routers/subscription.py`) call these
and translate the result into the right status code, mirroring how
`api/domain_verification.py::classify_scan_gate` and
`api/routers/scans.py::_require_verified_domain_or_403` split
responsibility in Round 2.

**Design decisions this round finalized** (the task raised these as
"decide and document"):

1. **"Monthly" = calendar month, UTC** (`current_period_key`), not a
   rolling 30-day or per-account billing-anniversary window — simpler,
   and matches how the tier table itself talks about limits ("Scans/mes"
   means "this calendar month," the ordinary reading).
2. **Tier change (upgrade/downgrade) applies immediately, never
   retroactively, and never silently**: `apply_tier_change` switches
   `subscriptions.tier` right away — the new scan quota and LLM ceilings
   apply to the REST of the current month (already-used counts are not
   reset or backdated). If a downgrade leaves the account over the new
   tier's limits (e.g. more verified domains than the new tier allows,
   or already more scans used this month than the new tier permits), **
   nothing already obtained is silently revoked**: existing verified
   domains keep working until their own Round-2 expiry, and a scan
   already-counted this month stays counted. The new, stricter ceiling
   only blocks NEW consumption going forward (a new domain registration
   past the new limit; a new scan once already at/over the new monthly
   count). `apply_tier_change`'s return value tells the caller exactly
   which of these now apply, so `POST /account/subscription` can surface
   it to the client instead of the client discovering it via a later,
   unexplained 403.
3. **Retention-window changes are recorded, not enforced by a purge job**
   — no scheduled retention-purge job exists in this codebase yet (Part
   B's original draft already described this as a *future* scheduled
   job, and Round 3's task list does not ask for one). A downgrade to a
   shorter retention window changes what `TierLimits.retention_days`
   *would* keep going forward; it does not retroactively delete
   anything. Flagged here rather than silently assumed built.
4. **Payment-failure grace period: 3 days** (`GRACE_PERIOD_DAYS`,
   Part D.3) — during grace (`status == "past_due"`), scans and
   already-issued API keys keep working exactly as `"active"` does;
   only `status == "suspended"` (grace expired with no resolving
   webhook) blocks `POST /scans` with `402`. `GET` on an already-
   completed report is never blocked by billing status at all — checked
   nowhere in this module, because the client already paid for that
   specific, already-delivered data (Part D.3's own reasoning).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, cast

from api.tiers import TIERS, LlmFeatureLimits, Tier, TierLimits, tier_limits

if TYPE_CHECKING:
    from api.control_db import ControlDB, SubscriptionRecord

GRACE_PERIOD_DAYS = 3
_TIER_ORDER: tuple[Tier, ...] = ("free", "medium", "pro", "ultra")


def current_period_key(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


def next_tier_with_bigger_scan_quota(tier: Tier) -> Tier | None:
    """Used to build "upgrade to X" messages when a scan quota is hit —
    the first tier above this one with a strictly larger monthly scan
    allowance (always true going up `_TIER_ORDER`, since the table is
    monotonically increasing)."""
    index = _TIER_ORDER.index(tier)
    for candidate in _TIER_ORDER[index + 1 :]:
        if TIERS[candidate].scans_per_month > TIERS[tier].scans_per_month:
            return candidate
    return None


def effective_limits(subscription: SubscriptionRecord) -> TierLimits:
    return tier_limits(subscription.tier)


def get_or_create_subscription(control_db: ControlDB, account_id: str) -> SubscriptionRecord:
    """Defensive: every account created via `POST /accounts` from Round 3
    onward gets a 'free' subscription row at creation time
    (`api/routers/accounts.py`), but an account created by an earlier
    round's code (before this table existed) would have none — default
    it to 'free' on first read rather than erroring, the same
    fail-safe-to-the-most-restrictive-tier posture as any missing
    entitlement record."""
    subscription = control_db.get_subscription(account_id)
    if subscription is not None:
        return subscription
    control_db.create_default_subscription(account_id, tier="free")
    return cast("SubscriptionRecord", control_db.get_subscription(account_id))


def access_blocked_by_billing(subscription: SubscriptionRecord) -> bool:
    """Only a fully `"suspended"` account is blocked — `"past_due"`
    (inside the grace window) behaves exactly like `"active"` for the
    purpose of running scans (Part D.3)."""
    return subscription.status == "suspended"


def grace_period_expired(subscription: SubscriptionRecord, *, now: datetime | None = None) -> bool:
    if subscription.grace_period_started_at is None:
        return False
    now = now or datetime.now(timezone.utc)
    started = datetime.fromisoformat(subscription.grace_period_started_at)
    return now >= started + timedelta(days=GRACE_PERIOD_DAYS)


def start_grace_period(control_db: ControlDB, account_id: str) -> None:
    control_db.set_subscription_status(
        account_id, "past_due", grace_period_started_at=datetime.now(timezone.utc).isoformat()
    )


def suspend_account(control_db: ControlDB, account_id: str) -> None:
    control_db.set_subscription_status(account_id, "suspended")


def restore_active_status(control_db: ControlDB, account_id: str) -> None:
    control_db.set_subscription_status(account_id, "active")


# --- scan quota -------------------------------------------------------


def check_scan_quota(
    control_db: ControlDB, account_id: str, limits: TierLimits
) -> tuple[bool, str | None]:
    usage = control_db.get_monthly_usage(account_id, current_period_key())
    if usage.scans_used < limits.scans_per_month:
        return True, None
    upgrade = next_tier_with_bigger_scan_quota(limits.tier)
    suggestion = (
        f" Upgrade to {upgrade!r} for a higher monthly limit."
        if upgrade is not None
        else " You are already on the highest tier's fair-use ceiling for this month."
    )
    return False, (
        f"Monthly scan quota reached ({limits.scans_per_month} for the {limits.tier!r} tier)."
        + suggestion
    )


# --- verified-domain concurrency limit (Part A x Part B) ---------------


def check_verified_domain_limit(
    control_db: ControlDB,
    account_id: str,
    limits: TierLimits,
    *,
    renewing_domain: str | None = None,
) -> tuple[bool, str | None]:
    """`renewing_domain`: pass the domain about to be (re-)verified — if
    it's already among this account's currently-active verifications,
    this is a RENEWAL (the old row is about to be superseded, not added
    alongside), so it never counts against the limit as a net-new
    domain, no matter how full the account already is."""
    if limits.max_concurrent_verified_domains is None:
        return True, None
    active = control_db.get_verified_domains_for_account(account_id)
    if renewing_domain is not None and any(v.domain == renewing_domain for v in active):
        return True, None
    current = len(active)
    if current < limits.max_concurrent_verified_domains:
        return True, None
    return False, (
        f"This account already has {current} verified domain(s), the maximum the "
        f"{limits.tier!r} tier allows ({limits.max_concurrent_verified_domains}). "
        "Upgrade your tier, or let an existing verification expire, before verifying "
        "another domain."
    )


# --- report format/language/white-label gating -------------------------


def check_report_options(
    limits: TierLimits, *, report_format: str, language: str, white_label: bool
) -> tuple[bool, str | None]:
    if report_format not in limits.report_formats:
        return False, (
            f"The {limits.tier!r} tier does not include {report_format!r} reports "
            f"(available: {sorted(limits.report_formats)}). Upgrade your tier to unlock it."
        )
    if language not in limits.report_languages:
        return False, (
            f"The {limits.tier!r} tier does not include {language!r}-language reports "
            f"(available: {sorted(limits.report_languages)}). Upgrade your tier to unlock it."
        )
    if white_label and not limits.white_label_report:
        return False, (
            f"White-label (no-Hydra-branding) reports are an Ultra-tier feature. "
            f"The {limits.tier!r} tier does not include it."
        )
    return True, None


# --- LLM feature gating + spend ceiling ---------------------------------


def llm_feature_limits(
    limits: TierLimits, feature: Literal["reportability", "hypotheses"]
) -> LlmFeatureLimits | None:
    return limits.reportability if feature == "reportability" else limits.hypotheses


@dataclass(frozen=True)
class AdversarialDecision:
    """What a provider+adversarial_provider request actually gets to
    run as, for this tier. `used_adversarial_provider` is None whenever
    cross-validation didn't happen — either because the client never
    asked for it, or because Medium's `auto_degrade` policy silently-but-
    visibly dropped it (`degraded` is the caller's cue to surface that in
    the response, per this module's own docstring point on never being
    silent about it)."""

    used_adversarial_provider: str | None
    degraded: bool


def resolve_adversarial_provider(
    feature_limits: LlmFeatureLimits, requested_adversarial_provider: str | None
) -> AdversarialDecision:
    if requested_adversarial_provider is None:
        return AdversarialDecision(used_adversarial_provider=None, degraded=False)
    if feature_limits.adversarial == "available":
        return AdversarialDecision(
            used_adversarial_provider=requested_adversarial_provider, degraded=False
        )
    if feature_limits.adversarial == "auto_degrade":
        # Medium: has the feature, not the cross-validation. Chosen over
        # outright rejecting the whole request (400) because the client
        # asked for something perfectly reasonable — just above their
        # tier — and blocking the ENTIRE assessment over one extra
        # parameter is disproportionate. The response always carries
        # `degraded_from_adversarial: true` so this is never invisible.
        return AdversarialDecision(used_adversarial_provider=None, degraded=True)
    # "unavailable" tiers never reach this function at all (the route
    # 404s before calling it) — defensive, not a reachable branch today.
    return AdversarialDecision(used_adversarial_provider=None, degraded=True)


def check_llm_budget(
    control_db: ControlDB,
    account_id: str,
    *,
    feature: Literal["reportability", "hypotheses"],
    feature_limits: LlmFeatureLimits,
    additional_cost_usd: float,
) -> tuple[bool, str | None]:
    usage = control_db.get_monthly_usage(account_id, current_period_key())
    already_spent = (
        usage.reportability_spend_usd if feature == "reportability" else usage.hypotheses_spend_usd
    )
    if already_spent + additional_cost_usd <= feature_limits.monthly_ceiling_usd:
        return True, None
    remaining = max(0.0, feature_limits.monthly_ceiling_usd - already_spent)
    return False, (
        f"This would exceed the account's monthly {feature} budget "
        f"(${feature_limits.monthly_ceiling_usd:.2f}, ${remaining:.2f} remaining this month). "
        "Upgrade your tier for a higher ceiling, or wait until next month."
    )


def record_llm_spend(
    control_db: ControlDB,
    account_id: str,
    *,
    feature: Literal["reportability", "hypotheses"],
    amount_usd: float,
) -> None:
    control_db.add_llm_spend(
        account_id, current_period_key(), feature=feature, amount_usd=amount_usd
    )


# --- tier changes --------------------------------------------------------


@dataclass(frozen=True)
class TierChangeResult:
    previous_tier: Tier
    new_tier: Tier
    verified_domains_count: int
    verified_domains_limit: int | None
    exceeds_domain_limit: bool
    scans_used_this_period: int
    scans_limit: int
    exceeds_scan_limit: bool


def apply_tier_change(
    control_db: ControlDB, account_id: str, new_tier: Tier, *, billing_email: str | None = None
) -> TierChangeResult:
    subscription = control_db.get_subscription(account_id)
    previous_tier: Tier = subscription.tier if subscription is not None else "free"  # type: ignore[assignment]
    control_db.set_tier(account_id, new_tier, billing_email=billing_email)

    new_limits = tier_limits(new_tier)
    verified_count = len(control_db.get_verified_domains_for_account(account_id))
    usage = control_db.get_monthly_usage(account_id, current_period_key())

    exceeds_domain_limit = (
        new_limits.max_concurrent_verified_domains is not None
        and verified_count > new_limits.max_concurrent_verified_domains
    )
    exceeds_scan_limit = usage.scans_used > new_limits.scans_per_month

    return TierChangeResult(
        previous_tier=previous_tier,
        new_tier=new_tier,
        verified_domains_count=verified_count,
        verified_domains_limit=new_limits.max_concurrent_verified_domains,
        exceeds_domain_limit=exceeds_domain_limit,
        scans_used_this_period=usage.scans_used,
        scans_limit=new_limits.scans_per_month,
        exceeds_scan_limit=exceeds_scan_limit,
    )


def dump_params(params: dict[str, object]) -> str:
    return json.dumps(params, sort_keys=True)
