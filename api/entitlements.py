"""Productization Phase 12a: per-tier entitlements, enforced.

The limits are data (`api/tiers.py`). The tier that applies is the tier of
the account performing the action, as for collection capabilities:

| Entitlement | Counted per | Free | Medium | Pro | Ultra |
|---|---|---|---|---|---|
| scans per month | account | 1 | 10 | 50 | 500 |
| imports per month | account | 2 | 20 | 100 | 1000 |
| organizations owned | account | 1 | 3 | 10 | unlimited |
| webhooks | account | 1 | 3 | 10 | 25 |
| members | organization | 2 | 5 | 20 | 100 |
| ticketing integrations | organization | 1 | 3 | 10 | 25 |

**Enforcement:**
- Monthly counts are reserved atomically (`ControlDB.reserve_usage`).
- Count-based limits are checked under a write lock, in the same
  transaction as the insert (`ControlDB._enforce_limit`).
- Concurrent requests, even from several API processes, can't exceed a
  limit.

**Existing data over a limit is kept.** Only new creations are refused,
with `entitlement_error`.

**An entitlement never grants authorization.** It only denies. Scanning a
target still requires its own domain verification, whatever the tier.
"""

from __future__ import annotations

from fastapi import HTTPException

from api import subscriptions
from api.control_db import ControlDB, LimitReachedError
from api.tiers import TIERS, Tier, TierLimits

# Entitlement name -> the TierLimits field holding its limit.
ENTITLEMENT_FIELDS: dict[str, str] = {
    "scans": "scans_per_month",
    "imports": "imports_per_month",
    "organizations": "max_organizations",
    "webhooks": "max_integrations",
    "members": "max_members_per_organization",
    "integrations": "max_integrations",
    "verified_domains": "max_concurrent_verified_domains",
}
_ORDER: tuple[Tier, ...] = ("free", "medium", "pro", "ultra")


def account_limits(db: ControlDB, account_id: str) -> TierLimits:
    """The limits of the account performing an action."""
    return subscriptions.effective_limits(subscriptions.get_or_create_subscription(db, account_id))


def limit_of(limits: TierLimits, entitlement: str) -> int | None:
    value: int | None = getattr(limits, ENTITLEMENT_FIELDS[entitlement])
    return value


def upgrade_for(tier: Tier, entitlement: str) -> Tier | None:
    """The cheapest higher tier with a larger (or no) limit."""
    current = limit_of(TIERS[tier], entitlement)
    for candidate in _ORDER[_ORDER.index(tier) + 1 :]:
        limit = limit_of(TIERS[candidate], entitlement)
        if limit is None or (current is not None and limit > current):
            return candidate
    return None


def _noun(entitlement: str, count: int) -> str:
    """'1 organization', '3 organizations' (every entitlement name is a
    regular plural)."""
    noun = entitlement.replace("_", " ")
    return noun[:-1] if count == 1 else noun


def entitlement_error(tier: Tier, entitlement: str, limit: int) -> HTTPException:
    """A typed 403, never a silent no-op: names what ran out and how to get
    more."""
    upgrade = upgrade_for(tier, entitlement)
    hint = f" Upgrade to {upgrade!r} for more." if upgrade else ""
    return HTTPException(
        status_code=403,
        detail={
            "error": "entitlement_exceeded",
            "entitlement": entitlement,
            "tier": tier,
            "limit": limit,
            "upgrade_to": upgrade,
            "message": f"Your {tier!r} tier allows {limit} {_noun(entitlement, limit)}.{hint}",
        },
    )


def refuse_if_full(limits: TierLimits, entitlement: str, current: int) -> None:
    """An early, cheap refusal when `current` has reached the limit. The
    creating transaction checks again, atomically."""
    limit = limit_of(limits, entitlement)
    if limit is not None and current >= limit:
        raise entitlement_error(limits.tier, entitlement, limit)


def from_limit_reached(tier: Tier, exc: LimitReachedError) -> HTTPException:
    return entitlement_error(tier, exc.entitlement, exc.limit)
