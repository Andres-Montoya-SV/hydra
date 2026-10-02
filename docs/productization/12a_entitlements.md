# Product Phase 12a — SaaS Entitlements

Branch: `productization/12a-entitlements`. Base: `main` @ `18bd9b0` (after
PR #120, Phase 11g).

The roadmap asks to audit the existing paid tiers rather than rebuild
them, then model and enforce the entitlements. One rule governs it: a
billing tier may **deny** product access but must **never grant**
authorization to scan a target.

Phase 12 is split in two:

| Part | Content |
|---|---|
| **12a** (this) | the audit; entitlements as data; atomic enforcement; the new per-tier limits |
| [12b](12b_account_state.md) | read-only suspension; the downgrade rule (oldest N domains stay scannable); the scan priority queue |

## Audit (2026-10-02, `main` @ `18bd9b0`)

| Question | Finding |
|---|---|
| Can a tier grant authorization? | **No.** The tier ceiling only narrows which tools a scan may run, and caps how many domains may be verified. No tier change verifies or un-verifies a domain. Scanning still requires the domain's own ownership verification (tested: an Ultra account still gets 403 on an unverified domain). |
| Scan quota | **Race across processes.** The quota was checked, then the scan created, then the counter incremented, as separate steps. A single API process is safe only because `create_scan` is an `async def` that never awaits between them. With several processes on one database (possible since Phase 10), 8 simultaneous scans were all accepted on a Free account with a quota of 1. **Fixed here.** |
| Billing suspension | Blocks only new manual scans and weekly active monitoring. Passive monitoring, imports, new organizations and integrations continue. → 12b |
| Organizations, members, imports | No limit on any tier. **Fixed here.** |
| Webhooks, ticketing integrations | A flat 10 on every tier. **Tiered here.** |
| `priority_queue` | Advertised for Pro and Ultra; a documented no-op. → 12b |
| After a downgrade | Verified domains beyond the new tier's limit keep working until they expire. → 12b |

## Entitlements (decision 2026-10-02)

The limits are data in `api/tiers.py`; `None` means unlimited. The tier
that applies is the **tier of the account performing the action**, the
same rule collection capabilities already use.

| Entitlement | Counted per | Free | Medium | Pro | Ultra |
|---|---|---|---|---|---|
| scans per month | account | 1 | 10 | 50 | 500 |
| imports per month | account | 2 | 20 | 100 | 1000 |
| organizations owned (including the default one) | account | 1 | 3 | 10 | unlimited |
| webhooks | account | 1 | 3 | 10 | 25 |
| members, the owner included | organization | 2 | 5 | 20 | 100 |
| ticketing integrations (active) | organization | 1 | 3 | 10 | 25 |

- **Existing data over a limit is kept**, for example after a downgrade.
  Only new creations are refused.
- **Imports count only real, new imports.** A dry run, a re-import of the
  same report, and a rejected upload don't use the quota.
- **Role changes are free.** Changing an existing member's role never
  counts against the member limit.

### The error

A refusal is always a structured 403. It is never a silent no-op or a
partial result.

```json
{"detail": {"error": "entitlement_exceeded", "entitlement": "organizations",
            "tier": "free", "limit": 1, "upgrade_to": "medium",
            "message": "Your 'free' tier allows 1 organizations. Upgrade to 'medium' for more."}}
```

`upgrade_to` names the cheapest tier with a larger limit, or `null` on
the highest tier. The existing scan-quota message is unchanged, for
compatibility.

`GET /account/subscription` now also reports:
- imports used and their limit;
- organizations owned and their limit;
- webhooks used and their limit;
- the per-organization member and integration limits.

## Enforcement: atomic, in any number of processes

- **Monthly counts** (scans, imports) use `ControlDB.reserve_usage`, a
  single `INSERT … ON CONFLICT DO UPDATE … WHERE used < cap`. The check
  and the count are one statement. If creating the scan then fails, the
  reservation is released.
- **Count-based limits** (organizations, members, webhooks, integrations)
  are checked under a write lock, in the same transaction as the insert
  (`_enforce_limit`):
  - **Postgres:** an advisory lock per owner and entitlement;
  - **SQLite:** `BEGIN IMMEDIATE`.

  Creating an organization now also writes its owner role in the same
  transaction.
- **Early refusals** stay where they were useful (webhooks before the DNS
  check, integrations before the outbound check), but the transactional
  check is the one that counts.

## Tests (`tests/test_entitlements.py`, both backends)

- **The table:** every entitlement grows with the tier and never returns
  to limited after unlimited; the decided numbers; the upgrade hint.
- **Atomicity:**
  - 8 `ControlDB` instances with their own connection pools (standing in
    for 8 API processes) reserve concurrently, and exactly the cap is
    accepted. Mutation-checked: without the `WHERE … < :cap`, 8 of 8 are
    accepted, which is the original bug;
  - 6 concurrent organization creations under a limit of 3 produce exactly
    3 owned organizations.
- **Organizations:** Free owns one; upgrading allows more.
- **Members:** the owner counts; a role change at the limit still works.
- **Downgrades:** data over a limit is kept, and the next creation is
  refused.
- **Imports:** a dry run, a re-import and a rejected report don't count;
  the third real import on Free is refused.
- **Webhooks:** refused at the limit; the subscription view shows usage.
- **No authorization from entitlements:** an Ultra account can't scan an
  unverified domain.

Existing tests that created a second organization on a Free account now
upgrade that account first. They test other properties.
