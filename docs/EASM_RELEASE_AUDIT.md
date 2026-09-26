# EASM release audit — 2026-09-26

## Release decision

**NOT CLEARED for a production launch of the complete multi-tenant EASM.**
The historical CLI certification in PRODUCTION_READINESS.md is narrower than
this product. Merging reviewed, additive foundations is not certification that
the original twelve-phase roadmap is complete. No production deployment was
performed in this review.

The repository's `docs/easm/00_baseline.md` now describes an extended roadmap;
its phase numbers differ from the original twelve-phase acceptance criteria.
Use capabilities, not matching numbers, to reconcile the two. `00_READ_FIRST.md`
is absent; `00_consolidation_plan.md` records that absence too. Do not invent
its instructions or claim they were followed.

## Capability acceptance against the original roadmap

| Phase | Evidence in the current code / reviewed PR | Outstanding launch acceptance |
| --- | --- | --- |
| 01 consolidation | `docs/easm/00_consolidation_plan.md`; canonical `core.intel` | Finish and verify retirement of legacy intelligence interfaces; audit all callers. |
| 02 organizations | `ControlDB` organization provisioning and membership model | Prove role enforcement through each new EASM route when those routes exist. |
| 03 assets | `api/asset_identity.py`, `api/asset_backfill.py` | Connect reconciliation to completed production runs; helpers alone do not populate the live product. |
| 04 observations | Durable observation identities and backfill | Wire the live ingestion lifecycle; define evidence lifecycle across the two databases. |
| 05 changes | `api/change_detection.py` and persisted change events | Connect live reconciliation and consumers without duplicate events. |
| 06 candidates | `api/candidate_assets.py`, `api/candidate_backfill.py`; candidate/asset separation tests | Missing human promotion/rejection API, auditable decisions, and suppression until new evidence. `docs/easm/06_candidate_assets.md` explicitly excludes promotion. Add an adversarial Speed 2 test for the actual human workflow before declaring this phase done. |
| 07 relationships | PR #64 persists existing intelligence relationships; bounded traversal, evidence and tenant guards | Validate typed evidence references end to end, finish legacy-engine consolidation, and expose an authorized query. Current source evidence IDs are opaque source references, not cross-database foreign keys. |
| 08 exposures | PR #67 adds stable identity, history, replay protection, resolve/reopen tests | Add in-progress workflow, explicit observation/change-event generation rules and live integration. Finding-backed backfill is not the complete phase-08 observation pipeline. |
| 09 monitoring | Existing worker, outbox and webhook isolation retained | Worker still needs to consume durable exposures/change events, cite them, and preserve exactly-once outcome semantics and needs_review gating. |
| 10 API | Existing account/domain/scan/monitoring routers | Organization/assets/observations/change-events/relationships/exposures API surface and per-endpoint negative IDOR tests are missing. Add bounded pagination and read-only role tests for each route. |
| 11 recovery | Existing SQLite Backup API, restore and retention tests | Extend populated round-trip fixtures to the full EASM graph, test cross-database evidence recovery, and define observation retention preserving evidence. Existing purge intentionally retains recon.db but deletes old output artifacts; screenshot/artifact evidence needs an explicit retention policy. |
| 12 risk/reports | Existing reportability/hypothesis infrastructure | Connect deterministic explainable risk and exposure history to customer reports; complete the original adversarial phase-by-phase review. |

Do not bypass any of these gaps by scanning candidates, adding a second scope
authorization path, or treating frontend demo data as live backend data.

## Corrections from the open-PR review

- Visual intelligence: a final URL alone no longer claims visual evidence;
  retain v2's artifact persistence and service merging. #65 supersedes #68.
- Relationship evidence: reject empty references and foreign-organization runs;
  require owned root assets; bound traversal depth and result size. The fixture
  has 3,000 cyclic edges, with depth-three traversal returning six edges in
  0.003733 seconds in the review environment (not a production SLA).
- Exposures: replaying old evidence cannot reopen a resolved exposure or erase
  its resolution; new evidence can reopen the same ID with preserved history.
  Five distinct runs produce one exposure and five confirmations. Rule and
  run-ownership validation fail closed.
- Cloud inventory: ignore absent/unsupported resources; UPSERT preserves raw
  resource identity on replay. Correct the test to inspect the documented
  observation wrapper. Preserve the reviewed DNS and visual changes when
  resolving the stacked branch conflicts.
- Dependencies: upgrade python-dotenv from 1.0.1 to patched 1.2.2 in both
  dependency manifests for GHSA-mf9w-mj56-hr94; add a runtime pip-audit CI gate
  and weekly dependency/action update PRs. The corrected runtime audit reports
  no known vulnerabilities (this does not audit the separate Go binaries).
  Advisory: https://github.com/theskumar/python-dotenv/security/advisories/GHSA-mf9w-mj56-hr94
- CI: pin checkout/setup-python to verified commit SHAs, restrict token to
  contents:read, bound job runtime, and run real-container checks on merged
  main as well as PRs. Keep all existing confinement checks.
- Frontend: supported dependency upgrades including TypeScript 7 passed its
  own build. This does not imply compatibility in hydra-styling: that library's
  tsup declaration bundler fails on TypeScript 7's compiler API. Keep its 5.9
  compiler until a separately tested declaration-toolchain migration.
- Keep frontend Node type declarations aligned with its Node 24 runtime;
  closing a Node 26 types-only update avoids claiming a runtime upgrade.

## Validation evidence and limits

PR #65 at `0ffcef74352c588d46172570197f43e75f71cb6c`:
Docker job `108353095988` reported **1,973 passed, 8 skipped** in the complete
suite, then **13 passed** in live confinement tests; the scope-exclusion canary
was clean. Its Python 3.10/3.11/3.12 jobs also passed.

Local focused regression suites passed for graph/exposure history (18 tests)
and combined cloud/DNS/visual/identity coverage (57 tests). Local frontend
`npm ci`, `npm run check`, and audit passed; styling build, packed-consumer
verification and audit passed; both app audits reported zero vulnerabilities.

The local backend full suite did **not** pass: 1,795 passed, 54 skipped,
14 failed in the restricted network/proxy environment. DNS/public-host and
network-confinement fixtures need the CI runtime. These failures were not
hidden by changing the tests. Container CI provides the separate real-tool
validation; use the exact commit's Actions results for release evidence.
Three different Python versions do not count as three complete consecutive
pipeline runs. No phase is certified against that original requirement here.

## Repository enforcement

The active backend ruleset `main-protection` (ID 23964855) requires a pull
request and blocks deletion/force pushes, but its `required_status_checks`
list is **empty**. CI success is currently a review discipline, not an enforced
merge gate. Configure required `check (3.10)`, `check (3.11)`, `check (3.12)` and
`docker` and `dependency-audit` checks and require an up-to-date branch (or a tested merge queue).
The frontend and styling ruleset listings are empty; that does not establish
whether legacy branch protection exists. Verify their protection and require
`validate` before merging. The connected GitHub capability does not provide
administration writes, so these settings were not changed or claimed enforced.

## Remaining deployment acceptance

1. Complete the capability gaps above in dependency order, with explicit
   evidence and adversarial tests. Keep candidate promotion a human action
   using the existing authorization mechanism.
2. Run the entire pipeline three times on the actual release candidate;
   record each run ID, counts, skips and confinement results. Confirm all
   repositories use compatible released contracts, not merely independent
   successful builds.
3. Rehearse migration, populated backup/restore, rollback, tenant isolation,
   and an authenticated frontend-to-backend flow in staging.
4. Validate the chosen hosting environment: TLS, secret injection, outbound
   backup recovery, health alerts and resource limits. No hosting target or
   production credentials were supplied in this review.
5. Apply and test the documented network egress controls for raw TCP/SYN tools;
   the historical certification identifies their DNS-rebinding limitation.
   Application HTTP confinement is not evidence that OS-level egress is set.

Do not silently replace this verdict with READY because branch conflicts and
CI failures have been resolved. Update each acceptance item with code and
measured evidence when its implementation is complete.
