# Product Phase 00 — Product Baseline & API Contract

Status: **complete** — reconnaissance-only, no product behavior changed.
Branch: `productization/00-baseline`. Base: `main` @ `bf46375` (includes
the merged Snyk remediation PR #92 — dependency floor, trixie base image,
path-traversal fix, SQLi false-positive tests, `.snyk` exclusion).

This document is the mandatory first deliverable of **HYDRA
PRODUCTIZATION — ROADMAP 01**, a new engineering cycle that follows the
now-complete 21-phase EASM architecture build (Fases 00–21, closed via PR
#91). It is reconnaissance, not a redesign: every claim below was verified
directly against current code on `main`, not inferred from docs alone —
docs and code disagree in a few places, and those disagreements are
called out explicitly rather than silently resolved in either direction.

---

## 1. Executive summary

The EASM *engine* (scan pipeline, scope/confinement, correlation,
verification, LLM triage) and the EASM *domain model* (Organization →
Asset → Observation → Evidence → Relationship → Exposure → ChangeEvent →
Risk) are both real, tested, and running in production paths — not
aspirational. So is a working paid multi-tenant API on top of them:
accounts, API keys, domain-ownership verification, four billing tiers
with real Wompi integration, a durable multi-worker scan queue, two-speed
continuous monitoring with email **and** signed webhook delivery,
automated backups/retention/reconciliation, and a real `/health` check.
This is materially further along than "engine exists, product doesn't."

The gap this roadmap exists to close is narrower than a first read of
Roadmap 01's phase list suggests: most of Phases 01, 05, 08, and parts of
04/06/12 already have real, shipped groundwork. The genuine gaps cluster
in three places — **(a)** a handful of missing read endpoints for
concepts that already exist in the database (relationships, per-asset
DNS/TLS/cloud/visual detail, evidence explainability as its own
resource), **(b)** two pieces of acknowledged, never-executed technical
debt from the EASM audit (`core/intelligence/` still running
unconditionally on every scan despite being marked deprecated;
`core/diff.py::ScanDiff` in the same state), and **(c)** operational
hardening (admin auth is a static bearer token; branch protection doesn't
actually enforce CI; one real per-account settings bug means paid scan
pipelines silently ignore `.env` overrides).

No P0 issue blocks the accuracy of this baseline, so **no code changes
are proposed in this phase**, per Roadmap 01 §"PRODUCT PHASE 00" ("Do not
make broad feature changes in this phase unless needed to fix a P0
blocker"). Everything below is classification and a proposed Phase 01
scope.

---

## 2. Method

Three parallel research passes against current `main` (not docs read in
isolation — every doc claim was cross-checked against the actual
importing/calling code where it mattered):

1. API surface, billing/tenancy, demo-data grep, tier table, webhook
   inventory.
2. Architecture, network confinement, the three prior audit documents
   (`EASM_RELEASE_AUDIT.md`, `PRODUCTION_READINESS.md`,
   `FINAL_PROJECT_AUDIT.md`), and a live grep for whether
   `core/intelligence/`/`core/diff.py` are still imported by production
   code (not just flagged as deprecated in a docstring).
3. Full `control.db` schema, and existence/location of each of the ten
   domain concepts Roadmap 01 requires reuse of (Organization, Asset,
   CandidateAsset, Observation, Evidence, Relationship, Exposure,
   ChangeEvent, Capability, ProviderContract), plus risk-scoring,
   reports-to-exposures, provider-qualification, and monitoring
   infrastructure.

Branches and PR state were checked directly (`git branch -r`,
`git rev-list --count`), not assumed from doc prose — `gh` is broken in
this environment (root-owned `~/.config/gh/config.yml`), same as prior
engagements in this repo.

---

## 3. Branch/PR reconnaissance (Roadmap 01 Rule 1)

- `main` is current (`bf46375`) and includes PR #92 (Snyk remediation),
  merged since the EASM roadmap closed.
- Of 60+ remote branches, all but 5 are fully merged into `main` (0
  commits ahead) and are stale artifacts of past PRs, safe to ignore/
  delete at the user's discretion — not investigated further here since
  none is ahead of current work.
- 5 branches have unmerged commits:
  - `dependabot/pip/mypy-2.3.1`, `dependabot/pip/ruff-0.16.8` — routine
    dependency-bot PRs, 1 commit each, not investigated further (not
    this roadmap's concern).
  - `feat/easm-candidate-assets` (13 commits) — this is the **original**
    branch that first built Candidate Asset persistence/backfill/tests
    (matches `docs/easm/06_candidate_assets.md`'s content almost
    verbatim). Its functionality is already live on `main` under the
    `candidate_assets`/`candidate_asset_reviews` tables and
    `api/candidate_assets.py` — confirmed by direct inspection, not
    branch diff. **This branch is superseded, not missing work; safe to
    delete.**
  - `feat/easm-technology-intelligence`, `feat/easm-visual-intelligence`
    — single leftover CI-fix commits each, from before those fixes were
    generalized elsewhere. Not investigated further; low-value, likely
    safe to delete.
- `origin/snyk-fix-6d00c14f9485dd3970e44ea3933dcac0` (Snyk's own
  auto-remediation bot branch) — 0 commits ahead of `main`; fully
  superseded by the manual Snyk remediation already merged (PR #92).
  Safe to delete.
- **One reconnaissance correction made during this phase**: one research
  pass's source material referenced a branch
  `fix/dnsx-nodata-soa-false-resolution` as "a real tested bugfix sitting
  unmerged on a forgotten local branch" (citing `FINAL_PROJECT_AUDIT.md`).
  Verified directly: this branch is **already merged** into `main` (0
  commits ahead; `d98a5d8` is an ancestor of `main` via PR #5, and the
  NODATA/SOA fix is present in `modules/dnsx.py` today). The audit
  document that flagged it is simply older than the merge. No action
  needed — noted here only as a demonstration of Rule 1 in practice: a
  doc's claim was checked against real branch state and found stale.

**No genuinely open, unmerged, unaccounted-for feature work exists on any
branch.** The reconnaissance in the sections below is therefore a true
reflection of `main`, not a partial view.

---

## 4. Capability-by-capability status

Classification per Roadmap 01's own taxonomy: **ALREADY_DONE**,
**PARTIALLY_DONE**, **MISSING**, **OBSOLETE**, **CONFLICTING**,
**UNSAFE**.

### 4.1 Onboarding & organization setup (Roadmap Phase 01 territory)

| Capability | Status | Evidence |
|---|---|---|
| Account creation | ALREADY_DONE | `POST /accounts`, per-IP rate limited (`account_creation_attempts` table), email-verification-gated before any scan runs |
| Email verification | ALREADY_DONE | `POST /accounts/verify-email`, `/resend-verification`; partial-unique DB index on `accounts.email` |
| API key issuance/rotation/revocation | ALREADY_DONE | `api/routers/keys.py`; Argon2id-hashed storage; 24h dual-validity rotation window |
| Organization creation / roles | PARTIALLY_DONE | `organizations` + `account_organization_roles` tables exist (owner/viewer roles); no dedicated `POST /organizations` endpoint was found in the router inventory — EASM's `api/routers/easm.py` reads organizations but organization *creation* appears to happen only via the EASM backfill path (`api/easm_backfill.py`), triggered implicitly by a scan, not as an explicit onboarding step a client calls |
| Domain ownership verification | ALREADY_DONE | `POST /domains`, `POST /domains/{domain}/verify` — real DNS TXT / well-known-file checks, 90-day expiry, first-verification-wins conflict policy, tier-gated verified-domain limits |
| Collection profile / intensity / capability selection | MISSING as an API concept | `ProviderIntensity`/capability taxonomy exist internally (`core/provider_contract.py`, `core/capabilities.py`) but no `POST /scans` option lets a client choose collection intensity or which capabilities to run — every scan runs Hydra's fixed default plugin set |
| Safe defaults | ALREADY_DONE | Existing pipeline defaults (conservative external-target-mode, opt-in active plugins) apply uniformly; nothing API-specific needed here |
| First-scan trigger | ALREADY_DONE | `POST /scans` — gated by email verification, billing/quota, verified-domain-freshness, in that order |
| Progress/status endpoint | ALREADY_DONE | `GET /scans/{scan_id}` |
| Failure/retry semantics | ALREADY_DONE | Durable SQLite-backed scan queue (`ControlDB.claim_next_queued_scan`, heartbeat-based stale-scan sweep, bounded retries at `scan_max_retries=3`) |
| Data model distinguishes Known/Candidate/Authorized-scope/Observed/Excluded | PARTIALLY_DONE | The underlying tables (`assets`, `candidate_assets`, domain verification, observations) cleanly separate these concepts *in storage*; whether every relevant API **response** surfaces this distinction explicitly (vs. requiring the client to infer it from which endpoint they called) was not exhaustively checked per-endpoint in this pass |

### 4.2 Attack surface inventory API (Roadmap Phase 02 territory)

| Capability | Status | Evidence |
|---|---|---|
| Asset inventory (filter/search/paginate/sort) | PARTIALLY_DONE | `api/routers/easm.py` exposes asset listing; exact filter/sort/pagination completeness not verified endpoint-by-endpoint in this pass — flagged for Phase 02's own reconnaissance, not re-verified here to avoid duplicate work |
| Asset detail (DNS/TLS/tech/cloud/visual) | MISSING (explicitly deferred) | `docs/PAID_API_DESIGN.md`'s own Fase 19 section states DNS/visual/cloud per-asset views were deferred; only change/cert/tech *event history* endpoints exist today |
| "Why is this asset here" (evidence/provenance) inline or linked | PARTIALLY_DONE | `evidence`/`observations` tables and their FK chain to `assets` exist; no confirmed dedicated per-asset "explain" response shape |
| Analyst/provider-debug endpoint separate from product endpoint | ALREADY_DONE (naming discipline) | `core/capabilities.py`'s `Capability` enum is the product-facing vocabulary; provider names stay internal to `core/provider_contract.py`; not yet confirmed whether a *raw* analyst-debug endpoint is exposed via `api/` (may not need to be, if internal-only) |

### 4.3 Evidence explainability API (Roadmap Phase 03 territory)

| Capability | Status | Evidence |
|---|---|---|
| Structured per-assertion explanation (why an asset/relationship/exposure/risk exists) | PARTIALLY_DONE | The *data* fully supports this — every `Exposure` risk classification already carries a `reasons: tuple[str, ...]` (`core/risk_scoring.py::classify_exposure_risk`), exposed via `ExposureRiskResponse` (`api/schemas.py:400`) — but this is one assertion type (exposure risk), not the "one reusable shape any future client can render generically" the roadmap asks for. Relationships and asset-existence assertions don't yet have an equivalent exposed explanation shape. |
| Relationships endpoint | MISSING (explicitly deferred) | `relationships`/`relationship_evidence` tables and identity logic (`api/relationship_identity.py`) exist and are populated every scan; `docs/PAID_API_DESIGN.md`'s Fase 19 section explicitly lists Relationships endpoints as deferred — this is real, populated data with **no API surface at all** today |
| Raw-provenance endpoint for analysts | MISSING | Not found; not urgent unless a real analyst consumer exists yet |

### 4.4 Exposure operations (Roadmap Phase 04 territory)

| Capability | Status | Evidence |
|---|---|---|
| Exposure inventory/detail/history/filtering | ALREADY_DONE | `api/routers/exposures.py`, 7 endpoints under `/{organization_id}/exposures...`; `exposure_history` table backs lifecycle |
| Resolution / reopen | ALREADY_DONE (needs Phase 04's own deeper audit) | `exposure_history` event types include reopened/resolved per the schema; exact endpoint-level auditability of *why* a reopen happened wasn't independently re-verified here |
| Reports-to-exposures connection | ALREADY_DONE | `core/client_report/exposure_report.py` — confirmed, by the module's own docstring, to be the first and only such connection (verified no other reporting path silently queries `exposures`) |
| Remediation notes / ownership / assignee / bulk triage | MISSING | No evidence found of workflow fields beyond status/history; this is squarely Roadmap Phase 07's job, correctly sequenced after 04 |

### 4.5 Continuous monitoring & signal quality (Roadmap Phase 05 territory)

| Capability | Status | Evidence |
|---|---|---|
| Scheduled monitoring, two-speed (passive/active) | ALREADY_DONE | `api/monitoring_worker.py`, `monitored_domains` table; Speed 1 daily/free/no-quota-cost, Speed 2 weekly/Pro+/quota-consuming |
| New/removed asset + exposure/cert/tech/DNS change signals | ALREADY_DONE | `change_events`/`certificate_events`/`technology_events`/`exposures` tables, cited into notifications via `_easm_citations_for_run` |
| Noise control (no raw pixel/HTML-diff alerting) | ALREADY_DONE | Signals are deterministic state-transition events, not raw diffs; asset-count sanity ceiling (`HYDRA_API_MONITORING_ASSET_CEILING=5000`) flags `needs_review` rather than alerting blindly |
| Failed/partial provider visibility via API | UNVERIFIED | Not specifically checked this pass; provider execution outcomes are persisted (`provider_run_outcomes` table) but whether monitoring-triggered scans surface this distinctly to the client wasn't traced end-to-end |
| Delivery mechanism | ALREADY_DONE | Durable outbox (`monitoring_pending_notifications`) plus **two** real channels: email (Postmark/console) and signed outbound webhooks — both crash-safe by design |
| Preserve exactly-once/outbox semantics | ALREADY_DONE | Confirmed: notification loss on crash-between-write-and-send was a real bug found and fixed with the durable outbox table |

### 4.6 Risk & business context (Roadmap Phase 06 territory)

| Capability | Status | Evidence |
|---|---|---|
| Deterministic risk engine with explicit reasons | ALREADY_DONE | `core/risk_scoring.py::classify_exposure_risk` — pure function, "No ML, no black-box score" per its own docstring; every classification carries concrete reasons, never just a restated label |
| Factors already considered | PARTIALLY_DONE (real subset of Roadmap's fuller wishlist) | Currently: base severity, domain-verified vs. candidate scope, days-open escalation (30-day threshold), relationship-to-critical-asset. **Not yet factored**: exploitability/validation state, internet reachability as a distinct signal, environment (prod/staging/dev), business criticality/owner/BU, auth surface, identity/payment/data-infra proximity, exposure age beyond the single 30-day threshold, external threat intelligence, confidence quality as a risk input (vs. only a correlation input) |
| "Unknown signal represented as unknown, never invented" | ALREADY_DONE (for what exists) | The `reasons` tuple pattern means an unevaluated factor simply contributes no reason, rather than a fabricated one — this discipline is already in place and should be preserved when extending, not re-invented |
| Note: a second, older, informal risk system still exists | CONFLICTING | `core/assets.py`'s `RiskLevel` enum / `Host.risk_reasons`, and `core/intelligence/risk.py` — a legacy per-run heuristic system, architecturally separate from the Fase 21 deterministic `Exposure` classifier. Phase 06 work should extend `core/risk_scoring.py` only; the legacy system is part of the broader `core/intelligence/` deprecation debt below, not something to also extend |

### 4.7 Remediation workflow (Roadmap Phase 07 territory)

| Capability | Status | Evidence |
|---|---|---|
| Everything past "exposure has a status" | MISSING | Owner/assignee/due-date/comments/guidance/ticket-link/accepted-risk/suppression/SLA/status-history — none found. Correctly sequenced as its own phase; nothing here to reuse-vs-rebuild yet, this is genuinely new ground |

### 4.8 Integrations (Roadmap Phase 08 territory)

| Capability | Status | Evidence |
|---|---|---|
| Generic signed outbound webhooks | ALREADY_DONE | `api/routers/webhooks.py` / `api/webhooks.py` — HMAC-SHA256 signed, SSRF-hardened (reuses `core/collection/ssrf.py`, re-resolved per delivery attempt), retry/backoff (3 attempts), auto-disable after 5 consecutive failures, 10/account cap, 3 fixed event types (`monitoring.changed`, `monitoring.needs_review`, `finding.high_severity`) |
| Native Jira/Slack/Linear/Teams/ServiceNow apps | MISSING (explicit non-goal so far) | Only the generic webhook + a documented suggestion to bridge via Zapier/n8n |
| SIEM export, CSV/JSON bulk export | MISSING | Confirmed absent by grep; no partial implementation found |
| One canonical event/outbox model | PARTIALLY_DONE | The webhook delivery path and the monitoring-email path both use durable outbox tables, but they are **two separate outbox tables/mechanisms** (`monitoring_pending_notifications` for email, whatever backs webhook delivery — confirmed as "synchronous/background-task, not a persisted durable queue" per the research pass, i.e., **less durable than the email path**, an explicit asymmetry) — Roadmap Phase 08's "use one canonical event/outbox model" is not yet true; this is real, specific technical debt to address in that phase, not a from-scratch build |
| Documented REST API as the primary integration surface | PARTIALLY_DONE | The API is real and extensive; whether it has a generated/maintained OpenAPI spec as a first-class deliverable (Roadmap's explicit ask) was not confirmed — FastAPI provides one automatically via `/openapi.json`, but "automatically available" and "documented, versioned, and treated as a stability contract" are different bars |

### 4.9 Provider qualification & engine hardening (Roadmap Phase 09 territory)

| Capability | Status | Evidence |
|---|---|---|
| Provider *execution contract* (intensity, authorization requirement, confinement level) | ALREADY_DONE | `core/provider_contract.py` — `ProviderKind`, `ProviderIntensity`, `AuthorizationRequirement`, `ConfinementLevel`, `ProviderDescriptor`, `provider_inventory()`, `execution_status_for_result()` — live, called from `core/runner.py:1295` and `api/routers/easm.py:390` |
| Provider *version qualification* (installed-version compatibility, fixture-based contract tests that fail CI on a breaking provider upgrade) | MISSING | Confirmed by grep: the word "qualification" appears only once in the whole repo, in a docs file (`docs/easm/16_cloud_asset_identity.md:45`), as a stated problem, not an implementation. This is exactly the EASM final audit's own open risk #11 ("provider version updates could silently change semantics undetected... not fixed in this pass") — Roadmap Phase 09 exists specifically to close this, and nothing has been built toward it yet |
| `core/intelligence/` deprecation | CONFLICTING / not done | Marked deprecated in `core/registry.py`'s own docstring (dated 2026-09-28) but **still unconditionally called every scan** (`core/registry.py:29`, `core/normalizer.py:65`) — its output is silently discarded whenever the newer `core.intel.engine` also ran, and `core/store.py` still persists its output into `clusters`/`graph_nodes`/`graph_edges` tables every single run. This is real wasted compute and real dead-but-persisted data on every production scan today, not a documentation nit |
| `core/diff.py::ScanDiff` deprecation | CONFLICTING / not done | Still imported by `core/runner.py:24` and `core/intel/cli.py:132` (confirmed live). One doc claim — that `core/verification/grounding.py` also imports it — was checked directly and found **false**; `grounding.py` only uses stdlib `difflib`, an unrelated import. Noted as a doc inaccuracy to fix when Phase 09 touches this area, not a third live caller |
| Confidence aggregation split | CONFLICTING / partially wired | `core/confidence_composition.py` (correlated-source capping) exists as "a new, additive capability for future callers," but `core/confidence.py`'s own `max()`-based aggregation — the path every existing consumer actually uses — was never migrated to it. This is the EASM audit's own open item #10 |

### 4.10 Production platform & scale (Roadmap Phase 10 territory)

Not deeply investigated this pass (Roadmap explicitly says "measure
first" as that phase's own first task — premature to pre-empt it here).
One relevant fact surfaced incidentally: continuous monitoring has
already been scale-tested to 300k `monitored_domains` rows with keyset
pagination, which is a real, if narrow, existing data point for that
phase to build on rather than re-measure from zero.

### 4.11 Product security, reliability & operations (Roadmap Phase 11 territory)

| Capability | Status | Evidence |
|---|---|---|
| Backups (control.db + every account's recon.db), restore-tested | ALREADY_DONE | `api/backup_worker.py`, daily online SQLite backup, optional S3 upload, restore tool tested via real delete+restore+compare |
| Retention purge | ALREADY_DONE | `api/reconciliation_worker.py::run_retention_purge_job` — scoped to completed/failed scans only, never touches `recon.db`, dry-run mode available |
| Health/readiness | ALREADY_DONE | Real `GET /health` — checks `sqlite_master` (not a false-passing `SELECT 1`) plus per-worker-loop heartbeat liveness |
| Structured logs / Sentry | ALREADY_DONE (opt-in) | `HYDRA_API_LOG_FORMAT=json`; Sentry off by default, explicit PII scrubbing when enabled |
| Rate limiting | ALREADY_DONE | Per-key persistent token bucket (`api/rate_limit.py::PersistentTokenBucketLimiter`), cross-process safe, survives restart |
| Admin auth | **UNSAFE** | `GET/POST /admin/wompi/unmatched|reconcile` are gated only by a static bearer token read from an env var (`HYDRA_API_ADMIN_TOKEN`) — explicitly documented in the code itself as MVP-only, "no real admin auth." Fine for a single-operator MVP; a real gap the moment more than one person operates this, and a natural Phase 11 item |
| CI enforcement | **UNSAFE** (repo-configuration gap, not code) | `docs/EASM_RELEASE_AUDIT.md` states the branch-protection ruleset's `required_status_checks` is empty — "CI success is currently a review discipline, not an enforced merge gate." This is a GitHub repository setting, not something a code PR fixes; flagged here for the user to change directly (this session's `gh` CLI is broken, same as every prior engagement note in this repo — cannot be fixed from this session) |
| Per-account settings bug | **UNSAFE** (real, unfixed) | `api/tenancy.py::account_settings()` constructs `Settings(project_root=...)` directly, **never** `Settings.from_env()` — every paid, per-account scan pipeline has, since Round 1, silently ignored real `.env` configuration (tool enable/disable flags, rate limits, LLM provider keys) in favor of dataclass defaults. Found during the Wompi-integration research pass, explicitly **not fixed** at the time ("out of scope, risk of regression"). This is a real correctness gap worth prioritizing early in Phase 11 (or sooner, as an isolated P1 fix) since it means the API layer's scans may not actually be running with the operator's intended configuration today |
| SSRF/path-traversal/SQLi/BOLA/IDOR | ALREADY_DONE (recent) | Just closed via PR #92 (this session's own prior work — urllib3 floor, trixie base image, `confine_path`+`validate_run_id` on the scans router, SQLi false-positive proof tests, `.snyk` test-fixture exclusion). Also: the EASM main-state-review audit (2026-09-26) found and fixed 3 real cross-tenant IDOR footguns in `ControlDB` accessors missing `organization_id` scoping — already resolved, not open |

### 4.12 SaaS entitlements & commercial controls (Roadmap Phase 12 territory)

| Capability | Status | Evidence |
|---|---|---|
| Tier model (org/domain/asset/scan-cadence/retention/integration limits) | ALREADY_DONE | Free/Medium/Pro/Ultra, `api/tiers.py` — real numbers, not placeholders (see table in §5 below) |
| Billing != scope authorization | ALREADY_DONE (verified, not just claimed) | Confirmed structurally: tier gates return 404 (feature doesn't exist for this tier) rather than ever touching `CollectionScope`/authorization; domain verification and billing are two entirely separate systems that only compose through account_id, never through each other |
| Deterministic, tenant-scoped enforcement at the API layer | ALREADY_DONE | `api/subscriptions.py` — pure functions (`check_scan_quota`, `check_verified_domain_limit`, `check_llm_budget`, etc.), called from the same mandatory-`account_id` gate position as domain-verification checks |
| `priority_queue` entitlement | PARTIALLY_DONE (honestly stated) | Recorded per-tier but genuinely inert — scan execution is still plain FIFO. Already documented as a no-op in the code itself, not a hidden gap |

### 4.13 Private beta readiness (Roadmap Phase 13 territory)

Not investigated this pass — correctly sequenced last-but-one; revisit
once Phases 01–12 have moved.

---

## 5. Current tier table (for reference — `api/tiers.py`, verified against
current code, not the Round 3 design doc which predates later tweaks)

| Tier | Scans/mo | Verified domains | Reportability ($/mo) | Hypotheses ($/mo) | Formats | Languages | White-label | Retention | Monitoring Speed 2 |
|---|---|---|---|---|---|---|---|---|---|
| Free | 1 | 1 | — (404) | — (404) | markdown | es | no | 7d | no |
| Medium | 10 | 3 | $10, auto-degrades adversarial | — (404) | md, docx | es, en | no | 90d | no |
| Pro | 50 | 10 | $40, adversarial available | $25 | md, docx | es, en | no | 365d | yes |
| Ultra | 500 | unlimited | $100 | $60 | md, docx | es, en | yes | 730d default, per-account override | yes |

---

## 6. Product vocabulary already established

`core/capabilities.py`'s `Capability` enum (12 values: DOMAIN_DISCOVERY,
DNS, NETWORK_DISCOVERY, HTTP, TECHNOLOGY, VISUAL, TLS, CLOUD,
EXPOSURE_DETECTION, EXTERNAL_INTELLIGENCE, IMPORT, UNCATEGORIZED) is
already the product-facing language, exposed via
`GET /organizations/{id}/capabilities` — provider tool names (nuclei,
dnsx, httpx, etc.) stay internal to `core/provider_contract.py` and are
never the product's own vocabulary. This discipline is already correct
and should simply be preserved, not redesigned, in every phase that adds
a new endpoint.

---

## 7. Canonical API/resource information architecture (current state)

Twelve routers, all registered in `api/main.py::create_app()` (none
orphaned): `health`, `accounts`, `keys`, `domains`, `exposures`, `easm`,
`monitoring`, `scans`, `reportability`, `hypotheses`, `subscription`,
`webhooks`.

Resource nesting is **mostly** consistent (`/scans/{scan_id}/...` for
scan-scoped operations, `/{organization_id}/exposures/...` and the EASM
router's own organization-scoped resources for durable domain-model
reads, `/domains/{domain}/...` for verification and monitoring) but not
perfectly uniform — scans are addressed by `scan_id` while most EASM
reads are addressed by `organization_id`, and a client has to know which
identifier space a given concept lives in rather than there being one
consistent tenancy-scoping convention across the whole API. Not a defect
serious enough to block anything today; worth a conscious decision (keep
as-is and document why, or unify) as new endpoints are added in Phases
02–04, rather than letting the inconsistency grow by accretion.

No OpenAPI-spec-as-a-stability-contract was confirmed (FastAPI's
auto-generated `/openapi.json` exists implicitly but wasn't verified as
a maintained, versioned artifact) — flagged for Phase 13's own explicit
"documented REST API" requirement, not urgent now.

---

## 8. Demo/mock/hardcoded data audit

**Clean.** A full grep across `api/*.py` and `api/routers/*.py` for
demo/mock/fake/todo/fixme/hardcoded/stub/placeholder/sandbox found only
benign matches: dev-only override fields that require an explicit
environment variable and default to `None`/off (documented as
"never set in production"), and a few negated comments ("never a
hardcoded glob/path") confirming the *absence* of a footgun rather than
its presence. No code path was found that would silently serve
demo/fake data to a real client in production.

---

## 9. Duplicate/inconsistent authorization logic

None found at the API-router level — every tenant-scoped endpoint routes
through `require_api_key` plus the same mandatory-`account_id`-parameter
discipline `docs/PAID_API_DESIGN.md` Part F.1 originally specified, and
the EASM main-state-review audit already found and fixed the one
generation of real gaps here (3 `organization_id`-scoping footguns in
`ControlDB` accessors, 2026-09-26, already merged).

The one duplication that exists is **computational, not
authorization-related**: `core/intelligence/` and `core/intel/` both run
on every scan and both write correlation-shaped output, with
`core/intelligence/`'s output silently discarded when the newer engine
also produced results. This is the same item flagged in §4.9 — listed
again here because it is, structurally, exactly the kind of "duplicate
concept" Roadmap 01's Rule 3 asks to watch for, just discovered as
already-existing debt rather than something this phase risked
introducing.

---

## 10. Blockers

**None that block Phase 01.** No P0 security issue was found in this
reconnaissance pass (PR #92, merged just before this phase began, closed
out the open Snyk findings). The items in §4.9 and §4.11 marked
CONFLICTING/UNSAFE are real, but none of them prevents onboarding work
from proceeding safely — they should be sequenced into Phases 09 and 11
respectively, as the roadmap's own numbering already anticipates, rather
than pulled forward and used to block Phase 01.

---

## 11. Deferred risks (explicit, per Roadmap 01 Rule "name deferred risks explicitly")

1. `core/intelligence/` and `core/diff.py::ScanDiff` remain live,
   unconsolidated technical debt (Phase 09's job).
2. Provider version-upgrade semantics remain unqualified/unguarded
   (Phase 09's job; this is the EASM audit's own open risk #11).
3. `core/confidence.py`'s `max()`-based aggregation was never migrated to
   the newer capped `core/confidence_composition.py` path (Phase 09-
   adjacent; small, but real).
4. `api/tenancy.py::account_settings()` never applies real `.env`
   overrides per account — a live correctness gap, not merely
   theoretical (flagged §4.11; recommend an isolated fix before or early
   in Phase 11, not bundled into Phase 01's onboarding work).
5. Admin endpoints (`/admin/wompi/...`) rely on a single static bearer
   token — explicitly MVP-only (Phase 11's job).
6. Branch protection's `required_status_checks` is empty — a repository
   setting, not a code fix; cannot be changed from this session (`gh` is
   broken here); flagged for the user to change directly on GitHub.
7. Outbound webhook delivery is less durable than the monitoring-email
   path (background-task delivery, not a persisted queue) — a real
   asymmetry Phase 08 should resolve when it revisits "one canonical
   event/outbox model."
8. Several sub-areas were explicitly **not** re-verified in this pass to
   avoid duplicating a future phase's own reconnaissance: asset
   inventory filter/sort/pagination completeness (Phase 02's job),
   exposure reopen/resolution endpoint-level audit trail depth (Phase
   04's job), and monitoring's failed/partial-provider visibility to the
   client (Phase 05's job). These are called out as open questions for
   those phases, not silently assumed complete.

---

## 12. Proposed Phase 01 scope (Onboarding & Organization Setup)

Given how much of "Roadmap Phase 01" already exists, the real remaining
work is narrower than the roadmap's generic phase description implies:

1. **`POST /organizations`** (or equivalent explicit creation step) — an
   organization is currently created only as an implicit side effect of
   the first scan's EASM backfill, not as its own onboarding action a
   client can call before scanning anything. Decide whether this
   implicit-creation model is actually fine (an account effectively gets
   one default organization automatically) or whether real multi-org
   support needs an explicit endpoint — this decision should come from
   this phase's own reconnaissance into how `account_organization_roles`
   is actually used today, not be assumed here.
2. **Collection profile/intensity/capability selection on `POST
   /scans`** — currently every scan runs Hydra's fixed default plugin
   set; expose at least a coarse choice (e.g., passive-only vs. full)
   using the capability taxonomy that already exists, rather than
   inventing a new one.
3. **Confirm/document the Known/Candidate/Authorized-scope/Observed/
   Excluded distinction is visible in every relevant onboarding-path API
   response**, not just present in storage — audit each response shape
   the roadmap's own customer journey touches before the first scan
   completes.
4. Everything else the roadmap's Phase 01 description asks for —
   account/org/member-roles, program/scope setup, root-domain/seed
   management, verification, exclusions, first-scan trigger,
   progress/status, failure/retry — is **already built and should be
   audited, not rebuilt**: write the acceptance test ("a new user can
   configure an organization and initiate an authorized first scan using
   only documented API calls") against what exists today, and treat any
   failure of that test as the actual Phase 01 backlog rather than
   re-implementing already-working endpoints.

This phase's own reconnaissance should start by writing that acceptance
test first — it will very quickly separate "genuinely missing" from
"exists, just needs a documentation pass," which this Phase 00 pass
could not fully resolve without executing real HTTP calls against a
running instance.

---

## 13. What this phase explicitly did not do

Per Roadmap 01: no broad feature changes were made (no P0 blocker was
found that required one). `hydra-frontend` and `hydra-styling` were not
opened, cloned, or referenced. No external/live scan was run. No new
persistent concept was proposed — every gap identified above maps onto
an existing table or an existing, not-yet-exposed piece of data, matching
Rule 3's "reuse before inventing" requirement.
