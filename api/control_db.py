"""The control-plane database — accounts, API keys, and the central
`scans` registry (docs/PAID_API_DESIGN.md Part F.3). This is deliberately
a SEPARATE, small SQLite database from any account's own `recon.db`
(`core.store.AssetStore`'s schema is the recon/findings domain; this is
the account/auth/scan-registry domain — mixing them would blur exactly
the boundary Part F exists to keep sharp). Reuses
`core.store.connect_sqlite`/`configure_sqlite` for the same WAL +
foreign-keys-on connection setup the rest of the project already uses,
rather than re-deriving those PRAGMAs here.

Every function that reads or writes account-scoped data (`api_keys`,
`scans`) takes `account_id` as a mandatory, explicit, non-optional
parameter — never inferred, never defaulted (Part F.1) — and the two
`scans` lookups used by the API layer (`get_scan`, `require_owned_scan`)
only ever return a row when `account_id` matches, never "found, wrong
owner" (that distinction is not the caller's to make; a mismatch reads
identically to "not found").
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from api.asset_identity import ExistingAsset, ReconciliationDecision
from api.candidate_assets import CandidateAssetDraft
from api.exposure_identity import ExposureDraft
from api.observation_identity import EvidenceContent
from core.store import connect_sqlite

_SCHEMA = """
-- `email`/`email_verified_at`/`email_verification_token`/
-- `email_verification_token_expires_at` are Hallazgo 1's account-abuse
-- fix (docs/PAID_API_DESIGN.md's own section on it): an account is
-- created immediately (so the client gets a usable api_key right away)
-- but starts unverified — POST /scans refuses to run anything for it
-- until `email_verified_at` is set. A fresh DB gets these columns
-- directly from this CREATE TABLE; an EXISTING control.db from an
-- earlier round gets them via `_migrate_table_columns` below (SQLite's
-- `CREATE TABLE IF NOT EXISTS` never adds columns to an already-existing
-- table on disk).
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    email TEXT,
    email_verified_at TEXT,
    email_verification_token TEXT,
    email_verification_token_expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)
    WHERE email IS NOT NULL;

-- Fase 02 (EASM roadmap — docs/easm/00_consolidation_plan.md's glossary:
-- "Organization... coexists with `accounts`; phase 02 extends") — the
-- TARGET organization being monitored, deliberately separate from
-- `accounts` (billing/login identity: Wompi, API keys, tier all stay on
-- `accounts` unchanged; see this table's own module docstring at the top
-- of this file for why that boundary matters). One `account` can hold a
-- role on one or more `organizations` (a security consultant managing
-- several clients under one billing account is the real case this
-- separation is for) — access is entirely mediated through
-- `account_organization_roles` below, never a direct FK from
-- `organizations` back to a single owning account.
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- One row per (account, organization) the account has a role on.
-- 'owner' can modify the organization's scope and manage its membership;
-- 'viewer' is read-only on both — checked via `role_can_modify_scope`/
-- `role_can_manage_members` below, never re-derived ad hoc at a call
-- site. No granular per-resource permission system yet (not needed by
-- this phase), but the (account_id, organization_id) composite primary
-- key plus a free-text `role` column is extensible without a schema
-- change if a third role is added later.
CREATE TABLE IF NOT EXISTS account_organization_roles (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (account_id, organization_id)
);
CREATE INDEX IF NOT EXISTS idx_account_org_roles_org
    ON account_organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_account_org_roles_account
    ON account_organization_roles(account_id);

-- Fase 03 (EASM roadmap, docs/easm/00_consolidation_plan.md) — the
-- cross-run Asset the consolidation plan's own glossary calls for:
-- "absorbs core/intel/model.py's IntelEntity identity scheme; new
-- cross-run table needed." Scoped to `organization_id`, NEVER `run_id`
-- — this is precisely the thing every run_id-scoped table in
-- `core/store.py` (hosts, ports, dns_records, urls, ...) cannot
-- express: "is this the same real-world asset as one observed in an
-- earlier run." `core/assets.py`'s `Host` and its sub-entities are
-- UNCHANGED and remain the per-run collection result (Fase 01's own
-- "coexist, Host reconciles INTO this, never the other way around"
-- decision) — nothing here replaces or migrates any run_id-scoped
-- table. `identity_key` is built by `api/asset_identity.py`'s pure,
-- DB-free functions (reused, not reinvented, from
-- `core.intel.model.entity_id()`'s own `"type:key"` format for the
-- `domain`/`url` asset types; `port`/`dns_record` are this module's own
-- additive extension — see its docstring). The
-- `(organization_id, asset_type, identity_key)` UNIQUE constraint IS the
-- entire reconciliation rule: an exact match on this triple is always
-- "the same asset, seen again," by construction — never a fuzzy/
-- heuristic merge (see `api/asset_identity.py`'s module docstring for
-- why this is also what makes the cross-organization-shared-IP
-- adversarial case structurally safe: a shared IP is recorded as an
-- `asset_identifiers` row on whichever asset actually observed it,
-- never used as a lookup key here).
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    asset_type TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_seen_run_id TEXT,
    UNIQUE (organization_id, asset_type, identity_key)
);
CREATE INDEX IF NOT EXISTS idx_assets_organization ON assets(organization_id);

-- One asset can carry more than one identifier over its lifetime (a
-- host resolving to a different IP on a later run does not make it a
-- new asset) — `identifier_value` is deliberately UNIQUE per
-- (organization, identifier_type), NOT per asset: this is what makes
-- "which asset (if any) already claims this identifier" an unambiguous
-- lookup, and is a plain data table, never itself a reconciliation
-- input (see `assets`' own comment above and
-- `api/asset_identity.py`'s module docstring for why identifiers are
-- observational metadata, not a merge key).
CREATE TABLE IF NOT EXISTS asset_identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE (organization_id, identifier_type, identifier_value)
);
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_asset ON asset_identifiers(asset_id);

-- Fase 04 (EASM roadmap): the deduplicated raw evidence backing an
-- observation. Content comes directly from the exact `core/assets.py`
-- sub-entity an observation is about (`Port.source`/`.confidence_score`,
-- `DnsRecord.source`/`.confidence_score`, `URL.source`/
-- `.confidence_score`, `TechnologyFinding.source`/`.confidence`,
-- `HttpService.source`/`.confidence_score` for a header) — never a fuzzy
-- match against the separate, free-text-keyed `Host.provenance` list
-- (checked against real `core/parsers/registry.py` call sites before
-- deciding this — see `api/observation_identity.py`'s own docstring for
-- why that match would have been unreliable). Deduplicated by CONTENT
-- scoped to one asset: the SAME (source, detail, confidence_score)
-- observed again on a later run reuses this same row (`last_seen_at`/
-- `last_seen_run_id` advance) rather than creating a new one — this is
-- what makes the phase's own "5 runs, no wasted duplicate evidence"
-- requirement real, not just a check on top of "insert everything."
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    source TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    confidence_score INTEGER,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_seen_run_id TEXT,
    UNIQUE (organization_id, asset_id, source, detail, confidence_score)
);
CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id);

-- Fase 04: the normalized "what this run observed about this asset"
-- projection the Fase 01 consolidation plan's glossary calls
-- "Observation" — one row per (asset, run, evidence), deliberately never
-- a copy of any run_id-scoped raw table in `core/store.py` (those stay
-- exactly as they are — see this table's own backfill in
-- `api/asset_backfill.py` for the one place that reads them). A neutral
-- fact only ("we saw X") — NEVER a risk judgment; Fase 08's Exposure
-- model is what turns a pattern of observations into a risk finding,
-- and is intentionally a separate, later concern (see this phase's own
-- "no mezclar observación con exposure" instruction).
-- `UNIQUE(asset_id, run_id, evidence_id)` is what makes replaying the
-- same run through the backfill twice (Fase 03's own idempotency
-- precedent) never create a duplicate observation row.
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    run_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    observation_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, run_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_observations_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);

-- Fase 05 (EASM roadmap): one row per ACTUAL state transition an asset
-- went through (`api/change_detection.py::compute_asset_state_transitions`
-- is the sole, pure, deterministic decision-maker — never an LLM, never
-- a fuzzy heuristic, per the phase's own explicit requirement). Never
-- one row per run — a run that leaves an asset's state unchanged
-- produces no row here at all, so this table is exactly the change
-- history, not a heartbeat log. `UNIQUE(asset_id, run_id)` makes
-- replaying the change-detection backfill idempotent, matching Fase
-- 03/04's own precedent; at most one transition can be attributed to
-- any single run for a given asset (a run either observed it or didn't,
-- and NEW/UNCHANGED/CHANGED/DISAPPEARED/REAPPEARED are mutually
-- exclusive outcomes for that one run).
CREATE TABLE IF NOT EXISTS change_events (
    change_event_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    run_id TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    previous_digest TEXT,
    new_digest TEXT,
    detected_at TEXT NOT NULL,
    UNIQUE (asset_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_change_events_asset ON change_events(asset_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_change_events_run ON change_events(run_id);

-- Fase 08 (EASM roadmap): durable external exposures. A raw Finding remains
-- a run-scoped detector result in the per-account AssetStore; this table is
-- the cross-run EASM identity of a security-relevant condition on one durable
-- Asset. Identity is exact and deterministic: organization + asset + source +
-- template + normalized location. No fuzzy deduplication, AI classification,
-- or ownership/scope inference occurs here.
CREATE TABLE IF NOT EXISTS exposures (
    exposure_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    source TEXT NOT NULL,
    template_id TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    confidence_score INTEGER,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    first_seen_run_id TEXT NOT NULL,
    last_seen_run_id TEXT NOT NULL,
    resolved_at TEXT,
    resolved_run_id TEXT,
    resolution_reason TEXT,
    UNIQUE (organization_id, asset_id, source, template_id, location)
);
CREATE INDEX IF NOT EXISTS idx_exposures_organization
    ON exposures(organization_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_exposures_asset
    ON exposures(asset_id, status, last_seen_at);

-- Immutable per-run support for an Exposure. The source finding remains in
-- its original AssetStore; this row records which account/run/finding id
-- supported the durable exposure so an analyst can trace it back precisely.
CREATE TABLE IF NOT EXISTS exposure_evidence (
    exposure_evidence_id TEXT PRIMARY KEY,
    exposure_id TEXT NOT NULL REFERENCES exposures(exposure_id),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    account_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    finding_id INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (exposure_id, run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_exposure_evidence_exposure
    ON exposure_evidence(exposure_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_exposure_evidence_run
    ON exposure_evidence(organization_id, run_id);

-- Fase 06 (EASM roadmap): organization-scoped Candidate Assets. The
-- run-scoped `core.store.intel_indicators` rows remain the source event;
-- this table answers "have we discovered this candidate before?" across
-- scans. A row is intelligence, not ownership and not authorization.
-- OUT_OF_SCOPE/UNKNOWN/NOT_ALLOWED candidates are intentionally retained
-- here so attribution/history is not destroyed, but nothing in this table
-- is an input to CollectionScope or authorize_active_indicator.
--
-- `lineage_reference` is intentionally NOT a foreign key. The legacy
-- intel_indicators.evidence_id field is documented as overloaded: some
-- producers store an intel_evidence id, others an observation id. Fase 06
-- preserves that reference verbatim rather than pretending its type is
-- stronger than the source can prove.
CREATE TABLE IF NOT EXISTS candidate_assets (
    candidate_asset_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    candidate_type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    first_seen_run_id TEXT NOT NULL,
    last_seen_run_id TEXT NOT NULL,
    scope_status TEXT NOT NULL,
    collection_status TEXT NOT NULL,
    authorization_status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    depth INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    collector TEXT NOT NULL DEFAULT '',
    source_entity_id TEXT NOT NULL DEFAULT '',
    parent_indicator_id TEXT,
    lineage_reference TEXT NOT NULL DEFAULT '',
    UNIQUE (organization_id, candidate_type, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_candidate_assets_organization
    ON candidate_assets(organization_id, first_seen_at);
CREATE INDEX IF NOT EXISTS idx_candidate_assets_value
    ON candidate_assets(organization_id, candidate_type, normalized_value);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    lookup_hash TEXT NOT NULL UNIQUE,
    verify_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    expires_at TEXT,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_lookup_hash ON api_keys(lookup_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_account_id ON api_keys(account_id);

-- `retry_count`/`worker_id`/`heartbeat_at` are the durable-queue fix
-- (docs/PAID_API_DESIGN.md's "Durable, multi-worker-safe scan
-- execution" section): `worker_id` + `heartbeat_at` let any worker
-- process (this one or another) tell a genuinely-still-running scan
-- apart from one whose worker died without updating it — a bare
-- `status='running'` alone can't make that distinction once more than
-- one worker process can exist. `retry_count` bounds how many times a
-- scan gets automatically requeued after an apparent interruption
-- before it's given up on as `failed` instead — see
-- `api/scan_worker.py`'s own module docstring for the exact numbers
-- and reasoning. A fresh DB gets these columns directly from this
-- CREATE TABLE; an existing `control.db` from an earlier round gets
-- them via `_migrate_table_columns` below.
-- `trigger_source` (continuous-monitoring task): 'manual' (a real
-- `POST /scans` call — the default, and the only value that ever existed
-- before this column) vs 'scheduled_passive'/'scheduled_active' (the
-- monitoring loop auto-queued this one). Every scan goes through this
-- SAME table/queue/worker regardless of trigger — monitoring invents no
-- second execution path — this column only records WHY a row exists, so
-- `api/scan_orchestrator.py::execute_scan` knows whether to run the full
-- pipeline or the passive-only plugin subset, and so a client listing its
-- own scan history can tell which ones it asked for.
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    db_path TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    worker_id TEXT,
    heartbeat_at TEXT,
    trigger_source TEXT NOT NULL DEFAULT 'manual',
    -- Fase 02: nullable at the schema level only because SQLite cannot
    -- ALTER TABLE ADD a NOT NULL column with a per-row (not fixed)
    -- default onto a table that already has rows — every code path that
    -- writes a scan (`create_scan`) always resolves and stores a real
    -- organization_id, so in practice this is never actually null for a
    -- row created after Fase 02 shipped; see `default_organization_id_for_account`.
    organization_id TEXT REFERENCES organizations(organization_id)
);
CREATE INDEX IF NOT EXISTS idx_scans_account_id ON scans(account_id);
CREATE INDEX IF NOT EXISTS idx_scans_organization_id ON scans(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Durable-queue fix, continued: a persisted replacement for
-- `api/rate_limit.py`'s old in-memory `TokenBucketLimiter` — one row
-- per API key, holding the bucket's current token count and when it
-- was last refilled, so the SAME limit is enforced correctly whether
-- one worker process serves the request or ten do, and survives a
-- restart instead of silently resetting everyone's bucket to full.
-- `last_refill_at` is wall-clock (ISO 8601), never `time.monotonic()`
-- (Round 1's in-memory version used monotonic time freely — safe only
-- because it never needed to be compared across processes/restarts,
-- which have independent monotonic-clock epochs; wall-clock is the
-- only meaningful choice once this state is shared).
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    key_id TEXT PRIMARY KEY,
    tokens REAL NOT NULL,
    last_refill_at TEXT NOT NULL
);

-- Hallazgo 1's IP-based rate limit on POST /accounts (the frontend-team
-- finding this fix closes) — one row per account-creation ATTEMPT,
-- keyed by source IP, so "how many accounts has this IP created
-- recently" is a real, persisted count that survives a process restart
-- (unlike Round 1's in-memory per-key `TokenBucketLimiter`, which is
-- the wrong tool here: that limiter only runs AFTER authentication,
-- and this endpoint is deliberately unauthenticated — see
-- api/routers/accounts.py's own docstring). Never pruned automatically;
-- rows older than the rate-limit window are simply never counted again
-- (a genuinely low-volume table — a few rows per IP per day at most).
CREATE TABLE IF NOT EXISTS account_creation_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_creation_attempts_ip
    ON account_creation_attempts(ip_address, created_at);

-- Part A (docs/PAID_API_DESIGN.md) domain-ownership verification. One row
-- per verification ATTEMPT, not per (account, domain) — a new attempt
-- (re-verify, retry after a failed check, renewal after expiry) is a new
-- row, never an in-place mutation of history. `status` is one of
-- 'pending' (token issued, no successful check yet), 'verified' (a real
-- DNS/HTTP check succeeded), 'failed' (a real check was attempted and did
-- not confirm the token), 'superseded' (this account's own older
-- verified/pending row for the same domain, replaced by a newer one).
CREATE TABLE IF NOT EXISTS domain_verifications (
    verification_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    method TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    expires_at TEXT,
    last_checked_at TEXT,
    last_check_error TEXT,
    -- Fase 02: see the identical comment on `scans.organization_id` for
    -- why this is schema-nullable but application-guaranteed non-null.
    organization_id TEXT REFERENCES organizations(organization_id)
);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_domain ON domain_verifications(domain);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_organization
    ON domain_verifications(organization_id);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_account
    ON domain_verifications(account_id, domain);

-- Continuous monitoring ("Hydra API — Continuous Monitoring for Verified
-- Domains" task). One row per (account, domain) the account has opted
-- into monitoring for — never created implicitly by verifying a domain,
-- always an explicit `POST /domains/{domain}/monitoring`. `speed2_enabled`
-- is the separate, tier-gated opt-in for the weekly ACTIVE deep-scan;
-- Speed 1 (daily passive re-scan) is implied by the row's mere existence
-- and is never tier-gated (see docs/PAID_API_DESIGN.md's dated monitoring
-- section for why: it reuses only genuinely-passive-source plugins, so
-- its marginal cost/risk per account is small enough not to need a
-- ceiling of its own beyond the account's overall scan quota, which
-- Speed 2 scans DO consume).
--
-- `next_passive_due_at`/`next_active_due_at` are this table's own
-- checkpoint: the monitoring loop only ever selects rows whose due
-- timestamp has passed, and advances it (to "now + cadence") as the
-- LAST step of successfully processing that row — so a cycle interrupted
-- partway through (crash, restart, time-budget exhausted) simply leaves
-- not-yet-processed rows' due timestamps unchanged, and the same or next
-- cycle picks them up again, identically to a domain that was never
-- attempted this cycle at all. No separate checkpoint/offset table is
-- needed for this idempotency.
--
-- `last_asset_digest`/`last_asset_count` are the lightweight diff key
-- (a hash of the sorted hostname set from the domain's last scan, not
-- the full Host/Finding rows) — cheap enough to hold for every monitored
-- domain even at real scale, so "did anything change" never requires
-- re-reading a large account's entire recon.db on every cycle.
-- `needs_review` is Part B's asset-count sanity ceiling
-- (HYDRA_API_MONITORING_ASSET_CEILING): set when a scan's host count
-- jumps past the ceiling without wildcard DNS explaining it — skips
-- auto-diff/notify for that domain until an operator/account clears it,
-- rather than either silently notifying on (likely-garbage) wildcard
-- noise or silently dropping the domain from monitoring altogether.
-- `status` is one of 'active' (normal), 'paused_verification_lapsed'
-- (Part A verification expired — monitoring pauses, not deletes, and
-- resumes automatically once re-verified), 'needs_review' (asset-count
-- ceiling tripped).
-- `pending_passive_scan_id`/`pending_active_scan_id`: set the moment the
-- monitoring loop enqueues a scheduled scan for this domain (Phase 1,
-- "enqueue"), cleared the moment that scan's result is harvested back
-- into this row (Phase 2, "harvest" — `next_*_due_at` only advances at
-- harvest time, never at enqueue time). This two-phase split, and the
-- pending marker that makes it possible, is what keeps a domain whose
-- scan takes hours from being re-enqueued every single poll cycle while
-- it's still in flight: `list_due_*_monitoring_page` only ever selects
-- rows where the relevant pending column is NULL.
CREATE TABLE IF NOT EXISTS monitored_domains (
    monitoring_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    speed2_enabled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    last_passive_scan_id TEXT,
    last_active_scan_id TEXT,
    last_passive_run_at TEXT,
    last_active_run_at TEXT,
    next_passive_due_at TEXT NOT NULL,
    next_active_due_at TEXT,
    pending_passive_scan_id TEXT,
    pending_active_scan_id TEXT,
    last_asset_digest TEXT,
    last_asset_count INTEGER,
    needs_review INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Fase 02: see the identical comment on `scans.organization_id` for
    -- why this is schema-nullable but application-guaranteed non-null.
    organization_id TEXT REFERENCES organizations(organization_id),
    UNIQUE (account_id, domain)
);
-- The monitoring loop's own read pattern is always "rows due now,
-- oldest-due first" — this composite index (due timestamp leading) is
-- what keeps `list_due_passive_monitoring_page`/
-- `list_due_active_monitoring_page`'s keyset pagination a real index
-- range scan at 300k+ rows, never a full-table scan with a sort step.
CREATE INDEX IF NOT EXISTS idx_monitored_domains_passive_due
    ON monitored_domains(next_passive_due_at, monitoring_id);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_active_due
    ON monitored_domains(next_active_due_at, monitoring_id);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_account ON monitored_domains(account_id);
CREATE INDEX IF NOT EXISTS idx_monitored_domains_organization
    ON monitored_domains(organization_id);

-- A durable outbox for continuous-monitoring notifications — closes a
-- real gap found while proving `run_monitoring_cycle`'s own "safe to
-- interrupt at any point" claim with an actual test: before this table
-- existed, a harvested outcome worth emailing lived ONLY in an
-- in-memory dict for the rest of that one `run_monitoring_cycle` call,
-- sent (if at all) as that function's very last step. A crash between
-- `batch_record_monitoring_progress`'s row update (which already
-- advances `next_*_due_at` and overwrites `last_asset_digest` — the
-- only place the PREVIOUS baseline needed to reconstruct the diff was
-- available) and that final send permanently lost the notification:
-- the next cycle's own digest comparison would see no change at all,
-- because the row already reflected the new state. Writing the
-- notification's full content into this table in the EXACT SAME
-- transaction as the row update (`batch_record_monitoring_progress`)
-- makes the two changes atomic — a crash can no longer separate "this
-- domain's progress was recorded" from "there is something to tell the
-- account about it." `sent_at IS NULL` is what makes a row due for
-- delivery; `run_monitoring_cycle` flushes every unsent row (from ANY
-- past cycle, not just its own) at the end of each cycle, so a
-- notification stranded by an interrupted earlier cycle is picked up
-- and delivered by the very next one — at-least-once, never
-- lost. (The narrow remaining window — a crash between the email
-- actually sending and `mark_notifications_sent` committing — can
-- produce at most one duplicate email; accepted as the safe direction
-- to err in for a security-relevant change notification, unlike silent
-- loss.)
CREATE TABLE IF NOT EXISTS monitoring_pending_notifications (
    notification_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    domain TEXT NOT NULL,
    speed TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    hosts_added_json TEXT NOT NULL,
    hosts_removed_json TEXT NOT NULL,
    asset_count INTEGER NOT NULL,
    asset_digest TEXT NOT NULL,
    needs_review INTEGER NOT NULL,
    review_reason TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_monitoring_pending_notifications_unsent
    ON monitoring_pending_notifications(sent_at);
-- Outbound webhooks ("Hydra API — outbound webhooks" task). One row per
-- registered delivery target — a customer's own Slack/Teams incoming-
-- webhook URL, or any HTTPS endpoint they control. `secret` is generated
-- by Hydra at creation time and shown to the client exactly once (the
-- same "only a value the client already has, never re-displayed" shape
-- api_keys already uses for its own raw key) — it is never re-derivable
-- from `secret` alone being lost; a client who loses it re-registers.
-- `event_types_json` is a JSON array of the small, fixed event-type set
-- (api/webhooks.py::EVENT_TYPES) this webhook wants delivered — never an
-- open string, so a typo can't silently create a permanently-unmatched
-- subscription.
-- `status` is 'active' or 'disabled' — flips to 'disabled' automatically
-- once `consecutive_failures` reaches api/webhooks.py's own threshold
-- (a dead endpoint stops being retried forever, per the task's own
-- "dead-letter/disable-after-N-failures" requirement); re-enabling
-- requires deleting and re-registering (simplest correct behavior for
-- this pass — see docs/PAID_API_DESIGN.md's non-goals for this task).
CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    event_types_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_delivery_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Fase 02: see the identical comment on `scans.organization_id` for
    -- why this is schema-nullable but application-guaranteed non-null.
    organization_id TEXT REFERENCES organizations(organization_id)
);
CREATE INDEX IF NOT EXISTS idx_webhooks_account ON webhooks(account_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_organization ON webhooks(organization_id);

-- Part B (docs/PAID_API_DESIGN.md, Round 3) tier/subscription state. One
-- row per account, created at account-creation time defaulting to
-- 'free' (api/routers/accounts.py) — every account has exactly one
-- current tier, never zero, never ambiguous between two rows.
-- `retention_days_override` is only ever meaningful for an Ultra account
-- ("configurable por cuenta" — api/tiers.py::retention_days_for); NULL
-- for every other tier.
-- `billing_email` is set once a paid enrollment activates
-- (api/routers/subscription.py's webhook handler) — it is what lets a
-- LATER webhook (a recurring monthly charge, success or failure) be
-- correlated back to this account even after the original
-- `wompi_pending_enrollments` row has done its one job and been marked
-- 'matched'. NULL for an account that has never had a paid tier.
-- `white_label_company_name`: the "Build the white-label client report
-- rendering" task — an Ultra account's own consultancy name, shown on
-- the client-report cover/title in place of no branding at all when
-- `white_label=true` is requested (api/routers/subscription.py's
-- `PUT /account/branding`). NULL means "never configured" — checked
-- explicitly by the client-report route before honoring
-- `white_label=true`, never silently falling back to an unbranded
-- report a paying reseller didn't ask for.
CREATE TABLE IF NOT EXISTS subscriptions (
    account_id TEXT PRIMARY KEY REFERENCES accounts(account_id),
    tier TEXT NOT NULL,
    status TEXT NOT NULL,
    billing_email TEXT,
    grace_period_started_at TEXT,
    retention_days_override INTEGER,
    white_label_company_name TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_billing_email ON subscriptions(billing_email);

-- Monthly usage counters, one row per (account, calendar month, UTC).
-- "Monthly" = calendar month, not a rolling 30-day or per-account
-- billing-anniversary window — simpler, and matches how the tier table
-- itself talks about limits ("Scans/mes"), not "scans per rolling 30
-- days." `period_key` is 'YYYY-MM'.
CREATE TABLE IF NOT EXISTS monthly_usage (
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    period_key TEXT NOT NULL,
    scans_used INTEGER NOT NULL DEFAULT 0,
    reportability_spend_usd REAL NOT NULL DEFAULT 0.0,
    hypotheses_spend_usd REAL NOT NULL DEFAULT 0.0,
    PRIMARY KEY (account_id, period_key)
);

-- Part E.1's estimate-then-confirm pattern, extended to reportability/
-- hypotheses (Round 3). One row per `GET .../estimate` call; `POST
-- .../assessment` (or hypotheses' equivalent) must reference a row here
-- that is unexpired AND not yet consumed — never trusts a cost figure
-- the client merely claims it saw.
CREATE TABLE IF NOT EXISTS cost_estimates (
    estimate_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    scan_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    provider TEXT NOT NULL,
    adversarial_provider TEXT,
    degraded_from_adversarial INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd REAL NOT NULL,
    params_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cost_estimates_account ON cost_estimates(account_id);

-- Wompi billing (Part D, Round 3). `wompi_pending_enrollments`: created
-- at `POST /account/subscription {"tier": ...}` time, one row per
-- upgrade *attempt* — the best-effort subscriber-identification
-- mechanism (docs/PAID_API_DESIGN.md's "Round 3 implemented" section
-- documents this honestly as unconfirmed against a real Wompi sandbox):
-- match an incoming webhook's `cliente.Email` against a still-'pending'
-- row's `billing_email` for the same tier/product. `status` is one of
-- 'pending' (no matching webhook yet), 'matched' (activated a real
-- account), or 'superseded' (this account requested another upgrade
-- before this one was ever matched — `create_pending_enrollment`
-- superseded it so at most one 'pending' row per account ever exists,
-- closing a real ambiguity a live sandbox attempt surfaced: more than
-- one 'pending' row for the same email/tier makes
-- `find_pending_enrollment_by_email` correctly refuse to guess,
-- silently sending a later genuinely-successful webhook to
-- `wompi_unmatched_payments` instead of activating anything).
CREATE TABLE IF NOT EXISTS wompi_pending_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    tier TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    matched_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_wompi_pending_email ON wompi_pending_enrollments(billing_email);

-- Idempotency + audit log for every webhook Wompi (or anyone claiming to
-- be Wompi) ever POSTs to this service — `transaction_id` is Wompi's own
-- `IdTransaccion`, unique, so a redelivered webhook (Wompi's own retry
-- behavior, or a replay attempt) is never double-processed.
CREATE TABLE IF NOT EXISTS wompi_webhook_events (
    transaction_id TEXT PRIMARY KEY,
    outcome TEXT NOT NULL,
    matched_account_id TEXT,
    raw_body TEXT NOT NULL,
    received_at TEXT NOT NULL
);

-- The manual-reconciliation backstop (Task's own explicit requirement):
-- any webhook that passed signature verification (so it IS genuinely
-- from Wompi) but could not be matched to a pending enrollment lands
-- here instead of being discarded or guessed — an operator resolves it
-- via `POST /admin/wompi/reconcile`, never automatically.
CREATE TABLE IF NOT EXISTS wompi_unmatched_payments (
    unmatched_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    payer_email TEXT,
    product_name TEXT,
    amount REAL,
    raw_body TEXT NOT NULL,
    received_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_account_id TEXT
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DuplicateEmailError(Exception):
    """Raised by `ControlDB.create_account` when `email` is already
    registered to a different account (Hallazgo 1's "distinct email per
    account" requirement) — the router turns this into a 409."""


def role_can_modify_scope(role: str | None) -> bool:
    """Fase 02: whether `role` (as returned by
    `ControlDB.get_role_for_account_organization`) may change an
    organization's authorized scope (register/verify a new domain,
    change monitoring settings for one). Only `'owner'` can — `'viewer'`
    and `None` (no role at all) cannot. A pure function, not a method,
    so callers never have to construct a `ControlDB` just to ask "is this
    role allowed to do X" — the same shape `api/subscriptions.py`'s own
    tier-limit checks already use for the identical reason."""
    return role == "owner"


def role_can_manage_members(role: str | None) -> bool:
    """Fase 02: whether `role` may add/change another account's role on
    this organization (invite a member, promote/demote them). Only
    `'owner'` can, for the same reason `role_can_modify_scope` is
    owner-only — a read-only member must never be able to grant itself
    or anyone else more access than it was given."""
    return role == "owner"


@dataclass(frozen=True)
class AccountRecord:
    account_id: str
    created_at: str
    email: str | None
    email_verified_at: str | None
    email_verification_token: str | None
    email_verification_token_expires_at: str | None

    @property
    def is_email_verified(self) -> bool:
        return self.email_verified_at is not None


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str
    account_id: str
    prefix: str
    created_at: str
    revoked_at: str | None
    expires_at: str | None
    last_used_at: str | None


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    account_id: str
    domain: str
    db_path: str
    status: str
    error_message: str | None
    created_at: str
    updated_at: str
    retry_count: int
    worker_id: str | None
    heartbeat_at: str | None
    trigger_source: str
    organization_id: str | None = None


@dataclass(frozen=True)
class SubscriptionRecord:
    account_id: str
    tier: str
    status: str
    billing_email: str | None
    grace_period_started_at: str | None
    retention_days_override: int | None
    white_label_company_name: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class MonthlyUsageRecord:
    account_id: str
    period_key: str
    scans_used: int
    reportability_spend_usd: float
    hypotheses_spend_usd: float


@dataclass(frozen=True)
class CostEstimateRecord:
    estimate_id: str
    account_id: str
    scan_id: str
    feature: str
    provider: str
    adversarial_provider: str | None
    degraded_from_adversarial: bool
    estimated_cost_usd: float
    params_json: str
    created_at: str
    expires_at: str
    consumed_at: str | None


@dataclass(frozen=True)
class MonitoredDomainRecord:
    monitoring_id: str
    account_id: str
    domain: str
    speed2_enabled: bool
    status: str
    last_passive_scan_id: str | None
    last_active_scan_id: str | None
    last_passive_run_at: str | None
    last_active_run_at: str | None
    next_passive_due_at: str
    next_active_due_at: str | None
    pending_passive_scan_id: str | None
    pending_active_scan_id: str | None
    last_asset_digest: str | None
    last_asset_count: int | None
    needs_review: bool
    created_at: str
    updated_at: str
    organization_id: str | None = None


@dataclass(frozen=True)
class WebhookRecord:
    webhook_id: str
    account_id: str
    url: str
    secret: str
    event_types: tuple[str, ...]
    status: str
    consecutive_failures: int
    last_delivery_at: str | None
    last_success_at: str | None
    last_error: str | None
    created_at: str
    updated_at: str
    organization_id: str | None = None


@dataclass(frozen=True)
class WompiPendingEnrollmentRecord:
    enrollment_id: str
    account_id: str
    tier: str
    billing_email: str
    status: str
    created_at: str
    matched_at: str | None


@dataclass(frozen=True)
class DomainVerificationRecord:
    verification_id: str
    account_id: str
    domain: str
    token: str
    method: str | None
    status: str
    created_at: str
    verified_at: str | None
    expires_at: str | None
    last_checked_at: str | None
    last_check_error: str | None
    organization_id: str | None = None


@dataclass(frozen=True)
class OrganizationRecord:
    organization_id: str
    name: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AssetRecord:
    asset_id: str
    organization_id: str
    asset_type: str
    identity_key: str
    first_seen_at: str
    last_seen_at: str
    last_seen_run_id: str | None


@dataclass(frozen=True)
class ExposureRecord:
    exposure_id: str
    organization_id: str
    asset_id: str
    source: str
    template_id: str
    location: str
    severity: str
    title: str
    description: str
    confidence_score: int | None
    status: str
    first_seen_at: str
    last_seen_at: str
    first_seen_run_id: str
    last_seen_run_id: str
    resolved_at: str | None
    resolved_run_id: str | None
    resolution_reason: str | None


@dataclass(frozen=True)
class ExposureEvidenceRecord:
    exposure_evidence_id: str
    exposure_id: str
    organization_id: str
    account_id: str
    run_id: str
    finding_id: int
    observed_at: str


@dataclass(frozen=True)
class CandidateAssetRecord:
    candidate_asset_id: str
    organization_id: str
    candidate_type: str
    normalized_value: str
    display_value: str
    first_seen_at: str
    last_seen_at: str
    first_seen_run_id: str
    last_seen_run_id: str
    scope_status: str
    collection_status: str
    authorization_status: str
    reason: str
    depth: int
    priority: int
    collector: str
    source_entity_id: str
    parent_indicator_id: str | None
    lineage_reference: str


@dataclass(frozen=True)
class AssetIdentifierRecord:
    id: int
    asset_id: str
    organization_id: str
    identifier_type: str
    identifier_value: str
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    organization_id: str
    asset_id: str
    source: str
    detail: str
    confidence_score: int | None
    first_seen_at: str
    last_seen_at: str
    last_seen_run_id: str | None


@dataclass(frozen=True)
class ObservationRecord:
    observation_id: str
    organization_id: str
    asset_id: str
    run_id: str
    account_id: str
    observation_type: str
    evidence_id: str
    observed_at: str


@dataclass(frozen=True)
class ObservationWithEvidence:
    """The single-query traceability shape the phase's own prompt asks
    for: from one row, an observation's `run_id` (its origin) AND the
    full evidence that backs it, with no manual join against the raw
    run_id-scoped tables required."""

    observation: ObservationRecord
    evidence: EvidenceRecord


@dataclass(frozen=True)
class ChangeEventRecord:
    change_event_id: str
    organization_id: str
    asset_id: str
    run_id: str
    previous_state: str | None
    new_state: str
    reason: str
    previous_digest: str | None
    new_digest: str | None
    detected_at: str


_ACCOUNTS_MIGRATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("email", "TEXT"),
    ("email_verified_at", "TEXT"),
    ("email_verification_token", "TEXT"),
    ("email_verification_token_expires_at", "TEXT"),
)

# Durable-queue fix: an existing `scans` table (every account with a
# scan predating this fix) needs these three columns added the same way
# `accounts` needed its email-verification columns added.
_SCANS_MIGRATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("retry_count", "INTEGER NOT NULL DEFAULT 0"),
    ("worker_id", "TEXT"),
    ("heartbeat_at", "TEXT"),
    ("trigger_source", "TEXT NOT NULL DEFAULT 'manual'"),
)

# White-label client report fix: an existing `subscriptions` table
# (every account created before this task) needs this column added the
# same way.
_SUBSCRIPTIONS_MIGRATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("white_label_company_name", "TEXT"),
)

# Fase 02 (EASM roadmap): every one of these four tables predates the
# `organizations` concept, so an existing `control.db` needs this column
# ALTER'd on exactly like the migrations above. Nullable here (SQLite
# cannot ALTER TABLE ADD a NOT NULL column with a per-row default onto a
# table that already has rows) — `_backfill_organizations` below fills
# every existing row's real value once `organizations`/
# `account_organization_roles` exist.
_ORGANIZATION_ID_MIGRATION_COLUMNS: tuple[tuple[str, str], ...] = (("organization_id", "TEXT"),)


def _migrate_table_columns(
    conn: sqlite3.Connection, table: str, columns: tuple[tuple[str, str], ...]
) -> None:
    """`CREATE TABLE IF NOT EXISTS` never adds columns to a table that
    already exists on disk — generalized from the accounts-table-only
    version this project's own Hallazgo 1 fix originally wrote (single
    caller became two, so this is now a shared helper rather than a
    second, drifting copy of the same four lines). `table`/`columns`
    are always literal, module-level constants below, never external
    input. A brand-new database never reaches the `ALTER TABLE` branch
    with any work to do (the table doesn't exist yet, so there's
    nothing to migrate) — checked explicitly rather than assumed, since
    running `ALTER TABLE` on a table that was never created would
    itself fail."""
    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if table_exists is None:
        return
    existing_columns = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})")  # noqa: S608  # nosec B608
    }
    for column, column_type in columns:
        if column not in existing_columns:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
            )  # noqa: S608  # nosec B608


_ORGANIZATION_SCOPED_TABLES: tuple[str, ...] = (
    "domain_verifications",
    "monitored_domains",
    "scans",
    "webhooks",
)


def _backfill_organizations(conn: sqlite3.Connection) -> None:
    """Fase 02's actual data migration: every account that predates the
    `organizations` concept (no row of its own in
    `account_organization_roles` yet) gets a real, distinct organization,
    1:1, automatically — no user action required, and this changes
    nothing observable for that account (every existing account-scoped
    accessor keeps returning exactly the same rows; only the new
    organization-scoped accessors become meaningful for it). Runs once
    per `ControlDB()` construction; a cheap no-op after the first real
    run, since the `NOT IN` subquery then matches zero accounts. A
    brand-new account never reaches this function at all —
    `create_account` provisions its organization inline, in the SAME
    transaction as the account row itself, so it's never in the "missing
    an organization" state this function looks for."""
    accounts_without_org = conn.execute(
        "SELECT account_id, email FROM accounts WHERE account_id NOT IN "
        "(SELECT account_id FROM account_organization_roles)"
    ).fetchall()
    now = _now_iso()
    for row in accounts_without_org:
        account_id = row["account_id"]
        organization_id = secrets.token_hex(16)
        name = row["email"] or f"Organization for account {account_id[:8]}"
        conn.execute(
            "INSERT INTO organizations (organization_id, name, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (organization_id, name, now, now),
        )
        conn.execute(
            "INSERT INTO account_organization_roles "
            "(account_id, organization_id, role, created_at) VALUES (?, ?, 'owner', ?)",
            (account_id, organization_id, now),
        )
        for table in _ORGANIZATION_SCOPED_TABLES:
            conn.execute(
                # table is always one of the fixed literals above, never
                # external input.
                f"UPDATE {table} SET organization_id = ? "  # noqa: S608  # nosec B608
                "WHERE account_id = ? AND organization_id IS NULL",
                (organization_id, account_id),
            )


class ControlDB:
    """One instance per process, backed by one SQLite file
    (`APISettings.control_db_path`) — this is the only database in the
    whole service allowed to have rows belonging to more than one
    account; every other database is per-account (`api/tenancy.py`)."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            _migrate_table_columns(conn, "accounts", _ACCOUNTS_MIGRATION_COLUMNS)
            _migrate_table_columns(conn, "scans", _SCANS_MIGRATION_COLUMNS)
            _migrate_table_columns(conn, "subscriptions", _SUBSCRIPTIONS_MIGRATION_COLUMNS)
            for table in _ORGANIZATION_SCOPED_TABLES:
                _migrate_table_columns(conn, table, _ORGANIZATION_ID_MIGRATION_COLUMNS)
            conn.executescript(_SCHEMA)
            _backfill_organizations(conn)
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{self.db_path}{suffix}")
            if path.exists():
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def _connect(self) -> sqlite3.Connection:
        return connect_sqlite(self.db_path)

    def ping(self) -> None:
        """`GET /health`'s (`api/health.py`) real reachability check —
        a trivial but GENUINE query, not just "the `ControlDB` object
        exists in memory." Raises whatever `sqlite3` itself raises if
        the file is missing, corrupted, or otherwise unreadable; the
        caller decides what that means for the response.

        **Deliberately NOT `SELECT 1`** — found the hard way, while
        writing this exact method's own test, that `SELECT 1` is a pure
        constant expression SQLite evaluates without ever reading the
        database file's header or schema, so it SUCCEEDS even against a
        completely corrupted, non-SQLite file — exactly the "a route
        that returns 200 without checking anything real" trap this
        health check exists to avoid. Querying `sqlite_master` (SQLite's
        own schema table) forces a real read of the file's actual
        content, which genuinely fails
        (`sqlite3.DatabaseError: file is not a database`) against a
        corrupted file — confirmed directly, not assumed."""
        with self._connect() as conn:
            conn.execute("SELECT count(*) FROM sqlite_master")

    # --- accounts ---------------------------------------------------

    def create_account(
        self,
        *,
        email: str | None = None,
        email_verification_token: str | None = None,
        email_verification_token_expires_at: str | None = None,
    ) -> str:
        """`email`/the token fields are optional here (not on
        `POST /accounts` itself — `api/routers/accounts.py` always
        supplies them) so pre-existing direct callers (a handful of
        tests whose subject is unrelated to email verification) keep
        working unchanged. Raises `DuplicateEmailError` if `email` is
        already registered to a different account — enforced by the
        table's own partial unique index (`WHERE email IS NOT NULL`),
        not just application-level convention, so this can never be
        bypassed by a second, uncoordinated code path.

        Fase 02: every new account gets its own 1:1 `organization` (owner
        role) created in this SAME transaction — never deferred to the
        next `ControlDB()` startup's `_backfill_organizations` sweep,
        which exists only for accounts that predate this feature."""
        account_id = secrets.token_hex(16)
        organization_id = secrets.token_hex(16)
        now = _now_iso()
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO accounts (account_id, created_at, email, "
                    "email_verification_token, email_verification_token_expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        account_id,
                        now,
                        email,
                        email_verification_token,
                        email_verification_token_expires_at,
                    ),
                )
                conn.execute(
                    "INSERT INTO organizations (organization_id, name, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        organization_id,
                        email or f"Organization for account {account_id[:8]}",
                        now,
                        now,
                    ),
                )
                conn.execute(
                    "INSERT INTO account_organization_roles "
                    "(account_id, organization_id, role, created_at) VALUES (?, ?, 'owner', ?)",
                    (account_id, organization_id, now),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEmailError(f"{email!r} is already registered") from exc
        return account_id

    def account_exists(self, account_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
        return row is not None

    def get_account(self, account_id: str) -> AccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
        return None if row is None else _account_record_from_row(row)

    def get_account_by_verification_token(self, token: str) -> AccountRecord | None:
        """Only ever used by `POST /accounts/verify-email` — matches on
        the token alone (it's the credential here, the same way an API
        key or a domain-verification token is), never combined with any
        other caller-supplied identifier."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email_verification_token = ?", (token,)
            ).fetchone()
        return None if row is None else _account_record_from_row(row)

    def mark_email_verified(self, account_id: str) -> None:
        """Clears the token on success — a consumed verification token
        is never reusable, the same single-use discipline
        `domain_verifications`/`cost_estimates` already established."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE accounts SET email_verified_at = ?, email_verification_token = NULL, "
                "email_verification_token_expires_at = NULL WHERE account_id = ?",
                (_now_iso(), account_id),
            )

    def set_email_verification_token(self, account_id: str, *, token: str, expires_at: str) -> None:
        """Used both at account creation and by a resend — regenerating
        always replaces any previous token outright (never two
        simultaneously-valid tokens for the same account)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE accounts SET email_verification_token = ?, "
                "email_verification_token_expires_at = ? WHERE account_id = ?",
                (token, expires_at, account_id),
            )

    # --- organizations (Fase 02, EASM roadmap) --------------------------

    def default_organization_id_for_account(self, account_id: str) -> str:
        """The account's own OWNER organization — every account has
        exactly one as of either `create_account`'s inline provisioning
        (new accounts) or the one-time `_backfill_organizations` sweep at
        `ControlDB()` startup (accounts that predate Fase 02). Used
        internally by every `create_*` method below that accepts an
        `organization_id: str | None` parameter, so every existing
        caller — every router, every pre-existing test — keeps working
        completely unchanged without ever having to learn about
        organizations. If more than one owner role exists for this
        account (a future phase's multi-owner-organization feature), the
        oldest one is treated as "the account's own" — the 1:1 one it
        started with."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT organization_id FROM account_organization_roles "
                "WHERE account_id = ? AND role = 'owner' ORDER BY created_at LIMIT 1",
                (account_id,),
            ).fetchone()
        if row is None:
            raise ValueError(
                f"account {account_id!r} has no organization — should be impossible after "
                "Fase 02's create_account provisioning / _backfill_organizations migration"
            )
        return row["organization_id"]

    def create_organization(self, *, name: str) -> str:
        """A SECOND (or later) organization for an account that already
        has its 1:1 default one — e.g. a consultant onboarding a new
        client. Grants no role to anyone by itself;
        `add_account_organization_role` is a separate, explicit call."""
        organization_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO organizations (organization_id, name, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (organization_id, name, now, now),
            )
        return organization_id

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM organizations WHERE organization_id = ?", (organization_id,)
            ).fetchone()
        if row is None:
            return None
        return OrganizationRecord(
            organization_id=row["organization_id"],
            name=row["name"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def add_account_organization_role(
        self, *, account_id: str, organization_id: str, role: str
    ) -> None:
        """`role` is `'owner'` or `'viewer'` — anything else is a caller
        bug, not user input to validate gently. Upserts: re-granting a
        role a second time (or changing it) replaces the prior row for
        this (account, organization) pair rather than erroring, since the
        table's own primary key is exactly that pair."""
        if role not in ("owner", "viewer"):
            raise ValueError(f"unknown organization role: {role!r}")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO account_organization_roles "
                "(account_id, organization_id, role, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(account_id, organization_id) DO UPDATE SET role = excluded.role",
                (account_id, organization_id, role, _now_iso()),
            )

    def get_role_for_account_organization(
        self, account_id: str, organization_id: str
    ) -> str | None:
        """`None` means this account has no role on this organization at
        all — indistinguishable from "organization doesn't exist" to a
        caller deciding access, which is the correct posture (never leak
        which is true)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT role FROM account_organization_roles "
                "WHERE account_id = ? AND organization_id = ?",
                (account_id, organization_id),
            ).fetchone()
        return row["role"] if row else None

    def list_organizations_for_account(self, account_id: str) -> list[tuple[str, str]]:
        """`(organization_id, role)` pairs, oldest first — the first
        entry is always the account's own 1:1 default organization for
        an account that has never been granted access to a second one."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT organization_id, role FROM account_organization_roles "
                "WHERE account_id = ? ORDER BY created_at",
                (account_id,),
            ).fetchall()
        return [(row["organization_id"], row["role"]) for row in rows]

    def get_verified_domains_for_organization(
        self, organization_id: str, *, now: str | None = None
    ) -> list[DomainVerificationRecord]:
        """The organization-scoped twin of `get_verified_domains_for_account`
        — every currently-active (verified, unexpired) domain this
        ORGANIZATION holds, never leaking a sibling organization's domains
        even when both share the same `account_id` (the consultant-with-
        two-clients case Fase 02 exists for)."""
        now = now or _now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE organization_id = ? AND status = 'verified' AND expires_at > ?",
                (organization_id, now),
            ).fetchall()
        return [_verification_record_from_row(row) for row in rows]

    def list_monitored_domains_for_organization(
        self, organization_id: str
    ) -> list[MonitoredDomainRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM monitored_domains WHERE organization_id = ? ORDER BY created_at",
                (organization_id,),
            ).fetchall()
        return [_monitored_domain_record_from_row(row) for row in rows]

    def list_webhooks_for_organization(self, organization_id: str) -> list[WebhookRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhooks WHERE organization_id = ? ORDER BY created_at",
                (organization_id,),
            ).fetchall()
        return [_webhook_record_from_row(row) for row in rows]

    def list_scans_for_organization(self, organization_id: str) -> list[ScanRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE organization_id = ? ORDER BY created_at",
                (organization_id,),
            ).fetchall()
        return [_scan_record_from_row(row) for row in rows]

    # --- assets (Fase 03, EASM roadmap) ---------------------------------

    def get_asset_by_identity(
        self, *, organization_id: str, asset_type: str, identity_key: str
    ) -> AssetRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE organization_id = ? AND asset_type = ? "
                "AND identity_key = ?",
                (organization_id, asset_type, identity_key),
            ).fetchone()
        return None if row is None else _asset_record_from_row(row)

    def get_asset(self, asset_id: str) -> AssetRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return None if row is None else _asset_record_from_row(row)

    def existing_assets_for_organization(self, organization_id: str) -> dict[str, ExistingAsset]:
        """The exact input shape `api/asset_identity.py::reconcile_observation`/
        `reconcile_host_observations` need — EVERY asset this
        organization already has, of every type, keyed by `identity_key`
        alone (never colliding across types, since every identity_key
        already carries its own type as a string prefix — see
        `api/asset_identity.py`'s key builders — so one combined dict is
        both correct and one query per organization instead of one per
        asset_type per host, which matters for `api/asset_backfill.py`
        replaying a whole account's run history). Built fresh from EVERY
        asset ever recorded for this organization, never just the most
        recent run's — this is what makes a reappeared asset (gone for
        one run, back the next) reconcile to the SAME row rather than a
        new one."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT asset_id, asset_type, identity_key FROM assets WHERE organization_id = ?",
                (organization_id,),
            ).fetchall()
        return {
            row["identity_key"]: ExistingAsset(
                asset_id=row["asset_id"],
                asset_type=row["asset_type"],
                identity_key=row["identity_key"],
            )
            for row in rows
        }

    def apply_asset_reconciliation(
        self,
        *,
        organization_id: str,
        run_id: str,
        decisions: list[ReconciliationDecision],
        observed_at: str | None = None,
    ) -> None:
        """The I/O half of `api/asset_identity.py`'s pure
        `reconcile_observation`/`reconcile_host_observations` — takes
        the DECISIONS that pure logic already made (this method makes no
        reconciliation decisions of its own) and persists them: a new
        row for `is_new` decisions, `last_seen_at`/`last_seen_run_id`
        touched for existing ones, plus an upserted
        `asset_identifiers` row (e.g. an observed IP) for each identifier
        the decision carries — attached to the asset that decision
        resolved to, per (organization_id, identifier_type,
        identifier_value), never a new row when that exact identifier is
        already recorded for that exact asset (`INSERT OR IGNORE`, since
        the table's own UNIQUE constraint already prevents a duplicate,
        and re-observing the same still-current IP on a later run is the
        overwhelmingly common case, not an error)."""
        observed_at = observed_at or _now_iso()
        with self._connect() as conn:
            for decision in decisions:
                if decision.is_new:
                    conn.execute(
                        "INSERT INTO assets (asset_id, organization_id, asset_type, "
                        "identity_key, first_seen_at, last_seen_at, last_seen_run_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            decision.asset_id,
                            organization_id,
                            decision.asset_type,
                            decision.identity_key,
                            observed_at,
                            observed_at,
                            run_id,
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE assets SET last_seen_at = ?, last_seen_run_id = ? "
                        "WHERE asset_id = ?",
                        (observed_at, run_id, decision.asset_id),
                    )
                for identifier_type, identifier_value in decision.identifiers:
                    conn.execute(
                        "INSERT OR IGNORE INTO asset_identifiers "
                        "(asset_id, organization_id, identifier_type, identifier_value, "
                        "first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            decision.asset_id,
                            organization_id,
                            identifier_type,
                            identifier_value,
                            observed_at,
                            observed_at,
                        ),
                    )
                    conn.execute(
                        "UPDATE asset_identifiers SET last_seen_at = ? "
                        "WHERE organization_id = ? AND identifier_type = ? "
                        "AND identifier_value = ?",
                        (observed_at, organization_id, identifier_type, identifier_value),
                    )

    def list_assets_for_organization(
        self, organization_id: str, *, asset_type: str | None = None
    ) -> list[AssetRecord]:
        with self._connect() as conn:
            if asset_type is None:
                rows = conn.execute(
                    "SELECT * FROM assets WHERE organization_id = ? ORDER BY first_seen_at",
                    (organization_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM assets WHERE organization_id = ? AND asset_type = ? "
                    "ORDER BY first_seen_at",
                    (organization_id, asset_type),
                ).fetchall()
        return [_asset_record_from_row(row) for row in rows]

    def list_identifiers_for_asset(self, asset_id: str) -> list[AssetIdentifierRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_identifiers WHERE asset_id = ? ORDER BY first_seen_at",
                (asset_id,),
            ).fetchall()
        return [_asset_identifier_record_from_row(row) for row in rows]

    # --- candidate assets (Fase 06, EASM roadmap) ----------------------

    def upsert_candidate_asset(
        self,
        *,
        organization_id: str,
        run_id: str,
        draft: CandidateAssetDraft,
        observed_at: str | None = None,
    ) -> tuple[str, bool]:
        """Persist one exact candidate identity across runs.

        Returns `(candidate_asset_id, created)`. Existing rows keep their
        original first-seen identity and receive the latest run's lifecycle
        metadata. This method never creates an `assets` row and never calls
        any authorization primitive.
        """
        observed_at = observed_at or _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT candidate_asset_id FROM candidate_assets "
                "WHERE organization_id = ? AND candidate_type = ? "
                "AND normalized_value = ?",
                (organization_id, draft.candidate_type, draft.normalized_value),
            ).fetchone()
            if row is not None:
                candidate_asset_id = str(row["candidate_asset_id"])
                conn.execute(
                    "UPDATE candidate_assets SET display_value = ?, last_seen_at = ?, "
                    "last_seen_run_id = ?, scope_status = ?, collection_status = ?, "
                    "authorization_status = ?, reason = ?, depth = ?, priority = ?, "
                    "collector = ?, source_entity_id = ?, parent_indicator_id = ?, "
                    "lineage_reference = ? WHERE candidate_asset_id = ?",
                    (
                        draft.display_value,
                        observed_at,
                        run_id,
                        draft.scope_status,
                        draft.collection_status,
                        draft.authorization_status,
                        draft.reason,
                        draft.depth,
                        draft.priority,
                        draft.collector,
                        draft.source_entity_id,
                        draft.parent_indicator_id,
                        draft.lineage_reference,
                        candidate_asset_id,
                    ),
                )
                return candidate_asset_id, False

            candidate_asset_id = secrets.token_hex(16)
            conn.execute(
                "INSERT INTO candidate_assets (candidate_asset_id, organization_id, "
                "candidate_type, normalized_value, display_value, first_seen_at, "
                "last_seen_at, first_seen_run_id, last_seen_run_id, scope_status, "
                "collection_status, authorization_status, reason, depth, priority, "
                "collector, source_entity_id, parent_indicator_id, lineage_reference) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    candidate_asset_id,
                    organization_id,
                    draft.candidate_type,
                    draft.normalized_value,
                    draft.display_value,
                    observed_at,
                    observed_at,
                    run_id,
                    run_id,
                    draft.scope_status,
                    draft.collection_status,
                    draft.authorization_status,
                    draft.reason,
                    draft.depth,
                    draft.priority,
                    draft.collector,
                    draft.source_entity_id,
                    draft.parent_indicator_id,
                    draft.lineage_reference,
                ),
            )
        return candidate_asset_id, True

    def list_candidate_assets_for_organization(
        self, organization_id: str, *, candidate_type: str | None = None
    ) -> list[CandidateAssetRecord]:
        with self._connect() as conn:
            if candidate_type is None:
                rows = conn.execute(
                    "SELECT * FROM candidate_assets WHERE organization_id = ? "
                    "ORDER BY first_seen_at, candidate_asset_id",
                    (organization_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM candidate_assets WHERE organization_id = ? "
                    "AND candidate_type = ? ORDER BY first_seen_at, candidate_asset_id",
                    (organization_id, candidate_type),
                ).fetchall()
        return [_candidate_asset_record_from_row(row) for row in rows]

    def get_candidate_asset(self, candidate_asset_id: str) -> CandidateAssetRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM candidate_assets WHERE candidate_asset_id = ?",
                (candidate_asset_id,),
            ).fetchone()
        return None if row is None else _candidate_asset_record_from_row(row)

    # --- observations and evidence (Fase 04, EASM roadmap) --------------

    def find_or_create_evidence(
        self,
        *,
        organization_id: str,
        asset_id: str,
        content: EvidenceContent,
        run_id: str,
        observed_at: str | None = None,
    ) -> str:
        """The evidence-side reconciliation: an exact match on
        `(organization_id, asset_id, source, detail, confidence_score)`
        — the table's own UNIQUE constraint — means "the same fact,
        observed again," and only `last_seen_at`/`last_seen_run_id`
        advance; no match means a genuinely new evidence row. Same "exact
        value match, never fuzzy" discipline `api/asset_identity.py`
        already established for asset identity, applied here to evidence
        content instead."""
        observed_at = observed_at or _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT evidence_id FROM evidence WHERE organization_id = ? AND asset_id = ? "
                "AND source = ? AND detail = ? AND confidence_score IS ?",
                (
                    organization_id,
                    asset_id,
                    content.source,
                    content.detail,
                    content.confidence_score,
                ),
            ).fetchone()
            if row is not None:
                evidence_id = row["evidence_id"]
                conn.execute(
                    "UPDATE evidence SET last_seen_at = ?, last_seen_run_id = ? "
                    "WHERE evidence_id = ?",
                    (observed_at, run_id, evidence_id),
                )
                return evidence_id
            evidence_id = secrets.token_hex(16)
            conn.execute(
                "INSERT INTO evidence (evidence_id, organization_id, asset_id, source, detail, "
                "confidence_score, first_seen_at, last_seen_at, last_seen_run_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    organization_id,
                    asset_id,
                    content.source,
                    content.detail,
                    content.confidence_score,
                    observed_at,
                    observed_at,
                    run_id,
                ),
            )
        return evidence_id

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        return None if row is None else _evidence_record_from_row(row)

    def record_observation(
        self,
        *,
        organization_id: str,
        asset_id: str,
        run_id: str,
        account_id: str,
        observation_type: str,
        evidence_id: str,
        observed_at: str | None = None,
    ) -> str | None:
        """Records that THIS run observed THIS fact about THIS asset.
        `INSERT OR IGNORE` against the table's own
        `UNIQUE(asset_id, run_id, evidence_id)` constraint — replaying
        the same run through the backfill a second time (Fase 03's own
        idempotency precedent) creates zero duplicate rows. Returns the
        new `observation_id`, or `None` if this exact (asset, run,
        evidence) combination was already recorded."""
        observed_at = observed_at or _now_iso()
        observation_id = secrets.token_hex(16)
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO observations (observation_id, organization_id, asset_id, "
                "run_id, account_id, observation_type, evidence_id, observed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    observation_id,
                    organization_id,
                    asset_id,
                    run_id,
                    account_id,
                    observation_type,
                    evidence_id,
                    observed_at,
                ),
            )
        return observation_id if cursor.rowcount else None

    def list_observations_for_asset(self, asset_id: str) -> list[ObservationWithEvidence]:
        """The phase's own required "one query, no manual joins against
        the raw tables" traceability: every observation this asset has
        ever had, each one already carrying its own `run_id` (where it
        came from) and its full, resolved `EvidenceRecord` (what backs
        it) — a real SQL join against `evidence` (an already-normalized,
        Fase-04-owned table), never against any run_id-scoped raw table
        in `core/store.py`."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT o.*, "
                "e.source AS e_source, e.detail AS e_detail, "
                "e.confidence_score AS e_confidence_score, e.first_seen_at AS e_first_seen_at, "
                "e.last_seen_at AS e_last_seen_at, e.last_seen_run_id AS e_last_seen_run_id, "
                "e.organization_id AS e_organization_id, e.asset_id AS e_asset_id "
                "FROM observations o JOIN evidence e ON o.evidence_id = e.evidence_id "
                "WHERE o.asset_id = ? ORDER BY o.observed_at",
                (asset_id,),
            ).fetchall()
        return [_observation_with_evidence_from_row(row) for row in rows]

    def observation_digest_input_for_run(
        self, *, asset_id: str, run_id: str
    ) -> list[tuple[str, str, str, int | None]]:
        """Every `(observation_type, evidence.source, evidence.detail,
        evidence.confidence_score)` tuple this ONE run recorded for this
        ONE asset — the exact, ready-to-hash input
        `api/change_detection.py::observation_digest` needs. An empty
        list here is exactly what "this run did not observe this asset"
        means to the change-detection engine."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT o.observation_type, e.source, e.detail, e.confidence_score "
                "FROM observations o JOIN evidence e ON o.evidence_id = e.evidence_id "
                "WHERE o.asset_id = ? AND o.run_id = ?",
                (asset_id, run_id),
            ).fetchall()
        return [
            (row["observation_type"], row["source"], row["detail"], row["confidence_score"])
            for row in rows
        ]

    def record_change_event(
        self,
        *,
        organization_id: str,
        asset_id: str,
        run_id: str,
        previous_state: str | None,
        new_state: str,
        reason: str,
        previous_digest: str | None,
        new_digest: str | None,
        detected_at: str | None = None,
    ) -> str | None:
        """Persists ONE `ChangeEvent` the pure engine already decided —
        this method makes no decision of its own. `INSERT OR IGNORE`
        against `UNIQUE(asset_id, run_id)` makes replaying the
        change-detection backfill a second time produce zero duplicate
        rows (Fase 03/04's own idempotency precedent). Returns the new
        `change_event_id`, or `None` if this (asset, run) pair already
        had a recorded transition."""
        detected_at = detected_at or _now_iso()
        change_event_id = secrets.token_hex(16)
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO change_events (change_event_id, organization_id, "
                "asset_id, run_id, previous_state, new_state, reason, previous_digest, "
                "new_digest, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    change_event_id,
                    organization_id,
                    asset_id,
                    run_id,
                    previous_state,
                    new_state,
                    reason,
                    previous_digest,
                    new_digest,
                    detected_at,
                ),
            )
        return change_event_id if cursor.rowcount else None

    def list_change_events_for_asset(self, asset_id: str) -> list[ChangeEventRecord]:
        """The phase's own required "historial de cambios de este
        asset" — an index range scan on `idx_change_events_asset`
        (`asset_id`, `detected_at`), never a full-table scan."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM change_events WHERE asset_id = ? ORDER BY detected_at",
                (asset_id,),
            ).fetchall()
        return [_change_event_record_from_row(row) for row in rows]

    def list_change_events_for_run(self, run_id: str) -> list[ChangeEventRecord]:
        """The phase's own required "todos los cambios detectados en
        este run" — an index range scan on `idx_change_events_run`."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM change_events WHERE run_id = ? ORDER BY detected_at",
                (run_id,),
            ).fetchall()
        return [_change_event_record_from_row(row) for row in rows]

    def get_current_lifecycle_state_for_asset(self, asset_id: str) -> str | None:
        """The most recent recorded transition's `new_state` — cheap
        (same index as `list_change_events_for_asset`, `LIMIT 1`), and
        `None` for an asset that has never had a recorded transition
        (unreachable in practice once the backfill has run at least
        once, since every asset's very first observation always
        produces a `NEW` event)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT new_state FROM change_events WHERE asset_id = ? "
                "ORDER BY detected_at DESC LIMIT 1",
                (asset_id,),
            ).fetchone()
        return row["new_state"] if row else None

    # --- account-creation rate limiting (Hallazgo 1) --------------------

    def record_account_creation_attempt(self, ip_address: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO account_creation_attempts (ip_address, created_at) VALUES (?, ?)",
                (ip_address, _now_iso()),
            )

    def count_recent_account_creations_from_ip(self, ip_address: str, *, since: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM account_creation_attempts "
                "WHERE ip_address = ? AND created_at >= ?",
                (ip_address, since),
            ).fetchone()
        return int(row["n"])

    # --- persisted per-key rate limiting (durable-queue fix) -------------

    def check_and_consume_rate_limit_token(
        self, key_id: str, *, capacity: float, refill_rate_per_second: float
    ) -> bool:
        """The cross-process-safe replacement for
        `api/rate_limit.py`'s old in-memory `TokenBucketLimiter` — one
        `INSERT ... ON CONFLICT DO UPDATE ... WHERE` statement does the
        entire refill-then-consume decision atomically in SQL, never a
        Python read-then-write (which would itself be a race between
        two processes checking the same key at once). The `WHERE`
        clause on the `DO UPDATE` is what makes this a real gate, not
        just bookkeeping: if the refilled token count would be below
        1.0, the clause is false, so NEITHER the insert NOR the update
        branch actually changes anything — `cursor.rowcount` comes back
        `0`, and the caller knows to reject the request without a
        separate check. Returns `True` (token consumed, request
        allowed) or `False` (no tokens available, request denied).
        Verified under real concurrent callers, not just reasoned
        about, by `tests/test_scan_queue_durability.py`."""
        now = _now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO rate_limit_buckets (key_id, tokens, last_refill_at) "
                "VALUES (?, ? - 1, ?) "
                "ON CONFLICT(key_id) DO UPDATE SET "
                "    tokens = MIN(?, tokens + (julianday(?) - julianday(last_refill_at)) "
                "        * 86400.0 * ?) - 1, "
                "    last_refill_at = ? "
                "WHERE MIN(?, tokens + (julianday(?) - julianday(last_refill_at)) "
                "    * 86400.0 * ?) >= 1.0",
                (
                    key_id,
                    capacity,
                    now,
                    capacity,
                    now,
                    refill_rate_per_second,
                    now,
                    capacity,
                    now,
                    refill_rate_per_second,
                ),
            )
        return cursor.rowcount == 1

    # --- api keys -----------------------------------------------------

    def insert_api_key(
        self, *, key_id: str, account_id: str, lookup_hash: str, verify_hash: str, prefix: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys "
                "(key_id, account_id, lookup_hash, verify_hash, prefix, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, account_id, lookup_hash, verify_hash, prefix, _now_iso()),
            )

    def find_key_by_lookup_hash(self, lookup_hash: str) -> tuple[ApiKeyRecord, str] | None:
        """Returns (record, verify_hash) so the caller can run the slow
        Argon2id check outside any DB transaction — this fast lookup
        column exists precisely so authentication doesn't require an
        Argon2id verify against every active key on every request (see
        `api/security.py` module docstring)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE lookup_hash = ?", (lookup_hash,)
            ).fetchone()
        if row is None:
            return None
        return _key_record_from_row(row), row["verify_hash"]

    def get_key(self, key_id: str, account_id: str) -> ApiKeyRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_id = ? AND account_id = ?",
                (key_id, account_id),
            ).fetchone()
        return None if row is None else _key_record_from_row(row)

    def touch_key_last_used(self, key_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (_now_iso(), key_id)
            )

    def revoke_key(self, key_id: str, account_id: str) -> bool:
        """Immediate revocation — never touches any other key on the
        account. Returns False if no matching, not-already-revoked key
        was found for that account (caller treats this as 404, never
        403, per the tenant-isolation convention above)."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked_at = ? "
                "WHERE key_id = ? AND account_id = ? AND revoked_at IS NULL",
                (_now_iso(), key_id, account_id),
            )
        return cursor.rowcount > 0

    def start_key_rotation_grace_period(
        self, key_id: str, account_id: str, *, grace_hours: int
    ) -> str | None:
        """The OLD key stays valid until `expires_at` rather than being
        revoked immediately — the 24h dual-validity window
        (docs/PAID_API_DESIGN.md Part C). Returns the new `expires_at`
        (ISO timestamp), or None if no matching, currently-valid key was
        found for that account."""
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=grace_hours)).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET expires_at = ? "
                "WHERE key_id = ? AND account_id = ? AND revoked_at IS NULL",
                (expires_at, key_id, account_id),
            )
        return expires_at if cursor.rowcount > 0 else None

    # --- scans ----------------------------------------------------------

    def create_scan(
        self,
        *,
        scan_id: str,
        account_id: str,
        domain: str,
        db_path: str,
        trigger_source: str = "manual",
        organization_id: str | None = None,
    ) -> None:
        """`organization_id` defaults to the account's own organization
        (Fase 02) when not given explicitly — every pre-existing caller
        (every router, every test) keeps working unchanged."""
        organization_id = organization_id or self.default_organization_id_for_account(account_id)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans "
                "(scan_id, account_id, domain, db_path, status, created_at, updated_at, "
                "trigger_source, organization_id) "
                "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)",
                (scan_id, account_id, domain, db_path, now, now, trigger_source, organization_id),
            )

    def update_scan_status(
        self, scan_id: str, status: str, *, error_message: str | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, error_message = ?, updated_at = ? "
                "WHERE scan_id = ?",
                (status, error_message, _now_iso(), scan_id),
            )

    def get_owned_scan(self, scan_id: str, account_id: str) -> ScanRecord | None:
        """The Part F.3 double-check in one call: a scan_id that exists
        but belongs to a different account returns None, identically to
        a scan_id that doesn't exist at all."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ? AND account_id = ?",
                (scan_id, account_id),
            ).fetchone()
        return None if row is None else _scan_record_from_row(row)

    # --- durable scan queue -------------------------------------------

    def claim_next_queued_scan(self, worker_id: str) -> ScanRecord | None:
        """Atomically claims the oldest `'queued'` scan for `worker_id`
        — one UPDATE statement, so this is safe under real concurrent
        callers (verified explicitly by
        `tests/test_scan_queue_durability.py`'s race test, two threads
        hammering this on the same single queued row, never both
        winning). The `WHERE scan_id = (SELECT ...) AND status =
        'queued'` shape means that even if two callers' subqueries both
        pick the same candidate row before either has committed,
        SQLite's own writer serialization guarantees only the FIRST to
        actually execute its UPDATE changes anything — by the time the
        second one runs, its own subquery re-evaluates against the
        now-current state and either picks a different row or finds
        none, never double-claiming the first caller's row. Returns
        `None` when there's nothing queued (the common, healthy case
        between bursts of traffic)."""
        now = _now_iso()
        with self._connect() as conn:
            # RETURNING (SQLite 3.35+) hands back the exact row this
            # statement just updated, in the same atomic operation —
            # no separate SELECT afterward that could, in principle,
            # pick up a DIFFERENT row this same worker_id claimed a
            # microsecond later (a real risk with a two-statement
            # claim-then-lookup under a tight, fast poll loop).
            row = conn.execute(
                "UPDATE scans SET status = 'running', worker_id = ?, heartbeat_at = ?, "
                "updated_at = ? "
                "WHERE scan_id = ("
                "    SELECT scan_id FROM scans WHERE status = 'queued' "
                "    ORDER BY created_at ASC LIMIT 1"
                ") AND status = 'queued' "
                "RETURNING *",
                (worker_id, now, now),
            ).fetchone()
        return None if row is None else _scan_record_from_row(row)

    def update_scan_heartbeat(self, scan_id: str) -> None:
        """Called periodically (`api/scan_worker.py`'s heartbeat
        sub-task) by whichever worker is actively executing this scan —
        proof of liveness distinct from `status='running'` alone, which
        can't tell a genuinely-still-executing scan apart from one whose
        worker process died without updating it."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET heartbeat_at = ? WHERE scan_id = ?",
                (_now_iso(), scan_id),
            )

    def sweep_stale_running_scans(
        self, *, stale_after_seconds: int, max_retries: int, reason_prefix: str
    ) -> tuple[list[str], list[str]]:
        """Finds every `'running'` scan whose `heartbeat_at` is older
        than `stale_after_seconds` — a worker was executing it and has
        not proven it's still alive recently, which can only mean that
        worker died (crashed, was killed, the process restarted)
        without ever getting to mark the scan `completed`/`failed`
        itself. Each one is either requeued (status back to `'queued'`,
        `retry_count` incremented, `worker_id`/`heartbeat_at` cleared so
        any worker — not necessarily this one — can claim it next) or,
        if it's already been requeued `max_retries` times, given up on
        as `failed` with a diagnosable reason instead of requeued
        forever. Returns `(requeued_scan_ids, failed_scan_ids)`."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat()
        now = _now_iso()
        with self._connect() as conn:
            stale_rows = conn.execute(
                "SELECT scan_id, retry_count FROM scans "
                "WHERE status = 'running' AND (heartbeat_at IS NULL OR heartbeat_at < ?)",
                (cutoff,),
            ).fetchall()
            requeued: list[str] = []
            failed: list[str] = []
            for row in stale_rows:
                scan_id = row["scan_id"]
                retry_count = row["retry_count"]
                if retry_count >= max_retries:
                    conn.execute(
                        "UPDATE scans SET status = 'failed', error_message = ?, "
                        "worker_id = NULL, heartbeat_at = NULL, updated_at = ? "
                        "WHERE scan_id = ? AND status = 'running'",
                        (
                            f"{reason_prefix}: exceeded {max_retries} retries after "
                            "repeated interruption",
                            now,
                            scan_id,
                        ),
                    )
                    failed.append(scan_id)
                else:
                    conn.execute(
                        "UPDATE scans SET status = 'queued', retry_count = retry_count + 1, "
                        "worker_id = NULL, heartbeat_at = NULL, updated_at = ? "
                        "WHERE scan_id = ? AND status = 'running'",
                        (now, scan_id),
                    )
                    requeued.append(scan_id)
        return requeued, failed

    # --- domain verification (Part A) --------------------------------

    def create_domain_verification(
        self, *, account_id: str, domain: str, token: str, organization_id: str | None = None
    ) -> DomainVerificationRecord:
        """`organization_id` defaults to the account's own organization
        (Fase 02) when not given explicitly — see `create_scan`'s
        identical note."""
        organization_id = organization_id or self.default_organization_id_for_account(account_id)
        verification_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO domain_verifications "
                "(verification_id, account_id, domain, token, method, status, created_at, "
                "organization_id) "
                "VALUES (?, ?, ?, ?, NULL, 'pending', ?, ?)",
                (verification_id, account_id, domain, token, now, organization_id),
            )
        return DomainVerificationRecord(
            verification_id=verification_id,
            account_id=account_id,
            domain=domain,
            token=token,
            method=None,
            status="pending",
            created_at=now,
            verified_at=None,
            expires_at=None,
            last_checked_at=None,
            last_check_error=None,
            organization_id=organization_id,
        )

    def get_latest_pending_verification(
        self, account_id: str, domain: str
    ) -> DomainVerificationRecord | None:
        """The token a client is currently trying to prove — the most
        recent 'pending' row for this exact (account, domain). Never
        returns another account's row (account_id is always part of the
        WHERE clause, same discipline as every other lookup here)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE account_id = ? AND domain = ? AND status = 'pending' "
                "ORDER BY created_at DESC LIMIT 1",
                (account_id, domain),
            ).fetchone()
        return None if row is None else _verification_record_from_row(row)

    def get_active_verification_for_domain(
        self, domain: str, *, now: str | None = None
    ) -> DomainVerificationRecord | None:
        """The current, unexpired 'verified' row for `domain`, across ALL
        accounts — used only for the conflict check at the moment a NEW
        verification is about to succeed (Task 3.2: first successful
        verification wins). Never used to authorize a scan directly —
        that always goes through `get_active_verifications_for_account`,
        scoped to one account, never a bare domain lookup."""
        now = now or _now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE domain = ? AND status = 'verified' AND expires_at > ? "
                "ORDER BY verified_at DESC LIMIT 1",
                (domain, now),
            ).fetchone()
        return None if row is None else _verification_record_from_row(row)

    def get_all_verifications_for_account(self, account_id: str) -> list[DomainVerificationRecord]:
        """Every row this account has ever had, any domain, newest
        first — used to distinguish "never verified" from "verified
        once, now expired" (Task 3, test 6) by filtering for domain
        coverage in Python (api/domain_verification.py::domain_is_covered),
        the same subdomain-aware matching the scan gate itself uses,
        rather than a second, narrower SQL-only exact-match notion of
        "the same domain"."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_verifications WHERE account_id = ? "
                "ORDER BY created_at DESC",
                (account_id,),
            ).fetchall()
        return [_verification_record_from_row(row) for row in rows]

    def get_verified_domains_for_account(
        self, account_id: str, *, now: str | None = None
    ) -> list[DomainVerificationRecord]:
        """Every currently-active (verified, unexpired) domain this
        account holds — the scan gate checks scan target coverage
        against this list in Python (subdomain matching), not SQL."""
        now = now or _now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_verifications "
                "WHERE account_id = ? AND status = 'verified' AND expires_at > ?",
                (account_id, now),
            ).fetchall()
        return [_verification_record_from_row(row) for row in rows]

    def mark_verification_succeeded(
        self, verification_id: str, *, method: str, verified_at: str, expires_at: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET status = 'verified', method = ?, "
                "verified_at = ?, expires_at = ?, last_checked_at = ?, last_check_error = NULL "
                "WHERE verification_id = ?",
                (method, verified_at, expires_at, verified_at, verification_id),
            )

    def mark_verification_failed(self, verification_id: str, *, method: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET method = ?, last_checked_at = ?, "
                "last_check_error = ? WHERE verification_id = ?",
                (method, _now_iso(), error, verification_id),
            )

    def supersede_other_verifications(
        self, account_id: str, domain: str, *, keep_verification_id: str
    ) -> None:
        """After a new verification succeeds, mark this SAME account's
        other rows for the SAME domain as superseded — exactly one
        canonical row per (account, domain) going forward, so "the
        account's active verification for this domain" is never
        ambiguous between two simultaneously-verified rows."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE domain_verifications SET status = 'superseded' "
                "WHERE account_id = ? AND domain = ? AND verification_id != ? "
                "AND status IN ('pending', 'verified')",
                (account_id, domain, keep_verification_id),
            )

    # --- continuous monitoring -------------------------------------------

    def create_or_update_monitored_domain(
        self,
        *,
        account_id: str,
        domain: str,
        speed2_enabled: bool,
        passive_interval_hours: int,
        active_interval_hours: int,
        organization_id: str | None = None,
    ) -> MonitoredDomainRecord:
        """Idempotent opt-in/settings-change entry point for
        `POST /domains/{domain}/monitoring` — a second call for the same
        (account, domain) updates `speed2_enabled` in place rather than
        erroring or creating a duplicate row (the table's own UNIQUE
        constraint would reject a duplicate insert anyway; this makes the
        common "toggle speed2 on/off" case a normal, expected call rather
        than a delete-then-recreate dance). Re-enabling `speed2_enabled`
        after it was off schedules the next active scan a full cadence
        out from now, not immediately — the client just asked to start
        monitoring, not to force an immediate scan (POST /scans already
        exists for that).

        `organization_id` defaults to the account's own organization
        (Fase 02) when not given explicitly, and is only ever written on
        the INSERT branch — an already-existing row's organization never
        changes on a settings update."""
        organization_id = organization_id or self.default_organization_id_for_account(account_id)
        now = _now_iso()
        next_passive_due_at = (
            datetime.now(timezone.utc) + timedelta(hours=passive_interval_hours)
        ).isoformat()
        next_active_due_at = (
            (datetime.now(timezone.utc) + timedelta(hours=active_interval_hours)).isoformat()
            if speed2_enabled
            else None
        )
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM monitored_domains WHERE account_id = ? AND domain = ?",
                (account_id, domain),
            ).fetchone()
            if existing is None:
                monitoring_id = secrets.token_hex(16)
                conn.execute(
                    "INSERT INTO monitored_domains "
                    "(monitoring_id, account_id, domain, speed2_enabled, status, "
                    "next_passive_due_at, next_active_due_at, needs_review, created_at, "
                    "updated_at, organization_id) VALUES (?, ?, ?, ?, 'active', ?, ?, 0, ?, ?, ?)",
                    (
                        monitoring_id,
                        account_id,
                        domain,
                        int(speed2_enabled),
                        next_passive_due_at,
                        next_active_due_at,
                        now,
                        now,
                        organization_id,
                    ),
                )
            else:
                monitoring_id = existing["monitoring_id"]
                # Only `next_active_due_at` is (re)armed here, and only
                # when speed2 was OFF and is now being turned ON — a
                # domain already being actively monitored keeps its
                # existing schedule rather than getting pushed back out
                # every time the client re-POSTs the same settings.
                set_next_active = speed2_enabled and not existing["speed2_enabled"]
                conn.execute(
                    "UPDATE monitored_domains SET speed2_enabled = ?, "
                    "next_active_due_at = CASE WHEN ? THEN ? ELSE next_active_due_at END, "
                    "updated_at = ? WHERE monitoring_id = ?",
                    (
                        int(speed2_enabled),
                        int(set_next_active),
                        next_active_due_at,
                        now,
                        monitoring_id,
                    ),
                )
            row = conn.execute(
                "SELECT * FROM monitored_domains WHERE monitoring_id = ?", (monitoring_id,)
            ).fetchone()
        return _monitored_domain_record_from_row(row)

    def get_monitored_domain(self, account_id: str, domain: str) -> MonitoredDomainRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM monitored_domains WHERE account_id = ? AND domain = ?",
                (account_id, domain),
            ).fetchone()
        return None if row is None else _monitored_domain_record_from_row(row)

    def list_monitored_domains_for_account(self, account_id: str) -> list[MonitoredDomainRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM monitored_domains WHERE account_id = ? ORDER BY domain",
                (account_id,),
            ).fetchall()
        return [_monitored_domain_record_from_row(row) for row in rows]

    def delete_monitored_domain(self, account_id: str, domain: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM monitored_domains WHERE account_id = ? AND domain = ?",
                (account_id, domain),
            )
        return cursor.rowcount > 0

    def set_monitoring_status(
        self, monitoring_id: str, status: str, *, needs_review: bool | None = None
    ) -> None:
        with self._connect() as conn:
            if needs_review is None:
                conn.execute(
                    "UPDATE monitored_domains SET status = ?, updated_at = ? "
                    "WHERE monitoring_id = ?",
                    (status, _now_iso(), monitoring_id),
                )
            else:
                conn.execute(
                    "UPDATE monitored_domains SET status = ?, needs_review = ?, updated_at = ? "
                    "WHERE monitoring_id = ?",
                    (status, int(needs_review), _now_iso(), monitoring_id),
                )

    def list_due_passive_monitoring_page(
        self, *, due_before: str, cursor: tuple[str, str] | None, limit: int
    ) -> list[MonitoredDomainRecord]:
        """Keyset pagination (never OFFSET) over every row whose
        `next_passive_due_at` has already passed — `cursor` is the
        `(next_passive_due_at, monitoring_id)` of the last row the
        PREVIOUS page returned; passing it again re-scans the same
        `idx_monitored_domains_passive_due` index range starting just
        past that row, an O(page size) operation regardless of how many
        pages came before it or how large the table has grown (an OFFSET
        of 250,000 would instead force SQLite to walk and discard a
        quarter-million rows on every single page). `None` starts from
        the beginning of the due set. This is a READ ONLY operation — a
        row is not "claimed" by being returned here, unlike
        `claim_next_queued_scan`'s scan-queue equivalent; the caller
        advances `next_passive_due_at` itself, per-row, only after that
        row's work actually succeeds (see `batch_record_monitoring_progress`)."""
        with self._connect() as conn:
            if cursor is None:
                rows = conn.execute(
                    "SELECT * FROM monitored_domains WHERE "
                    "pending_passive_scan_id IS NULL AND next_passive_due_at <= ? "
                    "ORDER BY next_passive_due_at, monitoring_id LIMIT ?",
                    (due_before, limit),
                ).fetchall()
            else:
                cursor_due_at, cursor_id = cursor
                rows = conn.execute(
                    "SELECT * FROM monitored_domains WHERE "
                    "pending_passive_scan_id IS NULL AND next_passive_due_at <= ? "
                    "AND (next_passive_due_at, monitoring_id) > (?, ?) "
                    "ORDER BY next_passive_due_at, monitoring_id LIMIT ?",
                    (due_before, cursor_due_at, cursor_id, limit),
                ).fetchall()
        return [_monitored_domain_record_from_row(row) for row in rows]

    def list_due_active_monitoring_page(
        self, *, due_before: str, cursor: tuple[str, str] | None, limit: int
    ) -> list[MonitoredDomainRecord]:
        """Speed 2's equivalent of `list_due_passive_monitoring_page` —
        same keyset-pagination shape, scoped to `speed2_enabled` rows
        whose `next_active_due_at` (never NULL for those rows) has
        passed.

        `status != 'needs_review'` is enforced HERE, at the query level
        — deliberately a DIFFERENT mechanism from how
        `'paused_verification_lapsed'` is handled (that state is instead
        re-checked every cycle inside `_try_enqueue_one`, in Python, so a
        verification that quietly becomes fresh again resumes monitoring
        on the very next poll with no action required). `needs_review`
        has no equivalent "became fresh again" condition to poll for —
        Part B's asset-count sanity ceiling exists precisely because a
        human is expected to look, and the task's own explicit
        requirement is that NOTHING auto-clears it, ever, no matter how
        many cycles pass or how the count changes. Excluding it from the
        due set entirely is simpler and correct for that "only an
        explicit action changes this" semantics — there is nothing to
        re-check on a schedule, unlike verification freshness. Clearing
        it (`clear_needs_review`, via `POST
        /domains/{domain}/monitoring/acknowledge`) does not need to
        touch `next_active_due_at` either: it was never advanced while
        the domain was excluded here, so the moment `status` changes
        back to `'active'` the row is already due again, and Speed 2
        resumes on the very next cycle without any special-cased
        "resume" logic of its own."""
        with self._connect() as conn:
            if cursor is None:
                rows = conn.execute(
                    "SELECT * FROM monitored_domains WHERE speed2_enabled = 1 "
                    "AND status != 'needs_review' "
                    "AND pending_active_scan_id IS NULL "
                    "AND next_active_due_at IS NOT NULL AND next_active_due_at <= ? "
                    "ORDER BY next_active_due_at, monitoring_id LIMIT ?",
                    (due_before, limit),
                ).fetchall()
            else:
                cursor_due_at, cursor_id = cursor
                rows = conn.execute(
                    "SELECT * FROM monitored_domains WHERE speed2_enabled = 1 "
                    "AND status != 'needs_review' "
                    "AND pending_active_scan_id IS NULL "
                    "AND next_active_due_at IS NOT NULL AND next_active_due_at <= ? "
                    "AND (next_active_due_at, monitoring_id) > (?, ?) "
                    "ORDER BY next_active_due_at, monitoring_id LIMIT ?",
                    (due_before, cursor_due_at, cursor_id, limit),
                ).fetchall()
        return [_monitored_domain_record_from_row(row) for row in rows]

    def clear_needs_review(self, account_id: str, domain: str) -> bool:
        """The human-acknowledge action `POST
        /domains/{domain}/monitoring/acknowledge` performs — the ONLY
        way a `needs_review` domain's status ever changes, by design.
        Only actually updates a row currently IN `needs_review` (mirrors
        `revoke_key`'s "only act on the state this call is meaningful
        for" discipline) — the router turns a `False` return into a
        clear "nothing to acknowledge" response rather than a silent
        no-op success, so a client can't mistake "already fine" for "I
        just cleared something real"."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE monitored_domains SET status = 'active', needs_review = 0, "
                "updated_at = ? WHERE account_id = ? AND domain = ? AND status = 'needs_review'",
                (_now_iso(), account_id, domain),
            )
        return cursor.rowcount > 0

    def mark_monitoring_scan_enqueued(
        self, monitoring_id: str, *, speed: Literal["passive", "active"], scan_id: str
    ) -> None:
        """Phase 1 ("enqueue") — sets the pending marker so this row
        drops out of `list_due_*_monitoring_page` until the scan is
        harvested, without touching `next_*_due_at` (that only advances
        at harvest time, in `batch_record_monitoring_progress`)."""
        column = "pending_passive_scan_id" if speed == "passive" else "pending_active_scan_id"
        with self._connect() as conn:
            conn.execute(
                f"UPDATE monitored_domains SET {column} = ?, updated_at = ? "  # noqa: S608  # nosec B608
                "WHERE monitoring_id = ?",
                (scan_id, _now_iso(), monitoring_id),
            )

    def list_pending_monitoring_harvest(
        self, *, speed: Literal["passive", "active"]
    ) -> list[MonitoredDomainRecord]:
        """Phase 2's candidate list — every row with an in-flight
        scheduled scan of this speed. Deliberately not keyset-paginated:
        at any given moment this is bounded by how many scans can
        possibly be `queued`/`running` at once (`max_concurrent_scans`
        globally, or a small multiple of it across accounts), never by
        the total monitored-domain count — a fundamentally different,
        much smaller set than the "due to enqueue" scan `list_due_*`
        methods above have to handle at 300k-row scale."""
        column = "pending_passive_scan_id" if speed == "passive" else "pending_active_scan_id"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM monitored_domains WHERE {column} IS NOT NULL"  # noqa: S608  # nosec B608
            ).fetchall()
        return [_monitored_domain_record_from_row(row) for row in rows]

    def batch_record_monitoring_progress(
        self, updates: list[dict], *, notifications: list[dict] | None = None
    ) -> None:
        """The batched-write half of the scale requirement: one
        transaction per call (never one commit per row, and never one
        giant unbounded transaction for an entire cycle) — the caller
        (`api/monitoring_worker.py`) chunks `updates` into
        `api_settings.monitoring_batch_size`-sized lists (500-1000 rows,
        the same range `api/reconciliation_worker.py`'s own retention-
        purge batching precedent uses) before calling this, so a single
        call's transaction never holds SQLite's write lock long enough to
        meaningfully delay a concurrent `claim_next_queued_scan`/
        `create_scan` write from the scan queue.

        Each dict: monitoring_id, speed(str, 'passive'|'active'), scan_id,
        ran_at (iso), next_due_at (iso), asset_digest, asset_count,
        needs_review (bool), status. Uses `executemany` — one prepared
        statement, N bindings — rather than N separate `execute` calls,
        which is what actually makes a 500-1000 row batch fast rather
        than just fewer-transactions-but-still-row-at-a-time.

        `notifications` (optional): the `MonitoringRunOutcome`-shaped
        dicts worth emailing, inserted into the durable
        `monitoring_pending_notifications` outbox IN THE SAME TRANSACTION
        as the row updates above — see that table's own schema comment
        for why this atomicity is the actual fix for a real lost-
        notification bug, not just tidiness."""
        if not updates and not notifications:
            return
        now = _now_iso()
        passive_rows = [
            (
                u["scan_id"],
                u["ran_at"],
                u["next_due_at"],
                u["asset_digest"],
                u["asset_count"],
                int(u["needs_review"]),
                u["status"],
                now,
                u["monitoring_id"],
            )
            for u in updates
            if u["speed"] == "passive"
        ]
        active_rows = [
            (
                u["scan_id"],
                u["ran_at"],
                u["next_due_at"],
                u["asset_digest"],
                u["asset_count"],
                int(u["needs_review"]),
                u["status"],
                now,
                u["monitoring_id"],
            )
            for u in updates
            if u["speed"] == "active"
        ]
        with self._connect() as conn:
            if passive_rows:
                conn.executemany(
                    "UPDATE monitored_domains SET last_passive_scan_id = ?, "
                    "last_passive_run_at = ?, next_passive_due_at = ?, last_asset_digest = ?, "
                    "last_asset_count = ?, needs_review = ?, status = ?, updated_at = ?, "
                    "pending_passive_scan_id = NULL "
                    "WHERE monitoring_id = ?",
                    passive_rows,
                )
            if active_rows:
                conn.executemany(
                    "UPDATE monitored_domains SET last_active_scan_id = ?, "
                    "last_active_run_at = ?, next_active_due_at = ?, last_asset_digest = ?, "
                    "last_asset_count = ?, needs_review = ?, status = ?, updated_at = ?, "
                    "pending_active_scan_id = NULL "
                    "WHERE monitoring_id = ?",
                    active_rows,
                )
            if notifications:
                conn.executemany(
                    "INSERT INTO monitoring_pending_notifications "
                    "(notification_id, account_id, domain, speed, scan_id, hosts_added_json, "
                    "hosts_removed_json, asset_count, asset_digest, needs_review, "
                    "review_reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            secrets.token_hex(16),
                            n["account_id"],
                            n["domain"],
                            n["speed"],
                            n["scan_id"],
                            json.dumps(n["hosts_added"]),
                            json.dumps(n["hosts_removed"]),
                            n["asset_count"],
                            n["asset_digest"],
                            int(n["needs_review"]),
                            n["review_reason"],
                            now,
                        )
                        for n in notifications
                    ],
                )

    def list_unsent_notifications(self) -> list[dict]:
        """Every row still `sent_at IS NULL`, from ANY past cycle — not
        scoped to "this cycle's own outcomes" the way the old in-memory
        `outcomes_by_account` dict was, which is exactly what makes this
        durable: a notification stranded by a cycle that crashed before
        reaching its own send step is still here, waiting, for the very
        next cycle (this process or another) to pick up. Returns plain
        dicts (already `json.loads`-ed) rather than a dataclass — the
        caller reconstructs `MonitoringRunOutcome` objects from these to
        reuse the existing ordering/rendering logic unchanged."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM monitoring_pending_notifications WHERE sent_at IS NULL "
                "ORDER BY created_at"
            ).fetchall()
        return [
            {
                "notification_id": row["notification_id"],
                "account_id": row["account_id"],
                "domain": row["domain"],
                "speed": row["speed"],
                "scan_id": row["scan_id"],
                "hosts_added": json.loads(row["hosts_added_json"]),
                "hosts_removed": json.loads(row["hosts_removed_json"]),
                "asset_count": row["asset_count"],
                "asset_digest": row["asset_digest"],
                "needs_review": bool(row["needs_review"]),
                "review_reason": row["review_reason"],
            }
            for row in rows
        ]

    def mark_notifications_sent(self, notification_ids: list[str]) -> None:
        """Called only AFTER `EmailSender.send_monitoring_alert` has
        actually returned successfully for the account those ids belong
        to — the deliberate ordering (send, then mark) that makes "at
        most one duplicate on a crash" the failure mode instead of
        silent loss: a crash between the send and this call means the
        next cycle's `list_unsent_notifications` finds the row again and
        re-sends it, never drops it."""
        if not notification_ids:
            return
        now = _now_iso()
        with self._connect() as conn:
            conn.executemany(
                "UPDATE monitoring_pending_notifications SET sent_at = ? WHERE notification_id = ?",
                [(now, nid) for nid in notification_ids],
            )

    def count_monitored_domains(self) -> int:
        """Test/observability helper — not on any hot path."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM monitored_domains").fetchone()
        return int(row["c"])

    # --- outbound webhooks -------------------------------------------

    def count_webhooks_for_account(self, account_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM webhooks WHERE account_id = ?", (account_id,)
            ).fetchone()
        return int(row["c"])

    def create_webhook(
        self,
        *,
        account_id: str,
        url: str,
        secret: str,
        event_types: tuple[str, ...],
        organization_id: str | None = None,
    ) -> WebhookRecord:
        """`organization_id` defaults to the account's own organization
        (Fase 02) when not given explicitly — see `create_scan`'s
        identical note."""
        organization_id = organization_id or self.default_organization_id_for_account(account_id)
        webhook_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO webhooks "
                "(webhook_id, account_id, url, secret, event_types_json, status, "
                "consecutive_failures, created_at, updated_at, organization_id) "
                "VALUES (?, ?, ?, ?, ?, 'active', 0, ?, ?, ?)",
                (
                    webhook_id,
                    account_id,
                    url,
                    secret,
                    json.dumps(list(event_types)),
                    now,
                    now,
                    organization_id,
                ),
            )
        return WebhookRecord(
            webhook_id=webhook_id,
            account_id=account_id,
            url=url,
            secret=secret,
            event_types=event_types,
            status="active",
            consecutive_failures=0,
            last_delivery_at=None,
            organization_id=organization_id,
            last_success_at=None,
            last_error=None,
            created_at=now,
            updated_at=now,
        )

    def get_webhook(self, webhook_id: str, account_id: str) -> WebhookRecord | None:
        """The same Part F.3 double-check every other account-scoped
        lookup in this file already enforces — a webhook_id that exists
        but belongs to a different account returns `None`, identical to
        one that doesn't exist at all, never a 403 that would confirm
        its existence to a non-owner."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhooks WHERE webhook_id = ? AND account_id = ?",
                (webhook_id, account_id),
            ).fetchone()
        return None if row is None else _webhook_record_from_row(row)

    def list_webhooks_for_account(self, account_id: str) -> list[WebhookRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhooks WHERE account_id = ? ORDER BY created_at", (account_id,)
            ).fetchall()
        return [_webhook_record_from_row(row) for row in rows]

    def list_active_webhooks_for_event(
        self, account_id: str, event_type: str
    ) -> list[WebhookRecord]:
        """Subscriber lookup for delivery — `status = 'active'` only (a
        disabled webhook is never attempted again automatically), event
        membership checked in Python since SQLite has no native JSON-
        array-contains operator portable across the versions this
        project supports; the per-account webhook count is always small
        (a real, enforced cap — `api/webhooks.py::MAX_WEBHOOKS_PER_ACCOUNT`),
        so this is never a hot-path performance concern."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM webhooks WHERE account_id = ? AND status = 'active'", (account_id,)
            ).fetchall()
        return [
            record
            for row in rows
            if event_type in (record := _webhook_record_from_row(row)).event_types
        ]

    def delete_webhook(self, webhook_id: str, account_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM webhooks WHERE webhook_id = ? AND account_id = ?",
                (webhook_id, account_id),
            )
        return cursor.rowcount > 0

    def record_webhook_delivery_success(self, webhook_id: str) -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE webhooks SET consecutive_failures = 0, last_delivery_at = ?, "
                "last_success_at = ?, last_error = NULL, updated_at = ? WHERE webhook_id = ?",
                (now, now, now, webhook_id),
            )

    def record_webhook_delivery_failure(
        self, webhook_id: str, *, error: str, disable_after: int
    ) -> None:
        """One atomic UPDATE decides both the incremented failure count
        AND whether that increment crosses the disable threshold — never
        a read-then-write pair, which would leave a window where a
        concurrent successful delivery's reset could be silently
        overwritten by a failure recorded from a stale read."""
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE webhooks SET consecutive_failures = consecutive_failures + 1, "
                "last_delivery_at = ?, last_error = ?, updated_at = ?, "
                "status = CASE WHEN consecutive_failures + 1 >= ? THEN 'disabled' ELSE status END "
                "WHERE webhook_id = ?",
                (now, error, now, disable_after, webhook_id),
            )

    # --- subscriptions / tiers (Part B, Round 3) ------------------------

    def create_default_subscription(self, account_id: str, *, tier: str = "free") -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO subscriptions "
                "(account_id, tier, status, created_at, updated_at) "
                "VALUES (?, ?, 'active', ?, ?)",
                (account_id, tier, now, now),
            )

    def get_subscription(self, account_id: str) -> SubscriptionRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM subscriptions WHERE account_id = ?", (account_id,)
            ).fetchone()
        return None if row is None else _subscription_record_from_row(row)

    def set_tier(
        self,
        account_id: str,
        tier: str,
        *,
        status: str = "active",
        billing_email: str | None = None,
    ) -> None:
        """`billing_email` is only ever passed (and only ever overwrites
        the stored value) when a NEW paid activation just happened
        (`api/routers/subscription.py`'s webhook handler) — a plain
        upgrade/downgrade call (`POST /account/subscription` for
        tier='free', or the admin reconciliation endpoint) leaves
        whatever billing email is already on file untouched."""
        with self._connect() as conn:
            if billing_email is not None:
                conn.execute(
                    "UPDATE subscriptions SET tier = ?, status = ?, billing_email = ?, "
                    "grace_period_started_at = NULL, updated_at = ? WHERE account_id = ?",
                    (tier, status, billing_email.strip().lower(), _now_iso(), account_id),
                )
            else:
                conn.execute(
                    "UPDATE subscriptions SET tier = ?, status = ?, "
                    "grace_period_started_at = NULL, updated_at = ? WHERE account_id = ?",
                    (tier, status, _now_iso(), account_id),
                )

    def find_account_id_by_billing_email(self, billing_email: str) -> str | None:
        """Correlates a RECURRING charge webhook (success or failure) —
        one that arrives after the original `wompi_pending_enrollments`
        row already did its one job — back to the account it belongs to.
        Same "no guessing" discipline as
        `find_pending_enrollment_by_email`: more than one account
        sharing a billing email is unusual enough to not guess between,
        so only an exact single match resolves."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id FROM subscriptions WHERE billing_email = ?",
                (billing_email.strip().lower(),),
            ).fetchall()
        if len(rows) != 1:
            return None
        return rows[0]["account_id"]

    def set_subscription_status(
        self, account_id: str, status: str, *, grace_period_started_at: str | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE subscriptions SET status = ?, grace_period_started_at = ?, "
                "updated_at = ? WHERE account_id = ?",
                (status, grace_period_started_at, _now_iso(), account_id),
            )

    # --- scheduled reconciliation (grace-period enforcement, Part D.3) --

    def list_past_due_account_ids(self) -> list[str]:
        """The candidate list `api/reconciliation_worker.py`'s grace-
        period job starts from — deliberately just account_ids, not
        full `SubscriptionRecord`s: the job re-reads each one fresh
        (`get_subscription`) right before acting on it, so a row this
        query saw as `'past_due'` a moment ago but that has since been
        resolved (a payment landed, `restore_active_status`) is never
        acted on based on this now-stale snapshot."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT account_id FROM subscriptions WHERE status = 'past_due'"
            ).fetchall()
        return [row["account_id"] for row in rows]

    def suspend_if_still_past_due(self, account_id: str) -> bool:
        """Atomically suspends `account_id` ONLY if its subscription is
        STILL `'past_due'` at the exact moment this statement executes
        — the same single-statement, conditional-UPDATE discipline
        `claim_next_queued_scan` uses to close a claim race, applied
        here to close the analogous race against a payment webhook
        restoring the account to `'active'` in a different worker
        process between this job's fresh re-read and its write. Returns
        whether a row was actually changed (i.e., whether this call is
        the one that suspended it) — `False` means something else
        already moved the account off `'past_due'` first, and this call
        correctly did nothing."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE subscriptions SET status = 'suspended', updated_at = ? "
                "WHERE account_id = ? AND status = 'past_due'",
                (_now_iso(), account_id),
            )
        return cursor.rowcount > 0

    # --- scheduled reconciliation (retention purge, Part B) --------------

    def list_account_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT account_id FROM accounts").fetchall()
        return [row["account_id"] for row in rows]

    def list_purgeable_scans_for_account(
        self, account_id: str, *, cutoff: str, limit: int
    ) -> list[ScanRecord]:
        """Every scan of this account old enough (`created_at < cutoff`,
        the account's own effective retention window) to purge —
        `status IN ('completed', 'failed')` is enforced HERE, in the
        query itself, not as a filter the caller has to remember to
        apply: a `'running'` or `'queued'` scan can never be a
        candidate no matter how old its `created_at` is, regardless of
        how long an unusually slow scan has been executing."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE account_id = ? "
                "AND status IN ('completed', 'failed') AND created_at < ? "
                "ORDER BY created_at ASC LIMIT ?",
                (account_id, cutoff, limit),
            ).fetchall()
        return [_scan_record_from_row(row) for row in rows]

    def delete_scan(self, scan_id: str, account_id: str) -> None:
        """Deletes the control-plane `scans` row only — the caller
        (`api/reconciliation_worker.py`) is responsible for removing
        the corresponding `output/<scan_id>/` directory on disk itself,
        since that's filesystem, not database, state. Idempotent:
        deleting a `scan_id` that's already gone affects zero rows and
        raises nothing, so running the purge job twice in a row is a
        safe no-op the second time."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM scans WHERE scan_id = ? AND account_id = ?", (scan_id, account_id)
            )

    def set_retention_override(self, account_id: str, retention_days: int | None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE subscriptions SET retention_days_override = ?, updated_at = ? "
                "WHERE account_id = ?",
                (retention_days, _now_iso(), account_id),
            )

    def set_white_label_branding(self, account_id: str, company_name: str | None) -> None:
        """`company_name=None` clears the account's configured branding
        (`PUT /account/branding {"company_name": null}` — same "set to
        remove" convention `set_retention_override` already uses, no
        separate delete endpoint needed)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE subscriptions SET white_label_company_name = ?, updated_at = ? "
                "WHERE account_id = ?",
                (company_name, _now_iso(), account_id),
            )

    # --- monthly usage (Part B) -----------------------------------------

    def get_monthly_usage(self, account_id: str, period_key: str) -> MonthlyUsageRecord:
        """Always returns a record — a period with no activity yet is
        all-zeros, never `None`, so callers never need a separate
        "no row yet" branch just to compare against a limit."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM monthly_usage WHERE account_id = ? AND period_key = ?",
                (account_id, period_key),
            ).fetchone()
        if row is None:
            return MonthlyUsageRecord(
                account_id=account_id,
                period_key=period_key,
                scans_used=0,
                reportability_spend_usd=0.0,
                hypotheses_spend_usd=0.0,
            )
        return MonthlyUsageRecord(
            account_id=row["account_id"],
            period_key=row["period_key"],
            scans_used=row["scans_used"],
            reportability_spend_usd=row["reportability_spend_usd"],
            hypotheses_spend_usd=row["hypotheses_spend_usd"],
        )

    def increment_scan_usage(self, account_id: str, period_key: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monthly_usage (account_id, period_key, scans_used) "
                "VALUES (?, ?, 1) "
                "ON CONFLICT(account_id, period_key) "
                "DO UPDATE SET scans_used = scans_used + 1",
                (account_id, period_key),
            )

    def add_llm_spend(
        self, account_id: str, period_key: str, *, feature: str, amount_usd: float
    ) -> None:
        # column is one of exactly two hardcoded literals chosen above,
        # never external input — same "identifier is a literal, values
        # are bound params" shape as core/store.py::get_findings's own
        # dynamic-column query (also suppressed below for the same reason).
        column = "reportability_spend_usd" if feature == "reportability" else "hypotheses_spend_usd"
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO monthly_usage (account_id, period_key, {column}) "  # noqa: S608  # nosec B608
                f"VALUES (?, ?, ?) "
                f"ON CONFLICT(account_id, period_key) "
                f"DO UPDATE SET {column} = {column} + excluded.{column}",
                (account_id, period_key, amount_usd),
            )

    # --- cost estimates (Part E.1, extended to LLM features) -----------

    def create_cost_estimate(
        self,
        *,
        account_id: str,
        scan_id: str,
        feature: str,
        provider: str,
        adversarial_provider: str | None,
        degraded_from_adversarial: bool,
        estimated_cost_usd: float,
        params_json: str,
        ttl_minutes: int = 10,
    ) -> CostEstimateRecord:
        estimate_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()
        created_at = now.isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cost_estimates (estimate_id, account_id, scan_id, feature, "
                "provider, adversarial_provider, degraded_from_adversarial, "
                "estimated_cost_usd, params_json, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    estimate_id,
                    account_id,
                    scan_id,
                    feature,
                    provider,
                    adversarial_provider,
                    int(degraded_from_adversarial),
                    estimated_cost_usd,
                    params_json,
                    created_at,
                    expires_at,
                ),
            )
        return CostEstimateRecord(
            estimate_id=estimate_id,
            account_id=account_id,
            scan_id=scan_id,
            feature=feature,
            provider=provider,
            adversarial_provider=adversarial_provider,
            degraded_from_adversarial=degraded_from_adversarial,
            estimated_cost_usd=estimated_cost_usd,
            params_json=params_json,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
        )

    def get_valid_cost_estimate(
        self, estimate_id: str, account_id: str, *, scan_id: str, feature: str
    ) -> CostEstimateRecord | None:
        """Only returns a row that is this account's, for this exact
        scan+feature, unexpired, AND not already consumed — the same
        single-use/short-lived/bound-to-what-was-shown discipline Part
        E.1 established for the scan cost-estimate flow."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cost_estimates WHERE estimate_id = ? AND account_id = ? "
                "AND scan_id = ? AND feature = ? AND consumed_at IS NULL "
                "AND expires_at > ?",
                (estimate_id, account_id, scan_id, feature, _now_iso()),
            ).fetchone()
        return None if row is None else _cost_estimate_record_from_row(row)

    def consume_cost_estimate(self, estimate_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE cost_estimates SET consumed_at = ? WHERE estimate_id = ?",
                (_now_iso(), estimate_id),
            )

    # --- Wompi billing (Part D, Round 3) --------------------------------

    def create_pending_enrollment(
        self, *, account_id: str, tier: str, billing_email: str
    ) -> WompiPendingEnrollmentRecord:
        """A real gap a live sandbox attempt surfaced: a client that
        calls `POST /account/subscription` more than once before ever
        completing payment (retrying because nothing seemed to happen,
        changing their mind on tier, or simply double-clicking) used to
        accumulate multiple `'pending'` rows for the same account.
        `find_pending_enrollment_by_email` correctly refuses to guess
        between more than one match — but that means a LATER, genuinely
        successful webhook would silently fall through to
        `wompi_unmatched_payments` instead of activating anything,
        indistinguishable from a real correlation failure. Superseding
        this account's own other still-`'pending'` rows first (same
        pattern `supersede_other_verifications` already uses for domain
        verification) means only the MOST RECENT upgrade attempt is ever
        a live candidate — exactly matching what a real user actually
        wants ("I asked to upgrade again, that's the one that should
        count"), and it can never be forgotten by a future caller since
        it happens here, not at each call site."""
        enrollment_id = secrets.token_hex(16)
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE wompi_pending_enrollments SET status = 'superseded' "
                "WHERE account_id = ? AND status = 'pending'",
                (account_id,),
            )
            conn.execute(
                "INSERT INTO wompi_pending_enrollments "
                "(enrollment_id, account_id, tier, billing_email, status, created_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (enrollment_id, account_id, tier, billing_email.strip().lower(), now),
            )
        return WompiPendingEnrollmentRecord(
            enrollment_id=enrollment_id,
            account_id=account_id,
            tier=tier,
            billing_email=billing_email.strip().lower(),
            status="pending",
            created_at=now,
            matched_at=None,
        )

    def find_pending_enrollment_by_email(
        self, billing_email: str, *, tier: str | None = None
    ) -> WompiPendingEnrollmentRecord | None:
        """The best-effort webhook->account correlation (documented as
        unconfirmed against a real Wompi sandbox — see
        docs/PAID_API_DESIGN.md's "Round 3 implemented" section). Matches
        the most recent still-'pending' enrollment for this email,
        optionally narrowed by tier/product. Returns None (never a
        guess) when there's no unambiguous match — the caller then routes
        to manual reconciliation instead of activating anything."""
        query = (
            "SELECT * FROM wompi_pending_enrollments "
            "WHERE billing_email = ? AND status = 'pending'"
        )
        params: list[str] = [billing_email.strip().lower()]
        if tier is not None:
            query += " AND tier = ?"
            params.append(tier)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        if len(rows) != 1:
            # Zero matches: nothing pending for this email. More than
            # one: ambiguous (e.g. two different tier upgrades requested
            # with the same email) — neither case is safe to guess from.
            return None
        return _pending_enrollment_record_from_row(rows[0])

    def mark_enrollment_matched(self, enrollment_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE wompi_pending_enrollments SET status = 'matched', matched_at = ? "
                "WHERE enrollment_id = ?",
                (_now_iso(), enrollment_id),
            )

    def webhook_event_already_processed(self, transaction_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM wompi_webhook_events WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
        return row is not None

    def record_webhook_event(
        self,
        *,
        transaction_id: str,
        outcome: str,
        matched_account_id: str | None,
        raw_body: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wompi_webhook_events "
                "(transaction_id, outcome, matched_account_id, raw_body, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (transaction_id, outcome, matched_account_id, raw_body, _now_iso()),
            )

    def create_unmatched_payment(
        self,
        *,
        transaction_id: str,
        payer_email: str | None,
        product_name: str | None,
        amount: float | None,
        raw_body: str,
    ) -> str:
        unmatched_id = secrets.token_hex(16)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO wompi_unmatched_payments "
                "(unmatched_id, transaction_id, payer_email, product_name, amount, "
                "raw_body, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    unmatched_id,
                    transaction_id,
                    payer_email,
                    product_name,
                    amount,
                    raw_body,
                    _now_iso(),
                ),
            )
        return unmatched_id

    def get_unresolved_payments(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM wompi_unmatched_payments WHERE resolved_at IS NULL "
                "ORDER BY received_at ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def resolve_unmatched_payment(self, unmatched_id: str, *, account_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE wompi_unmatched_payments SET resolved_at = ?, resolved_account_id = ? "
                "WHERE unmatched_id = ? AND resolved_at IS NULL",
                (_now_iso(), account_id, unmatched_id),
            )
        return cursor.rowcount > 0


def _subscription_record_from_row(row: sqlite3.Row) -> SubscriptionRecord:
    return SubscriptionRecord(
        account_id=row["account_id"],
        tier=row["tier"],
        status=row["status"],
        billing_email=row["billing_email"],
        grace_period_started_at=row["grace_period_started_at"],
        retention_days_override=row["retention_days_override"],
        white_label_company_name=row["white_label_company_name"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _cost_estimate_record_from_row(row: sqlite3.Row) -> CostEstimateRecord:
    return CostEstimateRecord(
        estimate_id=row["estimate_id"],
        account_id=row["account_id"],
        scan_id=row["scan_id"],
        feature=row["feature"],
        provider=row["provider"],
        adversarial_provider=row["adversarial_provider"],
        degraded_from_adversarial=bool(row["degraded_from_adversarial"]),
        estimated_cost_usd=row["estimated_cost_usd"],
        params_json=row["params_json"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def _pending_enrollment_record_from_row(row: sqlite3.Row) -> WompiPendingEnrollmentRecord:
    return WompiPendingEnrollmentRecord(
        enrollment_id=row["enrollment_id"],
        account_id=row["account_id"],
        tier=row["tier"],
        billing_email=row["billing_email"],
        status=row["status"],
        created_at=row["created_at"],
        matched_at=row["matched_at"],
    )


def _verification_record_from_row(row: sqlite3.Row) -> DomainVerificationRecord:
    return DomainVerificationRecord(
        verification_id=row["verification_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        token=row["token"],
        method=row["method"],
        status=row["status"],
        created_at=row["created_at"],
        verified_at=row["verified_at"],
        expires_at=row["expires_at"],
        last_checked_at=row["last_checked_at"],
        last_check_error=row["last_check_error"],
        organization_id=row["organization_id"],
    )


def _key_record_from_row(row: sqlite3.Row) -> ApiKeyRecord:
    return ApiKeyRecord(
        key_id=row["key_id"],
        account_id=row["account_id"],
        prefix=row["prefix"],
        created_at=row["created_at"],
        revoked_at=row["revoked_at"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
    )


def _scan_record_from_row(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        scan_id=row["scan_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        db_path=row["db_path"],
        status=row["status"],
        error_message=row["error_message"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        retry_count=row["retry_count"],
        worker_id=row["worker_id"],
        heartbeat_at=row["heartbeat_at"],
        trigger_source=row["trigger_source"],
        organization_id=row["organization_id"],
    )


def _monitored_domain_record_from_row(row: sqlite3.Row) -> MonitoredDomainRecord:
    return MonitoredDomainRecord(
        monitoring_id=row["monitoring_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        speed2_enabled=bool(row["speed2_enabled"]),
        status=row["status"],
        last_passive_scan_id=row["last_passive_scan_id"],
        last_active_scan_id=row["last_active_scan_id"],
        last_passive_run_at=row["last_passive_run_at"],
        last_active_run_at=row["last_active_run_at"],
        next_passive_due_at=row["next_passive_due_at"],
        next_active_due_at=row["next_active_due_at"],
        pending_passive_scan_id=row["pending_passive_scan_id"],
        pending_active_scan_id=row["pending_active_scan_id"],
        last_asset_digest=row["last_asset_digest"],
        last_asset_count=row["last_asset_count"],
        needs_review=bool(row["needs_review"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        organization_id=row["organization_id"],
    )


def _webhook_record_from_row(row: sqlite3.Row) -> WebhookRecord:
    return WebhookRecord(
        webhook_id=row["webhook_id"],
        account_id=row["account_id"],
        url=row["url"],
        secret=row["secret"],
        event_types=tuple(json.loads(row["event_types_json"])),
        status=row["status"],
        consecutive_failures=row["consecutive_failures"],
        last_delivery_at=row["last_delivery_at"],
        last_success_at=row["last_success_at"],
        last_error=row["last_error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        organization_id=row["organization_id"],
    )


def _asset_record_from_row(row: sqlite3.Row) -> AssetRecord:
    return AssetRecord(
        asset_id=row["asset_id"],
        organization_id=row["organization_id"],
        asset_type=row["asset_type"],
        identity_key=row["identity_key"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        last_seen_run_id=row["last_seen_run_id"],
    )


def _candidate_asset_record_from_row(row: sqlite3.Row) -> CandidateAssetRecord:
    return CandidateAssetRecord(
        candidate_asset_id=row["candidate_asset_id"],
        organization_id=row["organization_id"],
        candidate_type=row["candidate_type"],
        normalized_value=row["normalized_value"],
        display_value=row["display_value"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        first_seen_run_id=row["first_seen_run_id"],
        last_seen_run_id=row["last_seen_run_id"],
        scope_status=row["scope_status"],
        collection_status=row["collection_status"],
        authorization_status=row["authorization_status"],
        reason=row["reason"],
        depth=int(row["depth"]),
        priority=int(row["priority"]),
        collector=row["collector"],
        source_entity_id=row["source_entity_id"],
        parent_indicator_id=row["parent_indicator_id"],
        lineage_reference=row["lineage_reference"],
    )


def _asset_identifier_record_from_row(row: sqlite3.Row) -> AssetIdentifierRecord:
    return AssetIdentifierRecord(
        id=row["id"],
        asset_id=row["asset_id"],
        organization_id=row["organization_id"],
        identifier_type=row["identifier_type"],
        identifier_value=row["identifier_value"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
    )


def _evidence_record_from_row(row: sqlite3.Row) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=row["evidence_id"],
        organization_id=row["organization_id"],
        asset_id=row["asset_id"],
        source=row["source"],
        detail=row["detail"],
        confidence_score=row["confidence_score"],
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        last_seen_run_id=row["last_seen_run_id"],
    )


def _observation_with_evidence_from_row(row: sqlite3.Row) -> ObservationWithEvidence:
    observation = ObservationRecord(
        observation_id=row["observation_id"],
        organization_id=row["organization_id"],
        asset_id=row["asset_id"],
        run_id=row["run_id"],
        account_id=row["account_id"],
        observation_type=row["observation_type"],
        evidence_id=row["evidence_id"],
        observed_at=row["observed_at"],
    )
    evidence = EvidenceRecord(
        evidence_id=row["evidence_id"],
        organization_id=row["e_organization_id"],
        asset_id=row["e_asset_id"],
        source=row["e_source"],
        detail=row["e_detail"],
        confidence_score=row["e_confidence_score"],
        first_seen_at=row["e_first_seen_at"],
        last_seen_at=row["e_last_seen_at"],
        last_seen_run_id=row["e_last_seen_run_id"],
    )
    return ObservationWithEvidence(observation=observation, evidence=evidence)


def _change_event_record_from_row(row: sqlite3.Row) -> ChangeEventRecord:
    return ChangeEventRecord(
        change_event_id=row["change_event_id"],
        organization_id=row["organization_id"],
        asset_id=row["asset_id"],
        run_id=row["run_id"],
        previous_state=row["previous_state"],
        new_state=row["new_state"],
        reason=row["reason"],
        previous_digest=row["previous_digest"],
        new_digest=row["new_digest"],
        detected_at=row["detected_at"],
    )


def _account_record_from_row(row: sqlite3.Row) -> AccountRecord:
    return AccountRecord(
        account_id=row["account_id"],
        created_at=row["created_at"],
        email=row["email"],
        email_verified_at=row["email_verified_at"],
        email_verification_token=row["email_verification_token"],
        email_verification_token_expires_at=row["email_verification_token_expires_at"],
    )
