# Productization Roadmap v2 — closing the gaps in Phases 00–05

Branch: `productization/roadmap-v2-gaps`. Base: `main` @ `c1d1adc` (after
the Phase 05 merge, PR #99).

Roadmap v2 added requirements to phases that had already merged. This
branch closes every one that falls inside Phases 00–05, plus the "partial"
items those phases left open. Later-phase additions (09, 10, 12) are listed
at the end with their status.

Every new endpoint follows the existing tenancy rules: a member can read,
only an owner can change anything, and another organization's IDs return
404 rather than 403. Each endpoint is in the IDOR probe list in
`tests/test_api_easm.py` or has its own foreign-account test.

---

## 1. Capability & Tool Access (v2 cross-cutting invariant, Phase 01 addition)

**Before:** the optional providers a scan ran came from process-wide
`ENABLE_*` flags. An API customer could not choose them, and nothing
enforced tier limits.

**Now** (`api/collection_capabilities.py`, `api/routers/collection.py`):

| Endpoint | Who | What |
|---|---|---|
| `GET /organizations/{org}/collection-settings` | member | Saved default (or built-in default), tier, effective set, what the tier excludes, and the full provider catalog |
| `PUT /organizations/{org}/collection-settings` | owner | Replaces the default. An unknown provider or an always-on one returns `422 invalid_capability_request`. A provider above the tier returns `403 capability_not_entitled` and names the providers. |
| `GET /organizations/{org}/collection-settings/audit` | member | Every default change and scan override: who, before/after, when |
| `POST /scans` `{"providers": [...]}` | owner | Per-scan override, validated before any quota is spent |
| `GET /scans/{id}` | owner of scan | `capability_override` and `effective_providers` (what actually ran) |

- **Resolution order:** scan override, then the org default, then the
  settings' current flags. The result is always clipped to the tier ceiling
  at execution time, so a downgrade takes effect on the next scan.
- **The ceiling is data** (`api/tiers.py::TIER_PROVIDER_INTENSITIES`),
  keyed by the existing provider-intensity classes:
  - Free and Medium: passive, third-party API, and standard active collection.
  - Pro and Ultra: all of the above plus high-volume active collection.
- **No behavior change on day one:** all of today's default-enabled
  providers fit within Free.
- **No per-user toggles.** Tiers and roles are the only levers. The monitoring
  degraded-run check now considers only hostname-producing providers, so a
  failed nuclei run can no longer suppress a host-removal alert.

### Phase 00 addendum — the `ENABLE_*` audit

- **Count:** there are 34 `enable_*` settings. 31 are optional-provider
  toggles, each read only by its own plugin's `is_enabled()`. The other
  three are pipeline switches, not providers: `enable_cache`,
  `enable_followup_collection` and `enable_jq`.
- **API scans no longer depend on `.env` for providers.** They already
  ignored `.env`: `api/tenancy.py::account_settings()` builds a fresh
  `Settings()` per account (the bug Phase 00 recorded). The org/scan
  capability model now sets the 31 provider flags at execution time
  (`api/scan_orchestrator.py::_apply_collection_capabilities`). The flags
  still exist, but for API scans they are an output of the capability
  model, not configuration. The CLI is unchanged.
- **Moving the flags to per-org DB state was safe** because plugins read
  them only through `Settings` at run time, on a per-scan `Settings`
  instance. No module caches them, and none reads them at import time.
- **Not converted:** the three pipeline switches stay operator
  configuration. They change cost and caching, not what is collected
  against a target, so a customer toggle would add risk without product
  value.

---

## 2. Network & Geo Intelligence (Phase 02 addition)

- **Source:** geo comes from a local MaxMind-format database
  (`GEOIP_DB_PATH`, optional `maxminddb` reader, `core/geoip.py`). It is
  layered on the existing Team Cymru ASN lookup (`modules/asn_lookup.py`).
- **No outbound requests.** Every lookup is a local file read, and a test
  refuses all socket use while looking up.
- **What each host records:** country, region, city and coordinates, plus
  the database edition and build date (`geo_source`) and its age at lookup
  time (`geo_db_age_days`).
- **Which country wins:** the geo country (where the IP is) takes priority
  over the registry country (where the block was allocated).
- `GET /organizations/{org}/assets/{asset}/network` returns ASN, BGP prefix,
  hosting provider, IPs and geo. It sets `stale: true` past
  `GEOIP_MAX_AGE_DAYS` (45). **With no database, `geo` is `null`, never a
  guess.**
- **Licensing:** GeoLite2 needs a free MaxMind account. Its EULA requires
  the database to be refreshed, and MaxMind publishes updates about twice a
  week. Hydra does not download it. Operators install it (for example with
  `geoipupdate` on a cron job) and point `GEOIP_DB_PATH` at it. The stale
  flag is the safety net when that stops happening.
- **Failure semantics:** if Cymru is unreachable, `asn_lookup` now reports
  `UNAVAILABLE`, never a clean empty run. The same fix applies to `ctlogs`:
  all queries failing is `UNAVAILABLE`, some failing is `PARTIAL`.

## 3. Visual Intelligence (Phases 02 and 05)

Phase 00 and Phase 02 both found this capability had no EASM wiring.

- `GET /organizations/{org}/assets/{asset}/visual` returns, per URL: title,
  favicon hash and the screenshot artifact reference (a path, never the
  image). It also returns the significant changes since this
  organization's previous run of the target, and the significance rules
  themselves.
- **What counts as a visual change** (`core/visual.py`): only a favicon-hash
  change or a normalized-title change, and only on a URL both runs reached.
  - Screenshot pixels and body hashes are never compared.
  - A signal missing on either side is not a change, because a failed probe
    proves nothing about the page.
- A previous run belonging to another organization of the same account is
  never used for comparison.

## 4. Monitoring alerts (Phase 05 deferrals)

Monitoring notifications now also cite three new signal types:

- `VISUAL_CHANGED` — the visual rule above, comparing against the last good
  baseline run.
- `CANDIDATE_REVIEW` — pending candidates first seen in this run. Capped at
  20, plus one "N more" line.
- `RISK_CHANGED` — an exposure observed in this run whose deterministic
  risk level differs from the last run that observed it. The line includes
  the classifier's reasons.
  - Risk is computed on read, so each run's level is stored in
    `exposure_risk_snapshots`, one row per exposure per run. A retried
    harvest therefore compares the same pair and never double-alerts.
  - An exposure's first classification is not a change; its `OBSERVED`
    citation already covers it.

## 5. Scope exclusions and the five-way distinction (Phase 01)

- `GET/POST /organizations/{org}/scope/exclusions` and
  `DELETE /organizations/{org}/scope/exclusions/{id}` (owner-only for
  changes, reason required).
  - **Pattern syntax:** `host`, `*.host` or `host/path-glob`.
  - **Removal is a soft delete**, so the history (who, when, why) stays
    readable with `include_removed=true`.
- **Enforcement uses the scope engine's existing `!pattern` machinery**
  (`core/scope.py::configured_scope_patterns`), applied to every API scan,
  manual or monitoring.
  - An excluded host and all its subdomains are never probed.
  - A path exclusion blocks only that path subtree.
  - A run whose own target is excluded fails closed (`_enforce_scope`).
  - `POST /scans` refuses such a target up front with
    `422 target_excluded`, before spending quota.
- `GET /organizations/{org}/scope/classify?host=` answers the roadmap's
  required distinction. It checks in this order and returns the first match:
  1. `excluded` — always wins.
  2. `known_asset`
  3. `candidate` — an in-scope candidate still awaiting review.
  4. `observed_related` — an out-of-scope or discarded candidate: kept as
     intelligence, never probed.
  5. `authorized_scope` — covered by a verified domain but not yet
     discovered.
  6. `unknown`

  Each answer includes the reason and the ID of the record it rests on.

## 6. One explanation shape, and the analyst namespace (Phase 03 deferral)

- `GET /organizations/{org}/explanations/{asset|exposure|relationship}/{id}`
  returns the same fields for all three subjects:
  - claim, status and confidence;
  - first and last observed;
  - reasons (for exposures, the risk classifier's reasons);
  - evidence: the newest 20 plus the total count, selected in SQL.
- Evidence is attributed to the **Hydra capability** that produced it
  (`dns`, `http`, `domain_discovery`, …), never to a tool name.
- `GET /organizations/{org}/analyst/assets/{asset}/provenance` is the
  analyst/debug namespace. It returns:
  - raw provider names and evidence detail;
  - the latest run's per-tool provenance records, with artifact paths
    reduced to file names so the server's directory layout isn't exposed.

## 7. Smaller fixes

- Candidate-asset listing now pages in SQL. It had the same load-everything
  bug Phase 02 fixed for assets.
- Methods touched here were kept under Codacy's 50-line limit.
  `execute_scan`, `Host.merge_from` and `ctlogs.run` are shorter than on
  `main`.

---

## Later-phase v2 additions — status

| Phase | v2 addition | Status |
|---|---|---|
| 09 | Qualification verified per invocation (tenant-scoped enablement) | **Done for enablement:** effective providers are resolved and recorded for every scan at execution time. Provider *version* qualification is still Phase 09's work. |
| 09 | Geo DB qualification (edition, freshness, stale = degraded, license renewal, zero outbound) | **Done:** edition and age recorded per lookup, stale flag, renewal documented above, zero-network test. |
| 10 | SQLite → PostgreSQL (settled decision) | **Not started.** This is its own phase: full-graph schema migration, verified dump/transform/load, backup/restore rewrite, RLS. It does not fit in a gap-closing branch. |
| 12 | Tier → capability mapping as data | **Done:** `TIER_PROVIDER_INTENSITIES`. |

**Still open, by design:** notes, assignee and bulk triage on exposures
remain Phase 07, as Phase 04 recorded.
