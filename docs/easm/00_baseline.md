# EASM roadmap — Fase 00 baseline (before Fase 06)

One-time checkpoint before the 16-phase Bloque A–D build (Fases 06–21).
Confirms Fases 01–05 are merged into `main`, restates Fase 01's own
absorb/wrap/coexist decisions per system (binding, not re-opened here),
inventories what exists today across the areas the unified prompt names,
and records the real, current pipeline baseline.

## 1. Fases 01–05 — merged, confirmed directly against `origin/main`

```
35749f6 Merge pull request #57 from Andres-Montoya-SV/feat/easm-change-detection
d15e617 feat(api): add asset lifecycle state and change detection (Fase 05)
5e36b64 Merge pull request #56 from Andres-Montoya-SV/feat/easm-observations
b87d7dd feat(api): add cross-run Observations and Evidence (Fase 04)
0159aed Merge pull request #55 from Andres-Montoya-SV/feat/easm-asset-identity
671c834 feat(api): add cross-run Asset identity and reconciliation (Fase 03)
68aa8aa Merge pull request #54 from Andres-Montoya-SV/feat/easm-organization
c178c1e feat(api): add Organization identity, separate from billing accounts (Fase 02)
c5ddfff Merge pull request #53 from Andres-Montoya-SV/docs/easm-consolidation-plan
ca84cf8 docs(easm): consolidation plan for the EASM domain-model rebuild
```

`00_READ_FIRST.md` still does not exist anywhere in the repository —
confirmed again with `find . -iname "00_READ_FIRST.md"` (zero results),
consistent with every prior phase's own check. Every phase prompt so far
has referenced it without it ever existing; this is flagged, not
silently worked around, per the standing "si el código actual contradice
un documento viejo, manda el código" instruction (there is no
`00_READ_FIRST.md` to contradict, so nothing here depends on it).

## 2. Fase 01's decisions per existing system — restated, binding, not reopened

From `docs/easm/00_consolidation_plan.md` (full detail there; this is the
one-line-per-system summary Bloques A–D need before touching any of
these):

| System | Decision | What that means for Fases 06+ |
|---|---|---|
| `core/intel/model.py` (`Observation`/`Evidence`/`Relationship`/`IntelEntity`, `core/intel/scope.py`, `core/intel/authorize.py`) | **Absorb** | Fase 07's `relationships` table and any future entity work build on this vocabulary; the scope/authorization gate itself is never touched, never re-derived |
| `core/intelligence/` (clustering, graph, profile, risk) | **Absorb with migration** | already the superseded first pass — `core/registry.py:46-61` runs it then `core/intel/`'s richer engine overwrites its graph output; Fase 07 must build the consolidated graph from `intel_relationships`, not `graph_nodes`/`graph_edges` |
| `core/assets.py` (`Host` and sub-entities) | **Coexist**, explicit boundary | `Host` stays the per-run collection result; the EASM `assets` table (Fase 03, already built) is what it reconciles into, never the reverse |
| `api/control_db.py`'s `monitored_domains` | **Wrap**, not silently replaced | the one real pre-existing cross-run identity precedent; Fase 18 (not 06-17) is where its migration to the new model actually happens |
| `core/diff.py` (`ScanDiff`) | **Absorb logic** into a persisted model | done in Fase 05 (`change_events`) — the diffing logic itself was already correct, only needed a durable home |

**What Fases 02–05 actually built on top of this** (all in
`api/control_db.py`, all organization-scoped, all confirmed present in
the schema dump below): `organizations`, `account_organization_roles`
(Fase 02); `assets`, `asset_identifiers` (Fase 03); `evidence`,
`observations` (Fase 04); `change_events` (Fase 05). Pure logic lives
in `api/asset_identity.py`, `api/observation_identity.py`,
`api/change_detection.py`; the backfill/orchestration layer in
`api/asset_backfill.py`, `api/change_backfill.py`. **None of this is
wired into any live path yet** — confirmed by grep: no caller of
`backfill_assets_for_organization`/
`detect_and_record_changes_for_organization` exists anywhere outside
their own tests. This is a real, current fact Bloque D (Fase 18 in
particular) needs, not an assumption.

## 3. Inventory of the areas the unified prompt names

### Security model / network confinement / collection gateway (Invariant 1)

Confirmed present, unmodified by any EASM phase so far (`core/collection/`
was never touched in Fases 02–05):

- `core/collection/target.py::AuthorizedCollectionTarget` — the
  per-request authorization object every active collector must obtain
  before connecting.
- `core/collection/gateway.py::CollectionGateway` — the single gateway
  every tool-issued connection routes through.
- `core/collection/crawler_proxy.py::ScopeEnforcingProxy` — re-validates
  on every redirect hop, not just the initial URL.
- `core/collection/ssrf.py` — `classify_ip`/`resolve_hostname`/
  `validate_destination_ips`, the real SSRF policy (private/loopback/
  metadata-range rejection).
- `core/collection/whois_client.py` — the native, SSRF-validated WHOIS
  client (`docs/NETWORK_CONFINEMENT.md`'s own note: this replaced the
  raw system `whois` binary, the last unconfined case its own
  "Class B*" framing used to reference).
- `docs/NETWORK_CONFINEMENT.md` — the living reference; last
  independently re-verified 2026-09-13 per its own header, 22/22
  confinement live-tests passed against a real local arbiter server.
  This document was NOT re-verified again as part of this baseline pass
  (no code in `core/collection/` changed since Fase 01) — its own
  "living reference, re-verify on drift" framing is the standard to hold
  it to, not a fresh audit here.

### EASM domain model, current state

`api/control_db.py`'s schema, in the order the tables were actually
added (confirmed via `grep -n "^CREATE TABLE IF NOT EXISTS"`):
`accounts` → `organizations` → `account_organization_roles` → `assets`
→ `asset_identifiers` → `evidence` → `observations` → `change_events` →
`api_keys` → `scans` → ... (billing/monitoring/webhook tables, all
pre-existing, all untouched by the EASM phases).

### Monitoring (`api/monitoring_worker.py`)

Confirmed present and real, exactly as Fase 18's own prompt describes
it: Speed 1 (daily passive)/Speed 2 (weekly active, tier-gated),
`needs_review` gate, the durable outbox
(`monitoring_pending_notifications`, `list_unsent_notifications`,
`mark_notifications_sent`), webhook delivery
(`_deliver_webhooks_for_outcome`). Confirmed still comparing raw asset
digests (`_harvest_one`/`compute_asset_digest`), not yet reading from
`change_events`/`observations` — this is exactly the gap Fase 18 closes,
not yet touched by any phase through 05.

### Evidence/provenance

Two real, pre-existing mechanisms, confirmed distinct (this exact
distinction already drove a real design decision in Fase 04 — see
`api/observation_identity.py`'s own docstring): `core.provenance.
ProvenanceRecord`/`Host.provenance` (free-text `field`/`value` pairs,
populated by `core/parsers/registry.py`) and `core/intel/model.py`'s
`Evidence`/`Observation` dataclasses (run-scoped, in each account's own
`AssetStore`). Fase 04's own `evidence`/`observations` tables
(organization-scoped) read sub-entity fields directly
(`Port.source`/`.confidence_score`, etc.), never the free-text
provenance list, for exactly the fragility reason documented there.

### Parsers / plugin system

`modules/` — 37 files, confirmed via `ls modules/*.py`. `modules/_base.py::
BaseToolPlugin` is the shared execution contract (subprocess invocation,
retry-line detection, scope-enforcing proxy hookup). `core/models.py::
ToolStatus` is the current, single execution-status enum:
`PENDING, CHECKING, READY, RUNNING, COMPLETED, SKIPPED, FAILED, MISSING`
— **confirmed NOT to have the granularity Invariant 7 requires**
(`SUCCESS_WITH_RESULTS` vs `SUCCESS_NO_RESULTS` vs `PARTIAL` vs
`BLOCKED_BY_SCOPE` do not exist as distinct states today; `COMPLETED`
does not distinguish "found nothing" from "found results," and nothing
distinguishes a scope-denial from an ordinary failure). This is a real,
concrete gap for Fase 09 to close, not assumed — confirmed by reading
`core/models.py:12-23` directly.

`core/dependencies/` (`registry.py`, `models.py`, `capabilities.py`,
`discovery.py`, `validation.py`, `service.py`) — the existing
tool-dependency registry (`ToolDefinition`, `ToolHealth`, `InstallMethod`/
`InstallKind`). This is the "registro de dependencias existente" Fase 09
must extend, not duplicate. Note: `core/dependencies/capabilities.py`'s
own `CapabilityResult` already uses the word "capability" for a
different concept (per-tool binary availability/version detection, not
Fase 17's product-level capability taxonomy) — a real naming collision
Fase 17 needs to navigate explicitly, not silently paper over by reusing
the word for two different things.

### API surface, current state

`api/routers/`: `accounts.py`, `domains.py`, `health.py`,
`hypotheses.py`, `keys.py`, `monitoring.py`, `reportability.py`,
`scans.py`, `subscription.py`, `webhooks.py` — confirmed via `ls`.
**No router for organizations, assets, candidate_assets, observations,
change_events, relationships, or exposures exists yet** — Fase 19's own
job, confirmed genuinely not started, not merely "assumed not done."

### CI / pipeline reality

`.github/workflows/ci.yml`: a `check` job (ruff, black --check,
isort --check-only, mypy, bandit, pytest) across Python 3.10/3.11/3.12,
plus a `docker` job (pull-request-only) that builds the real image and
re-runs the full suite + lint inside the container — the only place CI
exercises the pinned Go binaries, `nmap`, and Playwright/WebKit. **Docker
is confirmed unavailable in this sandboxed environment** (`docker info`
fails) — this baseline's own pipeline numbers below are the `check`
job's equivalent only; the containerized re-verification remains a
GitHub-side guarantee this environment cannot reproduce locally, flagged
here explicitly rather than silently assumed equivalent.

## 4. Real pipeline baseline, this checkout, `main` at `35749f6`

```
$ python -m compileall -q -f .          -> exit 0, zero errors
$ ruff check .                          -> All checks passed!
$ black --check .                       -> 388 files would be left unchanged
$ isort --check-only .                  -> clean (4 files skipped, pre-existing/expected)
$ mypy .                                -> Success: no issues found in 203 source files
$ bandit -c pyproject.toml -r .         -> 0 issues (Undefined/Low/Medium/High all 0),
                                            43,074 lines scanned, 33 pre-existing
                                            #nosec suppressions (all pre-dating this
                                            baseline, not newly added)
```

`pytest tests/ -q`, 3 consecutive runs, real captured output:

```
Run 1: 1950 passed, 3 skipped, 521 warnings in 371.56s (0:06:11)
Run 2: 1950 passed, 3 skipped, 521 warnings in 388.79s (0:06:28)
Run 3: 1950 passed, 3 skipped, 521 warnings in 362.89s (0:06:02)
```

The 3 skips are the same 3 across all runs — the Wompi real-sandbox
replay tests (`tests/test_wompi_real_capture_replay.py`), correctly
skipped pending a real operator-provided capture, not a regression. As
of the commit this baseline was taken against, 185 test files exist
under `tests/`.

## 5. What this baseline does NOT do

No code was changed. No new tests were added (Fase 00 is confirmation,
not construction). `docs/NETWORK_CONFINEMENT.md`'s own confinement
live-tests were not independently re-run here (nothing in
`core/collection/` changed since they were last verified 2026-09-13);
Bloque C's cloud/DNS/TLS/visual phases are the ones that will actually
exercise that gate again for real, and should re-confirm it then, not
assume this baseline already did.
