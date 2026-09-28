# EASM Fase 19 — API Surface

## Purpose

Read/confirm HTTP endpoints for the domain model Fases 02-18 built,
following `api/routers/exposures.py`'s own established pattern exactly
(the one live EASM router before this phase) rather than inventing a
second convention.

## New endpoints (`api/routers/easm.py`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/organizations` | Organizations the caller is a member of, with role |
| GET | `/organizations/{id}/assets` | Paginated asset list, optional `asset_type` filter |
| GET | `/organizations/{id}/assets/{asset_id}` | One asset |
| GET | `/organizations/{id}/assets/{asset_id}/observations` | Paginated observation + evidence history |
| GET | `/organizations/{id}/assets/{asset_id}/change-events` | Fase 05 change history |
| GET | `/organizations/{id}/assets/{asset_id}/certificate-events` | Fase 12 certificate change history |
| GET | `/organizations/{id}/assets/{asset_id}/technology-events` | Fase 14 technology change history |
| GET | `/organizations/{id}/assets/{asset_id}/technologies` | Current technology inventory (Fase 14) |
| GET | `/organizations/{id}/candidate-assets` | Paginated candidate list, optional `candidate_type` filter |
| GET | `/organizations/{id}/candidate-assets/{id}` | One candidate |
| POST | `/organizations/{id}/candidate-assets/{id}/promote` | Fase 06's promotion flow, owner-gated |
| POST | `/organizations/{id}/candidate-assets/{id}/discard` | Fase 06's discard flow, owner-gated |
| GET | `/organizations/{id}/capabilities` | Fase 17's capability/provider/status model |
| POST | `/organizations/{id}/imports/nmap`, `/masscan` | *Deferred, see Non-goals* |

Every endpoint reuses `_require_member`/`_require_asset` helpers that
mirror `exposures.py`'s own tenant-isolation discipline exactly: a
non-member or a mismatched organization always gets 404, never 403 (an
API key must never learn whether an organization or asset it doesn't
belong to actually exists). Every mutation (`promote`, `discard`) calls
`ControlDB.promote_candidate_asset`/`discard_candidate_asset` directly —
the exact same and only code path Fase 06 already built; this router
adds no second authorization/promotion mechanism.

## Pagination

Every list endpoint takes `limit` (1-500, default 100) and `offset`
(≥0, default 0), matching `exposures.py`'s own contract exactly. Assets
and candidate assets paginate the same way exposures does. Observations,
certificate events, and technology events paginate in Python over an
already-fetched list (`list_observations_for_asset` and its siblings
have many existing callers across Fases 04/12/14/18 — backfills,
monitoring citations — extending their SQL to accept LIMIT/OFFSET would
mean auditing every one of those callers for a scope this phase doesn't
need). Externally identical, correct pagination behavior either way;
documented here rather than presented as identical implementations.

## A real bug found and fixed along the way

`ControlDB.get_exposure()`, added in Fase 18 for the monitoring
citation-builder, turned out to be an exact duplicate of the
already-existing `get_exposure_for_organization()` (Fase 08). Removed
the duplicate, updated its one caller
(`api/monitoring_worker.py::_easm_citations_for_run`) to use the
original — a small "reuse before build" miss caught while building this
phase's own routers and reading the existing exposures router closely.

## IDOR/BOLA coverage

Every new endpoint has an explicit foreign-account test in
`tests/test_api_easm.py::TestForeignAccountCannotProbeAnyEndpoint` — GET
and POST, confirmed 404 for a non-member on every single path (11 GET
paths + 2 POST actions, listed individually, not summarized). A
read-only member (`role="viewer"`) can read every endpoint but gets 403
on both mutations (`TestCandidateAssetPromotionFlow::
test_a_viewer_cannot_promote_or_discard`) — confirming role separation
holds at the API layer, not just in `ControlDB`'s own already-tested
role check.

## Non-goals

- **Nmap/Masscan import HTTP endpoints** (Fase 11's own "la exposición
  HTTP llega en la fase 19" note): not built in this pass. Wiring a
  multipart file-upload endpoint through `api/nmap_masscan_import.py`
  needs its own size-limit/auth/rate-limit design pass distinct from
  this phase's read/confirm surface, and risked expanding this already
  large phase further. Flagged explicitly as remaining work, not
  silently dropped — `api/nmap_masscan_import.py`'s own functions are
  already fully built and tested (Fase 11); only the HTTP wrapper is
  missing.
- **DNS posture, visual history, and cloud asset per-asset views**:
  Fases 13/15/16 were merged by earlier work this engagement didn't
  build, and their exact table shapes were not audited closely enough in
  this pass to build a confident, tested endpoint for each without
  materially expanding scope. Certificates and technologies (Fases 12/14,
  built directly in this engagement) are fully covered instead.
- **Relationships (Fase 07) endpoints**: not built in this pass, for the
  same reason as DNS/visual/cloud — deferred, not silently dropped.
- No endpoint answers the roadmap's fuller "why does Hydra think this
  asset exists" product query in one call — that's a composition of
  several of the endpoints above (assets + observations + candidate
  history), left to a frontend/client to assemble rather than a new
  bespoke endpoint in this pass.
