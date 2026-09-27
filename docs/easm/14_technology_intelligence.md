# EASM Fase 14 — Technology Intelligence

## Purpose

A persistent, historical technology inventory answering: which assets
run nginx/WordPress/React? Where is PHP 7 still visible? What technology
appeared this week? Which assets changed technology? Built entirely on
what already exists (`httpx`, `WhatWebParser`, `browser_probe` already
produce `TechnologyFinding`s; Fase 06 already turns them into
`technology_detected` observations on the domain asset) — no second
collection, no new asset type.

## The real gap this phase closes: name normalization

`core/parsers/registry.py`'s `WhatWebParser` and httpx's own
`-tech-detect` output can report the exact same real technology under
different casing/spelling (confirmed: WhatWeb dedups its own findings
with `.casefold()` but still stores the tool's raw string). Without
normalization, "nginx" (httpx) and "Nginx" (WhatWeb) became two different
evidence facts about the same real thing — never merged for inventory or
change-detection purposes.

`api/technology_catalog.py::normalize_technology_name()` fixes this with
a small, **curated** lookup table (nginx, Apache HTTP Server, React,
Next.js, WordPress, Cloudflare, IIS, ASP.NET, FastAPI, and a handful of
other common ones) — never a fuzzy/similarity match. Anything not in the
table passes through unchanged. Applied once, at write time, in
`api/observation_identity.py::observations_for_host()` before the
`technology_detected` evidence detail is built — the single source of
truth is the recorded evidence, never re-derived at read time.

**Never fuzzy**: "React" and "React Native" stay distinct — only an
exact, hand-curated alias entry may collapse two spellings of the SAME
real technology.

## Change classification

- `api/technology_events.py::classify_technology_transition()` — pure,
  deterministic. Unlike a certificate (one active value per domain), a
  domain can run many technologies at once, so a "snapshot" here is a
  `{canonical_name: version}` mapping, compared by set difference between
  two consecutive runs: `TECHNOLOGY_ADDED` (present now, wasn't before),
  `TECHNOLOGY_REMOVED` (was present, isn't now), `TECHNOLOGY_VERSION_CHANGED`
  (present in both, different version). Every event cites the concrete
  technology and version.
- `technology_events` table + `api/technology_backfill.py` — groups a
  domain's `technology_detected` observations by the run that produced
  them, walks consecutive run snapshots in chronological order, records
  the classified transitions. `UNIQUE(asset_id, run_id, event_type,
  technology_name, reason)` makes replaying the backfill idempotent.

## Inventory queries

- `ControlDB.list_current_technologies_for_asset(asset_id)` — the
  technologies observed in this domain's **most recent run only**, never
  "every technology ever seen regardless of whether a later run stopped
  detecting it" (that would have kept reporting a `TECHNOLOGY_REMOVED`
  technology as still present — caught and fixed during this phase's own
  smoke testing before it shipped).
- `ControlDB.list_assets_running_technology(organization_id, name)` —
  answers "which assets run WordPress" directly. Exact canonical-name
  match only, never a substring/fuzzy match.
- `ControlDB.list_technology_events_for_organization(organization_id,
  since=...)` — answers "what appeared this week" / "what changed",
  with an optional `since` lower bound on `detected_at`.

## Non-goals

- No new "technology" asset type — a detected technology is a fact about
  the domain asset, exactly as Fase 06 already established.
- WhatWeb itself was already evaluated and integrated in an earlier
  merge (`WhatWebParser` in `core/parsers/registry.py`) — this phase only
  adds the persistence/history/normalization layer on top of what it (and
  httpx/browser_probe) already produce.
- No de-duplication of a technology reported by multiple sources in the
  SAME run — httpx and WhatWeb both detecting "nginx" in one run produces
  two separate current-technology rows (one per source), consistent with
  the rest of the system's "keep every source's own evidence, never
  collapse provenance" discipline (Fase 09/10's own precedence model
  handles the "which source should a caller trust more" question at read
  time, not by deleting a corroborating fact).
