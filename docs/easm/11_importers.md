# EASM Fase 11 — Nmap/Masscan importers (+ IVRE evaluation)

## Purpose

Some organizations already have their own Nmap or Masscan scan reports
(a prior engagement, a customer-run scan, a compliance snapshot). This
phase lets those be imported as evidence — never as a second active
scanner Hydra itself runs. Nmap and Masscan are both explicitly excluded
from Hydra's own active-scanning toolset (roadmap section 3); this phase
only reads a file someone hands it.

Built entirely on Fase 10's ingestion pipeline
(`api/external_observation_ingest.py::ingest_external_observation_batch`)
— no second evidence/candidate pipeline, no new asset type.

## What is new

- `core/parsers/imported_hosts.py` — the shared, tool-neutral
  `ImportedHostRecord`/`ImportedPortRecord` shape both parsers below
  reduce their input to.
- `core/parsers/nmap_import.py::parse_nmap_xml()` — parses a previously
  run Nmap XML report. Uses `defusedxml`, never stdlib `xml.etree`
  (an uploaded report is untrusted input; stdlib XML parsing is
  documented as unsafe against entity-expansion/XML-bomb attacks —
  proven by `tests/test_nmap_masscan_parsers.py::
  test_billion_laughs_style_entity_expansion_is_rejected`).
- `core/parsers/masscan_import.py::parse_masscan_json()` — parses
  `masscan -oJ` output (plain `json.loads`, no XXE surface to begin
  with).
- `api/nmap_masscan_import.py::import_nmap_xml()` /
  `import_masscan_json()` — the safe import flow: size limit, compressed-
  archive rejection, parse, normalize, ingest.
- `observation_batches.artifact_hash` column (nullable) +
  `ControlDB.find_observation_batch_by_artifact_hash()` — the mechanism
  that makes "importing the same artifact twice never duplicates
  anything" true (see below).

## Every imported host becomes an IP candidate — never an authorized target

Each host Nmap/Masscan reports becomes an `candidate_type="IP"`
`candidate_assets` row, with `authorization_status="DENY"`, carrying a
human-readable summary of every port/service found in its evidence
`detail` (e.g. `"NMAP import: 22/tcp open ssh (OpenSSH 8.9); 80/tcp open
http"`). This is true regardless of how many open ports were reported —
proven by
`tests/test_nmap_masscan_import.py::TestImportedIpIsNeverAuthorized`.

If Nmap also resolved a hostname for that IP (`<hostnames><hostname
.../></hostnames>`), that hostname is reported **separately** as an
ordinary `DOMAIN` observation through the exact route Fase 10 already
built: corroborating evidence if that domain is already a known, owned
asset, or a `DOMAIN` candidate otherwise
(`TestHostnameCorroboratesAnAlreadyKnownDomain`). Masscan reports no
hostnames, so a Masscan-only host is always exactly one IP candidate.

Nmap's own product/version fingerprint (`<service product="..."
version="...">`) is carried through as-is in the evidence detail, never
treated as verified truth — the phase's own "el fingerprint de Nmap no
se trata como verdad absoluta" instruction. Both sources are recorded at
`ObservationConfidenceClass.THIRD_PARTY_CURRENT`, never
`DIRECT_CURRENT`.

## Idempotency: importing the same artifact twice

`sha256(raw_bytes)` is stored on `observation_batches.artifact_hash`.
`ControlDB.create_observation_batch()` reuses the existing `batch_id` for
a repeat `(organization_id, source, artifact_hash)` instead of minting a
new one. Since every downstream write this `batch_id` feeds as `run_id`
(`find_or_create_evidence`, `record_observation`, `upsert_candidate_asset`)
is already idempotent on its *content*, not on `run_id` being fresh,
replaying the identical `batch_id` a second time produces zero new rows
anywhere — proven directly by
`tests/test_nmap_masscan_import.py::TestImportingTheSameArtifactTwiceNeverDuplicates`
(same bytes → same batch, zero new candidates; different bytes → a
separate batch).

## Safe import flow

- Empty and oversized (`> 25 MiB`) artifacts are rejected before parsing.
- Common compressed-archive magic bytes (gzip/zip/bzip2/xz) are rejected
  outright — this module never decompresses anything, so a compressed
  upload fails loudly rather than being silently misparsed as garbage
  XML/JSON.
- A file that fails to parse at all (bad XML syntax, wrong root element,
  malformed JSON, wrong top-level shape) raises `ImportValidationError`
  **before any database write** — a genuinely corrupt artifact leaves
  zero partial state.
- One bad sub-record inside an otherwise-valid report (a host with no
  address, a port with an impossible port number, a masscan entry
  missing `ip`) is skipped by the parser itself and does not abort the
  rest of the batch.
- A host whose IP fails real validation (`api/candidate_assets.py::
  normalize_candidate_value("IP", ...)`, the same validator every other
  candidate path already uses) is skipped and counted
  (`hosts_skipped_invalid_ip`), never inserted as a candidate.
- `dry_run=True` runs the full parse+validate pass and reports what
  *would* happen, with zero database writes — useful for a future
  upload-preview UI (Fase 19's own concern; not built here).

## IVRE

Evaluated as this phase's own instruction requires (an import source,
not another scanning framework). **Not implemented**: IVRE requires its
own MongoDB deployment and scan-orchestration layer, which fails this
phase's "acotado, testeable, mantenible" bar for a first cut — it would
add a new required infrastructure dependency, not just a new parser. If
revisited, the adapter shape is exactly `_import_hosts` in
`api/nmap_masscan_import.py`: a byte-string parser producing
`list[ImportedHostRecord]`, nothing IVRE-specific leaking past that
boundary.

## Organization isolation

Every import call requires an explicit `organization_id`/`account_id`;
every row it writes (batch, candidate, evidence, observation) carries
`organization_id` through the same required-parameter path every prior
phase already established. No cross-organization query exists in this
module — proven by
`tests/test_nmap_masscan_import.py::TestCrossOrganizationIsolation`.

## Non-goals

- No HTTP upload endpoint — that is Fase 19's own concern
  ("la exposición HTTP llega en la fase 19").
- No IVRE integration (see above).
- No promotion of an imported IP/host to a real `assets` row — Fase 06's
  promotion currently only supports `DOMAIN`/`URL` candidates (an
  existing limitation, not new to this phase).
- No Masscan XML support — only the documented JSON (`-oJ`) output
  shape, which is Masscan's standard machine-readable format.
