# Competitive gaps — what other EASM projects do that Hydra didn't

Branch: `productization/competitive-gaps`. Base: `main` @ `b507709` (after
PR #101).

## How this list was chosen

Sixteen public repositories were reviewed, looking at what each one is,
how it works, and what it can do:

- **Full frameworks and platforms:** BBOT, OASM (open-asm), Red Kite
  (stalker), IVRE, X-Marshal.
- **Scanner pipelines:** EasyEASM, AutoEASM, Domain_checker,
  splunk_easm_worker, koko-moni.
- **Integrations only:** the FortiRecon EASM connector for FortiSOAR, and
  markolauren/easm (Defender EASM → Sentinel).
- **Not EASM tools at all:** EASMData (a UK railway signal map),
  krykoder/easm (a Rust library for Ethereum assembly), biu (a closed
  SaaS product) and DocuFinderJS (a Google-search bookmarklet).

Hydra was already ahead of all of them on several fronts:

- evidence lineage back to observations;
- fail-closed scope, with authorization separate from discovery;
- tested tenant isolation;
- truthful provider outcomes;
- deterministic, explainable risk.

Only features that were cheap, safe, and useful through the API were taken
into this branch. Larger items are listed at the end.

## What this branch adds

| Idea (source) | Hydra now |
|---|---|
| Upload external scan results (OASM/IVRE imports, FortiRecon) | `POST /organizations/{org}/imports/{nmap\|masscan}`, `GET .../imports` |
| Tool errors classified as fatal vs retryable (OASM connectors) | `failure_class` on every collector outcome in `GET /scans/{id}/collection` |
| Scan statistics: new/disappeared vs the previous scan (FortiRecon) | `GET /scans/{id}/summary` |
| Aggregation by fingerprint/port/title (koko-moni `/api/aggregate`) | `GET /organizations/{org}/inventory/facets` |
| CSV for risk registers (EasyEASM), SIEM feeds (BBOT, Sentinel) | `GET /organizations/{org}/exports/{assets\|exposures}?format=csv\|ndjson` |

### Imports

Fase 11 had already built a hardened Nmap XML / Masscan JSON importer:

- XML is parsed with defusedxml;
- compressed uploads are rejected, never decompressed;
- uploads are capped in size;
- importing the same artifact twice creates nothing new (idempotent by
  artifact hash).

It had no API. The new endpoint:

- **Access:** owner-only, since an import adds data to the organization.
- **Upload:** the report is the raw request body. It is read in chunks,
  and the request is refused with 413 as soon as it exceeds the cap, before
  the whole body is buffered.
- **Dry run:** `dry_run=true` validates the report and returns counts
  without writing anything.
- **Rejected input:** malformed, XXE-bearing, compressed and empty reports
  all return 422.
- **Imported is not authorized:** every imported host becomes a candidate,
  or evidence on an asset the organization already owns. It never becomes
  an authorized target.

### Failure class, and a bug found on the way

`failure_class` is derived only from signals the pipeline already records:
the outcome, and the per-tool timeout and rate-limit counters. It is never
guessed from error text.

| Class | When | What it tells the client |
|---|---|---|
| `transient` | The upstream was unreachable, the run was partial, or the tool failed with timeouts or rate limits recorded | Re-running is likely to help |
| `configuration` | The tool is enabled but its binary isn't installed | Fix the setup first |
| `unknown` | Any other failure | Needs investigation |

Building this uncovered a real bug on `main`. Some tools are only started
when there is input for them; httpx and naabu, for example, are skipped
when no host resolves. Such a tool is still in state `ready` when the run
ends. The orchestrator recorded that raw state, and the provider-outcome
ledger rejects it. The error was raised after the scan had already been
marked completed, so the orchestrator's catch-all turned a clean scan into
a failed one ("invalid provider execution outcome").

This affected any scan of a domain that resolves nothing, and it was
reproduced on `main` before fixing. `recorded_outcome` now maps every
end-of-run state to a proper outcome:

| End-of-run state | Recorded as |
|---|---|
| never started | `skipped` |
| binary missing | `unavailable` |
| still running | `failed` |
| legacy `completed` | `success_with_results` or `success_no_results` |

### Scan summary

The summary returns counts built with SQL aggregates over the existing
per-run tables:

- assets observed;
- assets new, changed, disappeared or reappeared, as judged by the change
  detector;
- exposures first seen, and exposure events;
- certificate and technology events;
- candidates first seen.

It also returns `degraded`, because a scan with a failed collector can
under-report.

### Inventory facets

The facets are:

- assets by type;
- exposures by status and severity;
- candidates by review status;
- the most common **current** technologies;
- the most common open ports.

"Current" technologies use the same latest-run rule as the per-asset view,
in a single SQL query. A test checks the two against each other on real
backfilled scans, including a technology that a later run stopped
detecting.

Port counts split the identity key from the right, so IPv6 hosts parse
correctly.

### Exports

- **Keyset paging:** rows are read in pages keyed on the primary key. OFFSET
  paging over `last_seen_at`, which scans keep updating, could skip or
  repeat rows during a long export.
- **CSV injection:** cells starting with `=`, `+`, `-`, `@`, a tab or a
  carriage return get a leading `'` (OWASP CSV Injection). Page titles and
  other scanned text reach these cells, and a spreadsheet would otherwise
  run them as formulas.

## Considered and deferred

- **A read-only MCP server** over the documented API, as in OASM and IVRE.
  It fits Hydra's rule that AI interprets but never controls, and deserves
  its own phase.
- **DNS zone import from Route53 or Cloudflare**, as ownership evidence
  (OASM has cloud-provider imports).
- **Declarative automation rules**, like Red Kite's event subscriptions
  with conditions and cooldowns. They must stay behind the scope and
  authorization gate.
- **Shodan or Censys** as a passive source (koko-moni aggregates similar
  engines).
- **Regular-expression URL exclusions**, like BBOT's `RE:` blacklist, for
  example to keep crawlers away from logout pages. Path-glob exclusions
  already exist.

## Considered and rejected

- **Kubernetes/Kafka infrastructure:** scaling choices stay "measure first".
- **One container per tool:** too heavy for now.
- **The Asian search engines** (FOFA, Hunter, Quake, ZoomEye).
- **Invasive modules** such as 4xx-bypass and dependency-confusion
  registration.
- **Coupling to Qualys.**
