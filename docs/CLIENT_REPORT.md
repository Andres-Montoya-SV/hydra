# `python app.py client-report` — client-facing report generation

Generates a plain-language, tool-name-free draft — Markdown or Word — from
a run's already-persisted artifacts — the same kind of document that used
to be assembled by hand after a pilot engagement (Metaverse Justice).
Standalone command, opt-in, same operational family as
`assess-reportability` and `suggest-hypotheses`: **never invoked by
`python app.py run`**, and it never sends anything anywhere — it only ever
writes a file to disk for the operator to review, edit, and (for the
Markdown default) convert before sharing it with a client.

## Usage

```bash
python app.py client-report RUN_ID
# Word instead of Markdown:
python app.py client-report RUN_ID --format docx
# write it somewhere specific:
python app.py client-report RUN_ID --output /path/to/draft.md
```

By default the draft is written to `output/<run_id>/client_report.md`
(or `client_report.docx` with `--format docx`). The command prints a
short summary (counts per category, any known verification gaps) and an
explicit reminder that this is a **draft** — Hydra does not send it to
anyone.

Requires the run's own `output/<run_id>/` artifacts and its row in
`output/recon.db` (the same data every other `RUN_ID`-based command
reads) — no API key, no network access, no extra cost. `--format docx`
additionally requires `python-docx` (`requirements-optional.txt`) —
`--format markdown` (the default) needs nothing beyond the base install.

## What it does

1. Reads the run's per-tool JSONL artifacts directly (not the SQLite
   `findings` table — see "Why artifacts, not the findings table" below)
   for the tools that can produce client-facing findings: `vuln_match`,
   `security_headers`, `param_fuzz`, `cloud_bucket_enum`, `browser_probe`,
   `nuclei`, `threat_intel`.
2. Consolidates duplicates (`core/client_report/dedup.py`):
   - The same page probed with and without a trailing slash, or under its
     bare-domain vs `www.` alias, is one page/one site — never two.
   - Several distinct raw findings that are really the same underlying
     pattern repeated under different labels on the same page (eight
     different query parameters that all reflect input, five different
     missing security headers) become **one** entry listing every label,
     not one entry per raw row.
   - A specific identifier (a CVE, a specific nuclei template match) is
     never merged with a *different* identifier just because both hit the
     same host — only its own URL-variant duplicates collapse.
3. Categorizes every consolidated entry into exactly one of three
   sections, never mixed:
   - **Vulnerabilidades confirmadas** — real evidence of impact (a
     published CVE match, a publicly-listable cloud bucket, a host
     cataloged as malicious).
   - **Indicios** — detected without conclusive evidence of
     exploitability (a reflected parameter probed only with plain text,
     never a real injection payload; a behavioral difference that needs
     manual confirmation).
   - **Áreas de mejora** — hardening recommendations, not vulnerabilities
     (missing security headers).
   - Scan-quality/reliability caveats about the collection itself
     (tarpit/portspoof defenses, wildcard DNS, soft-404 catch-alls) are
     never shown as client-facing findings at all — they belong to the
     "known limitations" section instead, if relevant.
4. Writes each entry with the exact same structure, regardless of
   severity or category (`core/client_report/explain.py`) — no tool or
   binary name ever appears in the document:
   - **Qué significa** — what it means and why it matters, in plain
     Spanish.
   - **Cómo se encontró** — the methodology in plain terms, e.g. "se
     probó agregando un valor de identificación única en cada parámetro
     de la URL, y se comparó la respuesta del sitio" — never the name of
     a specific tool or binary. Kept as its own content piece
     (`explain_methodology`), separate from the "qué significa" text, so
     either can be corrected independently.
   - **Ubicación** and the affected page(s).
   - **Limitación de esta prueba**, when the specific test type has one
     worth naming (`explain_caveat`) — e.g. a reflected-parameter finding
     always notes that only plain text was tried, never a real injection
     payload. This is distinct from the report-wide "Qué NO cubre este
     análisis" section below; it is the one specific gap in *this*
     particular check.
   - **Recomendación** — closing guidance calibrated to the finding's
     real severity (`severity_recommendation`), applied uniformly so tone
     never depends on whether a given finding type happens to have
     hand-tuned prose: calm and non-alarmist for `info`/`low` ("se
     recomienda tenerlo en cuenta, sin representar una urgencia
     inmediata"), direct and unambiguous for `high`/`critical` ("se
     recomienda atender esto de forma inmediata — el riesgo real es
     alto"), without ever downplaying a real one or dramatizing a minor
     one.

   Every one of these five pieces is computed once, in
   `core/client_report/dedup.py`, and attached to the shared
   `ConsolidatedFinding` object both renderers read — depth is identical
   for every finding regardless of severity; only wording/urgency scales
   with severity.
5. Adds a **Limitaciones conocidas de esta corrida** section, built from
   this specific run's own gaps:
   - Any technology `vuln_match` could not actually verify (invalid or
     missing `WPSCAN_API_TOKEN`, a network error, a rate limit — see the
     WPScan/OSV fail-visible fix below) — shown explicitly as "sin
     confirmar", never silently omitted.
   - Wildcard DNS detected for the target (subdomain results may include
     false positives).
   - A soft-404/catch-all host (URL existence can't be inferred from
     status codes alone).
   - A parameter-discovery baseline that was blocked/rate-limited (results
     for that host would be unreliable, not "zero findings").
6. Adds a fixed **Qué NO cubre este análisis** section — no active
   exploitation, no authenticated testing, no social engineering, indicios
   tested only with plain text never real payloads, point-in-time only,
   and vulnerability-database coverage depends on the source correctly
   cataloging the exact component/version.
7. Shows the run's real duration (`summary.json`'s `duration_seconds`),
   never a tool-by-tool breakdown.

## Why artifacts, not the `findings` table

The client report reads each tool's own JSONL artifact through the exact
same `core.parsers.registry` parser classes the main pipeline already
uses — not `AssetStore.get_findings()`. This was a deliberate choice, not
an oversight: verified against a real run that `security_headers.jsonl`
correctly holds 10 rows (5 missing headers × 2 URL variants), but an
unrelated existing cross-tool merge step upstream of the `findings` table
only keeps 2 of those 10 (rows sharing a `template_id` on one host can
overwrite each other during that merge). Parsing the tool's own artifact
directly recovers the full, correct set this report needs to consolidate
honestly — this report's own dedup step (see above) is what actually
collapses true duplicates, deliberately not relying on that unrelated
upstream behavior either way.

## Markdown by default, `.docx` on request — and why both, not one

The first round of this feature shipped Markdown only, with the
reasoning that a `pandoc`/word-processor conversion was one command away
and not worth a new dependency. The operator explicitly asked for a
direct Word output as well, so `--format docx` was added
(`core/client_report/render_docx.py`, `python-docx` in
`requirements-optional.txt`) — but Markdown stays the **default** and the
original reasoning still applies to why it stays that way:

- **Markdown needs nothing extra.** No dependency, trivially reviewable
  and diffable, and the exact string content can be asserted on directly
  in tests — this is still the fastest path for the operator to skim or
  patch a draft by hand.
- **`.docx` is opt-in and lazily imported.** `python-docx` is only
  required when `--format docx` is actually used — importing
  `core.client_report.cli` (or generating the Markdown default) never
  needs it installed at all, same discipline as `anthropic`/`openai` in
  `core/reportability`/`core/hypotheses`.
- **No content duplication between the two renderers.** Both
  `render_markdown` and `render_docx` consume the exact same
  `RunReportData`/`ConsolidatedFinding` objects — deduplication,
  categorization, methodology, caveats, and severity-calibrated
  recommendations are computed once, upstream, in
  `core/client_report/dedup.py`/`explain.py`. Neither renderer owns a
  content decision; each owns only its own presentation.
- **The non-negotiable is unchanged**: the operator reviews and edits
  before anything reaches a client, in whichever format they generate.

### What the Word output adds visually

No copy of the original hand-built pilot `.docx` was found in this repo
to match pixel-for-pixel — if the operator has that file, sharing it
would let a future round match its exact visual style more closely; in
its absence, `render_docx.py` follows conventional professional pentest-
report structure:

- A **cover page** — report title, client/target name, generation date,
  and the run's real duration, with an explicit "BORRADOR" mark so the
  file can never be mistaken for a finished, sent document even out of
  context.
- A **colored severity badge** on every finding — a shaded table cell
  (red/orange/yellow/blue-gray depending on severity, matching the same
  severity the Markdown version reports as text) immediately under each
  finding's heading, not just a severity word in a sentence.
- A **scope summary table** as the closing section — target(s), run
  duration, and the same three category counts as the executive summary,
  in one compact table for a quick final reference.

## Related: WPScan/OSV never fail silently into "clean" (`modules/vuln_match.py`)

Before this round, a failed vulnerability-database query (an invalid or
expired `WPSCAN_API_TOKEN`, a network error, a rate limit, an unparseable
response) produced an empty result — indistinguishable from "queried, no
vulnerabilities found." Confirmed against a real run: `Bookly:28.0` was
detected on a real target, but an invalid `WPSCAN_API_TOKEN` made every
WPScan query fail with a plain HTTP 404 — and the finding simply
vanished from the report, exactly as if the plugin had checked and found
nothing.

Every technology's check against OSV and (when applicable) WPScan is now
tracked as one of three states, persisted in `vuln_match.jsonl`'s new
`check_status` field:

- `checked_vulnerable` — queried, a real match was found (unchanged from
  before this round).
- `check_failed` — the query could not be completed (bad/expired/missing
  token, network error, rate limit, malformed response). Never silently
  folded into "nothing found." Surfaced as a run warning, in
  `metadata.json`'s `vuln_match_check_failed`, as its own info-severity
  `vuln-check-failed` finding, and in the client report's "Limitaciones
  conocidas" section.
- A technology genuinely checked clean across every applicable source
  still produces **zero rows** — this fix only adds visibility for
  failures, it never adds noise to a real clean result.

A WordPress-family plugin/theme detected with no `WPSCAN_API_TOKEN`
configured at all is treated the same way as a failed query: WPScan is
the authoritative source for that ecosystem (OSV rarely carries
WordPress-plugin advisories), so never attempting that check is exactly
as much of a verification gap as attempting it and having it fail.
