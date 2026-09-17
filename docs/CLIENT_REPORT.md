# `python app.py client-report` — client-facing report generation

Generates a plain-language, tool-name-free Markdown draft from a run's
already-persisted artifacts — the same kind of document that used to be
assembled by hand after a pilot engagement (Metaverse Justice). Standalone
command, opt-in, same operational family as `assess-reportability` and
`suggest-hypotheses`: **never invoked by `python app.py run`**, and it
never sends anything anywhere — it only ever writes a Markdown file to
disk for the operator to review, edit, and convert before sharing it with
a client.

## Usage

```bash
python app.py client-report RUN_ID
# or write it somewhere specific:
python app.py client-report RUN_ID --output /path/to/draft.md
```

By default the draft is written to `output/<run_id>/client_report.md`.
The command prints a short summary (counts per category, any known
verification gaps) and an explicit reminder that this is a **draft** —
Hydra does not send it to anyone.

Requires the run's own `output/<run_id>/` artifacts and its row in
`output/recon.db` (the same data every other `RUN_ID`-based command
reads) — no API key, no network access, no extra cost.

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
4. Writes each entry with a plain-Spanish explanation of what it means
   and why it matters (`core/client_report/explain.py`) — no tool or
   binary name ever appears in the document.
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

## Why Markdown, not `.docx`

Two options were considered: generate a `.docx` file directly (matching
the original hand-built pilot report's own format), or generate a
Markdown draft the operator converts afterward. Markdown was chosen:

- **No new dependency.** `python-docx` would be a new, fairly heavy
  dependency for comparatively little benefit — converting Markdown to
  `.docx` is already a single well-known command
  (`pandoc client_report.md -o client_report.docx`), and most modern word
  processors (Google Docs included) import Markdown directly.
- **Trivially reviewable and testable.** A Markdown file is plain text —
  diffable in a PR, editable in any editor, and the exact string content
  can be asserted on directly in tests. A generated `.docx` binary would
  need a much heavier test harness just to inspect its own content.
- **Consistent with the rest of the project.** `core/reporter.py` (the
  main recon report) already generates Markdown and HTML, never a binary
  document format — this keeps one rendering paradigm project-wide
  instead of introducing a second one just for this command.
- **The non-negotiable is already satisfied either way**: the operator
  reviews and edits before anything reaches a client. A Markdown draft
  makes that review step *easier*, not harder — and the one-command
  conversion to `.docx` (or a direct paste into a word processor) happens
  entirely on the operator's own machine, under their own control.

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
