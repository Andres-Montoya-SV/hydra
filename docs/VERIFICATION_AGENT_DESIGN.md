# Verification Agent — Design & Incident Catalog (Part 1)

Status: **design only, no implementation.** Written against `main` after
the correlation-engine (`docs/CORRELATION_ENGINE_DESIGN.md`), attribution
(`AUTHORIZED_USE.md`), scope-exclusion, and `security_headers`/`dnsx`
false-positive fixes closed. Same pattern as `docs/ARCHITECTURE_AUDIT_2.md`
and `docs/CORRELATION_ENGINE_DESIGN.md`: a document to review before any
detector gets built.

## 0. The principle, restated precisely

Hydra must not show a finding, or let a report cite a value, without first
having actively tried to contradict it against the raw evidence already on
disk — the same check a human does by hand before trusting a scan result.

This is **not** an autonomous agent. It does not expand scope, does not run
new modules on its own initiative, does not draft or send a final report
unsupervised. It is a layer of structural suspicion sitting between "raw
artifact" and "what the user sees" — the same relationship
`authorize_active_indicator` already has between "discovered" and
"collected." Discovery is not authorization; an interpretation is not
verification.

## 1. Part A — Incident catalog

Ten real incidents, each classified by **where the contradiction lived**:
**intra-artifact** (the artifact already contradicts itself — no second
source needed) or **inter-artifact** (two separate things that are supposed
to agree, didn't). This distinction drives Part B's layering: intra-artifact
contradictions can be checked immediately after the one plugin that wrote
the artifact runs; inter-artifact ones need a second source to exist first
(a `.env` declaration, a prior run, a different plugin's output).

| # | Incident | Contradiction | Evidence that would have revealed it | Pipeline layer | Class |
|---|---|---|---|---|---|
| 1 | WHOIS reported the **TLD's** (IANA-level) creation date instead of the real domain's | The referral chain's IANA hop (generic TLD-level fields) was read instead of the most specific registrar-level block | The same `whois_raw.txt` already has both blocks — the registrar block's `Creation Date:` sits after the `Registrar:` line | Post-module (per-plugin) | **Intra-artifact** |
| 2 | `security_headers` reported present headers as missing | httpx's JSON renames hyphens to underscores (`x_frame_options`); the checker compared against hyphenated names | `httpx.json`'s own `header` object already had the real value under the underscored key | Post-module | **Intra-artifact** |
| 3 | `naabu` "open" ports that `nmap` (second opinion) called `filtered` | Two tools that are supposed to agree about the same port, didn't | `port_verify`'s own nmap output vs. naabu's — both already on disk | Post-module (cross-plugin) | **Inter-artifact** |
| 4 | `tarpit_check`/`naabu` false negative — a real tarpit not detected because the quick check's timing was insufficient | Hydra's fast canary pass disagreed with the user's own repeated manual `nmap` runs | Nothing *inside* Hydra's own artifacts contradicted it — the contradiction came from an external, human-run second opinion | Report-grounding / **no internal detector can catch this one** | **Inter-artifact (external)** |
| 5 | `SCOPE_FILE` exclusions that looked syntactically fine but excluded nothing (`!mta*.domain.com`; `!domain/*/whistleblowing` not covering subpaths, first version) | The pattern parsed without error but the matching engine silently never matched anything | Nothing in a static artifact — this needs an **active** canary probe against a known-should-be-excluded name before trusting the exclusion | Pre-flight (canary test, not just parse-and-trust) | **Intra-artifact, but only detectable by acting, not reading** |
| 6 | `dnsx` counted NODATA (`NOERROR`, only `SOA`, no `a`/`aaaa`) as resolved | `status_code` alone can't distinguish NODATA from a real resolution | The same dnsx JSON record already has (or lacks) the `a`/`aaaa` field right next to `status_code` | Post-module | **Intra-artifact** |
| 7 | A program's `.env` reused against a different program (`RESEARCHER_ATTRIBUTION_HEADER` for Stripchat sent against Glassdoor); a stale `PROGRAM_NAME` gave it away | The header actually sent didn't match the program the operator meant to be running against | The header is capturable from `nuclei.json`/`param_fuzz_raw` (real request evidence); nothing today records "this header belongs to this program" to compare against | Pre-flight **and** post-module | **Inter-artifact — and no code artifact for this exists yet; see §1.1** |
| 8 | A `.env` typo — trailing text pasted after `WEBHOOK_URL`'s closing quote — silently corrupted the value | `Settings.from_env` only calls `.strip()` on `WEBHOOK_URL` (confirmed: `config/settings.py`, no format validation at all) — a malformed URL is accepted and only fails later, silently, when actually used | A URL-shape check at load time, before acceptance | Pre-flight | **Intra-artifact — and, confirmed, no validator exists yet; see §1.1** |
| 9 | Test-count discrepancies between environments (518 vs. 511; 559 vs. 561) never fully explained | Two counts of "the same thing" disagreed with no confirmed root cause | None identified with certainty | N/A | **Open — document as unresolved, not as fixed (see §1.2)** |
| 10 | A prior audit's prose (attributed to a different tool/session; commit `ae1a78b`) asserted something about the code — `AuthorizedCollectionTarget` "not sealed" when it was (and the reverse has also happened: something asserted "already sealed" that needed the load-bearing nuance made explicit) | A claim about the code was trusted without executing/reading the actual code | `core/collection/target.py`'s own docstring already states the precise, narrower truth — "sealed against accidental construction, not against a caller who deliberately imports and calls the private constructor" — which is more specific than a bare "sealed"/"not sealed" verdict | N/A (this is about **prose review**, not a runtime pipeline stage) | **Prose-vs-code — see §1.3** |

### 1.1 Items 7 and 8: real gaps, honestly still open

Verified directly against `config/settings.py` before writing this: no
URL-format validation exists for `WEBHOOK_URL` today (`webhook_url=os.getenv("WEBHOOK_URL", "").strip() or None` — line ~639, no `urlparse`/scheme check), and no mechanism records "this `RESEARCHER_ATTRIBUTION_HEADER`/`ATTRIBUTION_USER_AGENT` belongs to this `PROGRAM_NAME`" for cross-run comparison. These are not
retroactive fixes being documented after the fact — they are real incidents
that already happened, for which **no automated defense exists yet**. That
is precisely why they belong in this catalog: they are exactly the shape of
gap this agent exists to close, not evidence it already has.

### 1.2 Item 9: open case, not resolved — kept open deliberately

No confirmed root cause exists in this repository's history for the
518-vs-511 / 559-vs-561 test-count discrepancy. This entry is **not** a
design placeholder for a detector — there is nothing to detect yet, only
something to keep asking about. Its purpose in this catalog is to establish
a rule for the agent: **a phenomenon without a confirmed explanation must be
surfaced as "verification pending," never silently dropped for lack of a
detector to assign it to.** Section 3 (data model) accounts for this
explicitly — a `verification_flags` row can have status `UNRESOLVED`, not
just `CONFIRMED`/`DISMISSED`.

### 1.3 Item 10: prose-vs-code is a different kind of check

This one doesn't fit the pipeline-stage model at all — there's no artifact
and no run involved, just a claim in a document about what the code does.
It's included because the *rule* it establishes is the same rule the whole
agent is built on ("verify by executing, not by reading prose") and because
Part B.3's report-grounding check is a narrow, generalized version of
exactly this: does the words match what running the code (or, for a report,
reading the actual raw artifact) actually shows.

## 2. Part B — Proposed architecture

Three layers, each hooking into an existing point in the pipeline —
no new orchestration loop, no new "when does this run" question to answer
from scratch.

### B.1 — Pre-flight verification (before `PipelineRunner.run()`)

**Format validation** for values already known to have silently broken
before: `WEBHOOK_URL` (item 8) needs `urlparse` + scheme-in-`{http,https}`
+ no unexpected trailing content after the parsed URL's own end; the header
parsers already validate (`_parse_attribution_header` calls
`validate_header_value`) — the gap in item 7 isn't format, it's **cross-run
consistency**, addressed next.

**Historical cross-check**, built on infrastructure that already exists —
verified before proposing this, per the brief's own instruction:
`core/store.py`'s `runs` table already persists `program_name` and
`targets_json` per run (`AssetStore.create_run`), and
`find_latest_finished_run(domain=...)` / `find_previous_run(current_run_id)`
already do target-overlap lookups across runs. **No new table is needed for
the lookup itself** — only two new columns on `runs` (or a small
`run_config_json` blob, to avoid a schema migration for every future
"what else should we remember per run" question):
`scope_file_hash` and `attribution_fingerprint` (a hash of the
`RESEARCHER_ATTRIBUTION_HEADER`/`ATTRIBUTION_USER_AGENT` pair actually
in effect, not the raw values — these can carry a handle/token an operator
would not want duplicated verbatim into a queryable column).

Pre-flight check, concretely: given the current `PROGRAM_NAME`, look up the
most recent finished run with the same `program_name` via the query this
project already has; if the current `scope_file_hash` or
`attribution_fingerprint` differs from that historical run's, or if none of
the current `SCOPE_FILE`'s domains overlap with that historical run's
`targets_json`, emit a **pre-flight warning** (never a hard stop — this is
advisory, matching the brief's Part D boundary: this layer does not decide
anything, it surfaces a question for the operator). First run for a given
`program_name` naturally has nothing to compare against — no warning, not a
missing-history error.

### B.2 — Post-module contradiction detectors (after each plugin, before SQLite)

One pure function per catalog pattern. Deterministic, unit-testable,
**no LLM call anywhere in this layer** (Part D is explicit about this, and
it matters structurally: a detector's job is to answer "does field X match
field Y in the same/an adjacent artifact", a comparison, not a judgment —
introducing a model here would make the *verifier* itself something that
needs verifying).

```python
@dataclass(frozen=True)
class ContradictionFinding:
    claim: str                    # what was asserted (e.g. "x-frame-options: missing")
    evidence: str                 # what the raw artifact actually shows, verbatim excerpt
    raw_artifact: str             # relative path, same convention as every other raw_artifact
    severity: ContradictionSeverity  # INVALIDATES | DOWNGRADES_CONFIDENCE
    detector: str                 # which function raised this, for triage
    host: str | None = None
```

`ContradictionSeverity` is two-valued by design, not a 1-5 scale:
**INVALIDATES** (the claim is simply wrong — item 2, item 6: the header
*was* present, the host *was not* resolved — the original claim must not
reach the user unmodified) vs. **DOWNGRADES_CONFIDENCE** (the claim might
still be right, but a second source disagrees or the evidence is weaker
than the claim implies — item 3: naabu said open, nmap said filtered;
neither is proven wrong outright, but neither can be reported at
naabu's original confidence anymore). Collapsing these into one severity
would force every future detector into a false choice between "this is
fine" and "discard the finding," when the honest answer is often "keep it,
but say less about it."

Concrete detectors this catalog specifies (signatures only — no bodies):

```python
def detect_dnsx_nodata_as_resolved(
    raw_dnsx_record: dict,
) -> ContradictionFinding | None:
    """Item 6. status_code NOERROR with no a/aaaa is NODATA, not resolved."""

def detect_security_headers_key_mismatch(
    raw_httpx_headers: dict[str, str],
    parsed_missing_list: list[str],
) -> ContradictionFinding | None:
    """Item 2. A 'missing' header whose underscore-folded key is actually
    present in raw_httpx_headers is a false claim, not a real gap."""

def detect_whois_block_specificity(
    whois_raw_text: str,
    parsed_created_at: str,
) -> ContradictionFinding | None:
    """Item 1. parsed_created_at must come from the same block as the most
    specific (last) Registrar: line in whois_raw_text, not an earlier
    (IANA/registry-level) block."""

def detect_naabu_nmap_port_disagreement(
    naabu_port_state: str,
    nmap_port_state: str,
) -> ContradictionFinding | None:
    """Item 3. naabu 'open' vs. nmap 'filtered'/'closed' for the same host
    and port — DOWNGRADES_CONFIDENCE, not INVALIDATES: naabu could still be
    right (nmap is not infallible either), but the claim can no longer
    stand at naabu's original, unverified confidence."""

def detect_attribution_header_mismatch(
    program_name: str,
    sent_header: dict[str, str],
    historical_headers_for_program: dict[str, str] | None,
) -> ContradictionFinding | None:
    """Item 7. The header actually captured in this run's own artifacts
    (nuclei.json / param_fuzz_raw) doesn't match what this program_name has
    used historically. Returns None (not a finding) when
    historical_headers_for_program is None — nothing to compare against
    yet, same first-run rule as B.1."""

def detect_scope_exclusion_canary_failure(
    exclusion_pattern: str,
    canary_probe_result: bool,
) -> ContradictionFinding | None:
    """Item 5. canary_probe_result is the outcome of an ACTIVE check (does
    a synthetic/known name matching exclusion_pattern actually get denied
    by authorize_active_indicator right now) — this is the one detector
    that cannot be pure-function-over-an-artifact, because the artifact
    that would prove or disprove a SCOPE_FILE exclusion doesn't exist until
    something is tested against it. See the note below."""
```

**Honest exception, not glossed over**: `detect_scope_exclusion_canary_failure`
breaks the "pure function over an already-written raw artifact" pattern
every other detector in this layer follows — a scope exclusion's
correctness cannot be read off a file, because nothing on disk currently
records "we tried this pattern against a name and it worked/didn't." This
is why the brief's own item 5 framing says "una prueba activa contra un
caso canario" — the detector itself stays a pure function (given a boolean
result, decide what to do with it), but *producing* that boolean is a
pre-flight active check (call `authorize_active_indicator`/
`host_fully_excluded`/`hostname_matches_pattern` directly against a
synthetic name shaped like each configured exclusion pattern, e.g.
`!mta*.example.com` → probe `mta1.example.com`), not a passive read. This
belongs in **B.1**, not B.2 — flagged here because the catalog groups it by
incident, but its home in the architecture is the pre-flight layer, since
it must run before any real collection, using data the config layer already
has (`CollectionScope.path_exclusions`) with no dependency on any plugin
having run yet.

Item 4 (tarpit timing false negative) and item 9 (test-count discrepancy)
**have no B.2 detector** — item 4's contradiction only ever existed against
an external, human-run second opinion nothing in Hydra's own artifacts
recorded; item 9 has no confirmed mechanism to encode. Both are handled at
the reporting layer instead: item 4 by ensuring `tarpit_suspected` findings
are never presented at full confidence without disclosing the timing
parameters used (already partially true — see
`tests/test_intelligence.py::TestTarpitDetection`, whose docstring
independently documents this — but the disclosure isn't yet a structured,
report-visible field); item 9 by the open/`UNRESOLVED` status in the data
model itself (§3), not a detector.

### B.3 — Report-grounding check (before any export/CLI command shows a claim)

Before `investigate`/`graph`/any report renderer surfaces a value to the
user: confirm it has a `raw_artifact` reference, that the file still
exists, and that the cited value appears in it literally (a `grep`, not a
semantic check — the brief is explicit this needs no intelligence).
`core/intel/explain.py::explain_relationship` and
`core/intel/query.py` already assemble evidence-backed text for
`investigate`/`relationships` — this check is a **gate in front of** that
existing assembly, not a new rendering path: for every claim about to be
emitted, resolve its `raw_artifact`/`evidence_id` back through
`core/intel/query.py::evidence_for`/`evidence_by_relationship` (already
built), and if the referenced text can't be found verbatim in the file at
that path (or the path doesn't exist, or was never set), mark that specific
claim `UNVERIFIABLE` in the output instead of removing it or rendering it
identically to a grounded claim. This applies uniformly to a
`ContradictionFinding` too (an ungrounded contradiction claim is just as
untrustworthy as an ungrounded regular finding) and to the
`provenance`/`findings` tables' existing `artifact_path` column, which
already exists for exactly this purpose but is not currently checked at
render time.

## 3. Part C — Data model: new table, not a repurposed one

Reviewed the real schema (`core/store.py`) before deciding, per the brief's
explicit instruction — three existing candidates, each a near miss:

- **`findings`** (`run_id, host, template_id, severity, name, source, url,
  description, confidence_score`): this is a claim **about the target**
  (a vulnerability, a missing header). A `ContradictionFinding` is a claim
  **about Hydra's own prior claim** — reusing this table would let a
  self-audit flag ("we said X, the evidence says otherwise") sit
  indistinguishably next to a real security finding about the target,
  exactly the confusion this whole design exists to prevent.
- **`provenance`** (`run_id, host, tool, field, value, confidence,
  artifact_path, verified_by_json`): the closest structural match —
  it already has `artifact_path`. But its shape is "one tool observed one
  field," a single attribution, not "claim A conflicts with evidence B,"
  which needs to reference *two* things (the claim and the contradicting
  evidence) and a resolution status, neither of which this table has room
  for without overloading its meaning.
- **`intel_evidence`/`intel_relationships`**: purpose-built for
  infrastructure correlation (certificate/IP/ASN relationships between
  *hosts*) — a `ContradictionFinding` is not a relationship between two
  entities in the attack surface; it doesn't belong in the correlation
  graph at all.

**Decision: a new `verification_flags` table**, modeled on `provenance`'s
column shape (reuse the convention, not the table) plus what a
contradiction specifically needs beyond a single observation:

```sql
CREATE TABLE IF NOT EXISTS verification_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    host TEXT,                          -- nullable: item 8/9-style flags aren't host-scoped
    detector TEXT NOT NULL,             -- e.g. "detect_dnsx_nodata_as_resolved"
    claim TEXT NOT NULL,
    evidence TEXT NOT NULL,
    raw_artifact TEXT,
    severity TEXT NOT NULL,             -- INVALIDATES | DOWNGRADES_CONFIDENCE
    status TEXT NOT NULL DEFAULT 'CONFIRMED',  -- CONFIRMED | DISMISSED | UNRESOLVED
    related_table TEXT,                 -- e.g. "findings", "hosts", "intel_relationships"
    related_id TEXT,                    -- the row this flag is about, loosely typed
    discovered_at TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE INDEX IF NOT EXISTS idx_verification_flags_run ON verification_flags(run_id);
CREATE INDEX IF NOT EXISTS idx_verification_flags_related ON verification_flags(related_table, related_id);
```

`related_table`/`related_id` is a loose (not foreign-keyed) pointer on
purpose — a contradiction can point at a row in `findings`, `hosts`,
`intel_relationships`, or nothing at all (item 9's case: `related_table`
and `related_id` both `NULL`, `status='UNRESOLVED'`). A strict foreign key
per possible target table would mean a new nullable FK column per table
this could ever point at, growing forever as new detectors are added;
Hydra's own `intel_indicators`/`intel_hypotheses` tables already use this
same loosely-typed-reference convention (`discovered_from`,
`relationship_id` fields that aren't always enforced FKs either) for the
same reason.

## 4. Part D — Explicitly out of scope (restated, not just acknowledged)

Nothing in this design lets the agent: widen a run's scope on its own,
generate or rewrite `SCOPE_FILE`/`.env`, or send/finalize a report without
a human. B.2's detectors take inputs and return
`ContradictionFinding | None` — no side effects, no network calls (except
the one explicitly-flagged exception in B.1's canary check, which is a
**pre-flight, pre-collection, synthetic-name-only** probe against Hydra's
own authorization function, not a request to any real target). No detector
in B.2 calls an LLM; if a future hypothesis-suggestion layer is built on
top of this, it is explicitly a *different*, clearly-labeled layer sitting
downstream of a verification result, never inside the verification itself.

## 5. What Part 2 (implementation) would build, in order

Not committed here — recorded so review can weigh in before it starts:

1. `verification_flags` table + `VerificationFinding`/`ContradictionSeverity`
   model (mirrors `core/intel/model.py`'s existing dataclass-with-`to_dict()`
   convention).
2. B.2 detectors for items 1, 2, 3, 6 — each has a real fixture already
   sitting in this repo's test suite from the incidents themselves
   (`tests/test_dnsx.py`, `tests/test_security_headers.py`,
   `tests/test_infrastructure_plugins.py`'s WHOIS/port_verify tests) that
   can be reused directly as the detector's own regression fixture, since
   the "wrong" and "right" interpretations of each are already captured
   there.
3. B.1's two new `runs` columns + the historical cross-check, built on
   `find_latest_finished_run`/`find_previous_run` (no new query
   infrastructure).
4. B.1's `WEBHOOK_URL` format validator (small, isolated, no dependency on
   anything else here).
5. B.3's grounding gate in front of `core/intel/query.py`'s existing
   evidence assembly.
6. The one deliberately-harder piece: B.1's scope-exclusion canary check
   (needs to run before any real collection, using
   `CollectionScope.path_exclusions` and a synthetic-name generator per
   exclusion pattern shape).

## 6. Commit scope

This document only. No detector, no schema migration, no pre-flight check
implemented in this part.
