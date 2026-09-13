# Reportability Agent — Design (Part 1)

Status: **design only, no implementation.** Same pattern as
`docs/CORRELATION_ENGINE_DESIGN.md` and `docs/VERIFICATION_AGENT_DESIGN.md`:
a document to review before any code gets written. Written against `main`
after the Docker containerization work closed.

## 0. The principle, restated precisely

Before a human writes a report, Hydra should be able to say: *"this finding
is real and well-evidenced — but under Section X of this program's rules,
it is likely not eligible, and here is the exact sentence that says so"* —
or the inverse: *"this qualifies for the program's highest severity
category, and here is why."* This is exactly the manual cross-referencing
work already done, finding by finding, across Banco Plata, Coupang,
Stripchat, MathWorks, and Glassdoor. The goal is to save that specific work,
not to replace judgment about it.

## 1. Why this piece uses an LLM, unlike the verification agent

`core/verification/` is deterministic by design and must stay that way — it
compares structured fields against each other (a claimed date against a
WHOIS block, a port state against a second scanner's opinion). No language
model belongs in that comparison; a model would be strictly worse than a
string/field comparison at a task a string/field comparison already solves
exactly.

This piece is a different kind of problem: interpreting **natural-language
program rules** — prose, inconsistently structured, often with exceptions
and cross-references — against the characteristics of one finding, and
deciding whether that finding falls under a given eligibility clause. That
is a language-comprehension task, not a field comparison. An LLM is the
right tool here on the merits, not a convenience or a trend — the same way
`nmap` was the right tool to second-guess `naabu`'s port state instead of
writing a second port scanner from scratch.

These two systems must never be confused with each other in code or in
documentation: `core/verification/` never calls an LLM, and this new piece
never does deterministic field comparison as its primary judgment (only as
the grounding check on its own output — see Part C). Separate packages,
separate READMEs, a cross-reference in each pointing at the other's
docstring so a future contributor doesn't assume the pattern generalizes to
"any Hydra agent may or may not use an LLM" without reading which one they
are actually touching.

## 2. Part A — Scope and boundaries

### A.1 Input

1. **Program rules text.** Plain text or Markdown, of arbitrary length and
   structure — the same kind of long, loosely organized text already pasted
   directly into this conversation for Banco Plata, Coupang, Stripchat,
   MathWorks, and Glassdoor. No predefined schema, no required section
   headers, no assumption that eligibility/severity rules live in one
   contiguous block rather than scattered across a policy page. The
   operator supplies it as a file path (`--program-rules rules.txt`) — see
   Part D for why this is a flag on a standalone command, not a `.env`
   variable.
2. **One run's persisted `Finding` rows** (`core/assets.py::Finding`, the
   `findings` table) — real findings from a real, already-completed run,
   never a hypothetical or hand-typed description of a finding. This is
   the same "no rescan, query only" posture as `investigate`/`graph`/
   `relationships`/`verification-flags`.

### A.2 Output

One annotation per finding, containing:

- **Eligibility verdict**: `ELIGIBLE` / `NOT_ELIGIBLE` / `UNCERTAIN`.
  `UNCERTAIN` is a first-class outcome, not a fallback for a malformed
  response — program rules are often genuinely ambiguous about a specific
  finding shape, and a forced binary would misrepresent that ambiguity as
  confidence that doesn't exist.
- **The literal rule citation** — a short, verbatim quote from the rules
  text Claude was given, not a paraphrase (Part B explains why the prompt
  demands this specifically).
- **Where that citation lives** — a pointer to the exact rules-file
  snapshot this run's assessment was made against (Part C).
- **Grounding status** — did the citation verify against the real rules
  text, or is it `UNGROUNDED`? This is not optional metadata; it is the
  single most important field this system produces, and every consumer
  (CLI, report, whatever renders this later) must treat an `UNGROUNDED`
  citation as unverified, never with the same visual/textual confidence as
  a grounded one.

### A.3 Explicitly out of scope, no exceptions

- **Never hides or removes a finding from any report.** The strongest this
  system is allowed to say is "probably not eligible, here's why" — the
  operator decides what to do with that. This mirrors
  `docs/VERIFICATION_AGENT_DESIGN.md`'s own B.3 rule (an `INVALIDATES`
  verification flag moves a finding to a visible "Contradicted" section, it
  never deletes it) — the same non-negotiable applies here a fortiori,
  since this system's judgment is inherently less certain than a
  deterministic contradiction check.
- **Never drafts the final report sent to a program.** Already decided
  elsewhere in this project (`docs/VERIFICATION_AGENT_DESIGN.md` §0: "does
  not draft or send a final report unsupervised") and restated here because
  it is especially tempting to blur with this specific piece — an
  eligibility triage step sits right next to report drafting in the
  workflow, and it would be an easy scope-creep target. This system
  produces a triage annotation an operator reads before writing a report by
  hand; it does not produce report prose.
- **Never sends anything to any program.** No network call in this design
  reaches a bug-bounty platform, a program's own infrastructure, or
  anything other than the Anthropic API itself.
- **Never touches scope.** Nothing here reads its own output and decides to
  widen `SCOPE_FILE`, re-authorize a target, or trigger new collection.
  Program-rules text describes what a *program* considers reportable — it
  says nothing about what Hydra is *authorized to collect*, and this system
  must never conflate the two. `CollectionScope`/`authorize_active_indicator`
  remain the only source of truth for that question, entirely unaware this
  system exists.

## 3. Part B — Claude API integration design

### B.1 Optional-credential pattern — matches `URLHAUS_API_KEY`/`WPSCAN_API_TOKEN`/`SECURITYTRAILS_API_KEY` exactly

Reviewed all three existing opt-in API-key integrations
(`config/settings.py`, `modules/threat_intel.py`, `modules/vuln_match.py`,
`modules/passive_dns.py`) before designing this — the pattern is
consistent and this reuses it exactly, not a variant:

- `anthropic_api_key: str | None = None` on `Settings`, grouped under the
  existing `# Optional API credentials (never included in to_safe_dict)`
  comment block (`config/settings.py`, right next to
  `securitytrails_api_key`).
- Parsed the same way: `anthropic_api_key=os.getenv("ANTHROPIC_API_KEY",
  "").strip() or None`.
- `to_safe_dict()` gains `"has_anthropic_key": self.anthropic_api_key is
  not None` — a boolean, never the key itself, matching
  `has_wpscan_token`/`has_securitytrails_key`.
- `config/.env.example` gains a new block, same tone as the existing
  `URLHAUS_API_KEY` comment:

  ```
  # Reportability agent (optional, opt-in) — uses the Claude API to check a
  # finding's eligibility against a program's own rules text. Skipped
  # cleanly with a clear message if unset; see docs/REPORTABILITY_AGENT_DESIGN.md.
  # Get a key at https://console.anthropic.com/
  ANTHROPIC_API_KEY=
  # Model used for eligibility assessment — see design doc Part B.3 for why
  # this default was chosen. Override for a harder-to-classify program.
  ANTHROPIC_MODEL=claude-sonnet-5
  ```

- **Skip behavior**: the new `assess-reportability` command (Part D) checks
  for the key at the very start and exits with a clear, non-crashing
  message when it's unset — same style as `ThreatIntelPlugin.run()`'s
  `self._skip("URLhaus Auth-Key not configured")`, adapted to a standalone
  command rather than a plugin (there is no `run` pipeline stage to skip;
  the command itself refuses to start). This is never a silent no-op the
  way an unset `SECURITYTRAILS_API_KEY` is inside `passive_dns` — a command
  the operator explicitly invoked should tell them exactly why it did
  nothing, not exit 0 with no output.

### B.2 One batched call per run, not one call per finding

A single request carries: the full program-rules text once, and every
finding being assessed this pass (up to the configured limit — Part D).
Rationale, in order of importance:

1. **Correctness** — Claude needs the *whole* rules document in context to
   judge any one finding well; rules commonly cross-reference each other
   ("see the exclusions in Section 7") in ways a single-finding, single-rule-
   excerpt call would miss entirely.
2. **Cost** — one long input (rules text, likely a few thousand tokens) is
   paid once instead of once per finding; only the (small) per-finding
   description repeats.
3. **Consistency** — one conversation reading one rules document once is
   far less likely to interpret the same clause two different ways across
   findings than N independent calls would be.

### B.3 Model choice — checked live against the current model table, not assumed

Per this task's explicit instruction not to assume a model name, the
current Anthropic model lineup was checked directly (via the bundled
`claude-api` skill's live-maintained model reference, not recalled from
training) before choosing one. Current models, at design time:

| Model | Model ID | Input / Output $ per 1M tokens |
|---|---|---|
| Claude Fable 5.1 | `claude-fable-5-1` | $10 / $50 |
| Claude Opus 5 | `claude-opus-5` | $5 / $25 |
| Claude Sonnet 5 | `claude-sonnet-5` | $2 / $10 |
| Claude Haiku 4.5 | `claude-haiku-4-5-20251001` | $1 / $5 |

*Correction made during Part 2 implementation*: the model IDs above were
re-verified directly against `https://platform.claude.com/docs/en/about-claude/models/overview`
(not just the cached skill table this section originally cited) before
writing any code. Fable 5.1/Opus 5/Sonnet 5 are dateless, self-pinned IDs
("every Claude model ID is a pinned snapshot, including the dateless IDs
used from the 4.6 generation on" — official docs), so those three were
already exactly right. Haiku 4.5 was not: its real Claude API ID is the
dated snapshot `claude-haiku-4-5-20251001`; `claude-haiku-4-5` is only a
convenience alias that resolves to it, not the literal pinned ID. Fixed
above. This doesn't change the chosen default (Sonnet 5, not Haiku), but
the task's own review caught it and it's corrected here rather than left
wrong in an approved design doc.

**Chosen default: `claude-sonnet-5`.** This task's shape — read a
moderately long natural-language document once, then classify a batch of
short structured items against it and extract short literal quotes — is
squarely a reading-comprehension/extraction task, not an open-ended
agentic or long-horizon reasoning task. It is exactly the kind of workload
that does well at this tier without a quality cliff (per the same skill's
own cost-tuning guidance: "chat, classification, and high-volume routes
[...] do well at low[er tiers]", reserving the top tier for tasks that
respond strongly to it, like long-horizon coding/agentic work — this isn't
that). Given Part D's explicit cost-consciousness requirement, defaulting
to the tier that is 2.5x cheaper than Opus for a task this well-matched to
it is the right default, not a corner cut.

`ANTHROPIC_MODEL` (Part B.1) makes this an operator override, not a hard
constant — a program with unusually dense or adversarially-worded rules
text is a legitimate reason to point this at `claude-opus-5` for that one
run.

**Request shape**: a single non-streaming `client.messages.parse()` call
(batch sizes are capped low enough — Part D — that output stays well under
streaming-timeout territory), `thinking: {type: "adaptive"}` at
`output_config: {effort: "medium"}` (this is a single batched judgment call,
not a multi-turn agentic loop, so the cost of a slightly higher effort
level is bounded and paid once per run — worth it for a task where a wrong
`ELIGIBLE` call has real consequences), and **structured outputs** via
`output_format=<a Pydantic model>` (the SDK translates this to
`output_config.format` internally) rather than freeform text — validated,
typed output in, no ad hoc text parsing of Claude's response.

*Verified during Part 2 implementation, not assumed*: fetched
`https://platform.claude.com/docs/en/build-with-claude/structured-outputs`
and `https://platform.claude.com/docs/en/build-with-claude/token-counting`
directly, and introspected the real installed SDK
(`pip install anthropic==1.5.0`, the current release) rather than trusting
this section's original draft on faith. Every mechanic below matched what
this design already assumed, with no beta header required for any of it:
`output_config.format` with `{"type": "json_schema", "schema": {...}}` is
real and current; `client.messages.parse(..., output_format=SomePydanticModel)`
exists on the installed SDK and exposes `response.parsed_output`;
`client.messages.count_tokens(...)` (Part D.3) is a real, free,
no-beta-header endpoint that also accepts `output_config`/`output_format`,
so the pre-flight cost estimate can include the schema's own token
overhead, not just the raw text. Nothing about the request shape needed to
change — only the Haiku model ID above did.

Proposed schema (illustrative — Part 2 finalizes the exact field set):

```json
{
  "assessments": [
    {
      "finding_id": 142,
      "eligibility": "NOT_ELIGIBLE",
      "rule_citation": "Findings on assets not listed in the Scope table above are not eligible for reward.",
      "reasoning": "The affected host is not listed in the program's in-scope asset table."
    }
  ]
}
```

`rule_citation` is an empty string, never omitted, when Claude judges that
no specific rule text applies to a given finding (e.g. a genuinely
unaddressed edge case) — this is a valid, distinct outcome from
`UNGROUNDED` (Part C.3): "no citation offered" is not "a citation was
offered and failed to verify."

### B.4 The prompt must demand literal quotes, not summaries — for a mechanical reason, not a style preference

The system/user prompt explicitly instructs Claude to quote short, verbatim
spans of the rules text — never to summarize or paraphrase a rule before
citing it. This is not a wording nicety: it is what makes Part C.3's
grounding check possible as a **plain text comparison**, the same
`core/verification/grounding.py` principle the verification agent already
established (design constraint, restated from the top of this task: *"la
verificación de fundamento debe confirmarse con una comparación de texto
simple, no con otro LLM juzgando si la paráfrasis es fiel"*). A prompt that
allowed paraphrased citations would force the grounding check to become a
second semantic judgment — exactly the thing this constraint exists to
prevent.

## 4. Part C — Data model and persistence

### C.1 Decision: a new table, `reportability_assessments` — not a reuse of `findings` or `verification_flags`

Same review discipline as `docs/VERIFICATION_AGENT_DESIGN.md` Part C
applied here, not skipped because a precedent already exists:

- **Not `findings`.** A `Finding` is a claim *about the target*
  (`host`, `template_id`, `severity`, ...). A reportability assessment is a
  claim *about a `Finding`* — a different, one-level-removed kind of row.
  Folding it in would also force irrelevant columns (`template_id`,
  `severity`) onto every assessment row, or force reportability-specific
  columns (`eligibility`, `rule_citation`) onto every ordinary finding.
- **Not `verification_flags`.** Close in *shape* (both are meta-annotations
  over other persisted rows, both carry an evidence citation and a
  raw-artifact pointer) but wrong in *semantics*: `verification_flags.severity`
  is `ContradictionSeverity` (`INVALIDATES` / `DOWNGRADES_CONFIDENCE`) —
  meaningless for an eligibility verdict, which is a three-way
  classification on a completely different axis (reportable under a
  program's rules, not "does this claim contradict its own evidence").
  Reusing the column would mean overloading `severity` with two unrelated
  vocabularies, exactly the kind of ambiguity the verification agent's own
  design explicitly rejected when it chose not to reuse `findings`.
- Unlike `verification_flags.related_id` (a deliberately loose,
  non-foreign-key pointer, because a verification flag can point at a
  finding, a host, a relationship, or nothing at all), a reportability
  assessment **always** points at exactly one real `findings.id` — Part
  A.1 fixes the input shape to "a persisted `Finding`", nothing looser. So
  `finding_id` here is a real `FOREIGN KEY REFERENCES findings(id)`, a
  stronger guarantee than `verification_flags` could offer for its own,
  broader problem.

### C.2 Proposed schema

```sql
CREATE TABLE IF NOT EXISTS reportability_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    finding_id INTEGER NOT NULL,
    eligibility TEXT NOT NULL,          -- ELIGIBLE | NOT_ELIGIBLE | UNCERTAIN
    rule_citation TEXT,                 -- verbatim quote, or '' if none applies
    citation_grounded INTEGER,          -- 1/0/NULL — NULL when rule_citation is ''
    reasoning TEXT,                     -- short, informational only, never grounded/verified
    program_rules_artifact TEXT NOT NULL, -- path to this run's rules-text snapshot (C.3)
    source TEXT NOT NULL DEFAULT 'reportability_agent',
    model_used TEXT NOT NULL,           -- e.g. "claude-sonnet-5" — which version made this call
    assessed_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(run_id),
    FOREIGN KEY(finding_id) REFERENCES findings(id)
);
CREATE INDEX IF NOT EXISTS idx_reportability_run ON reportability_assessments(run_id);
CREATE INDEX IF NOT EXISTS idx_reportability_finding ON reportability_assessments(finding_id);
```

`source` and `model_used` are both required by this task's brief
explicitly, for the same reason: traceability if the default model ever
changes — a future reader must be able to tell which assessments came from
which model version without guessing from a timestamp.

### C.3 Grounding — shares `core/verification/grounding.py`, extended rather than duplicated

Per this task's explicit instruction not to reinvent the B.3 principle
separately: `core/verification/grounding.py::is_claim_grounded` already
does the core check this needs (resolve a raw-artifact path confined to a
run's own output directory, confirm the file exists, confirm the value
appears in it) — but it requires an **exact** substring match, and this
task's brief explicitly allows "minor paraphrase" in what still counts as
grounded (Claude may reflow whitespace, normalize a smart quote, or drop a
trailing ellipsis when quoting — none of that should register as a made-up
citation).

Proposed addition to the same module (not a new one — `grounding.py` is
already a small, dependency-light leaf module either system can import
without one depending on the other):

```python
def is_citation_grounded(
    citation: str, raw_artifact: str | None, output_dir: Path, *, allow_minor_paraphrase: bool = True
) -> bool:
    """Like is_claim_grounded, with a bounded tolerance for
    whitespace/punctuation-only reformatting — never for a semantically
    different rewording. Three checks, in order, first match wins:
      1. is_claim_grounded's own exact substring check (unchanged, reused).
      2. Both citation and source text normalized (lowercased, whitespace
         collapsed, smart quotes/ellipses folded to ASCII) — still an exact
         substring check, just on normalized text.
      3. Only if allow_minor_paraphrase: a difflib.SequenceMatcher ratio
         against the best-matching window of the source text, above a
         fixed, conservative threshold (proposed: 0.92) — deliberately
         high, to admit "the same sentence with one word's whitespace
         reflowed" and reject "the same idea in different words."
    No LLM at any step — every check here is a plain-text algorithm, per
    this design's own non-negotiable constraint.
    """
```

The threshold in step 3 is a real design decision with a real false-accept/
false-reject tradeoff, not a throwaway constant — Part 2 must justify
whatever value it ships with against real quotes from at least one of the
five programs' actual rules text already in hand (Banco Plata, Coupang,
Stripchat, MathWorks, Glassdoor), not a synthetic example, and must show
what a deliberately fabricated citation looks like failing the check at
that threshold.

`is_claim_grounded` itself is untouched — `verification_flags` keeps its
existing exact-match behavior; loosening it was never asked for and there
is no evidence it needs it (a deterministic contradiction detector citing
its own structured input has no "paraphrase" to tolerate in the first
place).

### C.4 Where the rules text itself lives

`assess-reportability` snapshots the `--program-rules` file the operator
passed into the run's own `output_dir` (e.g.
`output/<run_id>/program_rules_snapshot.txt`) at assessment time, rather
than reading it from wherever the operator's original file happens to live
later. Two reasons: it gives `program_rules_artifact` (C.2) the same
output-dir-confined resolution `is_claim_grounded`/`is_citation_grounded`
already require, and it preserves *exactly* which version of a program's
rules a given assessment was made against — program rules pages change
over time, and re-running `assess-reportability` a month later with an
updated rules file must never silently reinterpret an old assessment.

## 5. Part D — Cost and usage control

### D.1 A standalone command, never automatic after `run`

```
python app.py assess-reportability <run_id> --program-rules rules.txt [--limit N] [--severity high,critical] [--host example.com] [--yes]
```

Not wired into `python app.py run` in any way — running Hydra normally
must never silently spend Anthropic API credits. This mirrors
`docs/VERIFICATION_AGENT_DESIGN.md`'s own instinct to make the
harder-to-undo/costlier operations explicit commands rather than default
pipeline behavior, one level further: this is the only piece of Hydra
design so far that spends real, variable, per-run money on a third-party
API, so it gets the most explicit opt-in of anything in the project to
date.

### D.2 Configurable batch ceiling

`REPORTABILITY_MAX_FINDINGS_PER_BATCH` (proposed default: 50) on
`Settings`, same `.env` pattern as every other numeric limit
(`MAX_DISCOVERY_DEPTH`, `PORT_VERIFY_MAX_HOSTS`, ...). If the findings
selected for this run (after `--severity`/`--host` filters) exceed the
configured ceiling, the command **refuses to proceed** rather than
silently assessing only the first N — it prints the real count and asks
the operator to either narrow the selection with `--severity`/`--host` or
raise the ceiling explicitly with `--limit`. Silently truncating a batch
without saying so would be exactly the kind of unannounced-cost surprise
this whole section exists to prevent.

### D.3 Visible estimate before any classification call is made

Before the real assessment call, the command:

1. Prints how many findings matched the current filters and will be sent.
2. Calls `client.messages.count_tokens(...)` (a free, dedicated endpoint —
   not the classification call itself) against the actual assembled
   request (full rules text + all selected findings) to report a real
   input-token count, and multiplies by the chosen model's published
   per-token price for an approximate cost line — labeled as an estimate
   (output-token cost is not knowable in advance and is called out as
   such, not silently omitted).
3. Requires interactive confirmation before proceeding — same shape as
   `app.py::_external_mode_preflight`'s existing `input(...)` gate for
   running active modules against an unowned domain: prompts when a
   terminal is attached, and **fails closed** (refuses, does not proceed)
   on non-interactive stdin unless the operator passed `--yes` explicitly.
   No environment gets a surprise bill because a script piped this
   command's stdin from `/dev/null`.

### D.4 Dependency placement

`anthropic` (the Python SDK) goes in `requirements-optional.txt`, next to
`playwright` — both are opt-in, both are absent from a base install, and
neither should ever silently become a hard dependency of `python app.py
run`.

## 6. What Part 2 (implementation) built, in order

**Status: implemented** (branch `feat/reportability-agent-design`, commits
after this document's initial approval). Each step below links to the
test(s) proving it, per this project's standing practice.

1. **Done.** `reportability_assessments` table + `Settings.anthropic_api_key`/
   `anthropic_model`/`reportability_max_findings_per_batch` +
   `config/.env.example` block (Part B.1, C.2, D.2). `core/reportability/model.py`
   (`Eligibility`, `ReportabilityAssessment`) was built alongside this step
   rather than deferred to step 3 as originally listed here — the SQL
   layer needed the enum/dataclass to be testable at all, the same way the
   verification agent's own step 1 bundled its table with its model.py.
   Proven by `tests/test_reportability_model.py` (12 tests) — the
   three-value enum guard, the `__post_init__` invariant that makes
   "no citation offered" and "a citation failed to verify" impossible to
   conflate, and the full SQLite round-trip including the real foreign
   key to `findings.id`.
2. **Done.** `is_citation_grounded` in `core/verification/grounding.py`
   (Part C.3). The threshold in this document's original draft (0.92,
   proposed as a plausible placeholder) turned out to be too loose once
   measured against real text — real `tests/fixtures/stripchat_rules.txt`
   sentences with a single word negated ("...is prohibited." → "...is
   permitted.") scored as high as 0.975 by raw character similarity,
   despite inverting the sentence's meaning. Raised to 0.98, and — more
   importantly — restructured so whitespace/case/quote-style variation is
   absorbed by an exact match on *normalized* text (a separate, still-
   zero-fuzziness step) before the ratio-based fallback ever runs, so that
   fallback only ever has to cover genuine single-character-level slips,
   not the noise that made 0.92 unsafe in the first place. Proven by
   `tests/test_verification_grounding.py::TestIsCitationGroundedAgainstRealStripchatRules`
   (13 tests, all against the real fixture): exact match, two
   normalization cases, the one legitimate fuzzy-match case, two
   adversarial negation-flip rejections at the exact ratios that motivated
   raising the threshold, a dropped-word rejection, and the fabricated-
   citation-with-no-real-counterpart rejection.
3. **Done.** `core/reportability/` package (Part B): `schema.py`
   (`FindingAssessment`, `ReportabilityBatchResult`), `prompt.py`
   (`SYSTEM_PROMPT`, `build_user_message`), `client.py`
   (`ReportabilityClient`, `ReportabilityAPIError`). Built only after
   independently re-verifying the request shape against
   `platform.claude.com`'s current docs and the real installed
   `anthropic==1.5.0` SDK source (`Messages.parse`/`Messages.count_tokens`)
   — not this document's original, unverified draft. Finding: everything
   about the request shape (`output_config.format`, `thinking: {"type":
   "adaptive"}`, the free `count_tokens` endpoint) was already correct;
   only the Haiku model ID in this document's own model table was wrong
   (`claude-haiku-4-5` is an alias, not the real dated snapshot
   `claude-haiku-4-5-20251001` — corrected in Part B.3 above). Proven by
   `tests/test_reportability_client.py` (14 tests, the real Anthropic API
   call mocked in every one): the prompt actually contains its literal-
   quote/empty-citation/scope-and-report non-negotiables, `assess_batch`
   passes the right thinking/effort/schema and returns the parsed output
   unchanged, a `None` `parsed_output` raises rather than silently
   succeeding, and every mapped exception type (constructed as the real
   SDK classes) produces the right message.
4. **Done.** `python app.py assess-reportability` command (Part D):
   `--severity`/`--host`/`--limit` filtering, the batch-ceiling refusal,
   the real `count_tokens`-based cost estimate, and the interactive
   confirmation gate (fails closed on non-interactive stdin without
   `--yes`, mirroring `app.py::_external_mode_preflight`'s existing
   pattern exactly). Proven by `tests/test_reportability_cli.py`
   (17 tests): every failure mode fails clean and specific (missing key,
   missing database/run, empty rules file), the ceiling refuses on both
   the configured default and an explicit `--limit` and never truncates
   silently, the confirmation gate's fail-closed/`--yes`-bypass/decline
   paths, a hallucinated `finding_id` is discarded with a warning and
   never persisted, the rules snapshot is written verbatim only after a
   successful call, and — the test this whole system is built around — a
   fabricated citation is persisted as ungrounded *and* printed as a
   visible warning with its full text, never silently accepted.
5. **Done, with an honest limitation.** No `ANTHROPIC_API_KEY` was
   available in the implementation environment (checked directly — shell
   env, `.env`, `config/.env`, all unset — not assumed). Rather than
   fabricate a "verified live" claim, the same opt-in skip pattern this
   project already uses for real-binary confinement tests
   (`shutil.which(...)`/`pytest.importorskip(...)` in
   `tests/test_*_confinement_live.py`) was applied to a real credential
   instead: `tests/test_reportability_live.py` skips cleanly without a
   key and, when a real key is present, drives a real persisted finding
   through the real `cmd_assess_reportability` against the real, full
   Stripchat rules text end to end. What this document's author *did*
   confirm directly, honestly labeled as such: an end-to-end run through
   the real `cmd_assess_reportability` code path — real persisted
   `Host`/`Finding` rows, the real, full rules fixture, the real
   `is_citation_grounded` check, the real batch-ceiling/cost-estimate/
   confirmation/snapshot logic — with *only* the Anthropic network call
   itself mocked, proving one grounded real citation and one deliberately
   fabricated citation both resolve correctly (`citation_grounded: 1`
   and a clean grep of the snapshot for the first; `citation_grounded: 0`
   and a visible operator warning, absent from the snapshot on grep, for
   the second). This is not the same claim as a verified live API
   response and was not presented as one.

### Honest strength assessment

- **Strongest**: `is_citation_grounded`'s threshold and every adversarial
  case it rejects — measured against real program rules text, not
  invented numbers (step 2). The fail-closed batch ceiling and
  confirmation gate — directly exercised, no API involved at all (step 4).
- **Solid but network-mocked**: the Claude API request/response shape
  itself — verified against current, real documentation and the real SDK
  source, and exercised end-to-end with the network boundary mocked, but
  never against a real response from the model (steps 3 and 5).
- **Weakest, by necessity, not by choice**: whether Claude *itself*
  reliably follows the verbatim-quote instruction in practice, across a
  variety of real program rules texts and finding shapes — that can only
  be learned by actually running this against the real API on real runs,
  which requires `ANTHROPIC_API_KEY` and did not happen in this
  environment. `tests/test_reportability_live.py` is what to run, and
  what its own first real result should be sanity-checked against, once a
  key is available.

## 7. Commit scope

Part 2 implemented across incremental commits on
`feat/reportability-agent-design`, one per numbered step above. Not
merged — left for review via the project's own process (clone, run tests
independently, verify, then approve the merge).
