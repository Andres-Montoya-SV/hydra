# Hypothesis Engine — Design (Part 1)

**This is design only. No implementation in this document or its commit.**
Same discipline as the correlation engine, the verification agent, and the
reportability agent: document first, checkpoint, implement after review.

---

## 0. The principle, restated precisely

`core/intel/engine.py::_emit_hypotheses` already exists and already
populates `intel_hypotheses` — but it is one fixed rule: for every
`SAN_CONTAINS` relationship (a domain appearing as a SAN on a certificate),
emit a hypothesis that it might be related infrastructure, `OPEN` if
in-scope, `REJECTED` otherwise. It never looks at `SHARES_IPV4`,
`SHARES_ASN`, `SHARES_NAMESERVER`, `SHARES_CERTIFICATE`, or any
cross-module finding pattern — those relationships exist in the graph,
correctly confidence-scored, and are simply never turned into a
natural-language lead a human would act on.

The gap this design closes: a human analyst looking at a correlated
`virusbarrier.xyz`-shaped case doesn't stop at "SAN relationship exists" —
they reason across *everything* at once ("these six share a certificate,
which is strong; two of them also share an ASN, which on its own would be
weak, but combined with the certificate it's just corroborating, not
adding independent weight; the WHOIS registrant pattern across all six is
identical too — that's a fourth independent signal pointing the same
way"). That synthesis — reading several already-correlated signals
together and proposing what to look at next — is what an LLM can do that
a fixed per-relationship-type rule cannot. It is not a replacement for the
correlation engine (which already did the hard, deterministic, auditable
work of relationship extraction and confidence scoring); it is a reasoning
layer on top of that engine's output.

---

## 1. Why this piece uses an LLM, same test the reportability agent's design applied

`docs/REPORTABILITY_AGENT_DESIGN.md` Section 1 asked "why does *this*
piece need an LLM when the verification agent deliberately doesn't" and
answered: the verification agent's checks are mechanical (does this citation
exist verbatim, was this host actually in scope) — a rule engine is not
just adequate but *more trustworthy* than an LLM for those. Reportability's
task — does this specific finding fall inside program rules written in
free-form prose — requires genuine language understanding no rule engine
can approximate.

The hypothesis engine passes the same test the same way. "Does entity X
share IP with entity Y" is exactly the mechanical kind of question the
correlation engine already answers better than an LLM ever should — that
work stays exactly where it is, untouched. "Given everything the
correlation engine found, what is the single most useful thing for a human
to look at next, and how would you explain why" is not a question with a
deterministic right answer; it requires the same kind of synthesis-across-
evidence judgment that made an LLM the right tool for reportability's
prose-interpretation task, applied here to evidence-synthesis instead of
rule-interpretation.

---

## 2. Part A — Scope and boundaries

### A.1 Input

Exactly the already-persisted, already-correlated output of a run — never
raw collection artifacts:

- `intel_relationships` (every `RelationshipType`, not just
  `SAN_CONTAINS` — `SHARES_CERTIFICATE`, `SHARES_IPV4`/`SHARES_IPV6`,
  `SHARES_ASN`, `SHARES_NAMESERVER`, `SHARES_FAVICON`,
  `SHARES_BODY_HASH`, `SHARES_TLS_CHARACTERISTICS`, all with their real
  `confidence_band` and `data` payload — the same fields
  `core/intel/cli.py::cmd_evidence` already prints for a human).
- `intel_entities` for every entity referenced by a relationship above —
  domains, certificates, IPs, ASNs, nameservers — read-only, as already
  persisted.
- Findings from `findings` (the table `assess-reportability` also reads),
  filtered to a run, optionally filtered to hosts that appear in the
  relationship graph above (a finding on a host with no correlated
  relationships is reportability's problem, not this engine's).
- `verification_flags` **already resolved** — specifically, only
  `CONFIRMED` (or the equivalent non-`INVALIDATES`, non-pending) state.
  An unverified or invalidated finding must never become hypothesis
  input; feeding the LLM a claim the verification agent has already
  flagged as unreliable would launder that unreliability into a
  human-readable "lead" that looks more credible than the data underneath
  it warrants.

Explicitly **not** input: `alive.txt`, raw `httpx.json`/`dnsx_records.jsonl`,
anything a plugin wrote directly. If the correlation engine hasn't turned
it into an `intel_entities`/`intel_relationships` row, the hypothesis
engine has no business reading it — reprocessing raw artifacts would mean
duplicating (and inevitably drifting from) the correlation engine's own
extraction logic, exactly the redundancy Part 0 above says this design
must not create.

### A.2 Output

Per hypothesis:

- **Statement**: one to three sentences of natural language, written for
  the human analyst who will read `python app.py investigate <domain>` or
  an equivalent new command — not a data structure dump.
- **Supporting evidence, explicit and structured**: the list of
  `relationship_id`s and `entity_id`s the statement is actually built
  from. Not "trust me, I read the data" — a concrete, checkable list, the
  exact analog of reportability's `rule_citation`: the field the grounding
  check verifies mechanically, one item at a time (Section 6).
- **Confidence**: the LLM's own stated confidence in the hypothesis
  *given the evidence cited* — informational, like reportability's
  `confidence` field, never mechanically checked (there is no ground
  truth for "how confident should you be," only for "does the cited
  evidence exist").
- **Suggested next step, in words only**: "worth checking whether X and Y
  share infrastructure beyond what's already observed" is a valid thing
  for a hypothesis to say. It is never a structured, actionable field a
  human (or code) could accidentally pass straight into a collection
  call — see A.3.

### A.3 Explicitly out of scope, no exceptions

- **Never authorizes or expands collection.** The engine has no access to
  `CollectionGateway`, `authorize_active_indicator`, or any scope-mutating
  function, by construction — not by a runtime check that could be
  bypassed, but by simply never importing those modules. If a future
  human decides to act on a suggested next step, that action goes through
  the exact same `CollectionGateway`/authorization path any other
  collection request does; the hypothesis is a suggestion in a text
  field, indistinguishable at that point from a human analyst's own
  notes.
- **Never generates a final report.** `assess-reportability` decides what
  is submittable against program rules; this engine never touches that
  decision, that table, or that command.
- **Never runs inside `python app.py run`.** A standalone command
  (Section 5), exactly like `assess-reportability` — triggered explicitly,
  after a run has finished and been correlated, never silently, never
  automatically, never in the hot path of a live collection run.
- **Never uses actor/owner/attribution language.** `tests/test_virusbarrier_e2e.py`
  already asserts `"actor" not in blob` and `"owner" not in blob` against
  the correlation engine's own raw output; `README.md`'s Security model
  section states this as a standing design principle for the whole
  project. The hypothesis prompt must carry the identical instruction
  `core/intel/engine.py`'s own rationale strings already follow ("possible
  related infrastructure," never "operated by the same actor") — this is
  not a new constraint invented for this feature, it is the same one
  applied to a new surface that happens to be much better at sounding
  authoritative if not explicitly told not to.

---

## 3. Part B — Relationship to the reportability agent

### B.1 What is shared

**The provider abstraction, generalized one level.**
`core/reportability/provider.py`'s `ReportabilityProvider` Protocol and
`create_provider()` factory are *not* directly reusable as written — its
two methods, `assess_batch(rules_text, findings) -> ReportabilityBatchResult`
and `review_batch(...) -> AdversarialBatchResult`, are typed against the
reportability schema specifically. But the pattern underneath both
provider implementations (`core/reportability/client.py`,
`core/reportability/openai_client.py`) is generic: a thin per-SDK wrapper
whose only job is "take a system prompt, a user message, and a Pydantic
output schema; return the parsed structured result; map every SDK
exception to one domain error type via a most-specific-first `_describe`
function." That primitive — call it `StructuredLLMClient` or similar —
should be extracted into a shared module (e.g. `core/llm/client.py`) that
both `core/reportability/` and the new hypothesis-engine package build on,
rather than duplicating the `anthropic.messages.parse(...)`/
`openai...responses.parse(...)` plumbing and the exception-mapping table a
second time. `core/reportability/client.py`/`openai_client.py` would
become thin task-specific wrappers over that shared primitive (their
`assess_batch`/`review_batch` methods stay, calling the shared client
underneath) rather than being replaced.

**The cost-estimation table and cost-line formatting.**
`core/reportability/cli.py::_INPUT_PRICE_PER_MTOK`/`_cost_line` are
already fully generic (a model name and a token count in, a formatted
estimate string out) — no reportability-specific content at all. Move
this to the same shared module so both commands cite the same numbers
from one place; two independently-drifting pricing tables would be a real
maintenance hazard the first time a model's price changes.

**The fail-closed interactive-confirmation pattern.**
`core/reportability/cli.py`'s `sys.stdin.isatty()` check and its exact
refusal message are worth reusing verbatim as a pattern (not necessarily
factored into a shared function, since it's four lines and the exact
wording matters per-command) — Section 5 below applies it identically.

**The grounding *principle*, not the grounding *code*.** See Section 6 —
`is_citation_grounded` itself is a text-matching algorithm specific to
"does this quoted string appear in this text artifact." The hypothesis
engine's grounding check is a structured-data lookup ("does this
`relationship_id` exist in `intel_relationships` for this `run_id`") —
different code, same non-negotiable discipline: every factual claim is
checked against the real data, never taken on the model's word.

### B.2 What is deliberately separate

**The prompt and schema.** Reportability's prompt asks a closed question
about one finding against one rules text; this engine's prompt asks an
open question about a whole evidence graph. `core/reportability/prompt.py`/
`schema.py` stay exactly as they are; the hypothesis engine gets its own
`core/hypotheses/prompt.py`/`schema.py` (naming below, Section 4) with
content that has nothing in common with reportability's beyond both being
Pydantic models passed as `output_format`.

**The persisted schema.** See Section 4 — `intel_hypotheses` (the
existing, heuristic-populated table) is not reused as-is; a new table is
needed, for the same reason `reportability_assessments` was a new table
rather than a `findings`/`verification_flags` reuse
(`docs/REPORTABILITY_AGENT_DESIGN.md` Section C.1).

**The CLI command's actual logic**, even though its *shape* (cost
estimate, confirmation, batch limit) mirrors `assess-reportability`
closely (Section 5) — the input query (relationships + entities +
verified findings, not `findings` filtered by severity/host) and output
persistence are different enough that this is a new command, not a flag
on the existing one.

### B.3 The decision, stated plainly

Share the API-calling layer and the cost/confirmation UX pattern (both
generic, both would drift expensively if duplicated); do not share the
prompt, schema, or persisted data model (both are the actual substance of
each task, and that substance is genuinely different). This mirrors how
the verification agent and reportability agent already relate to each
other in this codebase: both use `core/store.py`, both follow the
run-scoped-SQL discipline, neither shares a prompt or a table with the
other.

---

## 4. Part C — Does adversarial cross-validation apply?

**Not as reportability implements it — independent generation compared
for disagreement — but a close relative of it does, and is worth
building.**

### 4.1 Why independent generation doesn't transfer

Reportability's adversarial signal works because eligibility is a closed
question: for one finding against one fixed rules text, there is a real
fact of the matter (`combine_eligibility` treats an adversarial `AGREE` as
the only way the final answer equals the primary's; any real `DISAGREE`,
or a reviewer that genuinely can't tell, collapses to `UNCERTAIN` rather
than trusting the primary alone). Two providers disagreeing on a closed
question is real signal: at least one of them is wrong, and "we don't
know which" is the honest, useful thing to report.

Hypothesis generation is not a closed question. Given six correlated
domains, "these share a certificate, which is a strong technical
relationship" and "the WHOIS registrant pattern across all six deserves a
closer look" are both perfectly valid hypotheses from the *same* evidence
— they're not competing answers to one question, they're two different
analysts each picking a defensible angle. Running two providers
independently and treating non-overlapping hypothesis lists as
"disagreement" would manufacture a false signal: of course two open-ended
brainstorms produce different lists. That would either (a) train the
operator to ignore the disagreement signal because it fires on every run,
or (b) get "fixed" by silently narrowing what the engine is allowed to
propose until it stops disagreeing with itself — actively worse than not
having the signal at all.

### 4.2 What does transfer: review, not regeneration

Look again at what reportability's adversarial call actually does — not
"generate your own answer from scratch" but `review_batch(rules_text,
findings, primary_result)`: **review a specific, already-produced verdict**
and say whether it holds up. That mechanism doesn't depend on the
underlying task having one right answer; it depends on the underlying
*claim* being checkable. A hypothesis makes a specific, checkable claim
too — not "is this the correct hypothesis" (no ground truth), but "does
this hypothesis's stated reasoning actually follow from the evidence it
cites, or does it overreach" (a real, checkable question about one
specific piece of reasoning, independent of whether some other valid
hypothesis exists).

So the design carries the *review* pattern over, reframed: a second
provider is shown one hypothesis at a time — its statement and its cited
evidence (the same entities/relationships, already grounding-checked
mechanically per Section 6) — and asked to classify it
`SOUND` / `OVERREACHES` / `INSUFFICIENT_EVIDENCE`, with the same fail-closed
combination reportability uses (`SOUND` is the only way the hypothesis
keeps its primary confidence; anything else downgrades it, never silently
kept). This catches a different, real failure mode than mechanical
grounding does: grounding proves the cited entities/relationships *exist*;
reasoning review catches a hypothesis that cites three real, existing
relationships but draws a conclusion those three relationships don't
actually support (e.g. inflating "these two share a hosting provider" into
language that reads like common ownership) — the same class of error
`allows_active_collection`/`_emit_hypotheses`'s own careful rationale
wording already goes out of its way to avoid making itself.

### 4.3 What this design does not do

It does not run two providers to *generate* the hypothesis list and diff
them. It does not treat "provider B didn't think of what provider A
thought of" as meaningful. Both would misapply a mechanism designed for a
closed-answer task onto an open-answer one. Reasoning-soundness review of
one provider's already-produced output, by a second, different provider,
is the part of adversarial cross-validation that generalizes — and only
that part.

---

## 5. Part D — Cost and control

Identical operational shape to `assess-reportability`, reusing the
generalized pieces from Section 3:

- **Standalone command**: `python app.py generate-hypotheses <run_id>`
  (working name), never invoked by `run`, never automatic.
- **Configurable batch ceiling**: a new setting
  (`HYPOTHESIS_MAX_RELATIONSHIPS_PER_BATCH` or similar — named to match
  the existing `REPORTABILITY_MAX_FINDINGS_PER_BATCH` convention exactly)
  bounding how many relationships/entities go into one call, with the
  same "refuse to silently process only some of them, raise the ceiling
  explicitly with `--limit` instead" behavior
  `cmd_assess_reportability` already implements.
- **Real cost estimate before spending anything**: `count_input_tokens`
  (or its shared-client equivalent, Section 3) called and printed before
  any classification call, using the same shared pricing table — for
  Anthropic, a real free-endpoint count; for OpenAI, the same disclosed
  character-based approximation reportability already uses and labels as
  such.
- **Fail-closed confirmation**: `sys.stdin.isatty()` check, `--yes` to
  bypass in an automated context, refuse (not silently proceed) when
  stdin isn't a terminal and `--yes` wasn't passed — the exact pattern
  from `core/reportability/cli.py` lines ~260-270, reused verbatim.
- **Adversarial review is opt-in**, exactly like
  `--adversarial-provider` — a second provider name flag, absent by
  default, and (Section 4) reframed as reasoning-soundness review rather
  than independent generation-and-diff.

---

## 6. Grounding — the mechanism, concretely

Reportability's grounding question is "does this exact quoted string
appear in this text file." The hypothesis engine's grounding question is
structural: "does this `relationship_id`/`entity_id` the model cited
actually exist, for this `run_id`, in `intel_relationships`/
`intel_entities`." That is a parameterized SQL lookup, not a text-matching
algorithm — no fuzzy tier, no normalization, no "close enough": either the
row exists for this run or it doesn't. This is *stricter* than
reportability's own default fuzzy-tolerant grounding, and deliberately
so — a fabricated `relationship_id` is not a paraphrase of a real one the
way a slightly-reworded quote might be; there is no legitimate reason for
an LLM to cite an ID that doesn't exist, so the check should never
tolerate one.

Grounding classification per hypothesis, mirroring
`citation_grounded`/`UNGROUNDED`'s severity framing from reportability:

- **GROUNDED**: every cited `relationship_id`/`entity_id` exists for this
  `run_id`.
- **PARTIALLY_GROUNDED**: at least one citation exists and at least one
  doesn't — surfaced distinctly, not collapsed into either extreme,
  since "half the evidence is real" is a materially different and more
  actionable state for an analyst than either GROUNDED or UNGROUNDED
  alone.
- **UNGROUNDED**: zero cited entries exist for this run. Treated exactly
  as severely as reportability treats an ungrounded citation — the
  hypothesis is not deleted (an analyst may still want to see what the
  model was trying to say), but it is never presented as equivalent to a
  grounded one, and any summary view sorts/flags ungrounded hypotheses
  distinctly, the same way reportability never lets an ungrounded
  assessment blend in as fully trustworthy.

A second, narrower check beyond existence: does the cited relationship's
*type* match what the hypothesis statement claims about it (a hypothesis
that says "these hosts share a certificate" citing a relationship whose
real `relationship_type` is `SHARES_ASN` is citing something real but
mischaracterizing it — existence alone wouldn't catch that). This is
still a mechanical, structural check (compare the claimed relationship
kind, extracted from a required structured field, against the real
`relationship_type` column) — never an LLM judging its own citation.

---

## 7. Part E — The virusbarrier.xyz foundational case

### 7.1 What a human analyst already concluded (the ground truth this design targets)

From the real, captured case (`tests/fixtures/virusbarrier/case.json`,
`tests/test_virusbarrier_e2e.py`): six domains share one TLS certificate
(`fingerprint_sha256`; `core/intel/correlate.py::shares_certificate_confidence`
returns `HIGH`/`"shared_leaf_certificate"` for a low-cardinality,
low-diversity certificate like this one — `SAN_CONTAINS`, a separate
relationship type for each domain's own membership on the certificate, is
independently `VERY_HIGH` per that same function's docstring) and, once
passive DNS closes the resolution gap, the same IPv4 on Google Cloud
Platform (`SHARES_IPV4`, capped at MEDIUM confidence —
`tests/test_virusbarrier_e2e.py` explicitly asserts `not any(r.confidence.value
== "HIGH" for r in shared_ip)`). The correlation engine already encodes
the exact distinction a human analyst would draw: a shared certificate
across six SANs is a strong, hard-to-fake technical relationship (whoever
requested that certificate controls all six names, at least at
issuance time); a shared IP alone is weak on a cloud platform where
thousands of unrelated tenants can share the same load balancer or
address pool — corroborating, never independently conclusive.

### 7.2 What the engine should propose, and how each claim would ground

Two hypotheses a human already implicitly formed, restated as what this
design expects the LLM to produce:

1. **"The six domains sharing this certificate are very likely
   commonly-provisioned infrastructure, not independently-registered
   sites that happen to overlap."** Cited evidence: the pairwise
   `SHARES_CERTIFICATE` relationship rows `_pairwise_share` creates across
   the six domains (each real, each carrying the real
   `fingerprint_sha256`; the exact count is bounded by
   `bounds.max_relationships_per_signal`, not necessarily one row per
   domain — the hypothesis should cite whichever rows it was actually
   given, not assume a fixed count) plus the certificate entity itself
   (`san_cardinality: 6`, real `not_before`/`not_after` window). Expected
   grounding: **GROUNDED** — every citation is a real row for this run.
   Expected confidence: HIGH, and the design's own worked example for
   what a *correct*, well-reasoned hypothesis looks like.
2. **"The shared Google Cloud Platform IPv4/ASN is consistent with, but
   does not independently establish, common infrastructure — cloud
   tenancy alone is not a reliable signal on its own."** Cited evidence:
   the `SHARES_IPV4` relationship(s) (MEDIUM confidence, real `ip`/
   `provider`/`asn` fields) plus explicit acknowledgment in the
   statement itself that this evidence is weaker than the certificate
   evidence above — the prompt should reward a hypothesis that
   *correctly characterizes* the strength of shared-IP evidence, not one
   that treats it as equally conclusive. Expected grounding:
   **GROUNDED**. A hypothesis that instead said "the same operator
   controls all six via this shared IP" — overstating a MEDIUM-confidence,
   cloud-tenancy relationship as ownership-equivalent to the certificate
   evidence — is exactly the shape of output the reasoning-soundness
   review (Section 4.2) exists to catch, even though every entity/
   relationship ID it cited would still pass the mechanical grounding
   check in Section 6. This is the concrete reason both checks are
   needed: grounding alone would pass that overreaching hypothesis
   cleanly.

### 7.3 A deliberately wrong hypothesis this design must reject

A hypothesis claiming a seventh, uncorrelated domain belongs to the
cluster — citing a `relationship_id` that doesn't exist for this run (or
exists but is a real relationship of a different, uninvolved pair) —
should surface as **UNGROUNDED**. This is the direct hypothesis-engine
analog of reportability's fabricated-citation test case, and the design's
own test suite (Part 2, when implementation begins) should include this
exact scenario using the same fixture, the same way
`tests/test_reportability_prompt_injection.py` proves a fabricated
citation gets caught regardless of what the model claims.

### 7.4 Prompt-injection surface, named explicitly (matching reportability's Section E.6)

Every string value inside `intel_entities`/`intel_relationships` that
ultimately came from the target's own infrastructure — a certificate's
`subject`/`issuer` common name, a domain name itself, an ASN
organization string from WHOIS/RDAP, an HTTP response's extracted
technology name — is attacker-influenceable data, exactly like
reportability's finding fields. The prompt must name every such field as
untrusted, the same way `SYSTEM_PROMPT`/`ADVERSARIAL_SYSTEM_PROMPT`
already do, before implementation begins — not retrofitted after a real
CT-log SAN containing an injection payload is observed in the wild
(plausible: SAN values are entirely attacker-chosen at certificate
request time, more directly attacker-controlled than most reportability
finding fields already are).

---

## 8. Persistence — a new table, not a reuse of `intel_hypotheses`

`intel_hypotheses` (existing schema, `core/store.py`) is structurally a
**one relationship → one target** shape: `relationship_id: str`,
`target_value: str`, singular. That fits its current sole producer
(`_emit_hypotheses`, one `SAN_CONTAINS` relationship implying one
candidate host) exactly. It does not fit what Section 4's design needs to
express — a single hypothesis naturally cites *several* relationships and
entities at once (Section 7.2's example 1 cites six relationship rows
plus one certificate entity in a single hypothesis).

Following the exact precedent
`docs/REPORTABILITY_AGENT_DESIGN.md` Section C.1 set (a new table,
`reportability_assessments`, rather than forcing the new concept into
`findings`/`verification_flags`): a new table pair,
`intel_llm_hypotheses` (one row per LLM-proposed hypothesis: statement,
confidence, grounding status, reasoning-review outcome if adversarial
review ran, provider/model, prompt version — mirroring
`reportability_assessments`'s own column shape) and
`intel_llm_hypothesis_evidence` (one row per cited entity/relationship
per hypothesis — the many-to-many join `intel_hypotheses`'s singular
`relationship_id`/`target_value` columns cannot express). The existing
`intel_hypotheses` table and `_emit_hypotheses` are untouched — this is
an additive layer, not a replacement, exactly as this document's opening
principle (Section 0) requires.

---

## 9. Honest open questions for the implementation checkpoint

- **Command naming**: `generate-hypotheses` is a working name in this
  document, not a commitment — should be settled at the implementation
  checkpoint alongside the exact setting names (Section 5).
- **Batch shape**: reportability batches by *finding* (one row per item).
  This engine's natural batch unit is less obvious — one call per
  correlated *cluster* (a connected component of the relationship graph)
  reads more analogous to how a human actually works a case than a fixed
  count of relationships, but needs a concrete graph-partitioning
  decision this document does not make.
- **Where a human sees the output**: whether hypotheses get their own
  `python app.py hypotheses <run_id>` read command (mirroring
  `investigate`/`graph`) or fold into an existing one is left to the
  implementation checkpoint, not decided here.

None of these affect Parts A-E's actual boundaries or grounding
discipline — they are presentation/ergonomics decisions appropriate to
defer to implementation review, not scope questions this design document
needs to resolve before that checkpoint.
