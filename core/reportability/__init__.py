"""Reportability agent — Claude-backed eligibility triage for persisted
findings against a program's own natural-language rules text.

See docs/REPORTABILITY_AGENT_DESIGN.md. Unlike `core/verification/`
(deterministic by design — structured-field comparison, never an LLM),
this package's primary judgment call is made by the Claude API, because
interpreting natural-language rules against a finding is a language-
comprehension task, not a field comparison. The two packages must never be
confused: this one imports `core.verification.grounding`'s citation-
grounding check (the one place they share logic, by design — see the
design doc Part C.3), and nothing else about either package is shared.

Never invoked by `python app.py run` — only by the standalone
`assess-reportability` command (`app.py`).
"""
