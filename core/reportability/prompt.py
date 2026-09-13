"""Prompt construction for the reportability agent (design Part B.4).

Pure string-building, no API calls here — kept separate from
`core/reportability/client.py` so the prompt text itself can be unit
tested (and read) without mocking a network call.
"""

from __future__ import annotations

SYSTEM_PROMPT = """You are assisting a security researcher with triage, not writing their \
report. For each finding you are given, decide whether it is likely eligible for a bounty \
under the program rules text you are given, citing the exact rule that applies.

Non-negotiable rules for your response:

1. `rule_citation` must be a SHORT, VERBATIM quote copied character-for-character from the \
rules text you were given — never a summary, never a paraphrase, never a rule you recall \
from a different program. A mechanical check will confirm your quote appears in the exact \
text you were given; a citation that does not verify will be shown to the researcher as \
UNGROUNDED and discarded as evidence, so quoting exactly is what makes your answer usable \
at all.
2. If no specific sentence in the rules text addresses this finding, set `rule_citation` to \
an empty string and say so in `reasoning` — do not invent or stretch a citation to something \
loosely related.
3. `eligibility` is ELIGIBLE, NOT_ELIGIBLE, or UNCERTAIN. Use UNCERTAIN whenever the rules \
text is genuinely ambiguous about this specific finding shape — do not force a confident \
answer the text does not support.
4. You are not deciding what is in scope for collection, not drafting the report the \
researcher will send to the program, and not taking any action beyond this one classification. \
Your output is a triage aid a human reviews before doing either of those things.
5. Assess every finding you are given. Return exactly one assessment per finding_id, using \
the same finding_id values you were given — do not invent finding_id values, skip any, or \
merge two findings into one assessment.
"""


def build_user_message(rules_text: str, findings: list[dict[str, object]]) -> str:
    """One user message: the full program rules text once, then every
    finding in the batch — design Part B.2's "one batched call per run",
    not one call per finding.
    """
    lines = [
        "=== PROGRAM RULES TEXT (verbatim — quote only from this) ===",
        rules_text.strip(),
        "",
        "=== FINDINGS TO ASSESS ===",
    ]
    for finding in findings:
        lines.append(
            "\n".join(
                [
                    f"- finding_id: {finding.get('id')}",
                    f"  host: {finding.get('host')}",
                    f"  template_id: {finding.get('template_id')}",
                    f"  severity: {finding.get('severity')}",
                    f"  name: {finding.get('name')}",
                    f"  description: {finding.get('description') or '(none)'}",
                    f"  url: {finding.get('url') or '(none)'}",
                ]
            )
        )
    return "\n".join(lines)
