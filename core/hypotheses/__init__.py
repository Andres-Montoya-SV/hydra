"""LLM-backed hypothesis engine — see docs/HYPOTHESIS_ENGINE_DESIGN.md.

Reads only already-correlated intel_relationships/intel_entities and
verified findings for a run; proposes natural-language investigation
leads for a human analyst to read. Never authorizes collection, never
runs inside `python app.py run`. A standalone, opt-in command
(`python app.py suggest-hypotheses`), same operational shape as
`python app.py assess-reportability`.
"""
