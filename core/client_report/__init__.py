"""Client-facing report generation (docs/CLIENT_REPORT.md): turns a run's
already-persisted per-tool artifacts into the same kind of plain-language,
tool-name-free document that used to be assembled by hand for a pilot
engagement. Standalone command (`python app.py client-report RUN_ID`),
never invoked by `run` — the operator always reviews the generated
Markdown before sending anything to a client.
"""
