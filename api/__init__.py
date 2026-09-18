"""Hydra paid EASM API (docs/PAID_API_DESIGN.md) — a separately deployable
HTTP facade over the existing single-tenant reconnaissance engine
(`core/runner.py`, `core/store.py`, `core/client_report/`). This package
never duplicates that engine's logic; it only decides *whose* data a
given request may touch (multi-tenancy, Part F) and translates the CLI's
interactive/synchronous shape into async HTTP (Part E).

Round 1 (this round) implements Parts C, E, and F only. Domain-ownership
verification (Part A), tiers/quotas (Part B), and Wompi billing (Part D)
are deferred to Rounds 2/3 — every authenticated account may scan any
domain without restriction for now; see docs/PAID_API_DESIGN.md's
"Round 1 implemented" section for the exact scope line.

Never imports from `app.py`'s `__main__` guard — only the module-level
functions it exposes (`_run_headless_pipeline`, `_external_mode_preflight`)
are reused, to avoid reimplementing pipeline orchestration a second time.
"""
