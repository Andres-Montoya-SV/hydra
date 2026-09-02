"""Verification agent: structural suspicion between a raw artifact and what
the user sees.

See docs/VERIFICATION_AGENT_DESIGN.md for the full design and incident
catalog this package implements. Three layers, none of them autonomous:

- core.verification.preflight — before PipelineRunner.run() (format
  validation, historical cross-run consistency, the scope-exclusion canary
  check).
- core.verification.detectors — after each plugin, before persistence
  (pure, deterministic contradiction detectors — no LLM, no side effects).
- core.verification.grounding — before any report/CLI command shows a
  claim to the user (does the cited raw_artifact actually contain it).
"""

from __future__ import annotations
