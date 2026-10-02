"""Productization Phase 13a: what is running.

- `HYDRA_VERSION` is the release, kept equal to `pyproject.toml` and the
  CLI's `--version` (a test checks both).
- `API_VERSION` is the contract version. It changes only for a breaking
  change to an existing endpoint; additions (new endpoints, new fields)
  keep it. A client can compare it before relying on a field.
- The build commit comes from `HYDRA_BUILD_COMMIT`, set at image build
  time. It is shown only to authenticated callers (support diagnostics),
  not on the public `GET /version`.
"""

from __future__ import annotations

import os

HYDRA_VERSION = "1.0.0"
API_VERSION = "1"


def build_commit() -> str | None:
    return os.environ.get("HYDRA_BUILD_COMMIT") or None
