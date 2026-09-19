"""API-level configuration — deliberately separate from `config.settings.
Settings` (the CLI/pipeline's own config object). This module only
answers "where does this account's data live" and "what are this
service's own operational knobs" (rate limit, data root); the actual
per-scan pipeline configuration is still a real `config.settings.Settings`
instance, one constructed per account (see `api/tenancy.py`) — Round 1
never touches the pipeline's own config surface.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class APISettings:
    """Round 1 has no per-account overrides for any of this — everyone
    gets the same rate limit and the same data-root layout. Tier-specific
    values arrive in Round 2 (docs/PAID_API_DESIGN.md Part B)."""

    data_dir: Path = field(default_factory=lambda: _PROJECT_ROOT / "api_data")
    rate_limit_per_minute: int = 60
    key_rotation_grace_hours: int = 24

    @property
    def control_db_path(self) -> Path:
        return self.data_dir / "control.db"

    def account_root(self, account_id: str) -> Path:
        """Every account's pipeline data lives under its own directory —
        `config.settings.Settings(project_root=...)` for that account
        then resolves `output/recon.db` underneath it, giving one
        physically separate SQLite file per account (Part F.2) with zero
        changes to `core/store.py`/`core/runner.py`."""
        return self.data_dir / "accounts" / account_id


def load_api_settings() -> APISettings:
    settings = APISettings()
    data_dir = os.getenv("HYDRA_API_DATA_DIR")
    if data_dir:
        settings.data_dir = Path(data_dir)
    rate_limit = os.getenv("HYDRA_API_RATE_LIMIT_PER_MINUTE")
    if rate_limit:
        settings.rate_limit_per_minute = int(rate_limit)
    return settings
