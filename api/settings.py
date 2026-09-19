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
    # Domain verification (Part A) always makes a REAL DNS/HTTP check
    # against the real internet by default — these two are None unless an
    # operator explicitly opts in via the env vars below, for local
    # development/demo only (e.g. pointing DNS checks at an in-process
    # test server instead of the live internet). Never set in production;
    # there is no way to enable this by accident — both require an
    # explicit environment variable, never a default.
    dev_dns_nameserver: str | None = None
    dev_dns_port: int | None = None
    dev_well_known_base_url: str | None = None

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
    settings.dev_dns_nameserver = os.getenv("HYDRA_API_DEV_DNS_NAMESERVER") or None
    dev_dns_port = os.getenv("HYDRA_API_DEV_DNS_PORT")
    if dev_dns_port:
        settings.dev_dns_port = int(dev_dns_port)
    settings.dev_well_known_base_url = os.getenv("HYDRA_API_DEV_WELL_KNOWN_BASE_URL") or None
    return settings
