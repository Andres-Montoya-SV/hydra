"""Account_id -> storage resolution (docs/PAID_API_DESIGN.md Part F.2).

One `config.settings.Settings` instance per account, its `project_root`
pointed at that account's own directory — `settings.output_directory`
(the existing default, "output") then resolves to
`<account_root>/output/recon.db`, giving one physically separate SQLite
file per account with zero changes to `core/store.py`, `core/runner.py`,
or `PipelineRunner`. A connection opened against Account A's file cannot
return Account B's rows because there is no shared file for a bug to
leak across — this is the isolation guarantee itself, not a convention
layered on top of a shared database.
"""

from __future__ import annotations

from pathlib import Path

from api.settings import APISettings
from config.settings import Settings
from core.intel.cli import default_db


def account_settings(api_settings: APISettings, account_id: str) -> Settings:
    account_root = api_settings.account_root(account_id)
    settings = Settings(project_root=account_root)
    settings.ensure_directories()
    return settings


def account_db_path(api_settings: APISettings, account_id: str) -> Path:
    settings = account_settings(api_settings, account_id)
    return default_db(settings.project_root, settings.output_directory)
