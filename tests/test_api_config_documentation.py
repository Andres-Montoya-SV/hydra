"""Productization Phase 13d: every environment variable the API reads is
documented in `api/.env.example`, the file the deployment guide tells
operators to copy (docs/DEPLOYMENT.md). The CLI's own config has the same
guard (tests/test_config_documentation_sync.py).

Found when this was added: `GEOIP_DB_PATH`,
`HYDRA_API_OBSERVATION_RETENTION_DAYS` and `HYDRA_BUILD_COMMIT` were read
but undocumented, and the retired `HYDRA_API_ADMIN_TOKEN` (still read,
only to warn) was not mentioned."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Read by libraries, not by our code, yet worth documenting.
READ_BY_LIBRARIES = frozenset({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"})


def _read_by_the_api() -> set[str]:
    source = "".join((ROOT / f).read_text() for f in ("api/settings.py", "api/version.py"))
    return set(re.findall(r'(?:getenv|environ\.get)\(\s*"([A-Z_0-9]+)"', source))


def _documented() -> set[str]:
    text = (ROOT / "api/.env.example").read_text()
    return set(re.findall(r"^#?\s*([A-Z][A-Z_0-9]+)=", text, re.M))


def test_every_variable_the_api_reads_is_documented() -> None:
    assert _read_by_the_api() - _documented() == set()


def test_nothing_documented_is_ignored() -> None:
    assert _documented() - _read_by_the_api() - READ_BY_LIBRARIES == set()
