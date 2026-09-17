"""`python app.py client-report RUN_ID` — the standalone command
(docs/CLIENT_REPORT.md). Never invoked by `python app.py run`; only ever
writes a Markdown draft to disk — it never sends anything anywhere. The
operator is expected to read, edit, and convert this draft (e.g. with
`pandoc` or by pasting into a word processor) before it ever reaches a
client.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.client_report.collect import RunNotFoundError, collect
from core.client_report.dedup import consolidate
from core.client_report.render import render_markdown
from core.intel.cli import default_db
from core.store import AssetStore
from utils.validators import sanitize_run_id

if TYPE_CHECKING:
    from config.settings import Settings


def cmd_client_report(
    settings: Settings,
    run_id: str,
    *,
    output_path: Path | None = None,
) -> int:
    sanitize_run_id(run_id)

    db_path = default_db(settings.project_root, settings.output_directory)
    if not db_path.exists():
        print(f"Error: intelligence database not found: {db_path}", file=sys.stderr)
        return 1

    store = AssetStore(db_path)
    try:
        data = collect(settings, store, run_id)
    except RunNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    consolidated = consolidate(data.findings)
    markdown = render_markdown(data, consolidated)

    dest = output_path or (db_path.parent / run_id / "client_report.md")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(markdown, encoding="utf-8")

    vulns = sum(1 for f in consolidated if f.category.value == "vulnerabilidad_confirmada")
    indicios = sum(1 for f in consolidated if f.category.value == "indicio")
    mejoras = sum(1 for f in consolidated if f.category.value == "area_mejora")
    print(f"Client report written to: {dest}")
    print(
        f"{vulns} vulnerabilidad(es) confirmada(s), {indicios} indicio(s), "
        f"{mejoras} área(s) de mejora."
    )
    if data.vuln_check_failed:
        print(
            f"⚠ {len(data.vuln_check_failed)} verificación(es) de vulnerabilidad no pudieron "
            "completarse esta corrida — documentado en 'Limitaciones conocidas'."
        )
    print(
        "\nEsto es un BORRADOR. Revísalo, edítalo y conviértelo al formato que prefieras "
        "(por ejemplo: pandoc client_report.md -o client_report.docx) antes de compartirlo "
        "con el cliente. Hydra nunca envía este documento automáticamente."
    )
    return 0
