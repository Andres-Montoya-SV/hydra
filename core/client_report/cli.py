"""`python app.py client-report RUN_ID` — the standalone command
(docs/CLIENT_REPORT.md). Never invoked by `python app.py run`; only ever
writes a Markdown or Word draft to disk — it never sends anything
anywhere. The operator is expected to read, edit, and (for the Markdown
default) convert this draft before it ever reaches a client.
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

SUPPORTED_FORMATS = ("markdown", "docx")


def cmd_client_report(
    settings: Settings,
    run_id: str,
    *,
    output_path: Path | None = None,
    output_format: str = "markdown",
) -> int:
    sanitize_run_id(run_id)

    if output_format not in SUPPORTED_FORMATS:
        print(
            f"Error: --format {output_format!r} is not supported — must be one of "
            f"{SUPPORTED_FORMATS}.",
            file=sys.stderr,
        )
        return 1

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

    # Both formats consume the exact same consolidated data — dedup,
    # categorization, methodology/caveat/recommendation text are computed
    # once here, never duplicated in either renderer.
    consolidated = consolidate(data.findings)

    if output_format == "docx":
        # Deferred: python-docx is an optional dependency
        # (requirements-optional.txt) — importing core.client_report.cli
        # itself must never require it, only actually choosing --format
        # docx does.
        from core.client_report.render_docx import DocxRenderError, render_docx

        try:
            content: str | bytes = render_docx(data, consolidated)
        except DocxRenderError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        default_name = "client_report.docx"
        write_mode = "wb"
    else:
        content = render_markdown(data, consolidated)
        default_name = "client_report.md"
        write_mode = "w"

    dest = output_path or (db_path.parent / run_id / default_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if write_mode == "wb":
        dest.write_bytes(content)  # type: ignore[arg-type]
    else:
        dest.write_text(content, encoding="utf-8")  # type: ignore[arg-type]

    # The CLI's own status output stays in English, matching every other
    # command (assess-reportability, suggest-hypotheses, etc.) — only the
    # generated document's CONTENT (render.py/render_docx.py/explain.py)
    # is in Spanish, since that is the actual deliverable for a Spanish-
    # speaking client. Coherence pass: this file previously printed its
    # own operator-facing status lines in Spanish too, the one command
    # that broke from the CLI-wide English convention.
    vulns = sum(1 for f in consolidated if f.category.value == "vulnerabilidad_confirmada")
    indicios = sum(1 for f in consolidated if f.category.value == "indicio")
    mejoras = sum(1 for f in consolidated if f.category.value == "area_mejora")
    print(f"Client report written to: {dest}")
    print(
        f"{vulns} confirmed vulnerability(ies), {indicios} unconfirmed lead(s), "
        f"{mejoras} improvement area(s)."
    )
    if data.vuln_check_failed:
        print(
            f"⚠ {len(data.vuln_check_failed)} vulnerability check(s) could not be completed "
            "this run — documented under the report's 'Limitaciones conocidas' section."
        )
    conversion_hint = (
        "" if output_format == "docx" else " (e.g.: pandoc client_report.md -o client_report.docx)"
    )
    print(
        f"\nThis is a DRAFT. Review and edit it{conversion_hint} before sharing it with the "
        "client. Hydra never sends this document automatically."
    )
    return 0
