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
from core.client_report.i18n import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES, t
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
    language: str = DEFAULT_LANGUAGE,
) -> int:
    sanitize_run_id(run_id)

    if output_format not in SUPPORTED_FORMATS:
        print(
            f"Error: --format {output_format!r} is not supported — must be one of "
            f"{SUPPORTED_FORMATS}.",
            file=sys.stderr,
        )
        return 1

    if language not in SUPPORTED_LANGUAGES:
        print(
            f"Error: --language {language!r} is not supported — must be one of "
            f"{SUPPORTED_LANGUAGES}.",
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
    # once here, never duplicated in either renderer. `language` only
    # selects which fixed wording (core.client_report.i18n) attaches to
    # that data — real findings/hosts/counts are identical either way.
    consolidated = consolidate(data.findings, language)

    if output_format == "docx":
        # Deferred: python-docx is an optional dependency
        # (requirements-optional.txt) — importing core.client_report.cli
        # itself must never require it, only actually choosing --format
        # docx does.
        from core.client_report.render_docx import DocxRenderError, render_docx

        try:
            content: str | bytes = render_docx(data, consolidated, language)
        except DocxRenderError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        default_name = "client_report.docx"
        write_mode = "wb"
    else:
        content = render_markdown(data, consolidated, language)
        default_name = "client_report.md"
        write_mode = "w"

    dest = output_path or (db_path.parent / run_id / default_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if write_mode == "wb":
        dest.write_bytes(content)  # type: ignore[arg-type]
    else:
        dest.write_text(content, encoding="utf-8")  # type: ignore[arg-type]

    # This console output follows --language, same as the document itself
    # — the operator just chose that language and seeing the summary in a
    # different one right after would be jarring. (Every other command's
    # own status output stays English, per the project-wide CLI
    # convention — but none of those commands have a --language of their
    # own to follow in the first place; this one does, so it does.)
    vulns = sum(1 for f in consolidated if f.category.value == "vulnerabilidad_confirmada")
    indicios = sum(1 for f in consolidated if f.category.value == "indicio")
    mejoras = sum(1 for f in consolidated if f.category.value == "area_mejora")
    print(t(language, "cli_report_written_to", dest=dest))
    print(t(language, "cli_summary_line", vulns=vulns, indicios=indicios, mejoras=mejoras))
    if data.vuln_check_failed:
        limitations_heading = t(language, "known_limitations_heading")
        print(
            t(
                language,
                "cli_vuln_check_failed_warning",
                count=len(data.vuln_check_failed),
                heading=limitations_heading,
            )
        )
    conversion_hint = "" if output_format == "docx" else t(language, "cli_conversion_hint_pandoc")
    print(t(language, "cli_draft_reminder", conversion_hint=conversion_hint))
    return 0
