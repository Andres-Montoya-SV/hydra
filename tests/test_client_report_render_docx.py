"""core/client_report/render_docx.py — the Word renderer
(docs/CLIENT_REPORT.md Task 4). Consumes the exact same
`RunReportData`/`ConsolidatedFinding` objects `render_markdown` does — no
content is computed here, only presentation (cover page, severity
badges, scope summary table).
"""

from __future__ import annotations

import io

import pytest

docx = pytest.importorskip("docx")

from core.assets import Finding  # noqa: E402
from core.client_report.collect import RunReportData  # noqa: E402
from core.client_report.dedup import consolidate  # noqa: E402
from core.client_report.render_docx import render_docx  # noqa: E402

_TOOL_NAMES = {
    "httpx",
    "nuclei",
    "naabu",
    "wpscan",
    "param_fuzz",
    "security_headers",
    "browser_probe",
}


def _data(**overrides: object) -> RunReportData:
    kwargs: dict[str, object] = dict(
        run_id="run1",
        targets=["metaversejustice.com"],
        started_at="2026-09-16T18:49:10Z",
        finished_at="2026-09-16T19:14:41Z",
        duration_seconds=1531.73,
    )
    kwargs.update(overrides)
    return RunReportData(**kwargs)  # type: ignore[arg-type]


def _header_finding(header: str, url: str) -> Finding:
    return Finding(
        host="www.metaversejustice.com",
        template_id="missing-security-header",
        severity="info",
        name=f"Missing security header: {header}",
        source="security_headers",
        url=url,
        description=f"{header} is not present on {url}.",
    )


def _param_finding(param: str, url: str) -> Finding:
    return Finding(
        host="www.metaversejustice.com",
        template_id="param-reflected",
        severity="medium",
        name=f"Parameter '{param}' reflects input in response body",
        source="param_fuzz",
        url=url,
        description="probe evidence",
    )


def _document_from_bytes(content: bytes) -> docx.Document:
    return docx.Document(io.BytesIO(content))


class TestRenderDocxProducesAValidDocument:
    def test_returns_nonempty_bytes_that_load_as_a_docx(self) -> None:
        data = _data()
        content = render_docx(data, [])
        assert isinstance(content, bytes)
        assert len(content) > 0
        document = _document_from_bytes(content)
        assert document.paragraphs

    def test_cover_page_shows_target_date_and_duration(self) -> None:
        data = _data(targets=["metaversejustice.com"], duration_seconds=1531.73)
        document = _document_from_bytes(render_docx(data, []))
        text = "\n".join(p.text for p in document.paragraphs)
        assert "metaversejustice.com" in text
        assert "25.5 minutos" in text
        assert "BORRADOR" in text

    def test_missing_duration_shown_honestly(self) -> None:
        data = _data(duration_seconds=None)
        document = _document_from_bytes(render_docx(data, []))
        text = "\n".join(p.text for p in document.paragraphs)
        assert "no disponible" in text


class TestWhiteLabelBranding:
    """docs/PAID_API_DESIGN.md's white-label section — `branding=None`
    (the default) must render byte-for-byte identical output to every
    prior round; a real value adds one attribution line, nothing else."""

    def test_no_branding_produces_byte_for_byte_identical_output_to_before(self) -> None:
        data = _data()
        with_default_arg = render_docx(data, [])
        with_explicit_none = render_docx(data, [], branding=None)
        assert with_default_arg == with_explicit_none

    def test_branding_adds_an_attribution_line_without_removing_anything(self) -> None:
        data = _data(targets=["metaversejustice.com"])
        unbranded_text = "\n".join(
            p.text for p in _document_from_bytes(render_docx(data, [])).paragraphs
        )
        branded_text = "\n".join(
            p.text
            for p in _document_from_bytes(
                render_docx(data, [], branding="Acme Security Consulting")
            ).paragraphs
        )
        assert "Acme Security Consulting" not in unbranded_text
        assert "Acme Security Consulting" in branded_text
        assert "Preparado por: Acme Security Consulting" in branded_text  # default language: es
        # Nothing existing was removed — the target/cover content is
        # still present in the branded version too.
        assert "metaversejustice.com" in branded_text


class TestSeverityBadgesAreVisualNotJustText:
    def test_finding_has_a_shaded_table_cell_with_severity(self) -> None:
        findings = [_param_finding("cat", "https://www.metaversejustice.com/")]
        consolidated = consolidate(findings)
        data = _data()
        content = render_docx(data, consolidated)
        document = _document_from_bytes(content)

        badge_tables = [t for t in document.tables if len(t.rows) == 1 and len(t.columns) == 1]
        assert badge_tables, "expected at least one 1x1 severity-badge table"
        badge_cell = badge_tables[0].cell(0, 0)
        assert "MEDIA" in badge_cell.text
        assert "w:shd" in badge_cell._tc.xml
        assert 'w:fill="ED7D31"' in badge_cell._tc.xml

    def test_info_severity_gets_a_different_color_than_medium(self) -> None:
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com/"),
            _header_finding("X-Frame-Options", "https://www.metaversejustice.com/"),
        ]
        consolidated = consolidate(findings)
        data = _data()
        document = _document_from_bytes(render_docx(data, consolidated))
        fills = set()
        for table in document.tables:
            if len(table.rows) == 1 and len(table.columns) == 1:
                xml = table.cell(0, 0)._tc.xml
                start = xml.index('w:fill="') + len('w:fill="')
                fills.add(xml[start : start + 6])
        assert len(fills) == 2


class TestUniformDepthAcrossFindingTypes:
    def test_every_finding_gets_meaning_methodology_location_and_recommendation(
        self,
    ) -> None:
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com/"),
            _header_finding("X-Frame-Options", "https://www.metaversejustice.com/"),
            Finding(
                host="metaversejustice.com",
                template_id="cloaking-detected",
                severity="medium",
                name="Browser destination differs from HTTP probe",
                source="browser_probe",
                url="about:blank",
                description="d",
            ),
        ]
        consolidated = consolidate(findings)
        assert len(consolidated) == 3
        data = _data()
        document = _document_from_bytes(render_docx(data, consolidated))
        text = "\n".join(p.text for p in document.paragraphs)
        for item in consolidated:
            assert f"Qué significa: {item.explanation}" in text
            assert f"Cómo se encontró: {item.methodology}" in text
            assert f"Ubicación: {item.host}" in text
            assert f"Recomendación: {item.recommendation}" in text


class TestScopeSummaryTableAtTheEnd:
    def test_final_table_has_target_duration_and_counts(self) -> None:
        findings = [_header_finding("X-Frame-Options", "https://www.metaversejustice.com/")]
        consolidated = consolidate(findings)
        data = _data(targets=["metaversejustice.com"], duration_seconds=1531.73)
        document = _document_from_bytes(render_docx(data, consolidated))
        last_table = document.tables[-1]
        header_row = [c.text for c in last_table.rows[0].cells]
        value_row = [c.text for c in last_table.rows[1].cells]
        assert "Objetivo(s)" in header_row
        assert "metaversejustice.com" in value_row
        assert "1" in value_row  # 1 área de mejora


class TestNoToolNamesAnywhereInTheDocument:
    def test_no_tool_names_in_paragraphs_or_tables(self) -> None:
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com/"),
            _header_finding("X-Frame-Options", "https://www.metaversejustice.com/"),
        ]
        consolidated = consolidate(findings)
        data = _data()
        document = _document_from_bytes(render_docx(data, consolidated))
        text_parts = [p.text for p in document.paragraphs]
        text_parts += [c.text for t in document.tables for row in t.rows for c in row.cells]
        haystack = "\n".join(text_parts).lower()
        for tool in _TOOL_NAMES:
            assert tool not in haystack, f"{tool!r} leaked into the .docx report"


class TestEmptyCategoriesShowHonestPlaceholderText:
    def test_no_vulnerabilities_shows_the_honest_empty_message(self) -> None:
        data = _data()
        document = _document_from_bytes(render_docx(data, []))
        text = "\n".join(p.text for p in document.paragraphs)
        assert "No se confirmó ninguna vulnerabilidad" in text
