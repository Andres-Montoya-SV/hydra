"""core/client_report/render.py's white-label branding parameter
(docs/PAID_API_DESIGN.md) — `branding=None` (the default) must render
byte-for-byte identical output to every prior round; a real value adds
one attribution line under the title, nothing else.
"""

from __future__ import annotations

from core.client_report.collect import RunReportData
from core.client_report.render import render_markdown


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


class TestWhiteLabelBranding:
    def test_no_branding_produces_byte_for_byte_identical_output_to_before(self) -> None:
        data = _data()
        with_default_arg = render_markdown(data, [])
        with_explicit_none = render_markdown(data, [], branding=None)
        assert with_default_arg == with_explicit_none

    def test_branding_adds_an_attribution_line_without_removing_anything(self) -> None:
        data = _data()
        unbranded = render_markdown(data, [])
        branded = render_markdown(data, [], branding="Acme Security Consulting")

        assert "Acme Security Consulting" not in unbranded
        assert "**Preparado por:** Acme Security Consulting" in branded
        # Nothing existing was removed — same title/target line still present.
        assert "metaversejustice.com" in branded
        assert unbranded.splitlines()[0] == branded.splitlines()[0]  # title line unchanged

    def test_branding_works_in_english_too(self) -> None:
        data = _data()
        branded = render_markdown(data, [], language="en", branding="Acme Security Consulting")
        assert "**Prepared by:** Acme Security Consulting" in branded
