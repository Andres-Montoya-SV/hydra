"""Bilingual client-report support (Task 1) and the "Lo que necesitas
saber" / "What You Need to Know" TL;DR section (Task 2) —
core.client_report.i18n, explain.py, dedup.py, render.py, render_docx.py,
cli.py all threading a `language` parameter without ever mixing fixed
template text between languages, and never translating real dynamic
content (hosts, domains, parameter names).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import Finding
from core.client_report.cli import cmd_client_report
from core.client_report.collect import RunReportData
from core.client_report.dedup import consolidate
from core.client_report.i18n import SUPPORTED_LANGUAGES, t
from core.client_report.render import render_markdown
from core.store import AssetStore

RUN_ID = "run1"
REAL_HOST = "www.metaversejustice.com"
REAL_DOMAIN = "metaversejustice.com"
REAL_PARAM = "búsqueda"  # deliberately Spanish-looking dynamic value


def _settings(project_root: Path, **overrides: object) -> Settings:
    kwargs: dict[str, object] = {"project_root": project_root}
    kwargs.update(overrides)
    return Settings(**kwargs)


def _data(**overrides: object) -> RunReportData:
    kwargs: dict[str, object] = dict(
        run_id=RUN_ID,
        targets=[REAL_DOMAIN],
        started_at="2026-09-16T18:49:10Z",
        finished_at="2026-09-16T19:14:41Z",
        duration_seconds=1531.73,
    )
    kwargs.update(overrides)
    return RunReportData(**kwargs)  # type: ignore[arg-type]


def _param_finding(param: str, severity: str = "medium") -> Finding:
    return Finding(
        host=REAL_HOST,
        template_id="param-reflected",
        severity=severity,
        name=f"Parameter '{param}' reflects input in response body",
        source="param_fuzz",
        url=f"https://{REAL_HOST}/",
        description="probe evidence",
    )


def _header_finding(header: str) -> Finding:
    return Finding(
        host=REAL_HOST,
        template_id="missing-security-header",
        severity="info",
        name=f"Missing security header: {header}",
        source="security_headers",
        url=f"https://{REAL_HOST}/",
        description=f"{header} is not present.",
    )


def _vuln_finding() -> Finding:
    return Finding(
        host=REAL_HOST,
        template_id="vuln-match",
        severity="high",
        name="CVE-2026-0001 in SomeCms 1.2.3",
        source="vuln_match",
        url=f"https://{REAL_HOST}/",
        description="matched",
    )


class TestSameFactualContentBothLanguages:
    def test_same_finding_counts_and_categories(self) -> None:
        findings = [_vuln_finding(), _param_finding(REAL_PARAM), _header_finding("X-Frame-Options")]
        es = consolidate(findings, "es")
        en = consolidate(findings, "en")
        assert len(es) == len(en) == 3
        assert [f.category for f in es] == [f.category for f in en]
        assert [f.severity for f in es] == [f.severity for f in en]
        assert [f.host for f in es] == [f.host for f in en]
        assert [f.occurrences for f in es] == [f.occurrences for f in en]

    def test_fixed_text_is_translated_and_not_mixed(self) -> None:
        findings = [_vuln_finding(), _param_finding(REAL_PARAM), _header_finding("X-Frame-Options")]
        data = _data()
        es_text = render_markdown(data, consolidate(findings, "es"), "es")
        en_text = render_markdown(data, consolidate(findings, "en"), "en")

        assert "## Vulnerabilidades confirmadas" in es_text
        assert "## Confirmed Vulnerabilities" in en_text
        assert "Qué NO cubre este análisis" in es_text
        assert "What This Analysis Does NOT Cover" in en_text
        assert "Lo que necesitas saber" in es_text
        assert "What You Need to Know" in en_text

        # No English marker leaking into the Spanish document, and vice versa.
        assert "Confirmed Vulnerabilities" not in es_text
        assert "What it means" not in es_text
        assert "Vulnerabilidades confirmadas" not in en_text
        assert "Qué significa" not in en_text

    def test_real_dynamic_content_is_identical_in_both_languages(self) -> None:
        findings = [_param_finding(REAL_PARAM), _header_finding("X-Frame-Options")]
        data = _data()
        es_text = render_markdown(data, consolidate(findings, "es"), "es")
        en_text = render_markdown(data, consolidate(findings, "en"), "en")
        for dynamic_value in (REAL_HOST, REAL_DOMAIN, REAL_PARAM, "X-Frame-Options"):
            assert dynamic_value in es_text
            assert dynamic_value in en_text


class TestTldrReflectsRealData:
    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    def test_zero_findings(self, language: str) -> None:
        data = _data()
        text = render_markdown(data, consolidate([], language), language)
        tldr = text.split(t(language, "tldr_heading"))[1].split("##")[0]
        assert t(language, "tldr_zero_vulns") in tldr
        assert t(language, "tldr_scope_line") in tldr
        assert t(language, "tldr_closing_line") in tldr

    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    def test_only_indicios(self, language: str) -> None:
        findings = [_param_finding("cat"), _param_finding("page")]
        data = _data()
        consolidated = consolidate(findings, language)
        assert {f.category.value for f in consolidated} == {"indicio"}
        text = render_markdown(data, consolidated, language)
        tldr = text.split(t(language, "tldr_heading"))[1].split("##")[0]
        assert t(language, "tldr_zero_vulns") in tldr
        assert t(language, "tldr_indicios_singular", count=1) in tldr
        assert t(language, "tldr_scope_line") in tldr

    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    def test_mix_of_indicios_and_hardening_areas(self, language: str) -> None:
        findings = [
            _param_finding("cat"),
            _param_finding("page"),
            _header_finding("X-Frame-Options"),
            _header_finding("Content-Security-Policy"),
        ]
        data = _data()
        consolidated = consolidate(findings, language)
        categories = {f.category.value for f in consolidated}
        assert categories == {"indicio", "area_mejora"}
        indicios = [f for f in consolidated if f.category.value == "indicio"]
        assert len(indicios) == 1  # both params merge-group into one entry
        text = render_markdown(data, consolidated, language)
        tldr = text.split(t(language, "tldr_heading"))[1].split("##")[0]
        # Zero confirmed vulnerabilities, despite hardening/indicio findings existing.
        assert t(language, "tldr_zero_vulns") in tldr
        assert t(language, "tldr_indicios_singular", count=1) in tldr
        assert t(language, "tldr_scope_line") in tldr

    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    def test_confirmed_vulnerabilities_present(self, language: str) -> None:
        findings = [_vuln_finding()]
        data = _data()
        consolidated = consolidate(findings, language)
        text = render_markdown(data, consolidated, language)
        tldr = text.split(t(language, "tldr_heading"))[1].split("##")[0]
        assert t(language, "tldr_vulns_singular", count=1) in tldr
        assert t(language, "tldr_scope_line") in tldr


class TestScopeLineAlwaysPresent:
    @pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
    @pytest.mark.parametrize(
        "findings",
        [
            [],
            [_vuln_finding()],
            [_param_finding("cat")],
            [_vuln_finding(), _param_finding("cat"), _header_finding("X-Frame-Options")],
        ],
    )
    def test_scope_line_present_regardless_of_findings(
        self, language: str, findings: list[Finding]
    ) -> None:
        data = _data()
        text = render_markdown(data, consolidate(findings, language), language)
        assert t(language, "tldr_scope_line") in text


class TestUnsupportedLanguageFailsClearly:
    def test_cli_function_rejects_unsupported_language(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True)
        run_dir = output_dir / RUN_ID
        run_dir.mkdir()
        AssetStore(output_dir / "recon.db")
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID, language="fr")
        assert rc == 1

    def test_error_message_is_clear_not_cryptic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True)
        (output_dir / RUN_ID).mkdir()
        AssetStore(output_dir / "recon.db")
        settings = _settings(tmp_path)
        cmd_client_report(settings, RUN_ID, language="fr")
        err = capsys.readouterr().err
        assert "--language" in err
        assert "fr" in err
        assert "en" in err and "es" in err

    def test_argparse_choices_also_reject_it_at_the_cli_layer(self) -> None:
        import app as hydra_app

        parser = hydra_app.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["client-report", RUN_ID, "--language", "fr"])
