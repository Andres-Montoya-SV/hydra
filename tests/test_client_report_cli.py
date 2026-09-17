"""core/client_report/cli.py::cmd_client_report — the standalone
`python app.py client-report` command (docs/CLIENT_REPORT.md). Builds a
synthetic run directory shaped exactly like the real Metaverse Justice
pilot data this feature was validated against (22 raw findings: 16
reflected-parameter rows across 8 parameters, 2 influences-only rows, 10
missing-header rows across 5 headers, 2 browser-behavior rows) and
confirms the generated report matches the pilot's own known structure:
8 parameters -> 1 indicio, 5 headers -> 1 área de mejora, 1 browser
indicio.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.client_report.cli import cmd_client_report
from core.store import AssetStore

RUN_ID = "run1"
SEED = "www.metaversejustice.com"
BARE = "metaversejustice.com"

_PARAMS = ["cat", "order", "orderby", "p", "page", "s", "search", "tag"]
_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]
_URL_VARIANTS = (f"https://{SEED}", f"https://{SEED}/")


def _settings(project_root: Path, **overrides: object) -> Settings:
    kwargs: dict[str, object] = {"project_root": project_root}
    kwargs.update(overrides)
    return Settings(**kwargs)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _seed_pilot_run(
    tmp_path: Path,
    *,
    vuln_match_check_failed: list[dict[str, object]] | None = None,
    duration_seconds: float = 1531.73,
) -> tuple[AssetStore, Path]:
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "recon.db"
    run_dir = output_dir / RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)

    store = AssetStore(db_path)
    store.create_run(ScanRun(run_id=RUN_ID, started_at="2026-09-16T18:49:10Z", targets=[BARE]))

    param_rows = []
    for variant in _URL_VARIANTS:
        for param in _PARAMS:
            param_rows.append(
                {
                    "host": SEED,
                    "url": variant,
                    "probe_url": f"{variant}?{param}=reconprobe123",
                    "parameter": param,
                    "baseline_status": 200,
                    "probe_status": 200,
                    "parameter_influences_response": True,
                    "reflected": True,
                }
            )
        param_rows.append(
            {
                "host": SEED,
                "url": variant,
                "probe_url": f"{variant}?page_id=reconprobe123",
                "parameter": "page_id",
                "baseline_status": 200,
                "probe_status": 200,
                "parameter_influences_response": True,
                "reflected": False,
            }
        )
    _write_jsonl(run_dir / "param_fuzz.jsonl", param_rows)

    header_rows = []
    for variant in _URL_VARIANTS:
        for header in _HEADERS:
            header_rows.append(
                {
                    "host": SEED,
                    "url": variant,
                    "header": header,
                    "header_key": header.lower(),
                    "missing": True,
                    "security_headers_score": 17,
                }
            )
    _write_jsonl(run_dir / "security_headers.jsonl", header_rows)

    browser_rows = [
        {
            "host": BARE,
            "httpx_final_url": f"https://{SEED}/",
            "browser_final_url": "about:blank",
            "cloaking_suspected": True,
        },
        {
            "host": SEED,
            "httpx_final_url": f"https://{SEED}",
            "browser_final_url": "about:blank",
            "cloaking_suspected": True,
        },
    ]
    _write_jsonl(run_dir / "browser_probe.jsonl", browser_rows)

    (run_dir / "vuln_match.jsonl").write_text("", encoding="utf-8")
    (run_dir / "cloud_bucket_enum.jsonl").write_text("", encoding="utf-8")

    summary = {
        "duration_seconds": duration_seconds,
        "warnings": ["Only 2/13 (15%) subdomains resolved."],
    }
    (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    metadata: dict[str, object] = {}
    if vuln_match_check_failed is not None:
        metadata["vuln_match_check_failed"] = vuln_match_check_failed
    (run_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    return store, run_dir


class TestMissingRunOrDatabase:
    def test_missing_database_is_rejected(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID)
        assert rc == 1

    def test_missing_run_directory_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "output").mkdir(parents=True, exist_ok=True)
        AssetStore(tmp_path / "output" / "recon.db")
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, "no-such-run")
        assert rc == 1


class TestPilotStructureRegression:
    def test_generates_expected_structure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.md"

        rc = cmd_client_report(settings, RUN_ID, output_path=output_path)
        assert rc == 0
        assert output_path.is_file()

        text = output_path.read_text(encoding="utf-8")

        # 8 params -> 1 indicio
        assert "8 parámetros" in text
        for param in _PARAMS:
            assert param in text
        # 5 headers -> 1 área de mejora
        assert "5 cabeceras" in text
        for header in _HEADERS:
            assert header in text
        # 1 browser-behavior indicio
        assert text.count("Comportamiento distinto entre una revisión automática") == 1

        # requirement 2: separated sections, never mixed
        assert "## Vulnerabilidades confirmadas" in text
        assert "## Indicios" in text
        assert "## Áreas de mejora" in text
        vulns_section = text.split("## Vulnerabilidades confirmadas")[1].split("## Indicios")[0]
        assert "cabecera" not in vulns_section.lower()

        # requirement 5: explicit honesty about plain-text-only probing
        assert "NO se probó con caracteres de inyección reales" in text

        # requirement 6: real run duration shown
        assert "25.5 minutos" in text or "1532 segundos" in text

        # requirement 7: what this does NOT cover
        assert "Qué NO cubre este análisis" in text

        out = capsys.readouterr().out
        assert "BORRADOR" in out

    def test_no_tool_names_anywhere_in_the_document(self, tmp_path: Path) -> None:
        _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.md"
        cmd_client_report(settings, RUN_ID, output_path=output_path)
        text = output_path.read_text(encoding="utf-8").lower()
        for tool in (
            "httpx",
            "nuclei",
            "naabu",
            "wpscan",
            "param_fuzz",
            "security_headers",
            "browser_probe",
        ):
            assert tool not in text, f"{tool!r} leaked into the client report"


class TestKnownLimitationsSection:
    def test_vuln_check_failed_is_reflected_as_a_known_limitation(self, tmp_path: Path) -> None:
        _seed_pilot_run(
            tmp_path,
            vuln_match_check_failed=[
                {
                    "host": SEED,
                    "technology": "Bookly",
                    "version": "28.0",
                    "source": "wpscan",
                    "reason": "query failed: HTTP Error 404: Not Found",
                }
            ],
        )
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.md"
        rc = cmd_client_report(settings, RUN_ID, output_path=output_path)
        assert rc == 0
        text = output_path.read_text(encoding="utf-8")
        limitations = text.split("## Limitaciones conocidas de esta corrida")[1].split("##")[0]
        assert "Bookly" in limitations
        assert "28.0" in limitations
        assert "sin confirmar" in limitations

    def test_no_check_failed_produces_the_honest_no_limitations_note(self, tmp_path: Path) -> None:
        _seed_pilot_run(tmp_path, vuln_match_check_failed=[])
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.md"
        cmd_client_report(settings, RUN_ID, output_path=output_path)
        text = output_path.read_text(encoding="utf-8")
        limitations = text.split("## Limitaciones conocidas de esta corrida")[1].split("##")[0]
        assert "No se identificaron limitaciones" in limitations


class TestDefaultOutputPath:
    def test_defaults_to_run_directory(self, tmp_path: Path) -> None:
        _, run_dir = _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID)
        assert rc == 0
        assert (run_dir / "client_report.md").is_file()


class TestUnsupportedFormat:
    def test_unknown_format_is_rejected(self, tmp_path: Path) -> None:
        _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID, output_format="pdf")
        assert rc == 1


class TestDocxFormat:
    def test_docx_format_writes_a_valid_document(self, tmp_path: Path) -> None:
        pytest.importorskip("docx")
        _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.docx"

        rc = cmd_client_report(settings, RUN_ID, output_path=output_path, output_format="docx")
        assert rc == 0
        assert output_path.is_file()

        import docx

        document = docx.Document(str(output_path))
        text = "\n".join(p.text for p in document.paragraphs)
        assert "metaversejustice.com" in text
        assert "8 parámetros" in text
        assert "5 cabeceras" in text

    def test_docx_default_output_path_uses_docx_extension(self, tmp_path: Path) -> None:
        pytest.importorskip("docx")
        _, run_dir = _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID, output_format="docx")
        assert rc == 0
        assert (run_dir / "client_report.docx").is_file()
        assert not (run_dir / "client_report.md").exists()

    def test_markdown_remains_the_default_format(self, tmp_path: Path) -> None:
        _, run_dir = _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        rc = cmd_client_report(settings, RUN_ID)
        assert rc == 0
        assert (run_dir / "client_report.md").is_file()

    def test_no_tool_names_in_docx_output(self, tmp_path: Path) -> None:
        pytest.importorskip("docx")
        _seed_pilot_run(tmp_path)
        settings = _settings(tmp_path)
        output_path = tmp_path / "client_report.docx"
        cmd_client_report(settings, RUN_ID, output_path=output_path, output_format="docx")

        import docx

        document = docx.Document(str(output_path))
        text_parts = [p.text for p in document.paragraphs]
        text_parts += [c.text for t in document.tables for row in t.rows for c in row.cells]
        haystack = "\n".join(text_parts).lower()
        for tool in (
            "httpx",
            "nuclei",
            "naabu",
            "wpscan",
            "param_fuzz",
            "security_headers",
            "browser_probe",
        ):
            assert tool not in haystack, f"{tool!r} leaked into the .docx report"


class TestUniformDepthAcrossAllFourRealFindingTypes:
    """docs/CLIENT_REPORT.md Task 2 + item 3 of 'Al terminar': every one
    of the pilot run's real finding types (reflected parameters, browser
    behavior, missing headers) — plus a confirmed-vulnerability item,
    exercising the type the WPScan fix can now reveal — must show the
    exact same structural depth: qué significa, cómo se encontró,
    ubicación, and a recommendation. Only tone/severity differs.
    """

    def _four_finding_types(self) -> list:
        from core.assets import Finding

        return [
            Finding(
                host=SEED,
                template_id="param-reflected",
                severity="medium",
                name="Parameter 'cat' reflects input in response body",
                source="param_fuzz",
                url=f"https://{SEED}/",
                description="probe evidence",
            ),
            Finding(
                host=BARE,
                template_id="cloaking-detected",
                severity="medium",
                name="Browser destination differs from HTTP probe",
                source="browser_probe",
                url="about:blank",
                description="d",
            ),
            Finding(
                host=SEED,
                template_id="missing-security-header",
                severity="info",
                name="Missing security header: X-Frame-Options",
                source="security_headers",
                url=f"https://{SEED}/",
                description="d",
            ),
            Finding(
                host=SEED,
                template_id="vuln-match",
                severity="high",
                name="CVE-2026-13395 in Bookly 28.0",
                source="vuln_match",
                url=f"https://{SEED}/",
                description="A real CVE match, now revealed by the WPScan fail-visible fix.",
            ),
        ]

    def test_every_type_has_the_same_content_fields_populated(self) -> None:
        from core.client_report.dedup import consolidate

        consolidated = consolidate(self._four_finding_types())
        assert len(consolidated) == 4
        for item in consolidated:
            assert item.title.strip()
            assert item.explanation.strip()
            assert item.methodology.strip()
            assert item.recommendation.strip()
            assert item.host.strip()
            # methodology must be genuinely distinct text from explanation
            assert item.methodology != item.explanation

    def test_markdown_renders_the_same_structural_fields_for_all_four(self, tmp_path: Path) -> None:
        from core.client_report.collect import RunReportData
        from core.client_report.dedup import consolidate
        from core.client_report.render import render_markdown

        consolidated = consolidate(self._four_finding_types())
        data = RunReportData(
            run_id=RUN_ID,
            targets=[BARE],
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:30:00Z",
            duration_seconds=1531.73,
        )
        text = render_markdown(data, consolidated)
        for item in consolidated:
            assert f"**Qué significa:** {item.explanation}" in text
            assert f"**Cómo se encontró:** {item.methodology}" in text
            assert f"- **Ubicación:** {item.host}" in text
            assert f"**Recomendación:** {item.recommendation}" in text
        # The confirmed vulnerability must land in its own section,
        # never mixed with indicios (requirement 2).
        vulns_section = text.split("## Vulnerabilidades confirmadas")[1].split("## Indicios")[0]
        assert "CVE-2026-13395" in vulns_section
