"""core/client_report/dedup.py — URL-variant dedup and label grouping
(docs/CLIENT_REPORT.md requirement 3: 'no asumas que cada fila de
findings es un hallazgo distinto'). Pure, offline.
"""

from __future__ import annotations

from core.assets import Finding
from core.client_report.dedup import (
    categorize_template,
    consolidate,
    normalize_host_for_grouping,
    normalize_page_url,
)
from core.client_report.model import FindingCategory

HOST = "www.metaversejustice.com"


def _param_finding(
    param: str, url: str, *, severity: str = "medium", reflected: bool = True
) -> Finding:
    template_id = "param-reflected" if reflected else "param-influences-response"
    verb = "reflects input in response body" if reflected else "influences HTTP response"
    return Finding(
        host=HOST,
        template_id=template_id,
        severity=severity,
        name=f"Parameter '{param}' {verb}",
        source="param_fuzz",
        url=url,
        description="probe evidence",
    )


def _header_finding(header: str, url: str) -> Finding:
    return Finding(
        host=HOST,
        template_id="missing-security-header",
        severity="info",
        name=f"Missing security header: {header}",
        source="security_headers",
        url=url,
        description=f"{header} is not present on {url}.",
    )


class TestNormalizeHostForGrouping:
    def test_strips_www_prefix(self) -> None:
        assert normalize_host_for_grouping("www.example.com") == "example.com"

    def test_bare_domain_unchanged(self) -> None:
        assert normalize_host_for_grouping("example.com") == "example.com"

    def test_case_insensitive(self) -> None:
        assert normalize_host_for_grouping("WWW.Example.COM") == "example.com"


class TestNormalizePageUrl:
    def test_trailing_slash_collapses(self) -> None:
        a = normalize_page_url("https://example.com/")
        b = normalize_page_url("https://example.com")
        assert a == b

    def test_query_string_is_dropped(self) -> None:
        a = normalize_page_url("https://example.com/?page=reconprobe123")
        b = normalize_page_url("https://example.com/?cat=reconprobe123")
        assert a == b

    def test_host_is_lowercased(self) -> None:
        assert normalize_page_url("https://EXAMPLE.com/") == normalize_page_url(
            "https://example.com/"
        )

    def test_no_netloc_returned_verbatim(self) -> None:
        assert normalize_page_url("about:blank") == "about:blank"

    def test_empty_url_returns_empty_string(self) -> None:
        assert normalize_page_url(None) == ""
        assert normalize_page_url("") == ""


class TestCategorizeTemplate:
    def test_vuln_match_is_confirmed_vulnerability(self) -> None:
        assert (
            categorize_template("vuln-match", "high") is FindingCategory.VULNERABILIDAD_CONFIRMADA
        )

    def test_cloud_bucket_public_is_confirmed_vulnerability(self) -> None:
        assert (
            categorize_template("cloud-bucket-public-listable", "high")
            is FindingCategory.VULNERABILIDAD_CONFIRMADA
        )

    def test_cloud_bucket_private_is_indicio(self) -> None:
        assert categorize_template("cloud-bucket-exists-private", "info") is FindingCategory.INDICIO

    def test_missing_header_is_area_mejora(self) -> None:
        assert categorize_template("missing-security-header", "info") is FindingCategory.AREA_MEJORA

    def test_check_failed_is_limitacion(self) -> None:
        assert categorize_template("vuln-check-failed", "info") is FindingCategory.LIMITACION

    def test_param_reflected_is_indicio_never_confirmed(self) -> None:
        """Even though param-reflected carries 'medium' severity, it must
        never be promoted to a confirmed vulnerability — no real
        injection payload was tried (requirement 5)."""
        assert categorize_template("param-reflected", "medium") is FindingCategory.INDICIO

    def test_scan_quality_template_ids_are_excluded(self) -> None:
        assert categorize_template("tarpit-detected", "info") is None
        assert categorize_template("wildcard-dns-detected", "info") is None
        assert categorize_template("soft-404-detected", "info") is None

    def test_unknown_template_id_falls_back_to_severity(self) -> None:
        assert categorize_template("some-nuclei-template", "critical") is (
            FindingCategory.VULNERABILIDAD_CONFIRMADA
        )
        assert categorize_template("some-nuclei-template", "info") is FindingCategory.INDICIO


class TestConsolidateUrlVariantDedup:
    def test_same_param_two_url_variants_collapses_to_one_occurrence_group(self) -> None:
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com?cat=x"),
            _param_finding("cat", "https://www.metaversejustice.com/?cat=x"),
        ]
        result = consolidate(findings)
        assert len(result) == 1
        assert result[0].occurrences == 2
        assert result[0].labels == ["cat"]

    def test_five_headers_two_url_variants_consolidate_into_one_entry(self) -> None:
        headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ]
        findings = [
            _header_finding(h, url)
            for url in ("https://www.metaversejustice.com", "https://www.metaversejustice.com/")
            for h in headers
        ]
        result = consolidate(findings)
        assert len(result) == 1
        entry = result[0]
        assert entry.category is FindingCategory.AREA_MEJORA
        assert entry.occurrences == 10
        assert set(entry.labels) == set(headers)

    def test_eight_reflected_params_two_url_variants_consolidate_into_one_indicio(self) -> None:
        params = ["cat", "order", "orderby", "p", "page", "s", "search", "tag"]
        findings = [
            _param_finding(p, url)
            for url in ("https://www.metaversejustice.com", "https://www.metaversejustice.com/")
            for p in params
        ]
        result = consolidate(findings)
        assert len(result) == 1
        entry = result[0]
        assert entry.category is FindingCategory.INDICIO
        assert entry.occurrences == 16
        assert set(entry.labels) == set(params)

    def test_reflected_and_influences_stay_in_separate_entries(self) -> None:
        """Different template_ids (param-reflected vs
        param-influences-response) must never merge into the same entry
        even though both are about 'a parameter' on the same host."""
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com/?cat=x", reflected=True),
            _param_finding(
                "page_id", "https://www.metaversejustice.com/?page_id=x", reflected=False
            ),
        ]
        result = consolidate(findings)
        assert len(result) == 2
        template_ids = {r.labels[0] for r in result}
        assert template_ids == {"cat", "page_id"}


class TestConsolidateBrowserBehaviorHostAlias:
    def test_bare_domain_and_www_alias_collapse_into_one_indicio(self) -> None:
        findings = [
            Finding(
                host="metaversejustice.com",
                template_id="cloaking-detected",
                severity="medium",
                name="Browser destination differs from HTTP probe",
                source="browser_probe",
                url="about:blank",
                description="httpx ended at https://www.metaversejustice.com/",
            ),
            Finding(
                host="www.metaversejustice.com",
                template_id="cloaking-detected",
                severity="medium",
                name="Browser destination differs from HTTP probe",
                source="browser_probe",
                url="about:blank",
                description="httpx ended at https://www.metaversejustice.com",
            ),
        ]
        result = consolidate(findings)
        assert len(result) == 1
        assert result[0].occurrences == 2
        assert result[0].category is FindingCategory.INDICIO


class TestConsolidateDistinctIdentifiersNeverMerge:
    def test_two_different_cves_on_the_same_host_stay_separate(self) -> None:
        findings = [
            Finding(
                host=HOST,
                template_id="vuln-match",
                severity="high",
                name="CVE-2026-1111 in Bookly 28.0",
                source="vuln_match",
                url=f"https://{HOST}/",
                description="d1",
            ),
            Finding(
                host=HOST,
                template_id="vuln-match",
                severity="high",
                name="CVE-2026-2222 in Bookly 28.0",
                source="vuln_match",
                url=f"https://{HOST}/",
                description="d2",
            ),
        ]
        result = consolidate(findings)
        assert len(result) == 2
        assert all(r.category is FindingCategory.VULNERABILIDAD_CONFIRMADA for r in result)

    def test_same_cve_two_url_variants_collapses(self) -> None:
        findings = [
            Finding(
                host=HOST,
                template_id="vuln-match",
                severity="high",
                name="CVE-2026-1111 in Bookly 28.0",
                source="vuln_match",
                url=f"https://{HOST}",
                description="d1",
            ),
            Finding(
                host=HOST,
                template_id="vuln-match",
                severity="high",
                name="CVE-2026-1111 in Bookly 28.0",
                source="vuln_match",
                url=f"https://{HOST}/",
                description="d1",
            ),
        ]
        result = consolidate(findings)
        assert len(result) == 1
        assert result[0].occurrences == 2


class TestConsolidateExcludesScanQualityAndLimitations:
    def test_tarpit_finding_never_appears_in_consolidated_output(self) -> None:
        findings = [
            Finding(
                host=HOST,
                template_id="tarpit-detected",
                severity="info",
                name="tarpit",
                source="tarpit_check",
                url=None,
                description="d",
            )
        ]
        assert consolidate(findings) == []

    def test_check_failed_becomes_a_limitacion_entry_not_a_vulnerability_or_indicio(self) -> None:
        findings = [
            Finding(
                host=HOST,
                template_id="vuln-check-failed",
                severity="info",
                name="Could not verify Bookly:28.0 against wpscan",
                source="vuln_match",
                url=None,
                description="query failed: HTTP Error 404: Not Found",
            )
        ]
        result = consolidate(findings)
        assert len(result) == 1
        assert result[0].category is FindingCategory.LIMITACION
        assert result[0].limitation_note


class TestNoToolNamesLeakIntoTitlesOrExplanations:
    def test_explanations_never_mention_known_tool_names(self) -> None:
        findings = [
            _param_finding("cat", "https://www.metaversejustice.com/?cat=x"),
            _header_finding("Strict-Transport-Security", "https://www.metaversejustice.com/"),
        ]
        result = consolidate(findings)
        banned = {"httpx", "nuclei", "naabu", "wpscan", "param_fuzz", "security_headers"}
        for item in result:
            haystack = (item.title + " " + item.explanation).lower()
            for tool in banned:
                assert tool not in haystack, f"{tool!r} leaked into client-facing text"
