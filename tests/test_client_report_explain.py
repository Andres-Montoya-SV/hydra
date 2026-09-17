"""core/client_report/explain.py — methodology, caveat, and severity-
recommendation content (docs/CLIENT_REPORT.md: 'cómo lo encontramos',
uniform depth, and tone calibrated by severity). Pure, offline.
"""

from __future__ import annotations

from core.client_report.explain import (
    explain_caveat,
    explain_consolidated,
    explain_methodology,
    severity_recommendation,
)

_KNOWN_TEMPLATE_IDS = [
    "vuln-match",
    "cloud-bucket-public-listable",
    "cloud-bucket-exists-private",
    "urlhaus-known-malicious",
    "param-reflected",
    "param-influences-response",
    "missing-security-header",
    "cloaking-detected",
]

_TOOL_NAMES = {
    "httpx",
    "nuclei",
    "naabu",
    "wpscan",
    "param_fuzz",
    "security_headers",
    "browser_probe",
}


class TestMethodologyNeverEmptyNeverNamesATool:
    def test_every_known_template_id_has_a_methodology(self) -> None:
        for template_id in _KNOWN_TEMPLATE_IDS:
            text = explain_methodology(template_id)
            assert text.strip()

    def test_unknown_template_id_still_gets_a_generic_methodology(self) -> None:
        text = explain_methodology("some-future-nuclei-template")
        assert text.strip()

    def test_no_methodology_names_a_known_tool(self) -> None:
        for template_id in [*_KNOWN_TEMPLATE_IDS, "vuln-check-failed", "unknown-thing"]:
            text = explain_methodology(template_id).lower()
            for tool in _TOOL_NAMES:
                assert tool not in text, f"{tool!r} leaked into methodology for {template_id!r}"

    def test_methodology_is_distinct_content_from_the_meaning_explanation(self) -> None:
        """Task 1's explicit requirement: methodology and 'qué significa'
        must be separate content pieces, not blended into one paragraph —
        confirmed here by checking neither string is a substring of the
        other for a representative template."""
        _, explanation = explain_consolidated("missing-security-header", ["X-Frame-Options"])
        methodology = explain_methodology("missing-security-header")
        assert methodology not in explanation
        assert explanation not in methodology


class TestCaveatsAreHonestAndSpecific:
    def test_param_templates_mention_plain_text_only(self) -> None:
        for template_id in ("param-reflected", "param-influences-response"):
            caveat = explain_caveat(template_id)
            assert caveat is not None
            assert "texto plano" in caveat or "payload" in caveat

    def test_unknown_template_id_returns_none_not_a_fabricated_caveat(self) -> None:
        """Honest default: if there's genuinely nothing specific to say
        about a template's limitations, return None rather than invent
        one."""
        assert explain_caveat("totally-unknown-template") is None

    def test_every_caveat_returned_is_non_empty_when_present(self) -> None:
        for template_id in _KNOWN_TEMPLATE_IDS:
            caveat = explain_caveat(template_id)
            if caveat is not None:
                assert caveat.strip()


class TestSeverityRecommendationCalibratedTone:
    def test_critical_and_high_use_urgent_but_not_panicked_language(self) -> None:
        for severity in ("critical", "high"):
            text = severity_recommendation(severity).lower()
            assert "recomienda" in text
            # No alarmist/panic words.
            for panic_word in ("peligroso", "urgente!!", "pánico", "catastrófico"):
                assert panic_word not in text

    def test_info_and_low_are_calm_never_alarmist(self) -> None:
        for severity in ("info", "low"):
            text = severity_recommendation(severity).lower()
            for alarmist_word in ("peligroso", "grave", "crítico", "urgente"):
                assert alarmist_word not in text

    def test_info_is_never_dismissive_of_a_real_recommendation(self) -> None:
        """Calm tone must not become 'this doesn't matter' — it still
        recommends something, just without urgency."""
        text = severity_recommendation("info").lower()
        assert "recomienda" in text

    def test_critical_reads_more_urgent_than_info(self) -> None:
        critical_text = severity_recommendation("critical").lower()
        info_text = severity_recommendation("info").lower()
        assert critical_text != info_text
        assert "inmediat" in critical_text
        assert "inmediat" not in info_text or "no representa una urgencia" in info_text

    def test_unknown_severity_gets_a_sensible_default_not_a_crash(self) -> None:
        text = severity_recommendation("some-unheard-of-severity")
        assert text.strip()

    def test_case_insensitive(self) -> None:
        assert severity_recommendation("HIGH") == severity_recommendation("high")

    def test_all_five_standard_severities_produce_distinct_text(self) -> None:
        texts = {severity_recommendation(s) for s in ("critical", "high", "medium", "low", "info")}
        assert len(texts) == 5
