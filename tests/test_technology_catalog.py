"""Fase 14 (EASM roadmap) — pure tests for `api/technology_catalog.py`."""

from __future__ import annotations

from api.technology_catalog import (
    normalize_technology_name,
    parse_technology_detail,
    technology_detail,
)


class TestNormalizeTechnologyName:
    def test_known_case_variants_collapse_to_the_same_canonical_name(self) -> None:
        assert normalize_technology_name("nginx") == "nginx"
        assert normalize_technology_name("Nginx") == "nginx"
        assert normalize_technology_name("NGINX") == "nginx"

    def test_known_aliases_collapse_to_one_canonical_name(self) -> None:
        assert normalize_technology_name("apache") == "Apache HTTP Server"
        assert normalize_technology_name("Apache HTTPD") == "Apache HTTP Server"
        assert normalize_technology_name("microsoft-iis") == "IIS"
        assert normalize_technology_name("aspnet") == "ASP.NET"

    def test_unknown_technology_is_returned_unchanged_never_guessed_at(self) -> None:
        assert normalize_technology_name("SomeObscureCMS") == "SomeObscureCMS"

    def test_never_fuzzy_matches_genuinely_different_technologies(self) -> None:
        # React and React Native are different real technologies -- only
        # an exact curated alias may collapse two names, never similarity.
        assert normalize_technology_name("React Native") == "React Native"
        assert normalize_technology_name("React") == "React"

    def test_whitespace_is_stripped(self) -> None:
        assert normalize_technology_name("  nginx  ") == "nginx"

    def test_empty_string_returns_empty(self) -> None:
        assert normalize_technology_name("") == ""


class TestTechnologyDetailSerialization:
    def test_round_trips_with_a_version(self) -> None:
        detail = technology_detail(name="nginx", version="1.24.0")
        assert detail == "nginx@1.24.0"
        assert parse_technology_detail(detail) == ("nginx", "1.24.0")

    def test_round_trips_without_a_version(self) -> None:
        detail = technology_detail(name="WordPress", version=None)
        assert detail == "WordPress"
        assert parse_technology_detail(detail) == ("WordPress", None)
