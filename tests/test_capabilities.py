"""Fase 17 (EASM roadmap) — pure tests for `core/capabilities.py`."""

from __future__ import annotations

from core.capabilities import Capability, capability_for


class TestCapabilityFor:
    def test_known_strings_map_to_the_expected_category(self) -> None:
        assert capability_for("enumerate_domains") == Capability.DOMAIN_DISCOVERY
        assert capability_for("resolve_dns") == Capability.DNS
        assert capability_for("port_scan") == Capability.NETWORK_DISCOVERY
        assert capability_for("http_probe") == Capability.HTTP
        assert capability_for("technology_intelligence") == Capability.TECHNOLOGY
        assert capability_for("browser") == Capability.VISUAL
        assert capability_for("tls_posture") == Capability.TLS
        assert capability_for("cloud_enum") == Capability.CLOUD
        assert capability_for("vuln_match") == Capability.EXPOSURE_DETECTION
        assert capability_for("registration") == Capability.EXTERNAL_INTELLIGENCE

    def test_unknown_string_falls_back_to_uncategorized_never_a_guess(self) -> None:
        assert capability_for("something_never_declared") == Capability.UNCATEGORIZED

    def test_empty_string_is_uncategorized(self) -> None:
        assert capability_for("") == Capability.UNCATEGORIZED

    def test_every_real_plugin_capability_string_is_categorized_or_documented_uncategorized(
        self,
    ) -> None:
        """Every `ReconPlugin.capability` string actually set by a real
        module under modules/ must resolve to something other than
        UNCATEGORIZED, except the one explicitly-accepted exception
        ("dedupe", a utility, not a product capability)."""
        import modules  # noqa: F401
        from core.plugin_base import ReconPlugin

        accepted_uncategorized = {"dedupe"}
        for plugin_cls in ReconPlugin.all_plugins():
            cap_string = plugin_cls.capability
            if cap_string in accepted_uncategorized:
                continue
            assert (
                capability_for(cap_string) != Capability.UNCATEGORIZED
            ), f"{plugin_cls.name!r}'s capability {cap_string!r} has no taxonomy entry"
