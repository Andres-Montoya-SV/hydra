"""Fase 17 (EASM roadmap) — tests for `core/capability_policy.py`.

Uses lightweight fake `ReconPlugin`-shaped objects rather than the real
registry, so the policy logic itself is tested in isolation from any
real tool's actual enablement defaults.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.capabilities import Capability
from core.capability_policy import capability_enabled, providers_for_capability


@dataclass
class _FakePlugin:
    capability: str
    _enabled: bool

    def is_enabled(self) -> bool:
        return self._enabled


class _FakePluginClass:
    """A fake plugin CLASS (not instance) for `providers_for_capability`,
    which operates on classes the way `ReconPlugin.all_plugins()` does."""

    def __init__(self, name: str, capability: str) -> None:
        self.name = name
        self.capability = capability


class TestCapabilityEnabled:
    def test_enabled_when_at_least_one_underlying_provider_is_enabled(self) -> None:
        plugins = [
            _FakePlugin(capability="technology_intelligence", _enabled=True),
            _FakePlugin(capability="tls_posture", _enabled=False),
        ]
        assert capability_enabled(Capability.TECHNOLOGY, plugins=plugins) is True

    def test_disabled_when_no_underlying_provider_is_enabled(self) -> None:
        plugins = [_FakePlugin(capability="technology_intelligence", _enabled=False)]
        assert capability_enabled(Capability.TECHNOLOGY, plugins=plugins) is False

    def test_policy_can_force_a_capability_off_even_if_a_provider_is_enabled(self) -> None:
        plugins = [_FakePlugin(capability="cloud_enum", _enabled=True)]
        assert (
            capability_enabled(
                Capability.CLOUD,
                plugins=plugins,
                disabled_capabilities=frozenset({Capability.CLOUD}),
            )
            is False
        )

    def test_policy_can_never_force_a_capability_on(self) -> None:
        """A policy narrows, never grants -- there is no
        `enabled_capabilities` override that could turn something on
        that no provider actually enables. Disabling a DIFFERENT
        capability must never affect this one."""
        plugins = [_FakePlugin(capability="technology_intelligence", _enabled=False)]
        result = capability_enabled(
            Capability.TECHNOLOGY,
            plugins=plugins,
            disabled_capabilities=frozenset({Capability.CLOUD}),
        )
        assert result is False

    def test_a_provider_for_a_different_capability_never_counts(self) -> None:
        plugins = [_FakePlugin(capability="cloud_enum", _enabled=True)]
        assert capability_enabled(Capability.TECHNOLOGY, plugins=plugins) is False


class TestProvidersForCapability:
    def test_returns_only_classes_matching_the_capability(self) -> None:
        classes = [
            _FakePluginClass("subfinder", "enumerate_domains"),
            _FakePluginClass("whatweb", "technology_intelligence"),
            _FakePluginClass("amass", "enumerate_domains"),
        ]
        matching = providers_for_capability(Capability.DOMAIN_DISCOVERY, plugin_classes=classes)
        assert {cls.name for cls in matching} == {"subfinder", "amass"}

    def test_returns_empty_list_for_a_capability_nothing_provides(self) -> None:
        classes = [_FakePluginClass("subfinder", "enumerate_domains")]
        assert providers_for_capability(Capability.VISUAL, plugin_classes=classes) == []
