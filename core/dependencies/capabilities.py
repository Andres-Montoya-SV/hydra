"""Phase 3 — capability detection from registry and runtime signals."""

from __future__ import annotations

from core.dependencies.models import CapabilityResult, ToolDefinition, ValidationResult


class CapabilityDetector:
    """Map declared capabilities; extend with runtime hints when available."""

    def detect(
        self,
        defn: ToolDefinition,
        validation: ValidationResult,
    ) -> CapabilityResult:
        detected: set[str] = set(defn.capabilities)

        if validation.can_execute:
            detected.add("executable")

        if validation.version_obtained:
            detected.add("version_reporting")

        output = " ".join(validation.notes).lower()
        if "help" in output or validation.probe_command:
            detected.add("cli_interface")

        return CapabilityResult(
            declared=frozenset(defn.capabilities),
            detected=frozenset(detected),
        )
