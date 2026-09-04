"""Custom exceptions for the reconnaissance framework."""

from __future__ import annotations


class ReconError(Exception):
    """Base exception for all framework errors."""


class ConfigurationError(ReconError):
    """Raised when configuration is invalid or missing."""


class ToolNotFoundError(ReconError):
    """Raised when a required external tool is not installed."""

    def __init__(self, tool_name: str, install_hint: str) -> None:
        self.tool_name = tool_name
        self.install_hint = install_hint
        super().__init__(f"Tool '{tool_name}' not found. {install_hint}")


class ToolExecutionError(ReconError):
    """Raised when a tool subprocess fails."""

    def __init__(self, tool_name: str, message: str, return_code: int | None = None) -> None:
        self.tool_name = tool_name
        self.return_code = return_code
        super().__init__(f"{tool_name}: {message}")


class ValidationError(ReconError):
    """Raised when user input fails validation."""


class PipelineInterruptedError(ReconError):
    """Raised when the pipeline is interrupted by the user."""


class ScopeVerificationError(ReconError):
    """Raised when a live pre-flight check proves a SCOPE_FILE exclusion has
    no effect (docs/VERIFICATION_AGENT_DESIGN.md B.1's
    scope_exclusion_canary_check). Fail-closed, same principle as
    STRICT_OPSEC's gate: an active collection run must never start when a
    configured scope protection is already known not to work."""


class EmptyOutputError(ReconError):
    """Raised when a tool produces no usable output."""
