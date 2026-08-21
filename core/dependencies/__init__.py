"""Dependency management subsystem — discovery, validation, capability detection."""

from core.dependencies.models import ToolHealth, ToolReport
from core.dependencies.registry import TOOL_REGISTRY, get_tool_definition
from core.dependencies.service import DependencyService

__all__ = [
    "DependencyService",
    "TOOL_REGISTRY",
    "ToolHealth",
    "ToolReport",
    "get_tool_definition",
]
