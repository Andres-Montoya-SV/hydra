"""Tool discovery package — legacy facade over dependency subsystem."""

from core.dependencies import DependencyService, ToolHealth, ToolReport
from core.discovery.tool_discovery import DiscoveredTool, ToolAvailability, ToolDiscovery

__all__ = [
    "DependencyService",
    "DiscoveredTool",
    "ToolAvailability",
    "ToolDiscovery",
    "ToolHealth",
    "ToolReport",
]
