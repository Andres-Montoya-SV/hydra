"""Parser package — tool output normalization."""

from core.parsers.registry import PARSER_REGISTRY, parse_tool_output

__all__ = ["PARSER_REGISTRY", "parse_tool_output"]
