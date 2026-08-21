"""Assetfinder subdomain enumeration plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class AssetfinderPlugin(BaseToolPlugin):
    name = "assetfinder"
    display_name = "Assetfinder"
    required = False
    stage_order = 15
    install_hint_macos = "go install github.com/tomnomnom/assetfinder@latest"
    install_hint_linux = "go install github.com/tomnomnom/assetfinder@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_assetfinder

    def get_binary_path(self) -> Path:
        return self.settings.assetfinder_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "assetfinder.txt")
        merged_path = self._output_path(context, "subdomains.txt")
        all_subs: list[str] = read_lines(merged_path)
        discovered: list[str] = []
        domains = [t.domain for t in context.targets]
        results: list[PluginResult] = []

        for domain in domains:
            context.current_target = domain
            args = [str(self.get_binary_path()), "--subs-only", domain]
            result = await self._execute(context, args, output_path, allow_empty=True)
            results.append(result)
            if result.output_path:
                found = read_lines(result.output_path)
                discovered.extend(found)
                all_subs.extend(found)

        raw_count = write_lines(output_path, discovered)

        count = write_lines(merged_path, all_subs)
        context.subdomains = read_lines(merged_path)

        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "assetfinder failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False,
                output_path=merged_path,
                lines_produced=raw_count or count,
                message=message,
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=raw_count or count)
        return PluginResult(
            success=True, output_path=merged_path, lines_produced=raw_count or count
        )
