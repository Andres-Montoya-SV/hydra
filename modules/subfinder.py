"""Subfinder subdomain enumeration plugin."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class SubfinderPlugin(BaseToolPlugin):
    name = "subfinder"
    display_name = "Subfinder"
    required = True
    stage_order = 10
    install_hint_macos = "brew install subfinder"
    install_hint_linux = (
        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    )

    def is_enabled(self) -> bool:
        return True

    def get_binary_path(self) -> Path:
        return self.settings.subfinder_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "subfinder.txt")
        merged_path = self._output_path(context, "subdomains.txt")
        domains = [t.domain for t in context.targets]

        all_subs: list[str] = []
        results: list[PluginResult] = []
        for domain in domains:
            context.current_target = domain
            args = [
                str(self.get_binary_path()),
                "-d",
                domain,
                "-silent",
                "-t",
                str(self.settings.threads),
                "-timeout",
                "30",
            ]
            if self.settings.rate_limit:
                args.extend(["-rate-limit", str(self.settings.rate_limit)])

            result = await self._execute(context, args, output_path, allow_empty=True)
            results.append(result)
            if result.output_path and result.output_path.exists():
                all_subs.extend(read_lines(result.output_path))

        # Include root domains
        all_subs.extend(domains)
        raw_count = write_lines(output_path, all_subs)
        count = write_lines(merged_path, all_subs)
        context.subdomains = read_lines(merged_path)

        # _execute() sets tool status per-domain, so the last domain processed
        # would otherwise determine the final status/PluginResult regardless
        # of how the other domains fared. Aggregate explicitly instead.
        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "subfinder failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False,
                output_path=merged_path,
                lines_produced=raw_count,
                message=message,
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=raw_count)
        return PluginResult(
            success=True,
            output_path=merged_path,
            lines_produced=raw_count,
            message=f"Found {count} subdomains",
        )
