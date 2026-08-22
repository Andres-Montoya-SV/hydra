"""amass subdomain enumeration plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class AmassPlugin(BaseToolPlugin):
    """amass passive/active subdomain enumeration.

    https://github.com/owasp-amass/amass
    """

    name = "amass"
    display_name = "amass"
    required = False
    stage_order = 16  # runs after subfinder (10) and before assetfinder-only dedup (17)
    produces = ("domains",)
    capability = "enumerate_domains"
    install_hint_macos = "brew install amass"
    install_hint_linux = "go install -v github.com/owasp-amass/amass/v4/...@master"

    def is_enabled(self) -> bool:
        return self.settings.enable_amass

    def get_binary_path(self) -> Path:
        return self.settings.amass_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "amass.txt")
        merged_path = self._output_path(context, "subdomains.txt")

        existing: list[str] = read_lines(merged_path) if merged_path.exists() else []
        all_subs: list[str] = list(existing)
        discovered: list[str] = []
        domains = [t.domain for t in context.targets]
        results: list[PluginResult] = []

        for domain in domains:
            context.current_target = domain
            args = [
                str(self.resolved_binary(context)),
                "enum",
                "-passive",
                "-d",
                domain,
                "-o",
                str(output_path),
                "-timeout",
                "5",  # minutes
            ]
            # amass writes its own output (-o), so use _execute_self_output
            result = await self._execute_self_output(context, args, output_path, allow_empty=True)
            results.append(result)
            if output_path.exists():
                found = read_lines(output_path)
                discovered.extend(found)
                all_subs.extend(found)

        raw_count = write_lines(output_path, discovered)

        # Merge into the shared subdomains.txt (dedup happens in runner stage 3)
        count = write_lines(merged_path, all_subs)
        context.subdomains = read_lines(merged_path)

        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "amass failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False,
                output_path=merged_path,
                lines_produced=raw_count or count,
                message=message,
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=raw_count or count)
        return PluginResult(
            success=True,
            output_path=merged_path,
            lines_produced=raw_count or count,
            message=f"amass found {len(discovered)} raw subdomain observations",
        )
