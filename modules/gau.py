"""gau URL discovery plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class GauPlugin(BaseToolPlugin):
    name = "gau"
    display_name = "gau"
    required = False
    stage_order = 20
    produces = ("urls",)
    capability = "url_archive"
    active_collection = True
    install_hint_macos = "brew install gau"
    install_hint_linux = "go install github.com/lc/gau/v2/cmd/gau@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_gau

    def get_binary_path(self) -> Path:
        return self.settings.gau_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.authorize import authorize_active_indicator
        from core.intel.scope import require_collection_scope

        output_path = self._output_path(context, "gau.txt")
        all_urls: list[str] = []
        scope = require_collection_scope(context)
        domains = [
            t.domain
            for t in context.targets
            if authorize_active_indicator(t.domain, scope, "gau", "seed_archive").allowed
        ]
        results: list[PluginResult] = []

        for domain in domains:
            context.current_target = domain
            args = [
                str(self.get_binary_path()),
                "--subs",
                domain,
            ]
            result = await self._execute(context, args, output_path, allow_empty=True)
            results.append(result)
            if result.output_path:
                all_urls.extend(read_lines(result.output_path))

        count = write_lines(output_path, all_urls)
        context.metadata["gau_urls"] = count

        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "gau failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False, output_path=output_path, lines_produced=count, message=message
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(success=True, output_path=output_path, lines_produced=count)
