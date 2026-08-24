"""waybackurls historical URL discovery plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class WaybackurlsPlugin(BaseToolPlugin):
    name = "waybackurls"
    display_name = "waybackurls"
    required = False
    stage_order = 21
    produces = ("urls",)
    capability = "url_archive"
    active_collection = True
    install_hint_macos = "go install github.com/tomnomnom/waybackurls@latest"
    install_hint_linux = "go install github.com/tomnomnom/waybackurls@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_waybackurls

    def get_binary_path(self) -> Path:
        return self.settings.waybackurls_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        from core.intel.authorize import authorize_active_indicator
        from core.intel.scope import require_collection_scope

        output_path = self._output_path(context, "waybackurls.txt")
        all_urls: list[str] = []
        scope = require_collection_scope(context)
        domains = [
            t.domain
            for t in context.targets
            if authorize_active_indicator(
                t.domain, scope, "waybackurls", "seed_archive"
            ).allowed
        ]
        results: list[PluginResult] = []

        for domain in domains:
            context.current_target = domain
            args = [str(self.get_binary_path())]
            input_data = domain + "\n"
            result = await self._execute(
                context, args, output_path, input_data=input_data, allow_empty=True
            )
            results.append(result)
            if result.output_path:
                all_urls.extend(read_lines(result.output_path))

        count = write_lines(output_path, all_urls)
        context.metadata["waybackurls_count"] = count

        any_success = any(result.success for result in results)
        if domains and not any_success:
            message = "waybackurls failed for all target domains"
            self.update_status(context, ToolStatus.FAILED, error_message=message)
            return PluginResult(
                success=False, output_path=output_path, lines_produced=count, message=message
            )

        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(success=True, output_path=output_path, lines_produced=count)
