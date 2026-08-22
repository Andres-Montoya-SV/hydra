"""unfurl URL parsing plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.security import atomic_write_text, validate_output_path


class UnfurlPlugin(BaseToolPlugin):
    name = "unfurl"
    display_name = "unfurl"
    required = False
    stage_order = 55
    produces = ("urls",)
    capability = "post_http"
    strict_opsec_allowed = True
    install_hint_macos = "go install github.com/tomnomnom/unfurl@latest"
    install_hint_linux = "go install github.com/tomnomnom/unfurl@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_unfurl

    def get_binary_path(self) -> Path:
        return self.settings.unfurl_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "unfurl_domains.txt")
        urls = self._alive_urls(context)

        if not urls:
            return self._skip("Skipped — no alive URLs for unfurl")

        input_data = "\n".join(urls) + "\n"

        self.update_status(context, ToolStatus.RUNNING)
        try:
            return_code, stdout, _ = await self._run_tool(
                context,
                self._argv(context, "domains"),
                input_data=input_data,
            )
        except Exception as exc:
            self.update_status(context, ToolStatus.FAILED, error_message=str(exc))
            return PluginResult(success=False, message=str(exc))

        if return_code != 0:
            self.update_status(context, ToolStatus.FAILED, error_message=f"Exit code {return_code}")
            return PluginResult(success=False, message=f"Exit code {return_code}")

        domains = sorted(set(line.strip() for line in stdout.splitlines() if line.strip()))
        output_path = validate_output_path(output_path, context.output_dir)
        atomic_write_text(output_path, "\n".join(domains) + ("\n" if domains else ""))
        context.metadata["unfurl_domains"] = len(domains)

        self.update_status(context, ToolStatus.COMPLETED, output_lines=len(domains))
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=len(domains),
        )
