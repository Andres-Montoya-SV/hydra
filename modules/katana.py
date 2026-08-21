"""katana web crawling plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_jsonl, read_lines


class KatanaPlugin(BaseToolPlugin):
    name = "katana"
    display_name = "katana"
    required = False
    stage_order = 50
    install_hint_macos = "brew install katana"
    install_hint_linux = "go install github.com/projectdiscovery/katana/cmd/katana@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_katana

    def get_binary_path(self) -> Path:
        return self.settings.katana_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "katana.jsonl")
        alive_path = self._output_path(context, "alive.txt")

        if not self._alive_urls(context):
            return self._skip("Skipped — no alive URLs for katana")

        args = [
            str(self.resolved_binary(context)),
            "-list",
            str(alive_path),
            "-silent",
            "-jsonl",
            "-c",
            str(self.settings.threads),
            "-o",
            str(output_path),
            "-jc",
        ]

        headers = self.settings.merged_headers()
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])

        result = await self._execute_self_output(context, args, output_path, allow_empty=True)
        records = read_jsonl(output_path)
        urls = [str(record.get("url", "")) for record in records if record.get("url")]
        if not urls:
            urls = read_lines(output_path)
        context.metadata["katana_urls"] = len(urls)

        return PluginResult(
            success=result.success,
            output_path=output_path,
            lines_produced=len(urls),
            message=f"Crawled {len(urls)} URLs" if urls else "No URLs crawled",
        )
