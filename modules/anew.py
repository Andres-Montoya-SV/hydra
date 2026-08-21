"""anew deduplication utility plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_lines


class AnewPlugin(BaseToolPlugin):
    name = "anew"
    display_name = "anew"
    required = False
    stage_order = 25
    install_hint_macos = "go install -v github.com/tomnomnom/anew@latest"
    install_hint_linux = "go install -v github.com/tomnomnom/anew@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_anew

    def get_binary_path(self) -> Path:
        return self.settings.anew_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "subdomains_anew.txt")
        subs_path = self._output_path(context, "subdomains.txt")
        lines = read_lines(input_path)
        input_data = "\n".join(lines) + "\n"

        self.update_status(context, ToolStatus.RUNNING)
        try:
            return_code, stdout, _ = await self._run_tool(
                context,
                self._argv(context, str(output_path)),
                input_data=input_data,
            )
        except Exception as exc:
            self.update_status(context, ToolStatus.FAILED, error_message=str(exc))
            return PluginResult(success=False, message=str(exc))

        if return_code != 0:
            self.update_status(context, ToolStatus.FAILED, error_message=f"Exit code {return_code}")
            return PluginResult(success=False, message=f"Exit code {return_code}")

        new_from_stdout = [line.strip() for line in stdout.splitlines() if line.strip()]
        new_lines = list(dict.fromkeys(new_from_stdout))

        if new_lines:
            merged = list(dict.fromkeys(lines + new_lines))
            write_lines(subs_path, merged, base_dir=context.output_dir)
            context.subdomains = merged

        context.metadata["anew_new_entries"] = len(new_lines)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=len(new_lines))

        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=len(new_lines),
            message=f"anew tracked {len(new_lines)} entries",
        )
