"""nuclei vulnerability scanning plugin (optional, disabled by default)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_jsonl, read_lines


class NucleiPlugin(BaseToolPlugin):
    name = "nuclei"
    display_name = "nuclei"
    required = False
    stage_order = 60
    produces = ("findings",)
    capability = "post_http"
    active_collection = True
    install_hint_macos = "brew install nuclei"
    install_hint_linux = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_nuclei

    def get_binary_path(self) -> Path:
        return self.settings.nuclei_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "nuclei.json")
        alive_path = self._authorized_input(
            context,
            (
                self._output_path(context, "authorized_alive.txt")
                if self._output_path(context, "authorized_alive.txt").exists()
                else (
                    input_path if input_path.exists() else self._output_path(context, "alive.txt")
                )
            ),
        )

        if not self._alive_urls(context) and not read_lines(alive_path):
            return self._skip("Skipped — no alive URLs for nuclei")

        args = [
            str(self.resolved_binary(context)),
            "-l",
            str(alive_path),
            "-silent",
            "-jsonl",
            "-o",
            str(output_path),
            "-c",
            str(self.settings.threads),
            "-rate-limit",
            str(self.settings.rate_limit),
        ]

        headers = self.settings.merged_headers()
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])

        if not self.settings.nuclei_enable_interactsh:
            # interactsh OOB polling contacts ProjectDiscovery's public
            # collaborator servers directly — third-party infra the confinement
            # proxy below would otherwise (correctly) refuse, silently
            # breaking every OOB template. Disable OOB templates instead of
            # letting that fail confusingly; NUCLEI_ENABLE_INTERACTSH=true
            # opts back in and accepts that unproxied third-party contact.
            args.append("-ni")

        # nuclei templates can declare their own redirect-following and OOB
        # interactsh callbacks regardless of global flags; route it through
        # a local scope-enforcing proxy so any host it reaches for beyond
        # the authorized -l list is checked first.
        async with self._crawler_confinement(context) as proxy:
            args.extend(["-proxy", proxy.proxy_url])
            result = await self._execute_self_output(context, args, output_path, allow_empty=True)
        findings = read_jsonl(output_path)
        context.metadata["nuclei_findings"] = len(findings)

        return PluginResult(
            success=result.success,
            output_path=output_path,
            lines_produced=len(findings),
            message=f"Nuclei found {len(findings)} results",
        )
