"""hakrawler web crawling plugin (optional)."""

from __future__ import annotations

from pathlib import Path

from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_lines, write_jsonl


class HakrawlerPlugin(BaseToolPlugin):
    name = "hakrawler"
    display_name = "hakrawler"
    required = False
    stage_order = 51
    produces = ("urls",)
    capability = "post_http"
    active_collection = True
    install_hint_macos = "go install github.com/hakluke/hakrawler@latest"
    install_hint_linux = "go install github.com/hakluke/hakrawler@latest"

    def is_enabled(self) -> bool:
        return self.settings.enable_hakrawler

    def get_binary_path(self) -> Path:
        return self.settings.hakrawler_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "hakrawler.txt")
        json_output = self._output_path(context, "hakrawler.jsonl")
        urls = self._alive_urls(context)

        if not urls:
            return self._skip("Skipped — no alive URLs for hakrawler")

        input_data = "\n".join(urls) + "\n"

        # hakrawler has no built-in scope/exclude flag and follows redirects
        # by default; a local scope-enforcing proxy is the only confinement
        # available for hosts it decides to reach on its own.
        async with self._crawler_confinement(context) as proxy:
            # -plain doesn't exist on the currently-packaged hakrawler
            # (github.com/hakluke/hakrawler) — plain URL-per-line is its
            # default output with no flag needed; depth is -d, not -depth.
            # Confirmed against the real installed binary's -h output; the
            # plugin previously errored on every invocation with "flag
            # provided but not defined: -plain" (masked because existing
            # tests mock _execute and never actually invoke the binary).
            args = self._argv(context, "-d", "2", "-insecure", "-proxy", proxy.proxy_url)
            # hakrawler has no dedicated UA flag either, and its only header
            # mechanism is "-h" (not "-H") taking "Name: value;;Name2: value2"
            # — confirmed against the installed binary's -h output. Previously
            # set no headers of any kind.
            user_agent = self.settings.effective_user_agent()
            if user_agent:
                args.extend(["-h", f"User-Agent: {user_agent}"])
            result = await self._execute(
                context, args, output_path, input_data=input_data, allow_empty=True
            )
        crawled = read_lines(output_path)
        write_jsonl(
            json_output,
            [{"url": url, "source": "hakrawler"} for url in crawled],
            base_dir=context.output_dir,
        )
        context.metadata["hakrawler_urls"] = len(crawled)

        return PluginResult(
            success=result.success,
            output_path=json_output,
            lines_produced=len(crawled),
            message=f"Crawled {len(crawled)} URLs" if crawled else "No URLs crawled",
        )
