"""httpx HTTP probing plugin."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from core.models import PipelineContext
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_jsonl, write_lines
from utils.security import atomic_write_text, validate_output_path


class HttpxPlugin(BaseToolPlugin):
    name = "httpx"
    display_name = "httpx"
    required = True
    stage_order = 40
    produces = ("urls", "certificates", "technologies", "ips")
    followup_kinds = ("domains",)
    capability = "http_probe"
    active_collection = True
    strict_opsec_allowed = True
    install_hint_macos = "brew install httpx"
    install_hint_linux = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def is_enabled(self) -> bool:
        return True

    def get_binary_path(self) -> Path:
        return self.settings.httpx_path

    def _build_args(
        self, context: PipelineContext, input_path: Path, json_output: Path
    ) -> list[str]:
        args = [
            str(self.resolved_binary(context)),
            "-l",
            str(input_path),
            "-silent",
            "-json",
            "-o",
            str(json_output),
            "-t",
            str(self.settings.httpx_threads),
            "-timeout",
            "10",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-web-server",
            "-location",
            "-favicon",
            "-hash",
            "sha256",
            "-include-response-header",
            "-disable-update-check",
            "-no-stdin",
        ]

        if not self.settings.strict_opsec:
            args.extend(["-ip", "-cname", "-tls-probe", "-tls-grab"])
        elif self.settings.outbound_proxy_url:
            args.extend(["-proxy", self.settings.outbound_proxy_url])

        headers = self.settings.merged_headers()
        for key, value in headers.items():
            args.extend(["-H", f"{key}: {value}"])

        user_agent = self.settings.effective_user_agent()
        if user_agent:
            args.extend(["-H", f"User-Agent: {user_agent}"])

        return args

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        input_path = self._authorized_input(context, input_path)
        suffix = str(context.metadata.get("httpx_output_suffix") or "")
        json_output = self._output_path(context, f"httpx{suffix}.json")
        alive_output = self._output_path(context, f"alive{suffix}.txt")
        csv_output = self._output_path(context, f"httpx{suffix}.csv")

        if not input_path.exists() or input_path.stat().st_size == 0:
            return PluginResult(success=False, message="No hosts to probe")

        args = self._build_args(context, input_path, json_output)
        # httpx writes JSONL via -o; must not capture stdout (would overwrite -o file)
        result = await self._execute_self_output(context, args, json_output, allow_empty=True)

        records = read_jsonl(json_output) if json_output.exists() else []
        context.httpx_results = records

        alive_urls = []
        for record in records:
            url = record.get("url") or record.get("input", "")
            if url:
                alive_urls.append(url)

        write_lines(alive_output, alive_urls, base_dir=context.output_dir)
        context.alive_urls = alive_urls

        if records:
            self._write_csv(csv_output, records, context)

        return PluginResult(
            success=result.success,
            output_path=json_output,
            lines_produced=len(alive_urls),
            message=f"Found {len(alive_urls)} live HTTP services",
            data={"records": len(records)},
        )

    def _write_csv(self, path: Path, records: list[dict], context: PipelineContext) -> None:
        if not records:
            return
        path = validate_output_path(path, context.output_dir)
        fieldnames = sorted({key for rec in records for key in rec.keys()})
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            flat = {k: json.dumps(v) if isinstance(v, list | dict) else v for k, v in rec.items()}
            writer.writerow(flat)
        atomic_write_text(path, output.getvalue())
