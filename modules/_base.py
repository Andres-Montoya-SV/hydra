"""Shared helpers for reconnaissance tool plugins."""

from __future__ import annotations

import re
import time
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult, ReconPlugin
from utils.files import read_lines
from utils.security import validate_output_path, validate_safe_filename
from utils.subprocess import run_command, run_command_to_file

_RETRY_PATTERN = re.compile(r"retrying|retry\s*#?\s*\d+|attempt\s*#?\s*\d+", re.IGNORECASE)


class BaseToolPlugin(ReconPlugin):
    """Common execution patterns for external CLI tools."""

    install_hint_macos: str = "brew install <tool>"
    install_hint_linux: str = "go install -v <module>@latest"

    def resolved_binary(self, context: PipelineContext) -> Path:
        """Return discovered absolute binary path."""
        return context.resolved_binaries.get(self.name, self.get_binary_path())

    def _argv(self, context: PipelineContext, *args: str) -> list[str]:
        """Build argv with resolved absolute binary path."""
        return [str(self.resolved_binary(context)), *args]

    async def _run_tool(
        self,
        context: PipelineContext,
        args: list[str],
        *,
        input_data: str | None = None,
        timeout: int | None = None,
    ) -> tuple[int, str, str]:
        """Run tool without capturing stdout to file (for tools that use -o)."""
        binary = self.resolved_binary(context)
        exec_args = [str(binary)] + args[1:] if args else [str(binary)]
        return await run_command(
            exec_args,
            input_data=input_data,
            timeout=self.settings.timeout if timeout is None else timeout,
            tool_name=self.name,
        )

    def _alive_urls(self, context: PipelineContext) -> list[str]:
        """Read alive URLs, re-checking scope. Discovery is not authorization."""
        authorized = self._output_path(context, "authorized_alive.txt")
        alive_path = authorized if authorized.exists() else self._output_path(context, "alive.txt")
        if not alive_path.exists():
            return []
        urls = read_lines(alive_path)
        from core.intel.scope import filter_authorized_indicators, require_collection_scope

        scope = require_collection_scope(context)
        return filter_authorized_indicators(urls, scope)

    def _skip(self, message: str) -> PluginResult:
        """Return a skipped plugin result (not counted as failure)."""
        return PluginResult(success=False, skipped=True, message=message)

    async def _execute(
        self,
        context: PipelineContext,
        args: list[str],
        output_path: Path,
        *,
        input_data: str | None = None,
        allow_empty: bool = False,
    ) -> PluginResult:
        """Run tool and capture stdout to output_path (tools that write to stdout)."""
        output_path = validate_output_path(output_path, context.output_dir)
        self.update_status(context, ToolStatus.RUNNING)
        start = time.monotonic()

        binary = self.resolved_binary(context)
        exec_args = [str(binary)] + args[1:] if args else [str(binary)]

        try:
            return_code, line_count, stderr = await run_command_to_file(
                exec_args,
                output_path,
                input_data=input_data,
                timeout=self.settings.timeout,
                tool_name=self.name,
                base_dir=context.output_dir,
            )

            # Scan telemetry
            stdout_sample = ""
            if output_path.exists():
                try:
                    with open(output_path, encoding="utf-8", errors="ignore") as f:
                        stdout_sample = f.read(102400)  # read first 100KB
                except OSError:
                    pass
            self._scan_telemetry(context, stdout_sample, stderr)

            duration = time.monotonic() - start

            if return_code != 0:
                self.update_status(
                    context,
                    ToolStatus.FAILED,
                    duration_seconds=duration,
                    output_lines=line_count,
                    error_message=f"Exit code {return_code}",
                )
                msg = f"Exit code {return_code}"
                if line_count == 0:
                    msg += " (no output)"
                return PluginResult(success=False, output_path=output_path, message=msg)

            if line_count == 0 and not allow_empty:
                self.update_status(
                    context,
                    ToolStatus.FAILED,
                    duration_seconds=duration,
                    error_message="Empty output",
                )
                return PluginResult(success=False, output_path=output_path, message="Empty output")

            self.update_status(
                context,
                ToolStatus.COMPLETED,
                duration_seconds=duration,
                output_lines=line_count,
            )
            return PluginResult(
                success=True,
                output_path=output_path,
                lines_produced=line_count,
            )

        except Exception as exc:
            duration = time.monotonic() - start
            if "timed out" in str(exc).lower():
                context.total_timeouts += 1
                info = context.tool_states.get(self.name)
                if info:
                    info.timeouts += 1

            self.update_status(
                context,
                ToolStatus.FAILED,
                duration_seconds=duration,
                error_message=str(exc),
            )
            return PluginResult(success=False, message=str(exc))

    async def _execute_self_output(
        self,
        context: PipelineContext,
        args: list[str],
        output_path: Path,
        *,
        input_data: str | None = None,
        allow_empty: bool = False,
    ) -> PluginResult:
        """Run tool that writes its own output file via -o (do not capture stdout)."""
        output_path = validate_output_path(output_path, context.output_dir)
        self.update_status(context, ToolStatus.RUNNING)
        start = time.monotonic()

        try:
            return_code, stdout, stderr = await self._run_tool(context, args, input_data=input_data)
            self._scan_telemetry(context, stdout, stderr)

            duration = time.monotonic() - start
            line_count = len(read_lines(output_path)) if output_path.exists() else 0

            if return_code != 0:
                self.update_status(
                    context,
                    ToolStatus.FAILED,
                    duration_seconds=duration,
                    error_message=f"Exit code {return_code}",
                )
                return PluginResult(
                    success=False,
                    output_path=output_path,
                    message=f"Exit code {return_code}",
                )

            if line_count == 0 and not allow_empty:
                self.update_status(
                    context,
                    ToolStatus.FAILED,
                    duration_seconds=duration,
                    error_message="Empty output",
                )
                return PluginResult(success=False, output_path=output_path, message="Empty output")

            self.update_status(
                context,
                ToolStatus.COMPLETED,
                duration_seconds=duration,
                output_lines=line_count,
            )
            return PluginResult(
                success=True,
                output_path=output_path,
                lines_produced=line_count,
            )

        except Exception as exc:
            duration = time.monotonic() - start
            if "timed out" in str(exc).lower():
                context.total_timeouts += 1
                info = context.tool_states.get(self.name)
                if info:
                    info.timeouts += 1

            self.update_status(
                context,
                ToolStatus.FAILED,
                duration_seconds=duration,
                error_message=str(exc),
            )
            return PluginResult(success=False, message=str(exc))

    def _scan_telemetry(self, context: PipelineContext, stdout: str, stderr: str) -> None:
        combined = (stdout + "\n" + stderr).lower()

        # Check rate limits
        rate_limit_indicators = [
            "rate limit",
            "ratelimit",
            "429 too many requests",
            "too many requests",
            "rate-limiting",
        ]
        rate_limit_hits = sum(combined.count(ind) for ind in rate_limit_indicators)
        if rate_limit_hits > 0:
            context.total_rate_limits += rate_limit_hits
            info = context.tool_states.get(self.name)
            if info:
                info.rate_limits += rate_limit_hits

        # Check retries. Match "retrying", "retry #2"/"retry 2/3", and
        # "attempt #2"/"attempt 2" — but not a bare "attempt" (too generic,
        # would false-positive on unrelated log lines).
        if _RETRY_PATTERN.search(combined):
            context.total_retries += 1
            info = context.tool_states.get(self.name)
            if info:
                info.retries += 1

    def get_install_hint(self) -> str:
        return f"macOS: {self.install_hint_macos} | Linux: {self.install_hint_linux}"

    def _output_path(self, context: PipelineContext, filename: str) -> Path:
        if self.active_collection:
            from core.intel.scope import require_collection_scope

            require_collection_scope(context)
        validate_safe_filename(filename)
        return context.output_dir / filename

    def _authorized_input(self, context: PipelineContext, input_path: Path) -> Path:
        """Re-check authorization immediately before this collector runs."""
        from core.intel.scope import authorize_plugin_input

        return authorize_plugin_input(context, input_path, self.name)
