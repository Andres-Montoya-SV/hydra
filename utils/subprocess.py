"""Secure subprocess execution utilities."""

from __future__ import annotations

import asyncio
import os
import shlex
import weakref
from collections.abc import Sequence
from pathlib import Path

from core.exceptions import ToolExecutionError
from core.logger import get_logger
from utils.security import (
    atomic_write_text,
    sanitize_log_message,
    validate_output_path,
)

logger = get_logger("subprocess")

MAX_STDOUT_BYTES = 50 * 1024 * 1024  # 50 MB cap per subprocess

# Track running processes for cleanup on cancellation
_running_processes: weakref.WeakSet[asyncio.subprocess.Process] = weakref.WeakSet()

# Environment variables passed through to external tool subprocesses.
# `asyncio.create_subprocess_exec` inherits the *entire* parent environment
# when `env` is omitted — and Hydra's own environment carries every secret
# `Settings.from_env()` reads (ANTHROPIC_API_KEY, OPENAI_API_KEY,
# WPSCAN_API_TOKEN, SECURITYTRAILS_API_KEY, URLHAUS_API_KEY, and any
# credential embedded in OUTBOUND_PROXY_URL), whether or not the tool being
# run has anything to do with those providers. None of Hydra's external
# tools (subfinder, httpx, naabu, katana, hakrawler, dnsx, nuclei, nmap,
# amass, assetfinder, gau, waybackurls, unfurl, anew, jq) read API keys or
# proxy settings from environment variables — proxying is always done via
# an explicit `-proxy` CLI flag (see modules/httpx.py, katana.py,
# hakrawler.py, nuclei.py) — so this allowlist carries only what real-world
# CLI tools need to run and find their own config/cache directories.
_CHILD_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TZ",
    "GOPATH",
    "GOCACHE",
)


def child_process_env() -> dict[str, str]:
    """Minimal environment for an external tool subprocess — never the
    full parent environment (see `_CHILD_ENV_ALLOWLIST` for why)."""
    return {name: os.environ[name] for name in _CHILD_ENV_ALLOWLIST if name in os.environ}


async def terminate_all_processes() -> None:
    """Terminate all tracked subprocesses. Used during pipeline cancellation."""
    for proc in list(_running_processes):
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except (ProcessLookupError, OSError):
                pass


def _validate_args(args: Sequence[str]) -> list[str]:
    """Convert args to strings and reject empty command."""
    safe_args = [str(a) for a in args]
    if not safe_args:
        raise ToolExecutionError("unknown", "Empty command arguments")
    return safe_args


async def run_command(
    args: Sequence[str],
    *,
    input_data: str | None = None,
    timeout: int = 300,
    cwd: Path | None = None,
    tool_name: str = "unknown",
) -> tuple[int, str, str]:
    """Execute a command securely without shell=True.

    Args:
        args: Command argument list (never a shell string).
        input_data: Optional stdin data.
        timeout: Seconds before killing the process.
        cwd: Optional working directory.
        tool_name: Name for error messages.

    Returns:
        Tuple of (return_code, stdout, stderr).

    Raises:
        ToolExecutionError: On timeout, missing binary, or OS errors.
    """
    safe_args = _validate_args(args)
    log_line = sanitize_log_message("Executing: " + " ".join(shlex.quote(a) for a in safe_args))
    logger.debug(log_line)

    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *safe_args,
            stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=child_process_env(),
        )
        _running_processes.add(proc)
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=input_data.encode("utf-8") if input_data else None),
            timeout=timeout,
        )
        if len(stdout_bytes) > MAX_STDOUT_BYTES:
            proc.kill()
            await proc.wait()
            raise ToolExecutionError(
                tool_name,
                f"Output exceeded {MAX_STDOUT_BYTES} bytes — possible runaway process",
            )
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return proc.returncode or 0, stdout, stderr

    except asyncio.TimeoutError as exc:
        if proc and proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise ToolExecutionError(tool_name, f"Timed out after {timeout}s") from exc

    except FileNotFoundError as exc:
        raise ToolExecutionError(tool_name, f"Binary not found: {safe_args[0]}") from exc

    except PermissionError as exc:
        raise ToolExecutionError(tool_name, f"Permission denied: {safe_args[0]}") from exc

    except OSError as exc:
        raise ToolExecutionError(tool_name, str(exc)) from exc


async def run_command_to_file(
    args: Sequence[str],
    output_path: Path,
    *,
    input_data: str | None = None,
    timeout: int = 300,
    tool_name: str = "unknown",
    base_dir: Path | None = None,
) -> tuple[int, int]:
    """Run a command and atomically write stdout to a file.

    Args:
        args: Command argument list.
        output_path: Destination file path.
        input_data: Optional stdin data.
        timeout: Process timeout in seconds.
        tool_name: Name for error messages.
        base_dir: Optional directory output must stay within.

    Returns:
        Tuple of (return_code, line_count).
    """
    if base_dir is not None:
        output_path = validate_output_path(output_path, base_dir)

    return_code, stdout, stderr = await run_command(
        args,
        input_data=input_data,
        timeout=timeout,
        tool_name=tool_name,
    )

    atomic_write_text(output_path, stdout)

    if stderr.strip():
        logger.debug(
            "%s stderr: %s",
            tool_name,
            sanitize_log_message(stderr[:500]),
        )

    line_count = sum(1 for ln in stdout.splitlines() if ln.strip())
    return return_code, line_count, stderr
