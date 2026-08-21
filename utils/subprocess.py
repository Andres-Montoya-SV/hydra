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
    validate_binary_path,
    validate_output_path,
)

logger = get_logger("subprocess")

MAX_STDOUT_BYTES = 50 * 1024 * 1024  # 50 MB cap per subprocess

# Track running processes for cleanup on cancellation
_running_processes: weakref.WeakSet[asyncio.subprocess.Process] = weakref.WeakSet()


async def terminate_all_processes() -> None:
    """Terminate all tracked subprocesses. Used during pipeline cancellation."""
    for proc in list(_running_processes):
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except (ProcessLookupError, OSError):
                pass


async def check_tool_available(binary: Path) -> bool:
    """Check if a tool binary exists and can execute (version not required)."""
    from core.discovery.tool_discovery import probe_binary_executable

    try:
        if binary.name == str(binary) and "/" not in str(binary) and os.sep not in str(binary):
            import shutil

            found = shutil.which(str(binary))
            if not found:
                return False
            binary = Path(found)
        if not binary.exists() or not os.access(binary, os.X_OK):
            return False
        return await probe_binary_executable(binary)
    except OSError:
        return False
    except Exception:
        return False


async def get_tool_version(binary: Path) -> str | None:
    """Attempt to retrieve tool version string.

    Args:
        binary: Tool binary path.

    Returns:
        Version string or None.
    """
    try:
        resolved = validate_binary_path(binary)
    except Exception:
        resolved = binary

    for flag in ("-version", "--version", "-v"):
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                str(resolved),
                flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _running_processes.add(proc)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = (stdout or stderr).decode("utf-8", errors="replace").strip()
            if output:
                return output.split("\n")[0][:80]
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            if proc and proc.returncode is None:
                proc.kill()
            continue
    return None


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
