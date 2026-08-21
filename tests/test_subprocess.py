"""Tests for subprocess utilities."""

from __future__ import annotations

import sys

import pytest

from core.exceptions import ToolExecutionError
from utils.subprocess import run_command


class TestSubprocess:
    @pytest.mark.asyncio
    async def test_run_command_success(self) -> None:
        code, stdout, stderr = await run_command(
            [sys.executable, "-c", "print('ok')"],
            tool_name="test",
        )
        assert code == 0
        assert "ok" in stdout

    @pytest.mark.asyncio
    async def test_run_command_no_shell_injection(self) -> None:
        code, stdout, _ = await run_command(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "hello"],
            tool_name="test",
        )
        assert "hello" in stdout

    @pytest.mark.asyncio
    async def test_missing_binary_raises(self) -> None:
        with pytest.raises(ToolExecutionError):
            await run_command(["/nonexistent/binary"], tool_name="test")

    @pytest.mark.asyncio
    async def test_empty_args_raises(self) -> None:
        with pytest.raises(ToolExecutionError):
            await run_command([], tool_name="test")

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        with pytest.raises(ToolExecutionError, match="Timed out"):
            await run_command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=1,
                tool_name="test",
            )
