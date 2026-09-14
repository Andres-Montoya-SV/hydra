"""Tests for subprocess utilities."""

from __future__ import annotations

import os
import sys

import pytest

from core.exceptions import ToolExecutionError
from utils.subprocess import _CHILD_ENV_ALLOWLIST, child_process_env, run_command


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


class TestChildProcessEnvironmentIsolation:
    """Hardening round 2, Task 5: `run_command` must never hand an external
    tool subprocess Hydra's own full environment — `Settings.from_env()`
    reads real secrets (ANTHROPIC_API_KEY, OPENAI_API_KEY, WPSCAN_API_TOKEN,
    SECURITYTRAILS_API_KEY, URLHAUS_API_KEY, and OUTBOUND_PROXY_URL, which
    may itself embed proxy credentials) directly into Hydra's process
    environment, and `asyncio.create_subprocess_exec` inherits everything
    when `env=` is omitted. See docs/HARDENING_ROUND2_P1.md, Task 5."""

    _SECRET_ENV_VARS = (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "WPSCAN_API_TOKEN",
        "SECURITYTRAILS_API_KEY",
        "URLHAUS_API_KEY",
        "OUTBOUND_PROXY_URL",
    )

    def test_allowlist_excludes_every_known_secret_bearing_variable(self) -> None:
        for secret_var in self._SECRET_ENV_VARS:
            assert secret_var not in _CHILD_ENV_ALLOWLIST

    def test_child_process_env_never_carries_a_secret_present_in_the_parent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for secret_var in self._SECRET_ENV_VARS:
            monkeypatch.setenv(secret_var, "sk-should-never-leak-to-a-child-process")
        env = child_process_env()
        for secret_var in self._SECRET_ENV_VARS:
            assert secret_var not in env

    @pytest.mark.asyncio
    async def test_run_command_child_process_does_not_see_a_parent_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-leak-canary")
        code, stdout, _stderr = await run_command(
            [sys.executable, "-c", "import os; print(os.environ.get('ANTHROPIC_API_KEY', ''))"],
            tool_name="test",
        )
        assert code == 0
        assert "sk-ant-leak-canary" not in stdout
        assert stdout.strip() == ""

    @pytest.mark.asyncio
    async def test_run_command_child_process_still_gets_a_usable_path(self) -> None:
        # A restricted environment must not be so restrictive the child
        # can't function at all — PATH (needed to resolve its own
        # sub-invocations) must still come through when present in Hydra's
        # own environment.
        if "PATH" not in os.environ:
            pytest.skip("PATH not set in this environment")
        code, stdout, _stderr = await run_command(
            [sys.executable, "-c", "import os; print(bool(os.environ.get('PATH')))"],
            tool_name="test",
        )
        assert code == 0
        assert stdout.strip() == "True"
