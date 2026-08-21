"""Tests for logging sanitization."""

from __future__ import annotations

import logging

from core.logger import SecretRedactingFilter, setup_logging


class TestLogging:
    def test_secret_filter_redacts(self, tmp_path) -> None:
        setup_logging("DEBUG", tmp_path)
        filt = SecretRedactingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="token=abc123",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert "abc123" not in record.msg

    def test_setup_logging_creates_file(self, tmp_path) -> None:
        setup_logging("INFO", tmp_path)
        assert (tmp_path / "recon.log").exists()
