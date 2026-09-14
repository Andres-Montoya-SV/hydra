"""Tests for logging sanitization."""

from __future__ import annotations

import io
import logging

from core.logger import RedactingFormatter, SecretRedactingFilter, setup_logging


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


class TestExceptionTracebackRedaction:
    """Hardening round 2, Task 6: a `SecretRedactingFilter` alone only
    sanitizes `record.msg`/`record.args` — it runs before `Formatter.format()`
    renders `record.exc_info` into text, so a secret embedded in an
    exception's own message (e.g. a proxy URL with embedded credentials, or
    a bearer token echoed into an error string) previously reached the log
    file completely unredacted via `logger.exception(...)`. See
    docs/HARDENING_ROUND2_P1.md, Task 6.
    """

    def _logger_with_handler(self, name: str) -> tuple[logging.Logger, io.StringIO]:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SecretRedactingFilter())
        handler.setFormatter(RedactingFormatter("%(message)s"))
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()
        logger.propagate = False
        logger.addHandler(handler)
        return logger, stream

    def test_credential_embedded_url_in_traceback_is_redacted(self) -> None:
        logger, stream = self._logger_with_handler("test.traceback.url")
        try:
            raise ValueError(
                "failed to connect to https://apikey:sk-ant-leak-canary@evil.example/path"
            )
        except ValueError:
            logger.exception("Request failed")
        output = stream.getvalue()
        assert "sk-ant-leak-canary" not in output

    def test_bearer_token_in_traceback_is_redacted(self) -> None:
        logger, stream = self._logger_with_handler("test.traceback.bearer")
        try:
            raise RuntimeError("Authorization: Bearer sk-real-bearer-token-leak rejected")
        except RuntimeError:
            logger.exception("Header validation failed")
        output = stream.getvalue()
        assert "sk-real-bearer-token-leak" not in output

    def test_setup_logging_wires_the_redacting_formatter(self, tmp_path) -> None:
        # Regression guard for the exact bug: setup_logging must attach
        # RedactingFormatter (whose format() re-sanitizes exc_info text),
        # not a bare logging.Formatter that only ever sees msg/args.
        root = setup_logging("DEBUG", tmp_path)
        assert root.handlers
        for handler in root.handlers:
            assert isinstance(handler.formatter, RedactingFormatter)
