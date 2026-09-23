"""Structured (JSON) logging — a small, real, optional feature
(docs/PAID_API_DESIGN.md's "Basic observability" section). Default
(`log_format="text"`) must format exactly like every prior round's
plain `logging.basicConfig` call did; `"json"` is opt-in.
"""

from __future__ import annotations

import json
import logging

from api.observability import JsonFormatter, configure_logging


def _make_record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="hydra.api.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


class TestJsonFormatter:
    def test_formats_a_record_as_real_parseable_json(self) -> None:
        formatter = JsonFormatter()
        line = formatter.format(_make_record("something happened"))

        parsed = json.loads(line)  # must actually parse — not just "looks like JSON"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "hydra.api.test"
        assert parsed["message"] == "something happened"
        assert "timestamp" in parsed

    def test_includes_a_real_formatted_exception_when_present(self) -> None:
        formatter = JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="hydra.api.test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="failed",
                args=(),
                exc_info=sys.exc_info(),
            )
        parsed = json.loads(formatter.format(record))
        assert "ValueError" in parsed["exception"]
        assert "boom" in parsed["exception"]


class TestConfigureLogging:
    def test_text_format_is_a_no_op_when_a_handler_already_exists(self) -> None:
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            root.handlers = [logging.NullHandler()]
            configure_logging("text")
            # Never replaced — a real deployment's own explicit logging
            # config, set up before this ever runs, always wins.
            assert root.handlers == [root.handlers[0]]
            assert isinstance(root.handlers[0], logging.NullHandler)
        finally:
            root.handlers = original_handlers

    def test_json_format_installs_a_json_formatter_on_a_clean_root_logger(self) -> None:
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            root.handlers = []
            configure_logging("json")
            assert len(root.handlers) == 1
            assert isinstance(root.handlers[0].formatter, JsonFormatter)
        finally:
            root.handlers = original_handlers

    def test_default_text_format_installs_the_original_human_readable_formatter(self) -> None:
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        try:
            root.handlers = []
            configure_logging("text")
            assert len(root.handlers) == 1
            formatted = root.handlers[0].formatter.format(_make_record("hello"))
            assert "hello" in formatted
            assert not formatted.strip().startswith("{")  # not JSON-shaped
        finally:
            root.handlers = original_handlers
