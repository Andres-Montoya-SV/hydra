"""Structured logging configuration for console and file output."""

from __future__ import annotations

import logging
import sys
from logging import Logger
from pathlib import Path

from utils.security import sanitize_log_message

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_CONFIGURED = False


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the log message before emission.

        Args:
            record: Log record to filter.

        Returns:
            Always True (record is kept, message is sanitized).
        """
        if isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: sanitize_log_message(str(v)) if isinstance(v, str) else v
                for k, v in record.args.items()
            }
        elif record.args:
            record.args = tuple(
                sanitize_log_message(str(a)) if isinstance(a, str) else a for a in record.args
            )
        return True


def setup_logging(log_level: str, log_dir: Path) -> Logger:
    """Configure root logger with console and file handlers.

    Args:
        log_level: Logging level name (DEBUG, INFO, etc.).
        log_dir: Directory for log files.

    Returns:
        Configured root logger.
    """
    global _CONFIGURED

    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        log_dir.chmod(0o700)
    except OSError:
        pass
    level = getattr(logging, log_level.upper(), logging.INFO)

    root = logging.getLogger("recon")
    root.setLevel(level)
    root.handlers.clear()

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
    redact_filter = SecretRedactingFilter()

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    console.addFilter(redact_filter)
    root.addHandler(console)

    log_file = log_dir / "recon.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    try:
        log_file.chmod(0o600)
    except OSError:
        pass
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redact_filter)
    root.addHandler(file_handler)

    _CONFIGURED = True
    return root


def get_logger(name: str) -> Logger:
    """Return a child logger under the recon namespace.

    Args:
        name: Logger suffix name.

    Returns:
        Child logger instance.
    """
    if not _CONFIGURED:
        setup_logging("INFO", Path("logs"))
    return logging.getLogger(f"recon.{name}")
