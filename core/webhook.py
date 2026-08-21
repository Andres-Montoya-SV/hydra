"""Optional Slack/Discord-compatible webhook for scan diffs."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from core.logger import get_logger

logger = get_logger("webhook")


def diff_has_changes(diff: dict[str, Any] | None) -> bool:
    if not diff:
        return False
    keys = ("new_hosts", "removed_hosts", "new_http", "removed_http")
    return any(diff.get(key) for key in keys)


def format_diff_message(diff: dict[str, Any]) -> str:
    parts = ["Hydra scan diff vs previous run:"]
    mapping = (
        ("new_hosts", "new hosts"),
        ("removed_hosts", "removed hosts"),
        ("new_http", "new HTTP services"),
        ("removed_http", "removed HTTP services"),
    )
    for key, label in mapping:
        items = diff.get(key) or []
        if items:
            preview = ", ".join(str(x) for x in items[:8])
            extra = f" (+{len(items) - 8} more)" if len(items) > 8 else ""
            parts.append(f"- {len(items)} {label}: {preview}{extra}")
    return "\n".join(parts)


def notify_scan_diff(webhook_url: str | None, diff: dict[str, Any] | None) -> bool:
    """POST a Slack/Discord payload. No-op (no warning) when URL is unset.

    Returns True if a request was sent successfully.
    """
    if not webhook_url or not diff_has_changes(diff):
        return False
    text = format_diff_message(diff or {})
    payload = json.dumps({"text": text, "content": text}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=10
        ) as response:  # nosec B310  # webhook_url from operator config, HTTPS expected
            response.read(256)
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("Webhook notification failed: %s", exc)
        return False
