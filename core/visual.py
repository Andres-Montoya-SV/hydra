"""Visual Intelligence: deterministic visual-change signals.

A web page's look changes constantly for reasons nobody needs to be told
about (rotating banners, CSRF tokens, timestamps, A/B tests), so raw
screenshot pixels and response-body hashes are never compared. Only two
identity signals count, and only for a URL both runs actually reached:

- the favicon hash changed (a different product or vendor now serves it);
- the normalized page title changed (whitespace and case differences
  ignored).

A signal missing on either side is not a change: a probe that failed or
was disabled this run proves nothing about the page. Same inputs always
produce the same changes, in the same order.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from core.assets import HttpService

VisualSignal = Literal["favicon", "title"]

SIGNIFICANCE_RULES: tuple[str, ...] = (
    "favicon hash changed on a URL reached in both runs",
    "normalized page title changed on a URL reached in both runs",
    "never compared: screenshot pixels, response-body hashes, or a signal missing in either run",
)


@dataclass(frozen=True)
class VisualChange:
    url: str
    signal: VisualSignal
    before: str
    after: str

    def reason(self) -> str:
        return f"{self.signal} changed on {self.url}: {self.before!r} -> {self.after!r}"


def _normalized_title(title: str | None) -> str:
    return " ".join((title or "").split()).casefold()


def _title_change(url: str, before: HttpService, after: HttpService) -> VisualChange | None:
    old, new = _normalized_title(before.title), _normalized_title(after.title)
    if not old or not new or old == new:
        return None
    return VisualChange(url, "title", str(before.title).strip(), str(after.title).strip())


def _favicon_change(url: str, before: HttpService, after: HttpService) -> VisualChange | None:
    old, new = before.favicon_hash, after.favicon_hash
    if not old or not new or old == new:
        return None
    return VisualChange(url, "favicon", old, new)


def visual_changes(
    previous: Iterable[HttpService], current: Iterable[HttpService]
) -> list[VisualChange]:
    """Significant visual changes between two runs' HTTP services."""
    before = {service.url: service for service in previous}
    changes: list[VisualChange] = []
    for service in sorted(current, key=lambda s: s.url):
        old = before.get(service.url)
        if old is None:
            continue
        for detect in (_favicon_change, _title_change):
            change = detect(service.url, old, service)
            if change is not None:
                changes.append(change)
    return changes
