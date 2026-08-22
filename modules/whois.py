"""Domain registration intelligence using the system whois client."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from core.domain import parse_hostname
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import atomic_write_text, relative_output_path, validate_output_path

_RATE_LIMIT_MARKERS = (
    "rate limit",
    "rate-limit",
    "too many requests",
    "too many queries",
    "query limit",
    "quota exceeded",
    "exceeded the maximum",
    "try again later",
    "access denied for abuse",
    "temporarily unavailable",
    "server is busy",
)


class WhoisPlugin(BaseToolPlugin):
    """Collect raw and normalized WHOIS data for each root target."""

    name = "whois"
    display_name = "WHOIS"
    required = False
    stage_order = 5
    produces = ("domains",)
    capability = "registration"
    active_collection = True
    install_hint_macos = "whois is included with macOS"
    install_hint_linux = "sudo apt install whois"

    def is_enabled(self) -> bool:
        return self.settings.enable_whois

    def get_binary_path(self) -> Path:
        return self.settings.whois_path

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "whois.jsonl")
        raw_path = self._output_path(context, "whois_raw.txt")
        records: list[dict[str, object]] = []
        raw_sections: list[str] = []
        warnings: list[str] = []

        # WHOIS registries (Verisign for .com, and equivalents for other
        # TLDs) index registrable/root domains only — they have no concept
        # of subdomains. Querying "www.example.com" or
        # "booking.staging.example.com" returns "No match for domain ...",
        # leaving only the generic IANA block about the TLD itself (whose
        # `created:`/`changed:` fields are the TLD's OWN delegation dates,
        # not this domain's). Always reduce each target to its root domain
        # before querying, and deduplicate so a run containing both
        # "www.example.com" and "example.com" as separate targets only
        # queries the registry once.
        root_domains = list(
            dict.fromkeys(
                parse_hostname(target.domain)[2] for target in context.targets if target.domain
            )
        )
        root_domains = [domain for domain in root_domains if domain]

        self.update_status(context, ToolStatus.RUNNING)
        for domain in root_domains:
            context.current_target = domain
            try:
                return_code, stdout, stderr, failure_kind = await self._query_with_retries(
                    context, domain
                )
            except Exception as exc:
                warnings.append(f"{domain}: {exc}")
                continue

            raw = stdout.strip() or stderr.strip()
            raw_sections.append(f"===== {domain} =====\n{raw}\n")
            if failure_kind:
                warnings.append(f"{domain}: {failure_kind}")
                continue
            if not raw:
                warnings.append(f"{domain}: WHOIS returned no data")
                continue

            rate_limit_msg = _detect_rate_limit(raw)
            if rate_limit_msg:
                warnings.append(f"{domain}: {rate_limit_msg}")
                continue

            parsed = _parse_whois(raw)
            parsed.update(
                {
                    "domain": domain,
                    "return_code": return_code,
                    "raw_artifact": relative_output_path(raw_path, context.output_dir),
                }
            )
            records.append(parsed)

        raw_path = validate_output_path(raw_path, context.output_dir)
        atomic_write_text(raw_path, "\n".join(raw_sections))
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        context.current_target = None

        if warnings:
            context.add_warning("WHOIS: " + "; ".join(warnings[:3]))

        # Total failure (every target errored or returned no data) must be
        # visible as a failure, not silently reported as a successful run
        # that happened to collect "0 domain(s)".
        success = count > 0 or not root_domains
        if success:
            self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
            message = f"Collected registration data for {count} domain(s)"
        else:
            self.update_status(
                context,
                ToolStatus.FAILED,
                output_lines=count,
                error_message="No WHOIS records collected for any target",
            )
            message = "WHOIS collection failed for all targets"

        return PluginResult(
            success=success,
            output_path=output_path,
            lines_produced=count,
            message=message,
        )

    async def _query_with_retries(
        self, context: PipelineContext, domain: str
    ) -> tuple[int, str, str, str | None]:
        """Run whois with a short per-attempt timeout and brief backoff retries.

        Returns ``(return_code, stdout, stderr, failure_kind)``. ``failure_kind``
        is None on a usable response; otherwise a human-readable reason that
        distinguishes timeout/no-response from explicit rate-limiting text.
        """
        attempts = max(1, self.settings.whois_retries)
        delay = max(0, self.settings.whois_retry_delay_seconds)
        last_exc: Exception | None = None
        last_code, last_out, last_err = 1, "", ""

        for attempt in range(1, attempts + 1):
            try:
                return_code, stdout, stderr = await self._run_tool(
                    context,
                    self._argv(context, domain),
                    timeout=self.settings.whois_timeout,
                )
            except Exception as exc:
                last_exc = exc
                if attempt < attempts and delay:
                    await asyncio.sleep(delay * attempt)
                continue

            last_code, last_out, last_err = return_code, stdout, stderr
            raw = (stdout or "").strip() or (stderr or "").strip()
            if raw:
                rate_limit_msg = _detect_rate_limit(raw)
                if rate_limit_msg:
                    if attempt < attempts:
                        # Explicit throttle text — backoff and try once more.
                        await asyncio.sleep(delay * attempt)
                        continue
                    return return_code, stdout, stderr, rate_limit_msg
                return return_code, stdout, stderr, None

            # Empty body: treat as no-response and retry.
            if attempt < attempts and delay:
                await asyncio.sleep(delay * attempt)

        if last_exc is not None:
            msg = str(last_exc)
            if "timed out" in msg.lower() or "timeout" in msg.lower():
                return (
                    1,
                    "",
                    msg,
                    (
                        f"timeout/no response after {attempts} attempt(s) "
                        f"(per-attempt limit {self.settings.whois_timeout}s): {msg}"
                    ),
                )
            return 1, "", msg, f"query failed after {attempts} attempt(s): {msg}"

        raw = (last_out or "").strip() or (last_err or "").strip()
        if not raw:
            return (
                last_code,
                last_out,
                last_err,
                (
                    f"timeout/no response after {attempts} attempt(s) "
                    f"(per-attempt limit {self.settings.whois_timeout}s)"
                ),
            )
        rate_limit_msg = _detect_rate_limit(raw)
        if rate_limit_msg:
            return last_code, last_out, last_err, rate_limit_msg
        return last_code, last_out, last_err, None


def _detect_rate_limit(raw: str) -> str | None:
    lowered = raw.lower()
    for marker in _RATE_LIMIT_MARKERS:
        if marker in lowered:
            return f"rate limited by WHOIS server ({marker!r} in response)"
    return None


_DOMAIN_BLOCK_RE = re.compile(r"^domain name:", re.IGNORECASE | re.MULTILINE)


def _authoritative_block(raw: str) -> str:
    """Return the most specific (registrar-level) block of a referral chain.

    For gTLDs that IANA delegates with a `refer:` line (e.g. .xyz, .mom, and
    many other CentralNic-backed TLDs), a whois client that follows the
    referral concatenates TWO blocks in the response: first a generic block
    about the TLD ITSELF (with its own lowercase `created:`/`changed:`
    fields — the TLD's delegation dates in the IANA root, not the domain's
    registration dates), followed by the actual per-domain registrar block
    (`Domain Name:`, `Creation Date:`, `Updated Date:`, ...). Parsing the
    whole blob top-to-bottom picks up the TLD's dates instead of the
    domain's, since they appear first.

    Anchor on the LAST "Domain Name:" line instead: whois referral chains
    are ordered root-first, so the final "Domain Name:" block is always the
    most specific one available (the referred registry/registrar's own
    record). Domains with no referral chain (e.g. most .com queries go
    straight to the registry) have exactly one such line, near the top, so
    this is a no-op for the simple case.
    """
    matches = list(_DOMAIN_BLOCK_RE.finditer(raw))
    if not matches:
        return raw
    return raw[matches[-1].start() :]


def _parse_whois(raw: str) -> dict[str, object]:
    """Parse common WHOIS fields without assuming a single registry format."""
    raw = _authoritative_block(raw)
    aliases = {
        "registrar": {"registrar", "sponsoring registrar"},
        "created_at": {"creation date", "created", "registered on", "registration time"},
        "updated_at": {"updated date", "last updated", "changed"},
        "expires_at": {
            "registry expiry date",
            "registrar registration expiration date",
            "expiration date",
            "expiry date",
            "paid-till",
        },
        "status": {"domain status", "status"},
        "registrant_organization": {
            "registrant organization",
            "registrant organisation",
            "org",
        },
    }
    values: dict[str, list[str]] = {key: [] for key in aliases}
    nameservers: list[str] = []

    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("%", "#", ">>>")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if normalized_key in {"name server", "nserver", "nameservers"}:
            nameserver = value.split()[0].lower().rstrip(".")
            if nameserver not in nameservers:
                nameservers.append(nameserver)
            continue
        for canonical, candidate_keys in aliases.items():
            if normalized_key in candidate_keys and value not in values[canonical]:
                values[canonical].append(value)

    return {
        "registrar": _first(values["registrar"]),
        "created_at": _first(values["created_at"]),
        "updated_at": _first(values["updated_at"]),
        "expires_at": _first(values["expires_at"]),
        "statuses": values["status"],
        "registrant_organization": _first(values["registrant_organization"]),
        "nameservers": nameservers,
    }


def _first(values: list[str]) -> str | None:
    return values[0] if values else None
