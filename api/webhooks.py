"""Outbound webhooks — a customer wires Hydra into whatever tool their
team actually lives in (Slack, Teams, Jira via a Zapier/n8n bridge, their
own automation) by registering a plain HTTPS URL, rather than Hydra
building a bespoke integration per destination. A single generic, signed
webhook gets most of that value for a fraction of the surface area of a
native Slack/Teams/Jira app — those remain explicit non-goals for this
pass (docs/PAID_API_DESIGN.md's dated section has the full reasoning).

**Reuses, never reinvents, two things this codebase already has real,
tested answers for**:

1. **"Is this notification-worthy"** — `api/monitoring_worker.py` already
   decides exactly this for the email path (a `MonitoringRunOutcome` only
   exists when there's something worth telling the account). Webhook
   delivery is wired into the SAME place that builds the email, off the
   SAME outcomes, never a second, potentially-drifting definition of
   "worth alerting."
2. **SSRF/private-network defense** — `core/collection/ssrf.py`'s
   `validate_destination_ips_async`/`classify_ip` already implement a
   real, tested "resolve, then check every returned IP against the
   RFC1918/loopback/link-local/metadata blocklist" policy, used
   everywhere this project makes an outbound connection to a caller-
   influenced hostname. Webhook delivery calls that SAME function,
   never a second, hand-rolled IP-range check.

**Why NOT `CollectionGateway`/`ScopeEnforcingProxy`, the OTHER existing
egress-control layer**: that machinery authorizes a hostname against a
*target's* `CollectionScope` — the whole point is "is this address inside
the domain(s) an account is authorized to scan." A webhook URL is the
exact opposite kind of destination: an account's OWN third-party
endpoint (Slack, their own server), never inside any scan's scope, and
was never meant to be. Routing webhook delivery through scope
authorization would be a category error, not reuse — it would either
reject every real webhook destination (correctly, since Slack is never
"in scope") or require inventing a fake always-allow scope, which would
then leak that same permissive scope into the SAME `CollectionScope`
object real recon collection is authorized against. The correct, narrow
reuse is `core/collection/ssrf.py`'s scope-INDEPENDENT IP-safety
primitives (already designed and documented as "an ADDITIONAL,
independent layer" over hostname authorization) — those are reused
directly; `CollectionGateway`'s scope-authorization half is deliberately
NOT involved here at all.

**DNS-rebinding defense — resolve, pin, connect to the resolved IP,
verified for real**: `validate_destination_ips_async` returns the
resolved IP(s); delivery then connects DIRECTLY to that IP (never lets
the HTTP client re-resolve the hostname at connect time, which is
exactly the TOCTOU window a rebinding attack needs), sending the
original hostname via the `Host` header (for virtual-hosting) and via
`httpx`'s `extensions={"sni_hostname": ...}` (so TLS certificate
verification still checks the certificate against the real hostname, not
the IP) — confirmed working for real against a live HTTPS site before
relying on it (a bare IP connection with a mismatched SNI/Host would
either fail TLS verification or hit the wrong virtual host, so this
isn't just "should work in theory"). Because the resolve-and-validate
step runs fresh on every single delivery ATTEMPT (including retries, and
including every future delivery of a later event), a URL that resolves
public at registration time but rebinds to a private/metadata address by
the time an event actually fires is still caught — registration-time
validation alone would not have been enough.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from api.control_db import ControlDB, WebhookRecord
    from api.monitoring import MonitoringRunOutcome

logger = logging.getLogger("hydra.api.webhooks")

# The complete, fixed event-type set — never an open string a client can
# invent, so a typo in a subscription can't silently create a
# permanently-unmatched webhook (`api/routers/webhooks.py` rejects any
# value outside this set at registration time).
EVENT_TYPES: frozenset[str] = frozenset(
    {"monitoring.changed", "monitoring.needs_review", "finding.high_severity"}
)

# A real, enforced cap — an account cannot use webhook registration to
# fan out an unbounded number of outbound requests from Hydra's own
# infrastructure.
MAX_WEBHOOKS_PER_ACCOUNT = 10

# Bounded retries with backoff for one event's delivery to one webhook —
# never unbounded (a permanently-down endpoint must not tie up the
# triggering account's own notification path indefinitely). Chosen to
# absorb an ordinary transient blip (a receiver mid-deploy, one dropped
# TCP connection) without meaningfully delaying the rest of a monitoring
# cycle's own per-account processing: worst case ~6s of retry sleep
# before this one event gives up, per webhook, per event.
MAX_DELIVERY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 5.0)
DELIVERY_TIMEOUT_SECONDS = 10.0

# After this many CONSECUTIVE delivered-events-that-each-exhausted-their-
# own-retries-and-still-failed, the webhook is automatically disabled
# (`ControlDB.record_webhook_delivery_failure`'s own atomic threshold
# check) — a dead endpoint stops being retried forever. Re-enabling
# requires deleting and re-registering (the simplest correct behavior for
# this pass; see docs/PAID_API_DESIGN.md's non-goals).
DISABLE_AFTER_CONSECUTIVE_FAILURES = 5

_SIGNATURE_HEADER = "X-Hydra-Signature"
_EVENT_HEADER = "X-Hydra-Event"


def generate_webhook_secret() -> str:
    return secrets.token_hex(32)


def sign_payload(secret: str, body: bytes) -> str:
    """`sha256=<hex digest>` — the same `sha256=` prefix convention
    GitHub's own outbound-webhook signatures use, so a receiver
    implementing verification against this header recognizes the shape
    immediately. HMAC, not a bare hash, specifically so a receiver can
    verify the body came from an entity that knows the shared secret —
    a bare hash would let anyone who intercepts one delivery forge the
    next."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str, body: bytes, signature_header: str) -> bool:
    """The receiver-side check, provided here mainly so this module's
    own tests can prove a tampered body actually fails verification —
    `hmac.compare_digest` (constant-time) rather than `==`, the same
    timing-attack-resistant comparison every signature check in this
    codebase already uses (e.g. Wompi's inbound webhook verification)."""
    expected = sign_payload(secret, body)
    return hmac.compare_digest(expected, signature_header)


def validate_webhook_url_scheme(url: str) -> tuple[bool, str]:
    """The cheap, synchronous half of URL validation — scheme and basic
    shape only, no network I/O. Real destination-safety (DNS resolution
    + private-range check) is `validate_webhook_destination`, async,
    called separately because it can't be done without a real DNS
    lookup."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False, "Only https:// URLs are accepted."
    if not parsed.hostname:
        return False, "URL has no host."
    return True, ""


async def validate_webhook_destination(url: str) -> tuple[bool, str, str]:
    """Returns `(allowed, reason, connect_ip)`. Real DNS resolution +
    `core/collection/ssrf.py`'s real private-range/metadata blocklist —
    never a hand-rolled second check. Called at BOTH registration time
    (so an obviously-bad URL is rejected immediately, a better UX than
    silently failing every future delivery) AND at every delivery
    attempt (the actual enforcement point — a URL can legitimately
    change what it resolves to between registration and any given
    delivery, and a rebinding attack specifically exploits exactly that
    gap)."""
    from core.collection.ssrf import validate_destination_ips_async

    parsed = urlparse(url)
    ok, reason = validate_webhook_url_scheme(url)
    if not ok:
        return False, reason, ""
    hostname = parsed.hostname
    if hostname is None:
        # Unreachable in practice: validate_webhook_url_scheme already
        # rejects a URL with no host before this point is ever reached.
        return False, "URL has no host.", ""
    decision = await validate_destination_ips_async(hostname, allow_private_network_targets=False)
    if not decision.allowed:
        return False, f"Destination refused: {decision.reason}", ""
    return True, "", decision.connect_ip


@dataclass(frozen=True)
class WebhookEvent:
    event_type: str
    payload: dict[str, object]


def event_for_monitoring_outcome(outcome: MonitoringRunOutcome) -> WebhookEvent:
    """The exact same significance decision `api/monitoring_worker.py`
    already made to decide THIS outcome is worth an email — reused
    verbatim (`outcome.needs_review`), never re-derived. A monitoring
    outcome is always either the needs-review event or the plain
    changed event, never both."""
    event_type = "monitoring.needs_review" if outcome.needs_review else "monitoring.changed"
    payload: dict[str, object] = {
        "event": event_type,
        "domain": outcome.domain,
        "speed": outcome.speed,
        "asset_count": outcome.asset_count,
        "hosts_added": outcome.hosts_added,
        "hosts_removed": outcome.hosts_removed,
        "needs_review": outcome.needs_review,
    }
    if outcome.review_reason:
        payload["review_reason"] = outcome.review_reason
    return WebhookEvent(event_type=event_type, payload=payload)


def event_for_high_severity_findings(
    *, domain: str, scan_id: str, findings: list[dict[str, str]]
) -> WebhookEvent:
    """`findings`: a list of `{"template_id", "severity", "name", "host"}`
    dicts, already filtered to `severity in {"high", "critical"}` by the
    caller (`api/scan_orchestrator.py`) — this function only shapes the
    payload, it never decides severity itself, so there is exactly one
    place in the codebase that answers "is this finding severe" for the
    webhook path (the same filter the caller applies)."""
    return WebhookEvent(
        event_type="finding.high_severity",
        payload={
            "event": "finding.high_severity",
            "domain": domain,
            "scan_id": scan_id,
            "finding_count": len(findings),
            "findings": findings,
        },
    )


async def _post_to_pinned_ip(
    *,
    url: str,
    connect_ip: str,
    hostname: str,
    body: bytes,
    signature: str,
    event_type: str,
    verify: bool = True,
) -> tuple[bool, str]:
    """The actual delivery attempt — connects to `connect_ip` (already
    validated), never lets the HTTP client re-resolve `hostname` itself.
    `verify` (real TLS certificate verification against `sni_hostname`,
    not the IP literal — a receiver whose certificate doesn't match the
    registered hostname fails closed exactly as it should) defaults to
    `True` and stays `True` on every real code path in this codebase;
    it exists as a parameter ONLY so this module's own tests can point
    delivery at a real local HTTPS server using a self-signed
    certificate without needing a CA this project doesn't control —
    the same "explicit override, production never passes it" shape
    `api/domain_verification.py`'s injectable `client`/`base_url`
    parameters already established for the same reason."""
    import httpx

    parsed = urlparse(url)
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    pinned_url = f"https://{connect_ip}:{port}{path}"

    try:
        async with httpx.AsyncClient(timeout=DELIVERY_TIMEOUT_SECONDS, verify=verify) as client:
            request = client.build_request(
                "POST",
                pinned_url,
                content=body,
                headers={
                    "Host": hostname,
                    "Content-Type": "application/json",
                    _SIGNATURE_HEADER: signature,
                    _EVENT_HEADER: event_type,
                },
                extensions={"sni_hostname": hostname},
            )
            response = await client.send(request)
    except httpx.RequestError as exc:
        return False, f"{type(exc).__name__}: {exc}"

    if 200 <= response.status_code < 300:
        return True, ""
    return False, f"HTTP {response.status_code}"


async def deliver_event(
    *, control_db: ControlDB, webhook: WebhookRecord, event: WebhookEvent, verify: bool = True
) -> bool:
    """Delivers ONE event to ONE webhook, with bounded retries — the
    caller (`api/monitoring_worker.py`) is responsible for iterating
    every subscribed webhook and for its own per-account error
    isolation (a `try`/`except` around this call, the same discipline
    every other per-domain operation in that loop already uses); this
    function never raises for an ordinary delivery failure, only for a
    genuinely unexpected bug, so one webhook's total failure can never
    silently take down another's delivery in the same cycle."""
    if event.event_type not in webhook.event_types:
        return False  # not subscribed to this event type — not a failure

    body = json.dumps(event.payload, sort_keys=True).encode("utf-8")
    signature = sign_payload(webhook.secret, body)

    last_error = "unknown error"
    for attempt in range(MAX_DELIVERY_ATTEMPTS):
        # Re-validated on EVERY attempt, not once before the loop — the
        # actual DNS-rebinding defense: a URL that resolved safely on
        # attempt 1 but rebinds to a private address by attempt 2 is
        # caught here, not connected to.
        allowed, reason, connect_ip = await validate_webhook_destination(webhook.url)
        if not allowed:
            last_error = reason
            logger.warning(
                "Webhook %s delivery refused for account %s: %s",
                webhook.webhook_id,
                webhook.account_id,
                reason,
            )
            break  # a refused destination will not become allowed by retrying immediately

        hostname = urlparse(webhook.url).hostname
        if hostname is None:
            # Unreachable in practice: validate_webhook_destination above
            # already confirmed this exact URL has a host.
            last_error = "URL has no host."
            break
        ok, error = await _post_to_pinned_ip(
            url=webhook.url,
            connect_ip=connect_ip,
            hostname=hostname,
            body=body,
            signature=signature,
            event_type=event.event_type,
            verify=verify,
        )
        if ok:
            control_db.record_webhook_delivery_success(webhook.webhook_id)
            return True
        last_error = error
        if attempt < MAX_DELIVERY_ATTEMPTS - 1:
            import asyncio

            await asyncio.sleep(RETRY_BACKOFF_SECONDS[attempt])

    control_db.record_webhook_delivery_failure(
        webhook.webhook_id, error=last_error, disable_after=DISABLE_AFTER_CONSECUTIVE_FAILURES
    )
    logger.warning(
        "Webhook %s delivery failed for account %s after %d attempt(s): %s",
        webhook.webhook_id,
        webhook.account_id,
        MAX_DELIVERY_ATTEMPTS,
        last_error,
    )
    return False


async def deliver_event_to_subscribers(
    *, control_db: ControlDB, account_id: str, event: WebhookEvent, verify: bool = True
) -> None:
    """The entry point callers (monitoring, scan completion) actually
    use — looks up every active, subscribed webhook for the account and
    delivers to each independently. One webhook's exception never stops
    delivery to the account's other webhooks."""
    webhooks = control_db.list_active_webhooks_for_event(account_id, event.event_type)
    for webhook in webhooks:
        try:
            await deliver_event(control_db=control_db, webhook=webhook, event=event, verify=verify)
        except Exception:
            logger.exception(
                "Unexpected error delivering %s to webhook %s for account %s",
                event.event_type,
                webhook.webhook_id,
                account_id,
            )
