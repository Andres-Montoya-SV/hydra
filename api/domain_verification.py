"""Domain-ownership verification (docs/PAID_API_DESIGN.md Part A) — the
non-negotiable gate: without this, the API is an unauthorized-scanning
vector against arbitrary third-party domains. Both methods perform a
real, active check every time — DNS TXT via a real UDP query
(`dnspython`), well-known file via a real HTTPS GET (`httpx`) — never
trusting what a client claims in a request body.

Design decisions this round finalized (docs/PAID_API_DESIGN.md's Part A
originally raised these without resolving them):

1. Verification expires 90 days after success, then requires
   re-verification. A domain can change hands after someone verified it;
   a fixed expiry bounds how stale that authorization can get without
   requiring a live re-check on every single scan (see point 3).
2. Two accounts, same domain: first successful verification wins. A
   second account's later, otherwise-valid proof is rejected with a
   clear conflict error while the first account's verification is still
   active — never silently accepted, never overwritten. (Once the first
   verification expires with no renewal, the domain becomes available to
   verify again, by anyone who can currently prove control — ordinary
   consequence of "no active row" rather than a special case.)
3. No live re-check on every scan. A `POST /scans` only reads the
   persisted `verified` status and its `expires_at` — it never re-queries
   DNS/HTTP live. Re-checking on every scan would add real latency
   (DNS/HTTP round-trips) and fragility (transient resolver hiccups,
   propagation delays) to every single request for a guarantee the fixed
   90-day expiry already bounds. The accepted trade-off: a domain that
   changes hands can remain scannable by the original account for up to
   90 days before its own expiry forces re-verification — the same
   window every similar verify-once-then-trust-until-expiry system
   (Google Search Console, ACME account-level challenges) accepts.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    import dns.asyncresolver
    import httpx

    from api.control_db import DomainVerificationRecord

DEFAULT_EXPIRY_DAYS = 90

ScanGateStatus = Literal["covered", "expired", "never_verified"]


def generate_token() -> str:
    return secrets.token_hex(16)


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def domain_is_covered(requested_domain: str, verified_domain: str) -> bool:
    """A verified domain also covers its subdomains — the same
    root-domain-covers-subdomains convention Hydra's own scope engine
    already uses (core/intel/scope.py, CollectionScope) for a bare
    `scope.txt` entry, reused here rather than inventing a second policy
    for the same idea."""
    requested = normalize_domain(requested_domain)
    verified = normalize_domain(verified_domain)
    return requested == verified or requested.endswith(f".{verified}")


def dns_record_name(domain: str) -> str:
    return f"_hydra-verification.{normalize_domain(domain)}"


def dns_record_value(token: str) -> str:
    return f"hydra-verify={token}"


def well_known_file_path(token: str) -> str:
    return f"/.well-known/hydra-verification-{token}.txt"


async def verify_dns_txt(
    domain: str,
    token: str,
    *,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> tuple[bool, str]:
    """A real DNS TXT query against `_hydra-verification.<domain>` —
    never a check against anything the client supplied. Returns
    (success, detail) — `detail` is always populated, success or not, so
    a failure can tell the operator exactly what was queried and what
    came back. `resolver` is injectable (an `dns.asyncresolver.Resolver`
    instance) so tests can point it at a real local DNS server instead of
    the live internet — production code never passes it, defaulting to a
    fresh resolver using the host's normal DNS configuration.
    """
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    record_name = dns_record_name(domain)
    expected_value = dns_record_value(token)
    resolver = resolver or dns.asyncresolver.Resolver()

    try:
        answer = await resolver.resolve(record_name, "TXT", lifetime=10)
    except dns.resolver.NXDOMAIN:
        return False, f"No DNS record found at {record_name} (NXDOMAIN)"
    except dns.resolver.NoAnswer:
        return False, f"{record_name} exists but has no TXT records"
    except dns.resolver.NoNameservers as exc:
        return False, f"No nameservers could answer for {record_name}: {exc}"
    except dns.exception.Timeout:
        return False, f"DNS query for {record_name} timed out"
    except dns.exception.DNSException as exc:
        return False, f"DNS query for {record_name} failed: {exc}"

    found_values = []
    for rdata in answer:
        value = b"".join(rdata.strings).decode("utf-8", errors="replace")
        found_values.append(value)
        if value == expected_value:
            return True, f"Found matching TXT record at {record_name}"

    return (
        False,
        f"{record_name} has TXT record(s) but none match the expected value "
        f"(found: {found_values!r})",
    )


async def verify_well_known_file(
    domain: str,
    token: str,
    *,
    client: httpx.AsyncClient | None = None,
    base_url: str | None = None,
) -> tuple[bool, str]:
    """A real HTTPS GET against
    `https://<domain>/.well-known/hydra-verification-<token>.txt` —
    never assumed to exist. `base_url` overrides the scheme+host (tests
    point it at a local `http://127.0.0.1:<port>`); production code
    never passes it, always using `https://<domain>`. `client` is
    injectable (an `httpx.AsyncClient`) for the same test-vs-production
    reason as `resolver` above.
    """
    import httpx

    path = well_known_file_path(token)
    url = f"{base_url or f'https://{normalize_domain(domain)}'}{path}"

    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=10.0)
    try:
        response = await http_client.get(url)
    except httpx.RequestError as exc:
        return False, f"Could not reach {url}: {exc}"
    finally:
        if owns_client:
            await http_client.aclose()

    if response.status_code != 200:
        return False, f"{url} returned HTTP {response.status_code}, expected 200"

    body = response.text.strip()
    if body != token:
        return False, f"{url} exists but its content does not match the expected token"

    return True, f"Found matching file at {url}"


def classify_scan_gate(
    requested_domain: str,
    *,
    active_verifications: list[DomainVerificationRecord],
    all_verifications: list[DomainVerificationRecord],
) -> tuple[ScanGateStatus, DomainVerificationRecord | None]:
    """The actual `POST /scans` gate decision (Task 2), factored out as a
    pure function so it's testable without a database or HTTP layer.
    `active_verifications` are this account's currently-verified,
    unexpired rows (`ControlDB.get_verified_domains_for_account`);
    `all_verifications` is every row this account has ever had
    (`ControlDB.get_all_verifications_for_account`), used only to tell
    "never verified" apart from "verified once, now expired" when
    nothing currently covers the request.
    """
    for record in active_verifications:
        if domain_is_covered(requested_domain, record.domain):
            return "covered", record

    for record in sorted(all_verifications, key=lambda r: r.created_at, reverse=True):
        if record.status == "verified" and domain_is_covered(requested_domain, record.domain):
            return "expired", record

    return "never_verified", None
