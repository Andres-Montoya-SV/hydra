"""Post-module contradiction detectors (design Part B.2).

Pure functions: raw evidence in, `VerificationFinding | None` out. No I/O,
no LLM, no side effects — each one answers "does the interpretation match
the raw evidence" for exactly one catalog incident
(docs/VERIFICATION_AGENT_DESIGN.md Part A).

Deviation from the design doc's signatures, noted here and in the design
doc's own "implemented" tracking (Section 5): the doc sketched each
detector with only the one or two fields strictly needed to describe the
contradiction (e.g. `raw_dnsx_record: dict`). A `VerificationFinding` also
needs a `host` and (where one exists) a `raw_artifact` path to be useful or
persistable — those are added here as keyword-only parameters with sane
defaults, not a change to what each detector actually checks.
"""

from __future__ import annotations

import re

from core.verification.model import ContradictionSeverity, VerificationFinding

# ---------------------------------------------------------------------------
# Item 6 — dnsx NODATA (NOERROR, only SOA, no a/aaaa) counted as resolved.
# Fixed in modules/dnsx.py and core/parsers/registry.py (both no longer
# treat a record with no address as resolved) — this detector is the
# explicit, auditable confirmation that the fix actually held for a given
# record, not a silent assumption. See tests/test_dnsx.py for the original
# regression fixture (the real fishbowlapp.com records) this reuses.
# ---------------------------------------------------------------------------


def detect_dnsx_nodata_as_resolved(
    raw_dnsx_record: dict,
    *,
    was_counted_resolved: bool,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """`was_counted_resolved` is what the caller (modules/dnsx.py, or a
    replay of an older run's dnsx_records.jsonl) actually did with this
    host — the detector needs that alongside the raw record, since a NODATA
    record that was correctly never counted as resolved is not a
    contradiction, it's the fix working. Without this second input every
    passively-observed NODATA subdomain would raise a finding regardless of
    whether anything downstream acted on it.
    """
    if not was_counted_resolved:
        return None
    host = str(raw_dnsx_record.get("host") or "").strip().rstrip(".")
    has_address = bool(raw_dnsx_record.get("a")) or bool(raw_dnsx_record.get("aaaa"))
    if has_address:
        return None
    status_code = str(raw_dnsx_record.get("status_code") or "")
    has_soa = bool(raw_dnsx_record.get("soa"))
    if status_code != "NOERROR" or not has_soa:
        # Not the NODATA shape this detector exists for (could be NXDOMAIN,
        # a timeout, etc.) — a different, not-yet-cataloged situation.
        return None
    return VerificationFinding(
        claim=f"{host or '(unknown host)'}: resolved",
        evidence=(
            f"dnsx record has status_code={status_code!r} with only an soa "
            "record, no a/aaaa — NODATA, the zone exists but this name has "
            "no address record"
        ),
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_dnsx_nodata_as_resolved",
        host=host or None,
    )


# ---------------------------------------------------------------------------
# Item 2 — security_headers underscore/hyphen key mismatch.
# Fixed in modules/security_headers.py (normalize_header_map folds
# underscores to hyphens) — this detector independently re-derives the fold
# rather than calling that function, so a future regression in the fix
# itself would still be caught. See tests/test_security_headers.py for the
# original real creator.stripchat.com header dict this reuses.
# ---------------------------------------------------------------------------


def detect_security_headers_key_mismatch(
    raw_httpx_headers: dict[str, str],
    parsed_missing_list: list[str],
    *,
    host: str | None = None,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """httpx's JSON encoder renames every hyphenated header name to use
    underscores (`X-Frame-Options` -> `x_frame_options`) — folding `_` to
    `-` here, independently of `modules.security_headers.normalize_header_map`,
    is what catches a header claimed "missing" that is actually present
    under its underscored key.
    """
    folded = {
        str(k).lower().replace("_", "-"): str(v) for k, v in (raw_httpx_headers or {}).items()
    }
    actually_present = {name: folded[name] for name in parsed_missing_list if folded.get(name)}
    if not actually_present:
        return None
    claim = ", ".join(f"{name}: missing" for name in sorted(actually_present))
    evidence = "; ".join(
        f"{name}: {value!r} present in raw httpx headers"
        for name, value in sorted(actually_present.items())
    )
    return VerificationFinding(
        claim=claim,
        evidence=evidence,
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_security_headers_key_mismatch",
        host=host,
    )


# ---------------------------------------------------------------------------
# Item 1 — WHOIS registrar-vs-TLD block specificity.
# Fixed in modules/whois.py (_authoritative_block anchors on the LAST
# "Domain Name:" line) — this detector independently re-derives which block
# a claimed creation date actually came from. See
# tests/test_infrastructure_plugins.py::
# test_whois_parser_prefers_registrar_dates_over_iana_referral_dates for the
# original real virusbarrier.xyz (.xyz / IANA referral) fixture this reuses.
# ---------------------------------------------------------------------------

_DOMAIN_NAME_LINE = re.compile(r"^[ \t]*domain name:", re.IGNORECASE | re.MULTILINE)
_CREATED_LIKE_LINE = re.compile(
    r"^[ \t]*(?:creation date|created|registered on|registration time)[ \t]*:[ \t]*(.+?)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


def _created_like_values(block: str) -> set[str]:
    return {m.group(1).strip() for m in _CREATED_LIKE_LINE.finditer(block)}


def detect_whois_block_specificity(
    whois_raw_text: str,
    parsed_created_at: str | None,
    *,
    host: str | None = None,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """The authoritative block is everything from the LAST "Domain Name:"
    line onward (`modules/whois.py::_authoritative_block`'s own rule) —
    everything before it is suspect, whether or not that earlier text has
    a "Domain Name:" line of its own. The real virusbarrier.xyz case has
    exactly one "Domain Name:" line total: the IANA block above it uses a
    bare "domain:" field instead, so requiring two matches (an earlier
    draft of this detector did) would miss it entirely — one match is
    enough, since "before the last match" and "before the only match" are
    the same slice. If `parsed_created_at` matches a date found only in
    that earlier text (the TLD/registry's own delegation date, not the
    domain's registration date) and not in the authoritative block, that
    is exactly the original bug's shape.
    """
    if not parsed_created_at:
        return None
    matches = list(_DOMAIN_NAME_LINE.finditer(whois_raw_text))
    if not matches:
        return None  # no "Domain Name:" line at all — nothing to anchor on
    last_block = whois_raw_text[matches[-1].start() :]
    earlier_text = whois_raw_text[: matches[-1].start()]
    claimed = parsed_created_at.strip()
    if claimed in _created_like_values(last_block):
        return None  # consistent with the authoritative (last) block
    if claimed not in _created_like_values(earlier_text):
        return None  # doesn't match any block — not this detector's pattern
    return VerificationFinding(
        claim=f"created_at: {claimed}",
        evidence=(
            f"{claimed!r} appears in an earlier (TLD/registry-level) WHOIS "
            "block, not in the last (authoritative, registrar-level) "
            "'Domain Name:' block in the same raw response"
        ),
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_whois_block_specificity",
        host=host,
    )


# ---------------------------------------------------------------------------
# Item 3 — naabu "open" vs. nmap (port_verify) second-opinion disagreement.
# Not "fixed" the way items 1/2/6 were — port_verify already exists
# specifically to catch this, so this detector is the explicit,
# structured record of a disagreement port_verify's own report text
# already describes in prose. See
# tests/test_infrastructure_plugins.py::test_port_verify_parser_rejects_naabu_false_positive
# for the original real virusbarrier.xyz fixture (port 37) this reuses.
# ---------------------------------------------------------------------------

_DISAGREEING_STATES = frozenset({"filtered", "closed"})


def detect_naabu_nmap_port_disagreement(
    naabu_port_state: str,
    nmap_port_state: str,
    *,
    host: str | None = None,
    port: int | None = None,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """DOWNGRADES_CONFIDENCE, not INVALIDATES (design Part B.2): naabu
    could still be right — nmap is a second opinion, not a ground truth —
    but the finding can no longer stand at naabu's original, unverified
    confidence once a second tool disagrees.
    """
    naabu_state = (naabu_port_state or "").strip().lower()
    nmap_state = (nmap_port_state or "").strip().lower()
    if naabu_state != "open" or nmap_state not in _DISAGREEING_STATES:
        return None
    where = f"{host}:{port}" if host and port else (host or "")
    return VerificationFinding(
        claim=f"{where}: open (naabu)".strip(": "),
        evidence=f"nmap (second opinion, port_verify) reports {nmap_state} for the same port",
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.DOWNGRADES_CONFIDENCE,
        detector="detect_naabu_nmap_port_disagreement",
        host=host,
    )


# ---------------------------------------------------------------------------
# New recon modules (email/OSINT, TLS posture, WAF detection) — each
# detector below traces to a real contradiction risk found while actually
# running the real tool during development (modules/sslyze.py,
# modules/wafw00f.py, modules/theharvester.py's own docstrings have the
# full story), not a hypothetical.
# ---------------------------------------------------------------------------


def detect_sslyze_result_used_despite_not_completed(
    scan_status: str,
    *,
    was_result_used: bool,
    scan_command: str = "",
    host: str | None = None,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """sslyze's own JSON shape (confirmed live, `modules/sslyze.py`'s
    docstring): `scan_result.<command>` is always
    `{"status", "error_reason", "error_trace", "result"}`, and `result`
    is only meaningful when `status == "COMPLETED"` — a real, observed
    case (`http_headers` when that scan command wasn't explicitly
    requested) has `status: "NOT_SCHEDULED"` and `result: null`. A caller
    that reads `result` without checking `status` first could
    misinterpret a `null`/absent field as "checked, nothing found"
    (e.g. "no HSTS header" from a scan that never actually ran) rather
    than "not checked at all" — this detector catches exactly that
    conflation.
    """
    if scan_status == "COMPLETED" or not was_result_used:
        return None
    where = f"{host} " if host else ""
    return VerificationFinding(
        claim=f"{where}{scan_command}: checked, result used".strip(),
        evidence=f"sslyze scan_status={scan_status!r} — this scan command did not complete, "
        "so its result field cannot be trusted as a real finding either way",
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_sslyze_result_used_despite_not_completed",
        host=host,
    )


def detect_wafw00f_generic_negative_overwrites_earlier_detection(
    detections_for_url: list[bool],
    *,
    host: str | None = None,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """`-a`/findall (confirmed live, `modules/wafw00f.py`'s docstring)
    makes wafw00f emit one entry per matched WAF signature PLUS a
    trailing generic-detection entry that is `detected: false` whenever
    the generic method found nothing NEW — a real, observed shape: a
    genuine Cloudflare detection immediately followed by a
    `detected: false` entry for the exact same URL. `detections_for_url`
    is every `detected` value for one URL, in the tool's own output
    order; a parser that only reads the LAST entry would wrongly
    conclude "no WAF" despite an earlier TRUE in the same list.
    """
    if not detections_for_url:
        return None
    if detections_for_url[-1] or not any(detections_for_url):
        return None
    return VerificationFinding(
        claim=f"{host or '(unknown host)'}: no WAF detected (last entry)",
        evidence=(
            f"wafw00f's own output for this URL has {sum(detections_for_url)} earlier "
            "detected=true entr(y/ies) before a trailing detected=false generic-detection "
            "entry — reading only the last entry would wrongly report no WAF"
        ),
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_wafw00f_generic_negative_overwrites_earlier_detection",
        host=host,
    )


def detect_theharvester_off_domain_email_counted(
    email: str,
    target_domain: str,
    *,
    was_counted: bool,
    raw_artifact: str | None = None,
) -> VerificationFinding | None:
    """`modules/theharvester.py`'s own hard boundary: only an email whose
    domain part is the target domain (or a subdomain of it) may ever be
    treated as organization-associated evidence. This detector
    independently re-derives that same domain-match check rather than
    calling the plugin's own filter function, so a future regression in
    the filter itself (the exact class of bug
    `detect_security_headers_key_mismatch`'s own docstring describes for
    a different fix) would still be caught here.
    """
    if not was_counted:
        return None
    if "@" not in email:
        return None
    _, _, domain_part = email.rpartition("@")
    domain_part = domain_part.strip().lower().rstrip(".")
    target = target_domain.strip().lower().rstrip(".")
    if domain_part == target or domain_part.endswith(f".{target}"):
        return None
    return VerificationFinding(
        claim=f"{email}: organization-associated work email for {target_domain}",
        evidence=f"the email's domain ({domain_part!r}) does not match the target domain "
        f"({target!r}) or any of its subdomains — this is not organization-associated "
        "evidence, regardless of what page it was found on",
        raw_artifact=raw_artifact,
        severity=ContradictionSeverity.INVALIDATES,
        detector="detect_theharvester_off_domain_email_counted",
        host=target_domain,
    )
