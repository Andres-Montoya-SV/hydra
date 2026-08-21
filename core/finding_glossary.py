"""Plain-language glossary for Finding template_ids (no LLM)."""

from __future__ import annotations

FINDING_GLOSSARY: dict[str, dict[str, str]] = {
    "tarpit-detected": {
        "what": "The host answered 'open' on unused canary ports that have no real service.",
        "why": (
            "Port-scan results on this host are unreliable (tarpit/portspoof). "
            "Do not treat listed ports as confirmed attack surface."
        ),
    },
    "wildcard-dns-detected": {
        "what": "Improbable random subdomains under this root resolve in DNS.",
        "why": (
            "Passive subdomain lists may include wildcard false positives until "
            "confirmed independently (CT, live HTTP)."
        ),
    },
    "soft-404-detected": {
        "what": "A made-up path returned HTTP 200 with a body like the site root.",
        "why": "You cannot infer that a URL exists from status codes alone on this host.",
    },
    "cloaking-detected": {
        "what": "A real browser landed on a different final host than httpx recorded.",
        "why": "The site may show scanners a different page than users (cloaking).",
    },
    "param-reflected": {
        "what": "A query parameter's canary value appeared literally in the response body.",
        "why": "Input reflection can enable XSS or cache poisoning; confirm with authorization.",
    },
    "param-influences-response": {
        "what": "Changing this parameter changed status, size, or body vs the baseline.",
        "why": "The parameter is live application input — a recon lead, not an exploit.",
    },
    "vuln-match": {
        "what": "A detected technology/version is listed in a public vulnerability database.",
        "why": "Patch or isolate the component; Hydra only reports the identifier the source published.",
    },
    "missing-security-header": {
        "what": "A recommended HTTP security header was absent on a live response.",
        "why": "Missing headers weaken browser-side defenses (clickjacking, MIME sniffing, HTTPS downgrade).",
    },
    "cloud-bucket-exists-private": {
        "what": "A brand-derived cloud bucket name exists but listing is denied.",
        "why": "Confirms an asset in the cloud account; not public data by itself.",
    },
    "cloud-bucket-public-listable": {
        "what": "A brand-derived cloud bucket returned a public object listing.",
        "why": "Public listings often leak sensitive files; treat as high priority.",
    },
}


def explain_template(template_id: str) -> dict[str, str]:
    if template_id in FINDING_GLOSSARY:
        return FINDING_GLOSSARY[template_id]
    if template_id.startswith("vuln-match"):
        return FINDING_GLOSSARY["vuln-match"]
    if template_id.startswith("missing-security-header"):
        return FINDING_GLOSSARY["missing-security-header"]
    return {
        "what": "A reconnaissance finding produced by a Hydra head.",
        "why": "Review the technical evidence before acting.",
    }
