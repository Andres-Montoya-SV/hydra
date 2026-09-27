"""Fase 14 (EASM roadmap): canonical technology name normalization and
the shared detail-string parsing every technology-observation consumer
uses. Pure module — no database access.

**Normalization is a small, curated lookup table, never a fuzzy/
similarity match** — the phase's own "sin fusionar tecnologías distintas
por parecido de nombre" requirement. `httpx` and `whatweb` can report the
exact same real technology under different casing/spelling today
(confirmed: `core/parsers/registry.py`'s `WhatWebParser` dedups its own
findings with `.casefold()` but still stores the tool's raw string, e.g.
"Nginx", while httpx's own `parse_tech_name_version` output is whatever
case the `-tech-detect` string used, e.g. "nginx") — without this table,
those become two different evidence facts about the same real thing.
Anything not in the table is returned unchanged (just stripped), never
guessed at or fuzzy-matched.
"""

from __future__ import annotations

_CANONICAL_NAMES: dict[str, str] = {
    "nginx": "nginx",
    "apache": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "apache/2": "Apache HTTP Server",
    "react": "React",
    "reactjs": "React",
    "react.js": "React",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "wordpress": "WordPress",
    "cloudflare": "Cloudflare",
    "iis": "IIS",
    "microsoft-iis": "IIS",
    "microsoft iis": "IIS",
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET",
    "fastapi": "FastAPI",
    "vue": "Vue.js",
    "vue.js": "Vue.js",
    "vuejs": "Vue.js",
    "angular": "Angular",
    "angularjs": "Angular",
    "jquery": "jQuery",
    "php": "PHP",
    "django": "Django",
    "flask": "Flask",
    "express": "Express",
    "expressjs": "Express",
    "node.js": "Node.js",
    "nodejs": "Node.js",
    "openresty": "OpenResty",
    "litespeed": "LiteSpeed",
    "varnish": "Varnish",
    "gunicorn": "Gunicorn",
    "tomcat": "Apache Tomcat",
    "apache tomcat": "Apache Tomcat",
}


def normalize_technology_name(raw: str) -> str:
    """Case-insensitive lookup against a curated alias table; anything
    unrecognized is returned as-is (stripped), never altered further."""
    stripped = raw.strip()
    if not stripped:
        return stripped
    canonical = _CANONICAL_NAMES.get(stripped.casefold())
    return canonical if canonical is not None else stripped


def technology_detail(*, name: str, version: str | None) -> str:
    """The single canonical serialization
    `api/observation_identity.py::observations_for_host` writes into
    `EvidenceContent.detail` for a `technology_detected` observation, and
    `parse_technology_detail` below reads back — one format, one place."""
    return f"{name}@{version}" if version else name


def parse_technology_detail(detail: str) -> tuple[str, str | None]:
    """Inverse of `technology_detail`. Technology names never legitimately
    contain "@" (none of this codebase's known providers emit one), so a
    plain partition on the first "@" is safe and exact, never a heuristic
    guess."""
    if "@" in detail:
        name, _, version = detail.partition("@")
        return name, version or None
    return detail, None
