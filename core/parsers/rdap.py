"""Fase 12 (EASM roadmap): pure parsing of an RDAP domain response
(RFC 9083 JSON) into the small set of fields this phase actually uses —
registrar name, registration/expiration dates. Deliberately minimal: RDAP
responses carry much more (full entity/vcard trees, nameservers, DNSSEC
status, notices) than this phase needs, and none of it is EVER used to
attribute ownership — "los campos de organización nunca atribuyen
automáticamente" is enforced by this module simply not extracting
anything beyond the registrar's own name string.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RdapDomainInfo:
    registrar: str
    registration_created_at: str
    registration_expires_at: str


def _entity_fn(entity: dict) -> str:
    """Pull the "fn" (formatted name) property out of an RDAP jCard
    (`vcardArray`) — the standard shape RDAP registrar entities use.
    Never falls back to raw vcard email/address fields; a registrar we
    can't name cleanly is simply not reported, not guessed at."""
    vcard_array = entity.get("vcardArray")
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return ""
    properties = vcard_array[1]
    if not isinstance(properties, list):
        return ""
    for prop in properties:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            value = prop[3]
            if isinstance(value, str):
                return value.strip()
    return ""


def _registrar_name(body: dict) -> str:
    entities = body.get("entities")
    if not isinstance(entities, list):
        return ""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and "registrar" in roles:
            name = _entity_fn(entity)
            if name:
                return name
            handle = entity.get("handle")
            if isinstance(handle, str) and handle.strip():
                return handle.strip()
    return ""


def _event_date(body: dict, action: str) -> str:
    events = body.get("events")
    if not isinstance(events, list):
        return ""
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") == action:
            date = event.get("eventDate")
            if isinstance(date, str):
                return date.strip()
    return ""


def parse_rdap_domain_response(body: dict) -> RdapDomainInfo:
    """Never raises — an RDAP response missing every field this phase
    cares about simply produces an all-empty `RdapDomainInfo`, which the
    caller (`api/rdap_lookup.py`) treats as "nothing worth recording,"
    never as an error."""
    return RdapDomainInfo(
        registrar=_registrar_name(body),
        registration_created_at=_event_date(body, "registration"),
        registration_expires_at=_event_date(body, "expiration"),
    )
