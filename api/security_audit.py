"""Productization Phase 11b: the security audit log.

Routers record an event after a security-relevant change succeeds:

- **Keys and authentication:** a key is created, rotated or revoked; a
  sign-in fails.
- **Organizations and members:** an organization is created; a member is
  added, changes role or is removed.
- **Integrations:** a webhook or ticketing integration is created or
  removed; a delivery is redelivered.
- **Administration:** every admin endpoint call, and every operator grant
  or revoke made from the host CLI.

Each event names its actor, the account whose security it concerns, the
organization, the target, the request id (api/edge.py) and the client
address.

What is never recorded: API keys, secrets and integration credentials.
Failed sign-ins are recorded at most once per client address per minute
(throttled through the persisted rate-limit buckets), so a credential
stuffing burst leaves a trace without flooding the log.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from api.control_db import ControlDB, SecurityEvent
from api.edge import current_request_id

# The actions this log records (stable strings: API consumers filter on them).
ACCOUNT_CREATED = "account.created"
KEY_CREATED = "key.created"
KEY_ROTATED = "key.rotated"
KEY_REVOKED = "key.revoked"
AUTH_FAILED = "auth.failed"
ORGANIZATION_CREATED = "organization.created"
MEMBER_ADDED = "member.added"
MEMBER_ROLE_CHANGED = "member.role_changed"
MEMBER_REMOVED = "member.removed"
WEBHOOK_CREATED = "webhook.created"
WEBHOOK_DELETED = "webhook.deleted"
WEBHOOK_REDELIVERED = "webhook.redelivered"
INTEGRATION_CREATED = "integration.created"
INTEGRATION_REMOVED = "integration.removed"
ADMIN_PAYMENTS_LISTED = "admin.payments_listed"
ADMIN_PAYMENT_RECONCILED = "admin.payment_reconciled"
ADMIN_EVENTS_LISTED = "admin.security_events_listed"
OPERATOR_GRANTED = "operator.granted"
OPERATOR_REVOKED = "operator.revoked"

# One failed-sign-in event per client address per minute.
_AUTH_FAILURE_EVENTS_PER_SECOND = 1 / 60


def _client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


def record(
    db: ControlDB,
    request: Request | None,
    action: str,
    *,
    actor_type: str = "account",
    actor_account_id: str | None = None,
    subject_account_id: str | None = None,
    organization_id: str | None = None,
    target: tuple[str, str] | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Appends one event. `target` is (type, id)."""
    target_type, target_id = target or (None, None)
    request_id = current_request_id()
    db.record_security_event(
        SecurityEvent(
            event_id=secrets.token_hex(16),
            occurred_at=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor_type=actor_type,
            actor_account_id=actor_account_id,
            subject_account_id=subject_account_id,
            organization_id=organization_id,
            target_type=target_type,
            target_id=target_id,
            request_id=None if request_id == "-" else request_id,
            client_ip=_client_ip(request),
            details_json=json.dumps(details or {}, sort_keys=True),
        )
    )


def record_auth_failure(db: ControlDB, request: Request, reason: str) -> None:
    """A failed sign-in, at most once per client address per minute. The
    presented key is never recorded, only why it was refused."""
    client = _client_ip(request) or "unknown"
    if db.check_and_consume_rate_limit_token(
        f"audit:auth-failed:{client}",
        capacity=1,
        refill_rate_per_second=_AUTH_FAILURE_EVENTS_PER_SECOND,
    ):
        record(
            db,
            request,
            AUTH_FAILED,
            actor_type="anonymous",
            details={"reason": reason, "path": request.url.path},
        )
