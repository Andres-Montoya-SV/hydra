"""Wompi integration (docs/PAID_API_DESIGN.md Part D) — everything
confirmed directly against `docs.wompi.sv` before being written here (not
assumed from memory or from the Colombia-specific product):

- OAuth2 client-credentials token exchange: `POST
  https://id.wompi.sv/connect/token`, form-encoded body
  (`grant_type=client_credentials&audience=wompi_api&client_id=...&
  client_secret=...`), response `{"access_token", "expires_in",
  "token_type": "Bearer", "scope"}` — confirmed via
  `docs.wompi.sv/autenticacion/autenticacion.md`.
- The REST API host is `https://api.wompi.sv` (confirmed via
  `docs.wompi.sv/metodos-api/enlace-de-pago.md`'s own
  `POST https://api.wompi.sv/EnlacePago` example) — `id.wompi.sv` is
  ONLY for token exchange, never for anything else.
- Webhook signature: header `wompi_hash`, HMAC-SHA256 of the raw,
  byte-for-byte request body, keyed with the merchant's "API Secret" —
  confirmed via `docs.wompi.sv/webhook/validar-webhook.md`.

**One inference this module makes, stated honestly (see
docs/PAID_API_DESIGN.md's "Round 3 implemented" section for the full
writeup)**: `docs.wompi.sv/autenticacion/autenticacion.md` calls the
OAuth2 `client_secret` the merchant's "API Secret," and
`validar-webhook.md` independently says the webhook HMAC key is also
called "API Secret" — same term, in two otherwise-unrelated pages. This
module therefore uses `WOMPI_CLIENT_SECRET` (the OAuth secret) as the
webhook HMAC key too, on the strength of that terminology match. No
sandbox account was available to observe a real webhook and its
`wompi_hash` computed against a *known* secret to confirm this
end-to-end — flagged here as the one part of this integration that is
"documentation-terminology-confirmed," not "observed-in-production-
confirmed," exactly as the task asked to state honestly.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

_REAL_ID_BASE_URL = "https://id.wompi.sv"
_REAL_API_BASE_URL = "https://api.wompi.sv"
# Refresh this many seconds before the token's own reported expiry — never
# cut it exactly at the edge (clock skew, request latency).
_TOKEN_REFRESH_SKEW_SECONDS = 60


class WompiAuthError(Exception):
    """The OAuth2 token exchange itself failed (bad credentials, Wompi
    unreachable) — distinct from a downstream API call failing with an
    otherwise-valid token."""


class WompiAPIError(Exception):
    """A downstream Wompi API call (link creation, transaction lookup)
    returned an error response."""


@dataclass
class _CachedToken:
    access_token: str
    expires_at: float  # time.monotonic() timestamp


class WompiClient:
    """One instance per process (`app.state.wompi_client`), same
    long-lived-singleton shape as `ControlDB`/`TokenBucketLimiter` —
    the token cache below is only useful if it survives across
    requests."""

    def __init__(
        self,
        *,
        client_id: str | None,
        client_secret: str | None,
        id_base_url: str | None = None,
        api_base_url: str | None = None,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._id_base_url = id_base_url or _REAL_ID_BASE_URL
        self._api_base_url = api_base_url or _REAL_API_BASE_URL
        self._cached_token: _CachedToken | None = None

    @property
    def is_configured(self) -> bool:
        return bool(self._client_id and self._client_secret)

    async def _get_access_token(self, *, client: httpx.AsyncClient) -> str:
        """Caches and reuses the token across calls, refreshing only once
        it's within `_TOKEN_REFRESH_SKEW_SECONDS` of its own reported
        `expires_in` — Wompi's own docs explicitly say not to request a
        fresh token on every call."""
        if not self.is_configured:
            raise WompiAuthError("WOMPI_CLIENT_ID/WOMPI_CLIENT_SECRET are not configured.")

        now = time.monotonic()
        if self._cached_token is not None and now < self._cached_token.expires_at:
            return self._cached_token.access_token

        response = await client.post(
            f"{self._id_base_url}/connect/token",
            data={
                "grant_type": "client_credentials",
                "audience": "wompi_api",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != 200:
            raise WompiAuthError(
                f"Wompi OAuth token request failed: HTTP {response.status_code} {response.text}"
            )
        body = response.json()
        access_token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not access_token or not isinstance(expires_in, int | float):
            raise WompiAuthError(f"Unexpected Wompi OAuth response shape: {body!r}")

        self._cached_token = _CachedToken(
            access_token=access_token,
            expires_at=now + expires_in - _TOKEN_REFRESH_SKEW_SECONDS,
        )
        return access_token

    async def get_access_token(self) -> str:
        """Public one-shot entry point (used by the live OAuth
        confirmation demo and by tests) — opens and closes its own
        client. `create_recurring_link`/`get_transaction` below reuse a
        caller-supplied client instead, so a single request handler
        doesn't open a new TCP connection per Wompi call."""
        import httpx as _httpx

        async with _httpx.AsyncClient(timeout=15.0) as client:
            return await self._get_access_token(client=client)

    async def create_recurring_link(
        self,
        *,
        nombre: str,
        monto: float,
        dia_de_pago: int,
        id_aplicativo: str,
        descripcion_producto: str,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, object]:
        """One-time SETUP utility, not a per-subscription runtime call —
        Part D.1: the merchant creates ONE shared enrollment link per
        pricing tier, not one per customer. An operator runs this once
        per tier when setting up billing, then pastes the resulting
        `urlEnlace` into `HYDRA_WOMPI_LINK_URL_<TIER>` — `POST
        /account/subscription` (api/routers/subscription.py) only ever
        reads that configured, already-created URL, never calls this
        method on the request path."""
        import httpx as _httpx

        owns_client = client is None
        client = client or _httpx.AsyncClient(timeout=15.0)
        try:
            token = await self._get_access_token(client=client)
            response = await client.post(
                f"{self._api_base_url}/EnlacePagoRecurrente",
                json={
                    "diaDePago": dia_de_pago,
                    "nombre": nombre,
                    "idAplicativo": id_aplicativo,
                    "monto": monto,
                    "descripcionProducto": descripcion_producto,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code not in (200, 201):
                raise WompiAPIError(
                    f"Wompi EnlacePagoRecurrente creation failed: HTTP {response.status_code} "
                    f"{response.text}"
                )
            return response.json()
        finally:
            if owns_client:
                await client.aclose()

    async def get_transaction(
        self, transaction_id: str, *, client: httpx.AsyncClient | None = None
    ) -> dict[str, object]:
        """The belt-and-suspenders second check Part D.2 recommends: even
        after a webhook's `wompi_hash` verifies, independently confirm
        the transaction exists and is approved via
        `GET /TransaccionCompra/{id}` before acting on it — defends
        against a forged webhook that somehow produced a valid-looking
        hash for a transaction that was never actually approved (or
        never existed)."""
        import httpx as _httpx

        owns_client = client is None
        client = client or _httpx.AsyncClient(timeout=15.0)
        try:
            token = await self._get_access_token(client=client)
            response = await client.get(
                f"{self._api_base_url}/TransaccionCompra/{transaction_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code != 200:
                raise WompiAPIError(
                    f"Wompi TransaccionCompra lookup failed: HTTP {response.status_code} "
                    f"{response.text}"
                )
            return response.json()
        finally:
            if owns_client:
                await client.aclose()


def verify_webhook_signature(raw_body: bytes, signature_header: str | None, secret: str) -> bool:
    """HMAC-SHA256 of the exact raw body bytes, keyed with the merchant's
    Wompi "API Secret" (`docs.wompi.sv/webhook/validar-webhook.md`) —
    the caller MUST pass the literal bytes FastAPI received (`await
    request.body()`), never a re-serialized/re-parsed-then-dumped version
    of the JSON, since re-serialization is not guaranteed byte-identical
    (key order, whitespace) to what Wompi actually hashed.
    `hmac.compare_digest` — never `==` — for the comparison, so this
    can't be timed to leak the correct hash one byte at a time."""
    if not signature_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


TIER_PRODUCT_NAMES: dict[str, str] = {
    "medium": "Hydra Medium",
    "pro": "Hydra Pro",
    "ultra": "Hydra Ultra",
}


def tier_for_product_name(product_name: str | None) -> str | None:
    if product_name is None:
        return None
    normalized = product_name.strip().lower()
    for tier, name in TIER_PRODUCT_NAMES.items():
        if name.lower() == normalized:
            return tier
    return None
