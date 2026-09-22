"""API-level configuration — deliberately separate from `config.settings.
Settings` (the CLI/pipeline's own config object). This module only
answers "where does this account's data live" and "what are this
service's own operational knobs" (rate limit, data root); the actual
per-scan pipeline configuration is still a real `config.settings.Settings`
instance, one constructed per account (see `api/tenancy.py`) — Round 1
never touches the pipeline's own config surface.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class APISettings:
    """Round 1 has no per-account overrides for any of this — everyone
    gets the same rate limit and the same data-root layout. Tier-specific
    values arrive in Round 2 (docs/PAID_API_DESIGN.md Part B)."""

    data_dir: Path = field(default_factory=lambda: _PROJECT_ROOT / "api_data")
    rate_limit_per_minute: int = 60
    key_rotation_grace_hours: int = 24
    # Domain verification (Part A) always makes a REAL DNS/HTTP check
    # against the real internet by default — these two are None unless an
    # operator explicitly opts in via the env vars below, for local
    # development/demo only (e.g. pointing DNS checks at an in-process
    # test server instead of the live internet). Never set in production;
    # there is no way to enable this by accident — both require an
    # explicit environment variable, never a default.
    dev_dns_nameserver: str | None = None
    dev_dns_port: int | None = None
    dev_well_known_base_url: str | None = None

    # Wompi billing (Part D, Round 3). `wompi_client_id`/`wompi_client_secret`
    # are the operator's real OAuth2 client-credentials pair
    # (docs.wompi.sv/autenticacion/autenticacion.md) — an operator secret,
    # never exposed to any Hydra API client. The webhook-signing secret
    # (docs.wompi.sv/webhook/validar-webhook.md's "API Secret") uses the
    # SAME terminology as the OAuth "API Secret" in Wompi's own docs, so
    # `wompi_client_secret` doubles as the HMAC key — see
    # docs/PAID_API_DESIGN.md's "Round 3 implemented" section for why
    # this is a documented inference, not something confirmed against an
    # actual observed webhook (no live sandbox transaction was available
    # to verify against).
    wompi_client_id: str | None = None
    wompi_client_secret: str | None = None
    # id.wompi.sv (OAuth token endpoint) / api.wompi.sv (everything else)
    # are the real, confirmed hosts — overridable only for tests, same
    # explicit-env-var-required discipline as the DNS/well-known overrides
    # above. Never set in production.
    dev_wompi_id_base_url: str | None = None
    dev_wompi_api_base_url: str | None = None
    # One pre-created Wompi `EnlacePagoRecurrente` URL per paid tier
    # (Part D.1: the merchant creates ONE shared link per pricing tier,
    # not one per customer) — set once by the operator after creating
    # each link in the Wompi dashboard/API. `None` means "not configured
    # yet," which `POST /account/subscription` reports as 503 rather than
    # returning a broken/empty link.
    wompi_link_url_medium: str | None = None
    wompi_link_url_pro: str | None = None
    wompi_link_url_ultra: str | None = None
    # A temporary, MVP-only admin credential for the manual-reconciliation
    # endpoint (`POST /admin/wompi/reconcile`) — no real operator/admin
    # auth system exists yet (same honestly-stated gap as
    # `api/routers/accounts.py`'s unauthenticated `POST /accounts` in
    # Round 1). `None` means the endpoint refuses every request (fail
    # closed), never "admin auth is optional."
    admin_token: str | None = None

    # Hallazgo 1 (account-creation abuse) fix. `account_creation_rate_
    # limit_per_ip_per_day`: a rolling 24h window, not a calendar day
    # (a fixed reset lets a script burst again right at midnight) —
    # "3 cuentas por IP por día" from the finding, implemented as
    # "3 per IP in the trailing 24 hours." `email_verification_token_
    # ttl_hours`: how long a verification token/email stays valid before
    # a resend is required.
    account_creation_rate_limit_per_ip_per_day: int = 3
    email_verification_token_ttl_hours: int = 24

    # Real email delivery (Postmark, postmarkapp.com) for the
    # verification email above — `api/email_sender.py::PostmarkEmailSender`.
    # Both `postmark_server_token` and `email_from_address` must be set
    # together or not at all (`validate_email_provider_config` below,
    # called from `api/main.py::create_app`) — `None`/`None` means
    # `ConsoleEmailSender` (log-only, the zero-config default, unchanged
    # from before Postmark support existed).
    postmark_server_token: str | None = None
    email_from_address: str | None = None
    email_from_name: str = "Hydra"
    # api.postmarkapp.com is the real, confirmed host
    # (postmarkapp.com/developer/api/email-api) — overridable only for
    # tests, same explicit-field-required discipline as the Wompi/DNS/
    # well-known dev overrides above. Never set in production.
    dev_postmark_send_url: str | None = None

    @property
    def control_db_path(self) -> Path:
        return self.data_dir / "control.db"

    def account_root(self, account_id: str) -> Path:
        """Every account's pipeline data lives under its own directory —
        `config.settings.Settings(project_root=...)` for that account
        then resolves `output/recon.db` underneath it, giving one
        physically separate SQLite file per account (Part F.2) with zero
        changes to `core/store.py`/`core/runner.py`."""
        return self.data_dir / "accounts" / account_id


def load_api_settings() -> APISettings:
    """A real gap this round's own live demonstration surfaced, fixed
    here: this function used to read only `os.environ` directly, never
    the repo-root `.env` file — unlike `config.settings.Settings.from_env`
    (the CLI/pipeline's own config loader), which has always called
    `load_dotenv()` first. An operator who puts `WOMPI_CLIENT_ID`/
    `WOMPI_CLIENT_SECRET`/etc. in `.env` (the documented, expected place)
    rather than exporting them as real shell environment variables would
    have had every Wompi call silently fail with "not configured," with
    no obvious link back to the cause. `override=False` means any
    variable already actually exported in the process environment still
    wins — this only fills in what's otherwise unset, never overrides a
    real deployment's explicit environment configuration."""
    env_path = _PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)

    settings = APISettings()
    data_dir = os.getenv("HYDRA_API_DATA_DIR")
    if data_dir:
        settings.data_dir = Path(data_dir)
    rate_limit = os.getenv("HYDRA_API_RATE_LIMIT_PER_MINUTE")
    if rate_limit:
        settings.rate_limit_per_minute = int(rate_limit)
    settings.dev_dns_nameserver = os.getenv("HYDRA_API_DEV_DNS_NAMESERVER") or None
    dev_dns_port = os.getenv("HYDRA_API_DEV_DNS_PORT")
    if dev_dns_port:
        settings.dev_dns_port = int(dev_dns_port)
    settings.dev_well_known_base_url = os.getenv("HYDRA_API_DEV_WELL_KNOWN_BASE_URL") or None
    settings.wompi_client_id = os.getenv("WOMPI_CLIENT_ID") or None
    settings.wompi_client_secret = os.getenv("WOMPI_CLIENT_SECRET") or None
    settings.dev_wompi_id_base_url = os.getenv("HYDRA_API_DEV_WOMPI_ID_BASE_URL") or None
    settings.dev_wompi_api_base_url = os.getenv("HYDRA_API_DEV_WOMPI_API_BASE_URL") or None
    settings.wompi_link_url_medium = os.getenv("HYDRA_WOMPI_LINK_URL_MEDIUM") or None
    settings.wompi_link_url_pro = os.getenv("HYDRA_WOMPI_LINK_URL_PRO") or None
    settings.wompi_link_url_ultra = os.getenv("HYDRA_WOMPI_LINK_URL_ULTRA") or None
    settings.admin_token = os.getenv("HYDRA_API_ADMIN_TOKEN") or None
    rate_limit_per_ip = os.getenv("HYDRA_API_ACCOUNT_CREATION_RATE_LIMIT_PER_IP_PER_DAY")
    if rate_limit_per_ip:
        settings.account_creation_rate_limit_per_ip_per_day = int(rate_limit_per_ip)
    token_ttl = os.getenv("HYDRA_API_EMAIL_VERIFICATION_TOKEN_TTL_HOURS")
    if token_ttl:
        settings.email_verification_token_ttl_hours = int(token_ttl)
    settings.postmark_server_token = os.getenv("POSTMARK_SERVER_TOKEN") or None
    settings.email_from_address = os.getenv("HYDRA_API_EMAIL_FROM") or None
    settings.email_from_name = os.getenv("HYDRA_API_EMAIL_FROM_NAME") or "Hydra"
    settings.dev_postmark_send_url = os.getenv("HYDRA_API_DEV_POSTMARK_SEND_URL") or None
    return settings


class EmailProviderMisconfiguredError(RuntimeError):
    """Raised by `validate_email_provider_config` — the app refuses to
    boot rather than silently falling back to `ConsoleEmailSender` (which
    would mean real users' verification emails silently go nowhere but
    the server's own logs) or silently failing every send later (which
    would surface as a confusing runtime error on the first
    `POST /accounts` instead of an immediate, clear one at startup)."""


def validate_email_provider_config(settings: APISettings) -> None:
    """`postmark_server_token`/`email_from_address` must be set TOGETHER
    or NOT AT ALL — a startup-time check beats a runtime surprise.
    Called from `api/main.py::create_app` for every `APISettings`
    regardless of whether it came from `load_api_settings()` (a real
    deployment) or was constructed directly (tests), so this can never
    be bypassed by whichever path constructed the settings object."""
    token_set = bool(settings.postmark_server_token)
    from_set = bool(settings.email_from_address)
    if token_set == from_set:
        return
    missing = "HYDRA_API_EMAIL_FROM" if token_set else "POSTMARK_SERVER_TOKEN"
    present = "POSTMARK_SERVER_TOKEN" if token_set else "HYDRA_API_EMAIL_FROM"
    raise EmailProviderMisconfiguredError(
        f"{present} is set but {missing} is not — Postmark needs both to send real "
        f"email. Set {missing} too, or unset {present} to keep using the console/"
        "log-only email sender."
    )
