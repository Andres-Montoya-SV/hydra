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

    # Durable, multi-worker-safe scan execution
    # (docs/PAID_API_DESIGN.md's "Durable, multi-worker-safe scan
    # execution" section) — see `api/scan_worker.py`'s own module
    # docstring for the full reasoning behind each number below.
    #
    # How many scans this ONE process executes concurrently — naabu/
    # httpx/nuclei subprocesses are real host resources, not free just
    # because they're async. A scan beyond this ceiling stays `queued`
    # until a slot frees up; it is never dropped.
    max_concurrent_scans: int = 3
    # How often the worker loop checks for claimable queued work and
    # sweeps for stale running scans, in the same cycle. Against a scan
    # that takes ~25 minutes, even a full second of claim latency is
    # noise — kept well under that (0.5s) mainly so the existing test
    # suite's stubbed-pipeline scans (near-instant once claimed) don't
    # pay multiple seconds of avoidable poll latency each.
    scan_poll_interval_seconds: float = 0.5
    # How often an actively-executing scan proves it's still alive.
    scan_heartbeat_interval_seconds: float = 30.0
    # A `running` scan whose heartbeat is older than this is treated as
    # orphaned (its worker died) — comfortably more than one heartbeat
    # interval so a single slow/delayed heartbeat write under load never
    # false-triggers a requeue of a scan that's actually fine.
    scan_stale_after_seconds: int = 120
    # A scan that gets interrupted (worker died) this many times in a
    # row stops being automatically requeued and is given up on as
    # `failed` instead — an unbounded requeue loop on a scan that
    # reliably crashes the process on every attempt would itself become
    # an outage (the same slot never frees up for other work).
    scan_max_retries: int = 3

    # Automatic billing enforcement and data retention purge
    # (docs/PAID_API_DESIGN.md's "Automatic billing enforcement and
    # data retention purge" section) — see `api/reconciliation_worker.py`'s
    # own module docstring for the full reasoning behind each value
    # below.
    #
    # How often the grace-period-suspension and retention-purge jobs
    # run, in the SAME cycle. Daily is the right granularity for both:
    # grace periods are measured in days (GRACE_PERIOD_DAYS = 3,
    # api/subscriptions.py) and retention windows in months
    # (api/tiers.py) — polling either one every few seconds like the
    # scan queue does would just be wasted work for no operational
    # benefit.
    reconciliation_interval_seconds: float = 86400.0
    # How many scans (per account, per cycle) the retention-purge job
    # deletes in one pass — bounded so a large backlog never becomes one
    # long-held transaction that could stall other traffic; the rest of
    # the backlog simply finishes over the next scheduled cycle(s).
    retention_purge_batch_size: int = 200
    # OFF by default (real deletion happens): an operator has to opt
    # into a rehearsal explicitly, never opt into the actually-
    # destructive behavior by omission. When True, the purge job only
    # logs what it WOULD delete.
    retention_purge_dry_run: bool = False

    # Automated backups (docs/PAID_API_DESIGN.md's "Automated backups
    # and a real deployment target" section) — see
    # `api/backup_worker.py`'s own module docstring for the full
    # reasoning. Daily, like the reconciliation loop — a database this
    # size doesn't need finer-grained snapshots, and every account's
    # `recon.db` gets backed up in the same cycle as `control.db`.
    backup_interval_seconds: float = 86400.0
    # How many of the most recent local snapshot directories to keep —
    # one week of daily backups by default, a real, bounded retention
    # policy rather than "keep everything forever" (which would grow
    # without limit) or "keep nothing" (which defeats the purpose the
    # first time a restore is actually needed a few days after a bad
    # deploy, not the same day). `rotate_backups` always keeps AT LEAST
    # the single most recent snapshot even if this is misconfigured to
    # 0 or a negative number — a backup system that could delete its
    # only copy through a config typo is worse than having no retention
    # limit at all.
    backup_retention_count: int = 7
    # Remote (S3-compatible) upload is entirely OPT-IN — `None` means
    # backups stay local-only, logged loudly (never a silent gap) but
    # never a hard failure, since a fresh deployment that hasn't
    # provisioned a bucket yet should still get local backups working.
    # Deliberately not locked to AWS: `backup_s3_endpoint_url` lets this
    # point at any S3-compatible provider (DigitalOcean Spaces, Backblaze
    # B2, Cloudflare R2) — credentials themselves are never a field here,
    # read via boto3's own standard `AWS_ACCESS_KEY_ID`/
    # `AWS_SECRET_ACCESS_KEY` environment variables instead, the same
    # convention every S3-compatible provider's own docs recommend.
    backup_s3_bucket: str | None = None
    backup_s3_prefix: str = "hydra-backups"
    backup_s3_endpoint_url: str | None = None
    backup_s3_region: str | None = None

    # Basic observability (docs/PAID_API_DESIGN.md's "Basic
    # observability" section). `sentry_dsn`: unset means error tracking
    # is simply off — same "zero-config keeps working" discipline as
    # Postmark/Wompi (api/settings.py's own existing convention), never
    # a startup failure. `log_format`: "text" (default, unchanged from
    # every prior round) or "json" — see api/observability.py for the
    # formatter itself.
    sentry_dsn: str | None = None
    log_format: str = "text"

    @property
    def control_db_path(self) -> Path:
        return self.data_dir / "control.db"

    @property
    def backup_root(self) -> Path:
        return self.data_dir / "backups"

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
    max_concurrent = os.getenv("HYDRA_API_MAX_CONCURRENT_SCANS")
    if max_concurrent:
        settings.max_concurrent_scans = int(max_concurrent)
    poll_interval = os.getenv("HYDRA_API_SCAN_POLL_INTERVAL_SECONDS")
    if poll_interval:
        settings.scan_poll_interval_seconds = float(poll_interval)
    heartbeat_interval = os.getenv("HYDRA_API_SCAN_HEARTBEAT_INTERVAL_SECONDS")
    if heartbeat_interval:
        settings.scan_heartbeat_interval_seconds = float(heartbeat_interval)
    stale_after = os.getenv("HYDRA_API_SCAN_STALE_AFTER_SECONDS")
    if stale_after:
        settings.scan_stale_after_seconds = int(stale_after)
    max_retries = os.getenv("HYDRA_API_SCAN_MAX_RETRIES")
    if max_retries:
        settings.scan_max_retries = int(max_retries)
    reconciliation_interval = os.getenv("HYDRA_API_RECONCILIATION_INTERVAL_SECONDS")
    if reconciliation_interval:
        settings.reconciliation_interval_seconds = float(reconciliation_interval)
    purge_batch_size = os.getenv("HYDRA_API_RETENTION_PURGE_BATCH_SIZE")
    if purge_batch_size:
        settings.retention_purge_batch_size = int(purge_batch_size)
    settings.retention_purge_dry_run = os.getenv(
        "HYDRA_API_RETENTION_PURGE_DRY_RUN", ""
    ).strip().lower() in ("1", "true", "yes")
    backup_interval = os.getenv("HYDRA_API_BACKUP_INTERVAL_SECONDS")
    if backup_interval:
        settings.backup_interval_seconds = float(backup_interval)
    backup_retention = os.getenv("HYDRA_API_BACKUP_RETENTION_COUNT")
    if backup_retention:
        settings.backup_retention_count = int(backup_retention)
    settings.backup_s3_bucket = os.getenv("HYDRA_API_BACKUP_S3_BUCKET") or None
    settings.backup_s3_prefix = os.getenv("HYDRA_API_BACKUP_S3_PREFIX") or "hydra-backups"
    settings.backup_s3_endpoint_url = os.getenv("HYDRA_API_BACKUP_S3_ENDPOINT_URL") or None
    settings.backup_s3_region = os.getenv("HYDRA_API_BACKUP_S3_REGION") or None
    settings.sentry_dsn = os.getenv("SENTRY_DSN") or None
    settings.log_format = os.getenv("HYDRA_API_LOG_FORMAT") or "text"
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
