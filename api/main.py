"""FastAPI application factory. A separate, independently-deployable
service — never imported by `app.py`, and imports only the module-level
functions it needs from `app.py` (deferred, inside
`api/scan_orchestrator.py`), never the reverse. Run locally with:

    uvicorn api.main:app --reload

(see docs/PAID_API_DESIGN.md's "Round 1 implemented" section for the
full local-run walkthrough, including how to create a test account).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.backup_worker import run_backup_loop
from api.control_db import ControlDB
from api.email_sender import ConsoleEmailSender, EmailSender, PostmarkEmailSender
from api.rate_limit import PersistentTokenBucketLimiter
from api.reconciliation_worker import run_reconciliation_loop
from api.routers import accounts, domains, hypotheses, keys, reportability, scans, subscription
from api.scan_worker import generate_worker_id, run_worker_loop
from api.settings import APISettings, load_api_settings, validate_email_provider_config
from api.wompi_client import WompiClient

# A real gap this task's own "never ambiguous from the logs alone"
# requirement surfaced: nothing in this service ever configured Python
# logging. Without a handler, the stdlib's "handler of last resort"
# (stderr, WARNING+) is all that's active — an INFO-level line (this
# module's own email-provider-selection log, and the pre-existing
# Hallazgo 2 orphaned-scan reconciliation log) is silently dropped by
# default, never actually visible in a real `uvicorn` process's console
# output. `basicConfig` is a no-op if the root logger already has a
# handler (a real deployment's own explicit logging config, set up
# before this module imports, always wins) — safe to call
# unconditionally as a sensible zero-config default otherwise.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

logger = logging.getLogger("hydra.api")


def create_app(api_settings: APISettings | None = None) -> FastAPI:
    settings = api_settings or load_api_settings()
    # Fails loudly HERE, synchronously, at app-construction time — never
    # a silent half-configured boot that only breaks on the first real
    # POST /accounts (api/settings.py::validate_email_provider_config's
    # own docstring has the full reasoning). Runs for every APISettings
    # regardless of whether it came from load_api_settings() (a real
    # deployment) or was constructed directly (tests).
    validate_email_provider_config(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.api_settings = settings
        app.state.control_db = ControlDB(settings.control_db_path)
        # Durable-queue fix: persisted, cross-process-safe — see
        # api/rate_limit.py's own module docstring for why this replaced
        # the old in-memory TokenBucketLimiter as what the real app
        # wires up.
        app.state.rate_limiter = PersistentTokenBucketLimiter(
            control_db=app.state.control_db, requests_per_minute=settings.rate_limit_per_minute
        )
        app.state.wompi_client = WompiClient(
            client_id=settings.wompi_client_id,
            client_secret=settings.wompi_client_secret,
            id_base_url=settings.dev_wompi_id_base_url,
            api_base_url=settings.dev_wompi_api_base_url,
        )
        # Hallazgo 1 follow-up: PostmarkEmailSender only when BOTH a
        # server token and a from-address are configured (already
        # enforced together-or-not-at-all above) — ConsoleEmailSender
        # (log-only) remains the unconditional zero-config default.
        # Logged once, in plain words, so it's never ambiguous from the
        # logs alone which mode a running deployment is in.
        # A typed local (not just `app.state.email_sender` directly) so
        # the reconciliation loop below can be passed a real `EmailSender`
        # — reading it back off `app.state` after this if/else would
        # type-check as `object` (mypy joins the two unrelated concrete
        # classes assigned across the two branches), not `EmailSender`.
        email_sender: EmailSender
        if settings.postmark_server_token and settings.email_from_address:
            email_sender = PostmarkEmailSender(
                server_token=settings.postmark_server_token,
                from_address=settings.email_from_address,
                from_name=settings.email_from_name,
                send_url=settings.dev_postmark_send_url,
            )
            logger.info("Postmark configured — sending real verification emails.")
        else:
            email_sender = ConsoleEmailSender()
            logger.info(
                "No email provider configured — verification emails are only logged, " "not sent."
            )
        app.state.email_sender = email_sender

        # Durable-queue fix: supersedes Hallazgo 2's old one-time
        # startup-only `fail_orphaned_scans` — a `'running'` scan whose
        # heartbeat has gone stale is now automatically REQUEUED (and
        # actually re-executed) rather than unconditionally marked
        # `failed`, and this sweep runs continuously (every poll cycle),
        # not just once at process start. See api/scan_worker.py's own
        # module docstring for the full design.
        worker_id = generate_worker_id()
        stop_event = asyncio.Event()
        worker_task = asyncio.create_task(
            run_worker_loop(
                api_settings=settings,
                control_db=app.state.control_db,
                worker_id=worker_id,
                stop_event=stop_event,
            )
        )
        logger.info("Scan worker loop started (worker_id=%s).", worker_id)

        # Automatic billing enforcement and data retention purge fix:
        # its own periodic loop, sharing `stop_event` with the scan
        # worker (both simply stop being scheduled once shutdown
        # begins) but NOT its interval — see
        # api/reconciliation_worker.py's own module docstring for why a
        # day-granularity job needs a separate loop from a sub-second
        # scan-claim one, rather than being folded into it.
        reconciliation_task = asyncio.create_task(
            run_reconciliation_loop(
                api_settings=settings,
                control_db=app.state.control_db,
                email_sender=email_sender,
                stop_event=stop_event,
            )
        )
        logger.info(
            "Billing/retention reconciliation loop started (interval=%.0fs, " "dry_run=%s).",
            settings.reconciliation_interval_seconds,
            settings.retention_purge_dry_run,
        )

        # Automated backups fix: same "own periodic loop, shared
        # stop_event, independent interval" shape as the reconciliation
        # loop above — see api/backup_worker.py's own module docstring
        # for the full design.
        backup_task = asyncio.create_task(
            run_backup_loop(
                api_settings=settings,
                control_db=app.state.control_db,
                stop_event=stop_event,
            )
        )
        logger.info(
            "Backup loop started (interval=%.0fs, remote_upload=%s).",
            settings.backup_interval_seconds,
            "on" if settings.backup_s3_bucket else "off",
        )

        yield
        stop_event.set()
        await worker_task
        await reconciliation_task
        await backup_task

    app = FastAPI(
        title="Hydra EASM API",
        description=(
            "Round 3: Free/Medium/Pro/Ultra tiers gate scan quotas, verified-"
            "domain counts, report formats/languages, and the assess-"
            "reportability/suggest-hypotheses LLM features; Wompi billing "
            "(OAuth client-credentials, webhook-signature-verified tier "
            "activation, payment-failure grace period) sits behind "
            "POST /account/subscription. Round 2's domain-ownership "
            "verification and Round 1's multi-tenant core/auth/async scans "
            "underneath. Post-Round-3 hardening: POST /accounts is "
            "per-IP rate limited (persisted, cross-process-safe) and "
            "gated by email verification before POST /scans will run "
            "anything (real delivery via Postmark when configured, "
            "console-logged otherwise). Scans run on a durable, SQLite-"
            "backed queue (api/scan_worker.py) — a scan interrupted by "
            "a worker crash or restart is automatically requeued and "
            "re-executed, up to a bounded retry ceiling, rather than "
            "silently abandoned. A daily reconciliation loop "
            "(api/reconciliation_worker.py) suspends accounts whose "
            "payment-failure grace period expired (emailing them when "
            "it does) and purges scans/artifacts past each account's "
            "tier retention window. A daily backup loop "
            "(api/backup_worker.py) snapshots control.db and every "
            "account's recon.db via SQLite's own online backup API, "
            "optionally pushing them to S3-compatible storage — see "
            "docs/PAID_API_DESIGN.md."
        ),
        lifespan=lifespan,
    )
    app.include_router(accounts.router)
    app.include_router(keys.router)
    app.include_router(domains.router)
    app.include_router(scans.router)
    app.include_router(reportability.router)
    app.include_router(hypotheses.router)
    app.include_router(subscription.router)
    return app


app = create_app()
