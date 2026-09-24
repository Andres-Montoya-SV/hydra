"""Replays a REAL Wompi sandbox webhook capture through the actual
verification + handler path — the one confirmation nothing in this
codebase can produce on its own (docs/PAID_API_DESIGN.md's dated
"Wompi webhook — confirmed against docs, sandbox capture pending"
section has the full operator runbook for producing the fixture this
test needs).

**Skipped, not deleted, not xfail, until the fixture exists** — the
whole point is that this test turns green the moment a real capture is
dropped in, with zero code changes, proving the signature scheme and
payload shape genuinely match what Wompi's real sandbox sends (not just
what its docs say it sends).

**How the fixture gets here**: `scripts/capture_wompi_webhook.py`
writes one timestamped JSON file per captured request, in the exact
shape `_load_capture` below reads. An operator (see the runbook)
copies ONE real, representative capture to
`tests/fixtures/wompi_real_capture.json` (gitignored — never commit a
real customer's email/name) and sets `WOMPI_REAL_CAPTURE_SECRET` to the
real Wompi API Secret used to sign it (also never committed).
Optionally also setting `WOMPI_REAL_CAPTURE_CLIENT_ID` (the OAuth
client id from the same sandbox app) lets the full end-to-end replay
test additionally exercise the handler's independent
`api.wompi.sv` re-confirmation step for real, rather than that step
correctly-but-uninterestingly failing for lack of credentials.

**Why the secret is a separate env var, never read from the fixture
file itself**: the captured file only ever contains what Wompi actually
SENT over the wire (headers + body) — the secret is never part of that
wire data (it's the shared key on Hydra's own side), so there is no
field in the capture to read it from even if we wanted to; it must come
from wherever the operator actually configured `WOMPI_CLIENT_SECRET`
for that sandbox run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "wompi_real_capture.json"
_SECRET_ENV_VAR = "WOMPI_REAL_CAPTURE_SECRET"
_CLIENT_ID_ENV_VAR = "WOMPI_REAL_CAPTURE_CLIENT_ID"

_SKIP_REASON = (
    f"Needs a real captured Wompi sandbox webhook — see "
    f"docs/PAID_API_DESIGN.md's operator runbook. Drop the capture at "
    f"{_FIXTURE_PATH} (gitignored) and set {_SECRET_ENV_VAR} to the real "
    "API Secret it was signed with, then this test activates automatically."
)


def _load_capture() -> dict:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.skipif(not _FIXTURE_PATH.is_file(), reason=_SKIP_REASON)
@pytest.mark.skipif(not os.environ.get(_SECRET_ENV_VAR), reason=_SKIP_REASON)
class TestReplayARealCapturedWompiWebhook:
    def test_the_real_captured_signature_verifies_against_the_real_secret(self) -> None:
        from api.wompi_client import verify_webhook_signature

        capture = _load_capture()
        raw_body = capture["raw_body_text"].encode("utf-8")
        # Header lookup is case-insensitive on the wire (HTTP headers
        # always are) — the capture script preserves whatever casing
        # Wompi actually sent, which this test must not assume in advance.
        headers = {k.lower(): v for k, v in capture["headers"].items()}
        signature = headers.get("wompi_hash")
        secret = os.environ[_SECRET_ENV_VAR]

        assert verify_webhook_signature(raw_body, signature, secret) is True, (
            "A REAL Wompi signature failed to verify against the documented "
            "scheme (raw-body HMAC-SHA256, keyed with the API Secret) — this "
            "means api/wompi_client.py's implementation does not match what "
            "Wompi's real sandbox actually sends, a genuine, high-priority bug."
        )

    def test_the_real_captured_payload_has_the_fields_the_handler_reads(self) -> None:
        capture = _load_capture()
        body = capture.get("parsed_json_body")
        assert body is not None, "captured body was not valid JSON"

        for field in ("IdTransaccion", "ResultadoTransaccion", "Monto"):
            assert field in body, f"real capture is missing {field!r} — handler assumption is wrong"
        assert "Email" in (body.get("cliente") or {}), "real capture's cliente has no Email field"
        assert "NombreProducto" in (
            body.get("EnlacePago") or {}
        ), "real capture's EnlacePago has no NombreProducto field"

    def test_the_real_capture_replayed_through_the_full_handler_activates_or_reconciles(
        self, tmp_path: Path
    ) -> None:
        """The end-to-end proof: seed a pending enrollment matching
        whatever email/tier the REAL capture actually contains (read
        from the capture itself, since a real sandbox transaction's
        content can't be predicted in advance), then replay the exact
        raw bytes through the real `/webhooks/wompi` endpoint and
        confirm it does something sane — either a real activation (if
        the product name maps to a known tier) or a clean route to
        manual reconciliation, never a 500 or a guess.

        The handler's Part D.2 belt-and-suspenders step independently
        re-confirms the transaction via a REAL call to `api.wompi.sv`
        (OAuth'd against `id.wompi.sv`), which needs real
        `wompi_client_id`/`wompi_client_secret` credentials, not just the
        webhook secret. Without `WOMPI_REAL_CAPTURE_CLIENT_ID` set, that
        independent check will itself fail against the live API (no
        client id configured) and the handler correctly refuses to act,
        returning 502 — a legitimate, expected outcome here, not a test
        failure; only with a real client id does this test observe the
        full activation/reconciliation path."""
        pytest.importorskip("fastapi")
        from _verified_account import create_verified_account
        from fastapi.testclient import TestClient

        from api.main import create_app
        from api.settings import APISettings
        from api.wompi_client import tier_for_product_name

        capture = _load_capture()
        raw_body = capture["raw_body_text"].encode("utf-8")
        headers = {k.lower(): v for k, v in capture["headers"].items()}
        body = capture["parsed_json_body"]
        secret = os.environ[_SECRET_ENV_VAR]
        client_id = os.environ.get(_CLIENT_ID_ENV_VAR)

        email = (body.get("cliente") or {}).get("Email")
        product_name = (body.get("EnlacePago") or {}).get("NombreProducto")
        tier = tier_for_product_name(product_name)

        settings = APISettings(
            data_dir=tmp_path / "api_data", wompi_client_id=client_id, wompi_client_secret=secret
        )
        with TestClient(create_app(settings)) as client:
            if email and tier:
                api_key, _account_id = create_verified_account(client)
                client.post(
                    "/account/subscription",
                    json={"tier": tier, "billing_email": email},
                    headers={"X-API-Key": api_key},
                )

            resp = client.post(
                "/webhooks/wompi",
                content=raw_body,
                headers={"wompi_hash": headers.get("wompi_hash", "")},
            )

        # A real, signed, real-shaped payload must never 401 (that would
        # mean the signature scheme is wrong) or 500 (a crash on real
        # data) — it may legitimately be "activated" (a matching pending
        # enrollment existed) or a clean reconciliation outcome, never a
        # server error.
        assert resp.status_code in (
            200,
            400,
            502,
        ), f"unexpected status {resp.status_code} replaying a real capture: {resp.text}"
        if resp.status_code == 200:
            assert resp.json()["status"] in (
                "activated",
                "already_processed",
                "unmatched_pending_manual_reconciliation",
                "renewal_confirmed",
                "grace_period_started",
                "unmatched_failure_logged",
            )
