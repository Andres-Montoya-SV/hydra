"""`POST /scans/{scan_id}/reportability-estimate` /
`-assessment` through the real FastAPI app — the LLM provider itself is
always mocked (`api.reportability_orchestrator.create_provider`
monkeypatched, the exact same "patch where it's imported into" pattern
tests/test_reportability_cli.py already uses for the CLI command this
endpoint reuses the underlying primitives of), so these tests never
touch a real Anthropic/OpenAI API — only the HTTP/tier/budget layer
around them is under test here. Task 5, test 4 (Medium's cross-
validation auto-degrade) lives in this file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("argon2")
pytest.importorskip("httpx")
pytest.importorskip("anthropic")
pytest.importorskip("pydantic")

from _verified_account import unique_email  # noqa: E402
from _verified_domain import seed_verified_domain  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from api.settings import APISettings  # noqa: E402
from api.subscriptions import current_period_key  # noqa: E402
from config.settings import Settings  # noqa: E402
from core.assets import Finding, Host, RiskLevel, ScanRun  # noqa: E402
from core.reportability.schema import FindingAssessment, ReportabilityBatchResult  # noqa: E402
from core.store import AssetStore  # noqa: E402

DOMAIN = "reportability-api-test.example"
SCAN_ID = "scan-1"


@pytest.fixture(autouse=True)
def fake_operator_llm_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The provider itself is always mocked in this file, but
    `_resolve_provider_or_raise` still checks for a configured API key
    BEFORE ever reaching the mocked `create_provider` — using the real
    ambient `.env`/environment here (gitignored, absent in CI) would make
    these tests pass locally and fail in CI, exactly the trap this
    project's own process explicitly warns against repeating. Fake,
    deterministic credentials, independent of any real environment."""
    fake_settings = Settings(
        project_root=tmp_path,
        anthropic_api_key="sk-fake-anthropic",  # noqa: S106 - test fixture, not a real secret
        anthropic_model="claude-sonnet-5",
        openai_api_key="sk-fake-openai",  # noqa: S106 - test fixture, not a real secret
        openai_model="gpt-5.6-terra",
    )
    monkeypatch.setattr("api.reportability_orchestrator._operator_settings", lambda: fake_settings)
    monkeypatch.setattr("api.hypotheses_orchestrator._operator_settings", lambda: fake_settings)


class _FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, assessments: list[FindingAssessment]) -> None:
        self._assessments = assessments

    def count_input_tokens(self, rules_text: str, findings: list[dict[str, object]]) -> int:
        return 1000

    def assess_batch(
        self, rules_text: str, findings: list[dict[str, object]]
    ) -> ReportabilityBatchResult:
        return ReportabilityBatchResult(assessments=self._assessments)

    def review_batch(self, rules_text, findings, primary_result):  # pragma: no cover - unused here
        raise AssertionError("review_batch should never be called when adversarial is degraded")


@pytest.fixture
def client_with_completed_scan(tmp_path: Path):
    settings = APISettings(data_dir=tmp_path / "api_data")
    with TestClient(create_app(settings)) as client:
        account = client.post("/accounts", json={"email": unique_email()}).json()
        api_key = account["api_key"]
        account_id = account["account_id"]
        client.app.state.control_db.mark_email_verified(account_id)
        seed_verified_domain(client, account_id, DOMAIN)

        control_db = client.app.state.control_db
        db_path = client.app.state.api_settings.account_root(account_id) / "output" / "recon.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        store = AssetStore(db_path)
        store.create_run(
            ScanRun(run_id=SCAN_ID, started_at="2026-01-01T00:00:00Z", targets=[DOMAIN])
        )
        host = Host(
            domain=DOMAIN,
            hostname=DOMAIN,
            risk_level=RiskLevel.HIGH,
            risk_score=70,
            findings=[
                Finding(
                    host=DOMAIN,
                    template_id="exposed-admin-panel",
                    severity="high",
                    name="Exposed admin panel",
                    source="nuclei",
                    description="Login reachable without VPN",
                    url=f"https://{DOMAIN}/admin",
                )
            ],
        )
        store.persist_registry(SCAN_ID, {DOMAIN: host})
        # A real scan always creates its own output/<run_id>/ directory
        # (core/runner.py) before anything writes into it — mirror that
        # here rather than relying on the orchestrator to create it.
        (db_path.parent / SCAN_ID).mkdir(parents=True, exist_ok=True)

        control_db.create_scan(
            scan_id=SCAN_ID, account_id=account_id, domain=DOMAIN, db_path=str(db_path)
        )
        control_db.update_scan_status(SCAN_ID, "completed")

        yield client, api_key, account_id


def _assessment_for(finding_id: int) -> FindingAssessment:
    return FindingAssessment(
        finding_id=finding_id,
        eligibility="ELIGIBLE",
        confidence="HIGH",
        rule_citation="",
        reasoning="Clearly in scope.",
    )


class TestMediumAutoDegradesAdversarial:
    def test_medium_requesting_cross_validation_is_silently_but_visibly_degraded(
        self, client_with_completed_scan, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, api_key, account_id = client_with_completed_scan
        client.app.state.control_db.set_tier(account_id, "medium")

        def fake_create_provider(provider: str, *, api_key: str, model: str):
            return _FakeProvider([_assessment_for(1)])

        monkeypatch.setattr("api.reportability_orchestrator.create_provider", fake_create_provider)

        estimate = client.post(
            f"/scans/{SCAN_ID}/reportability-estimate",
            json={
                "program_rules_text": "Anything reachable without auth is in scope.",
                "provider": "anthropic",
                "adversarial_provider": "openai",
            },
            headers={"X-API-Key": api_key},
        )
        assert estimate.status_code == 200
        body = estimate.json()
        assert body["degraded_from_adversarial"] is True
        assert body["adversarial_provider"] is None

        confirm = client.post(
            f"/scans/{SCAN_ID}/reportability-assessment",
            json={"estimate_id": body["estimate_id"], "confirm": True},
            headers={"X-API-Key": api_key},
        )
        assert confirm.status_code == 200
        confirm_body = confirm.json()
        assert confirm_body["cross_validated"] is False
        assert confirm_body["degraded_from_adversarial"] is True
        assert confirm_body["eligible_count"] == 1

    def test_pro_gets_real_cross_validation_not_degraded(
        self, client_with_completed_scan, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from core.reportability.schema import AdversarialBatchResult, AdversarialFindingChallenge

        client, api_key, account_id = client_with_completed_scan
        client.app.state.control_db.set_tier(account_id, "pro")

        class _AdversarialProvider(_FakeProvider):
            def review_batch(self, rules_text, findings, primary_result):
                return AdversarialBatchResult(
                    reviews=[
                        AdversarialFindingChallenge(finding_id=1, challenge="AGREE", reasoning="ok")
                    ]
                )

        providers = {
            "anthropic": _FakeProvider([_assessment_for(1)]),
            "openai": _AdversarialProvider([_assessment_for(1)]),
        }

        def fake_create_provider(provider: str, *, api_key: str, model: str):
            return providers[provider]

        monkeypatch.setattr("api.reportability_orchestrator.create_provider", fake_create_provider)

        estimate = client.post(
            f"/scans/{SCAN_ID}/reportability-estimate",
            json={
                "program_rules_text": "Anything reachable without auth is in scope.",
                "provider": "anthropic",
                "adversarial_provider": "openai",
            },
            headers={"X-API-Key": api_key},
        )
        assert estimate.status_code == 200
        assert estimate.json()["degraded_from_adversarial"] is False
        assert estimate.json()["adversarial_provider"] == "openai"

        confirm = client.post(
            f"/scans/{SCAN_ID}/reportability-assessment",
            json={"estimate_id": estimate.json()["estimate_id"], "confirm": True},
            headers={"X-API-Key": api_key},
        )
        assert confirm.status_code == 200
        assert confirm.json()["cross_validated"] is True


class TestLlmBudgetCeiling:
    def test_an_estimate_that_would_exceed_the_monthly_ceiling_is_rejected(
        self, client_with_completed_scan, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, api_key, account_id = client_with_completed_scan
        client.app.state.control_db.set_tier(account_id, "medium")  # $10/mo ceiling
        client.app.state.control_db.add_llm_spend(
            account_id, current_period_key(), feature="reportability", amount_usd=9.999
        )

        def fake_create_provider(provider: str, *, api_key: str, model: str):
            return _FakeProvider([_assessment_for(1)])

        monkeypatch.setattr("api.reportability_orchestrator.create_provider", fake_create_provider)

        resp = client.post(
            f"/scans/{SCAN_ID}/reportability-estimate",
            json={
                "program_rules_text": "x" * 20000,  # push the token/cost estimate up
                "provider": "anthropic",
            },
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 402
