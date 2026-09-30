"""Productization Phase 06: risk engine v2 with declared business context.

The engine stays deterministic and explainable: every factor carries its
source (observed / declared) and effect, signals Hydra can't assess are
listed as unknowns, and with no new inputs the Fase 21 result is unchanged."""

from __future__ import annotations

from pathlib import Path

import pytest
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from test_api_exposure_operations import _account, _client, _seed_exposure

from api.monitoring_worker import _risk_change_citations
from core.risk_scoring import (
    BusinessContext,
    RiskFactors,
    RiskLevel,
    classify_exposure_risk,
)


def _factors(severity: str = "medium", **kwargs) -> RiskFactors:  # noqa: ANN003
    base = {"domain_verified": True, "days_open": 0, "related_to_critical_asset": False}
    return RiskFactors(severity=severity, **{**base, **kwargs})


def _effects(result) -> dict[str, str]:  # noqa: ANN001
    return {f.name: f.effect for f in result.factors}


class TestEngineBackwardCompatibility:
    def test_no_new_inputs_reproduces_the_fase_21_result(self) -> None:
        result = classify_exposure_risk(_factors("high", days_open=45))

        assert result.level is RiskLevel.CRITICAL
        assert result.reasons == (
            "base severity is high",
            "asset's domain is under confirmed, verified scope",
            "open for 45 day(s) without resolution (>= 30-day threshold)",
        )

    def test_everything_not_assessed_is_listed_as_unknown(self) -> None:
        unknowns = classify_exposure_risk(_factors()).unknowns

        assert "business criticality: not declared" in unknowns
        assert "environment (production/staging/development/test): not declared" in unknowns
        assert any(u.startswith("exploitability:") for u in unknowns)
        assert "detector confidence: not reported" in unknowns


class TestDeclaredContext:
    @pytest.mark.parametrize(
        "context",
        [
            BusinessContext(criticality="critical"),
            BusinessContext(data_handled=frozenset({"payment"})),
            BusinessContext(criticality="high", data_handled=frozenset({"identity"})),
        ],
    )
    def test_business_impact_escalates_exactly_once(self, context: BusinessContext) -> None:
        result = classify_exposure_risk(_factors("medium", context=context))

        assert result.level is RiskLevel.HIGH
        assert _effects(result)["business_impact"] == "escalates"
        assert any(f.source == "declared" for f in result.factors)

    def test_non_production_de_escalates_with_a_floor(self) -> None:
        staging = BusinessContext(environment="staging")

        assert classify_exposure_risk(_factors("high", context=staging)).level is RiskLevel.MEDIUM
        assert classify_exposure_risk(_factors("low", context=staging)).level is RiskLevel.LOW

    def test_non_production_never_lowers_a_business_critical_asset(self) -> None:
        context = BusinessContext(environment="test", criticality="critical")

        result = classify_exposure_risk(_factors("medium", context=context))

        assert result.level is RiskLevel.HIGH
        assert _effects(result)["environment"] == "none"

    def test_low_criticality_and_production_are_cited_but_neutral(self) -> None:
        context = BusinessContext(
            environment="production", criticality="low", owner="payments-team"
        )

        result = classify_exposure_risk(_factors("medium", context=context))

        assert result.level is RiskLevel.MEDIUM
        assert {n: e for n, e in _effects(result).items() if n in ("environment", "owner")} == {
            "environment": "none",
            "owner": "none",
        }
        assert "owner / business unit: not declared" not in result.unknowns


class TestObservedSignals:
    def test_low_detector_confidence_caps_every_escalation(self) -> None:
        result = classify_exposure_risk(
            _factors(
                "medium",
                days_open=90,
                related_to_critical_asset=True,
                context=BusinessContext(criticality="critical"),
                confidence_score=30,
            )
        )

        assert result.level is RiskLevel.MEDIUM
        assert _effects(result)["detector_confidence"] == "caps"

    def test_a_remote_detection_is_observed_reachability(self) -> None:
        with_location = classify_exposure_risk(_factors(detected_location="https://a.test/x"))
        without = classify_exposure_risk(_factors())

        assert _effects(with_location)["internet_reachability"] == "none"
        assert any(u.startswith("internet reachability") for u in without.unknowns)

    def test_deterministic_and_never_without_reasons(self) -> None:
        inputs = _factors(
            "critical", context=BusinessContext(environment="development"), confidence_score=90
        )

        first, second = classify_exposure_risk(inputs), classify_exposure_risk(inputs)

        assert first == second
        assert first.reasons and all(f.reason for f in first.factors)


def _put_context(client: TestClient, key: str, org: str, **body):  # noqa: ANN003, ANN202
    return client.put(
        f"/organizations/{org}/assets/asset-example/context", headers={"X-API-Key": key}, json=body
    )


class TestContextApi:
    def test_owner_declares_and_the_audit_keeps_before_and_after(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ctx-owner@example.com")
            _seed_exposure(client, account_id, org)
            url = f"/organizations/{org}/assets/asset-example/context"

            before = client.get(url, headers={"X-API-Key": key}).json()
            _put_context(client, key, org, environment="production", criticality="high")
            _put_context(client, key, org, environment="production", criticality="high")
            _put_context(
                client,
                key,
                org,
                environment="production",
                criticality="critical",
                data_handled=["payment"],
                owner="  payments-team ",
            )
            after = client.get(url, headers={"X-API-Key": key}).json()
            audit = client.get(f"{url}/audit", headers={"X-API-Key": key}).json()

            assert before["declared"] is False
            assert (after["criticality"], after["data_handled"], after["owner"]) == (
                "critical",
                ["payment"],
                "payments-team",
            )
            assert len(audit) == 2  # the identical second save wrote nothing
            assert audit[0]["before"]["criticality"] == "high"
            assert audit[0]["after"]["criticality"] == "critical"

    def test_invalid_values_are_422(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ctx-invalid@example.com")
            _seed_exposure(client, account_id, org)

            codes = [
                _put_context(client, key, org, **body).status_code
                for body in (
                    {"environment": "prod"},
                    {"criticality": "extreme"},
                    {"data_handled": ["secrets"]},
                    {"owner": "team\nX-Injected: 1"},
                )
            ]

            assert codes == [422, 422, 422, 422]

    def test_roles_tenancy_and_unknown_assets(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ctx-roles@example.com")
            _seed_exposure(client, account_id, org)
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            foreign_key, _, _ = _account(client, "ctx-foreign@example.com")
            url = f"/organizations/{org}/assets/asset-example/context"

            assert client.get(url, headers={"X-API-Key": viewer_key}).status_code == 200
            assert _put_context(client, viewer_key, org, criticality="low").status_code == 403
            assert client.get(url, headers={"X-API-Key": foreign_key}).status_code == 404
            assert _put_context(client, foreign_key, org, criticality="low").status_code == 404
            assert client.get(f"{url}/audit", headers={"X-API-Key": foreign_key}).status_code == 404
            missing = client.get(
                f"/organizations/{org}/assets/nope/context", headers={"X-API-Key": key}
            )
            assert missing.status_code == 404


class TestRiskReflectsContext:
    def test_declared_context_changes_the_level_and_is_explained(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ctx-risk@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            url = f"/organizations/{org}/exposures/{exposure_id}/risk"

            before = client.get(url, headers={"X-API-Key": key}).json()
            _put_context(client, key, org, criticality="critical", data_handled=["identity"])
            after = client.get(url, headers={"X-API-Key": key}).json()

            impact = next(f for f in after["factors"] if f["name"] == "business_impact")
            assert before["level"] != after["level"]
            assert (impact["source"], impact["effect"]) == ("declared", "escalates")
            assert "business criticality: not declared" in before["unknowns"]
            assert "business criticality: not declared" not in after["unknowns"]

    def test_a_context_change_surfaces_as_a_risk_change_alert(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "ctx-alert@example.com")
            _seed_exposure(client, account_id, org, run_id="run-1")
            db = client.app.state.control_db
            _risk_change_citations(db, org, "run-1")

            _put_context(client, key, org, criticality="critical")
            _seed_exposure(client, account_id, org, run_id="run-2")
            citations = _risk_change_citations(db, org, "run-2")

            assert len(citations) == 1
            assert "declared business criticality is critical" in citations[0]
