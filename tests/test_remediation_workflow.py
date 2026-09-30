"""Productization Phase 07: remediation workflow.

Human workflow state lives apart from detection truth: nothing here may
change an exposure, its evidence or its history. The effective state is
derived on read (resolved -> closed, expired acceptance -> triage,
re-detected after a fix claim -> in_progress), identically in Python and
in the worklist SQL."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from _verified_account import create_verified_account
from fastapi.testclient import TestClient
from test_api_exposure_operations import _FINDING, _account, _client, _seed_exposure

from api.control_db import _WORKLIST_SQL
from api.exposure_identity import exposure_from_finding
from core.remediation import (
    SLA_DAYS,
    RemediationFacts,
    TransitionConflictError,
    TransitionError,
    check_transition,
    effective_remediation,
    sla_due_at,
    to_utc_iso,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def _in(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _facts(**overrides) -> RemediationFacts:  # noqa: ANN003
    base = {
        "stored_state": "triage",
        "state_changed_at": None,
        "accepted_until": None,
        "exposure_status": "open",
        "exposure_last_seen_at": "2026-09-01T00:00:00+00:00",
        "first_seen_at": "2026-09-01T00:00:00+00:00",
        "severity": "high",
        "due_at": None,
    }
    return RemediationFacts(**{**base, **overrides})


class TestStateMachine:
    @pytest.mark.parametrize(
        ("current", "target"),
        [
            ("triage", "fixed_pending_verification"),
            ("false_positive", "in_progress"),
            ("fixed_pending_verification", "triage"),
            ("closed", "in_progress"),
        ],
    )
    def test_disallowed_moves_are_conflicts(self, current: str, target: str) -> None:
        with pytest.raises(TransitionConflictError):
            check_transition(current, target, reason="r", accepted_until=None, now=NOW)

    @pytest.mark.parametrize(
        ("target", "reason", "until", "message"),
        [
            ("false_positive", "  ", None, "requires a reason"),
            ("accepted_risk", "ok", None, "requires accepted_until"),
            ("accepted_risk", "ok", "2026-09-29T00:00:00+00:00", "in the future"),
            ("accepted_risk", "ok", "2028-01-01T00:00:00+00:00", "at most 365 days"),
            ("in_progress", None, "2026-12-01T00:00:00+00:00", "only applies"),
        ],
    )
    def test_invalid_requests_are_errors_not_conflicts(
        self, target: str, reason: str | None, until: str | None, message: str
    ) -> None:
        with pytest.raises(TransitionError, match=message) as exc:
            check_transition("triage", target, reason=reason, accepted_until=until, now=NOW)
        assert not isinstance(exc.value, TransitionConflictError)

    def test_timestamps_need_a_timezone_and_are_stored_as_utc(self) -> None:
        assert to_utc_iso("2026-10-01T09:00:00-05:00", field="x") == "2026-10-01T14:00:00+00:00"
        with pytest.raises(TransitionError, match="timezone"):
            to_utc_iso("2026-10-01T09:00:00", field="x")


class TestEffectiveState:
    def test_resolved_is_closed(self) -> None:
        result = effective_remediation(_facts(exposure_status="resolved"), now=NOW)
        assert (result.state, result.derived_reason) == ("closed", "exposure resolved")

    def test_an_expired_acceptance_returns_to_triage(self) -> None:
        facts = _facts(stored_state="accepted_risk", accepted_until="2026-09-29T00:00:00+00:00")
        result = effective_remediation(facts, now=NOW)
        assert result.state == "triage"
        assert "expired" in result.derived_reason

    def test_redetection_after_a_fix_claim_fails_verification(self) -> None:
        facts = _facts(
            stored_state="fixed_pending_verification",
            state_changed_at="2026-09-10T00:00:00+00:00",
            exposure_last_seen_at="2026-09-20T00:00:00+00:00",
        )
        result = effective_remediation(facts, now=NOW)
        assert result.state == "in_progress"
        assert result.derived_reason.startswith("verification failed")

    def test_sla_and_overdue(self) -> None:
        facts = _facts(severity="critical", first_seen_at="2026-09-01T00:00:00+00:00")
        result = effective_remediation(facts, now=NOW)
        assert result.sla_due_at == sla_due_at("2026-09-01T00:00:00+00:00", "critical")
        assert result.overdue is True  # 7-day SLA long past
        accepted = effective_remediation(
            _facts(
                severity="critical",
                stored_state="accepted_risk",
                accepted_until="2026-12-01T00:00:00+00:00",
            ),
            now=NOW,
        )
        assert accepted.overdue is False  # an accepted risk is not overdue work


def _url(org: str, exposure_id: str, suffix: str = "") -> str:
    return f"/organizations/{org}/exposures/{exposure_id}/remediation{suffix}"


def _move(client: TestClient, key: str, org: str, exposure_id: str, **body):  # noqa: ANN003, ANN202
    return client.post(_url(org, exposure_id, "/transition"), headers={"X-API-Key": key}, json=body)


def _redetect(client: TestClient, account_id: str, org: str, run_id: str) -> None:
    db = client.app.state.control_db
    db.create_scan(
        scan_id=run_id,
        account_id=account_id,
        organization_id=org,
        domain="example.com",
        db_path="x",
    )
    draft = exposure_from_finding(_FINDING, asset_id="asset-example")
    assert draft is not None
    db.upsert_exposure(
        organization_id=org,
        account_id=account_id,
        run_id=run_id,
        finding_id=2,
        draft=draft,
        observed_at=(datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat(),
    )


def _detection_snapshot(client: TestClient) -> list:
    """Every detection-truth row, to prove remediation never changes one."""
    with client.app.state.control_db._connect() as conn:
        return [
            conn.execute("SELECT * FROM exposures ORDER BY exposure_id").fetchall(),
            conn.execute("SELECT * FROM exposure_evidence ORDER BY 1").fetchall(),
            conn.execute("SELECT * FROM exposure_history ORDER BY 1").fetchall(),
        ]


class TestWorkflowApi:
    def test_a_full_remediation_cycle_with_failed_verification(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-cycle@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            headers = {"X-API-Key": key}

            initial = client.get(_url(org, exposure_id), headers=headers).json()
            _move(client, key, org, exposure_id, to_state="in_progress")
            fixed = _move(
                client, key, org, exposure_id, to_state="fixed_pending_verification"
            ).json()
            _redetect(client, account_id, org, "run-2")
            after = client.get(_url(org, exposure_id), headers=headers).json()

            assert (initial["state"], initial["stored_state"]) == ("triage", "triage")
            assert initial["sla_due_at"].startswith("2026-10-26")  # high: 30 days
            assert fixed["state"] == "fixed_pending_verification"
            assert after["state"] == "in_progress"
            assert after["derived_reason"].startswith("verification failed")

    def test_accepted_risk_and_false_positive_never_touch_detection(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-evidence@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            before = _detection_snapshot(client)

            accepted = _move(
                client,
                key,
                org,
                exposure_id,
                to_state="accepted_risk",
                reason="compensating WAF rule",
                accepted_until=_in(30),
            )
            _move(client, key, org, exposure_id, to_state="triage")
            fp = _move(
                client,
                key,
                org,
                exposure_id,
                to_state="false_positive",
                reason="test page, not production",
            )

            assert (accepted.status_code, fp.status_code) == (200, 200)
            assert _detection_snapshot(client) == before

    def test_conflicts_are_409_and_bad_input_is_422(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-codes@example.com")
            exposure_id = _seed_exposure(client, account_id, org)

            conflict = _move(client, key, org, exposure_id, to_state="fixed_pending_verification")
            no_reason = _move(
                client, key, org, exposure_id, to_state="accepted_risk", accepted_until=_in(10)
            )
            naive_time = _move(
                client,
                key,
                org,
                exposure_id,
                to_state="accepted_risk",
                reason="x",
                accepted_until="2026-12-01T00:00:00",
            )

            assert conflict.status_code == 409
            assert conflict.json()["detail"]["error"] == "invalid_transition"
            assert (no_reason.status_code, naive_time.status_code) == (422, 422)

    def test_a_resolved_exposure_is_closed_and_frozen(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-closed@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            client.post(
                f"/organizations/{org}/exposures/{exposure_id}/resolve",
                headers={"X-API-Key": key},
                json={"reason": "patched"},
            )

            state = client.get(_url(org, exposure_id), headers={"X-API-Key": key}).json()
            move = _move(client, key, org, exposure_id, to_state="in_progress")

            assert state["state"] == "closed"
            assert move.status_code == 409


class TestAssignmentAndComments:
    def test_fields_comments_and_the_event_log(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-fields@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            headers = {"X-API-Key": key}

            patched = client.patch(
                _url(org, exposure_id),
                headers=headers,
                json={
                    "assignee_account_id": account_id,
                    "due_at": "2026-10-05T09:00:00-05:00",
                    "ticket_url": "https://tracker.example.com/SEC-42",
                },
            ).json()
            client.patch(
                _url(org, exposure_id), headers=headers, json={"assignee_account_id": account_id}
            )  # unchanged: no event
            client.post(
                _url(org, exposure_id, "/comments"),
                headers=headers,
                json={"body": "  Rolled out patch to staging  "},
            )
            events = client.get(_url(org, exposure_id, "/events"), headers=headers).json()

            assert (patched["assignee_account_id"], patched["due_at"]) == (
                account_id,
                "2026-10-05T14:00:00+00:00",
            )
            assert sorted(e["event_type"] for e in events) == [
                "assignee_changed",
                "comment",
                "due_at_changed",
                "ticket_changed",
            ]
            comment = next(e for e in events if e["event_type"] == "comment")
            assert (comment["body"], comment["actor_account_id"]) == (
                "Rolled out patch to staging",
                account_id,
            )

    def test_invalid_fields_are_422(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-bad@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            outsider_key, outsider_id = create_verified_account(client)
            headers = {"X-API-Key": key}

            codes = [
                client.patch(_url(org, exposure_id), headers=headers, json=body).status_code
                for body in (
                    {"assignee_account_id": outsider_id},
                    {"ticket_url": "http://tracker.example.com/1"},
                    {"ticket_url": "javascript:alert(1)"},
                    {"due_at": "next tuesday"},
                )
            ]
            blank = client.post(
                _url(org, exposure_id, "/comments"), headers=headers, json={"body": "   "}
            )

            assert codes == [422, 422, 422, 422]
            assert blank.status_code == 422


def _two_exposures(client: TestClient, account_id: str, org: str) -> list[str]:
    first = _seed_exposure(client, account_id, org, run_id="run-a")
    db = client.app.state.control_db
    draft = exposure_from_finding(
        {**_FINDING, "template_id": "other", "severity": "critical"}, asset_id="asset-example"
    )
    assert draft is not None
    second, _, _ = db.upsert_exposure(
        organization_id=org, account_id=account_id, run_id="run-a", finding_id=3, draft=draft
    )
    return [first, second]


class TestBulkAndWorklist:
    def test_bulk_is_all_or_nothing(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-bulk@example.com")
            ids = _two_exposures(client, account_id, org)
            headers = {"X-API-Key": key}
            bulk = f"/organizations/{org}/remediation/bulk"
            _move(client, key, org, ids[1], to_state="in_progress")

            conflict = client.post(
                bulk,
                headers=headers,
                json={
                    "exposure_ids": ids,
                    "transition": {"to_state": "fixed_pending_verification"},
                },
            )
            foreign = client.post(
                bulk,
                headers=headers,
                json={
                    "exposure_ids": [ids[0], "not-mine"],
                    "transition": {"to_state": "in_progress"},
                },
            )
            ok = client.post(
                bulk,
                headers=headers,
                json={"exposure_ids": ids, "fields": {"assignee_account_id": account_id}},
            )
            states = [client.get(_url(org, i), headers=headers).json() for i in ids]

            assert (conflict.status_code, foreign.status_code, ok.status_code) == (409, 404, 204)
            assert [s["stored_state"] for s in states] == ["triage", "in_progress"]
            assert all(s["assignee_account_id"] == account_id for s in states)

    @pytest.mark.parametrize(
        "body",
        [
            {"exposure_ids": ["a"] * 2, "transition": {"to_state": "in_progress"}},
            {
                "exposure_ids": [str(i) for i in range(101)],
                "transition": {"to_state": "in_progress"},
            },
            {
                "exposure_ids": ["a"],
                "transition": {"to_state": "in_progress"},
                "fields": {"ticket_url": None},
            },
            {"exposure_ids": ["a"]},
        ],
    )
    def test_malformed_bulk_requests_are_422(self, tmp_path: Path, body: dict) -> None:
        with _client(tmp_path) as client:
            key, _, org = _account(client, "rem-bulk-bad@example.com")
            resp = client.post(
                f"/organizations/{org}/remediation/bulk", headers={"X-API-Key": key}, json=body
            )
            assert resp.status_code == 422

    def test_worklist_filters_on_the_effective_state_and_orders_by_due(
        self, tmp_path: Path
    ) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-list@example.com")
            ids = _two_exposures(client, account_id, org)
            headers = {"X-API-Key": key}
            url = f"/organizations/{org}/remediation"

            everything = client.get(url, headers=headers).json()
            _move(client, key, org, ids[0], to_state="in_progress")
            in_progress = client.get(url, headers=headers, params={"state": "in_progress"}).json()

            # critical (7-day SLA) is due before high (30-day SLA)
            assert [i["severity"] for i in everything] == ["critical", "high"]
            assert [i["exposure_id"] for i in in_progress] == [ids[0]]

    def test_sql_and_python_effective_states_agree(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            key, account_id, org = _account(client, "rem-agree@example.com")
            ids = _two_exposures(client, account_id, org)
            _move(client, key, org, ids[0], to_state="in_progress")
            _move(client, key, org, ids[0], to_state="fixed_pending_verification")
            _redetect(client, account_id, org, "run-b")  # re-detects ids[0]'s finding
            db = client.app.state.control_db
            with db._connect() as conn:  # an already-expired acceptance
                conn.execute(
                    "INSERT INTO exposure_remediation (exposure_id, organization_id, state, "
                    "accepted_until) VALUES (?, ?, 'accepted_risk', '2026-01-01T00:00:00+00:00')",
                    (ids[1], org),
                )

            now = datetime.now(timezone.utc)
            rows = db.remediation_worklist(org, now=now)
            python_states = {
                exposure.exposure_id: effective_remediation(
                    RemediationFacts(
                        stored_state=record.state,
                        state_changed_at=record.state_changed_at,
                        accepted_until=record.accepted_until,
                        exposure_status=exposure.status,
                        exposure_last_seen_at=exposure.last_seen_at,
                        first_seen_at=exposure.first_seen_at,
                        severity=exposure.severity,
                        due_at=record.due_at,
                    ),
                    now=now,
                ).state
                for exposure, record, _ in rows
            }

            assert {e.exposure_id: sql for e, _, sql in rows} == python_states
            assert python_states == {ids[0]: "in_progress", ids[1]: "triage"}

    def test_the_sql_sla_matches_the_python_table(self) -> None:
        for dialect, prefix in (("sqlite", "+"), ("postgres", "")):
            sql = _WORKLIST_SQL[dialect]
            for severity, days in SLA_DAYS.items():
                if severity != "low":
                    assert f"WHEN '{severity}' THEN '{prefix}{days} days'" in sql
            assert f"ELSE '{prefix}{SLA_DAYS['low']} days'" in sql


class TestRolesAndTenancy:
    def test_viewer_reads_but_cannot_change_anything(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            _, account_id, org = _account(client, "rem-owner@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            viewer_key, viewer_id = create_verified_account(client)
            client.app.state.control_db.add_account_organization_role(
                account_id=viewer_id, organization_id=org, role="viewer"
            )
            v = {"X-API-Key": viewer_key}

            reads = [
                client.get(_url(org, exposure_id), headers=v).status_code,
                client.get(_url(org, exposure_id, "/events"), headers=v).status_code,
                client.get(f"/organizations/{org}/remediation", headers=v).status_code,
            ]
            writes = [
                _move(client, viewer_key, org, exposure_id, to_state="in_progress").status_code,
                client.patch(
                    _url(org, exposure_id), headers=v, json={"ticket_url": None}
                ).status_code,
                client.post(
                    _url(org, exposure_id, "/comments"), headers=v, json={"body": "x"}
                ).status_code,
                client.post(
                    f"/organizations/{org}/remediation/bulk",
                    headers=v,
                    json={"exposure_ids": [exposure_id], "transition": {"to_state": "in_progress"}},
                ).status_code,
            ]

            assert reads == [200, 200, 200]
            assert writes == [403, 403, 403, 403]

    def test_foreign_accounts_get_404_everywhere(self, tmp_path: Path) -> None:
        with _client(tmp_path) as client:
            _, account_id, org = _account(client, "rem-victim@example.com")
            exposure_id = _seed_exposure(client, account_id, org)
            foreign_key, _, foreign_org = _account(client, "rem-attacker@example.com")
            f = {"X-API-Key": foreign_key}

            codes = [
                client.get(_url(org, exposure_id), headers=f).status_code,
                client.get(_url(org, exposure_id, "/events"), headers=f).status_code,
                client.get(f"/organizations/{org}/remediation", headers=f).status_code,
                _move(client, foreign_key, org, exposure_id, to_state="in_progress").status_code,
                # Own organization, someone else's exposure id: still not found.
                _move(
                    client, foreign_key, foreign_org, exposure_id, to_state="in_progress"
                ).status_code,
                client.post(
                    f"/organizations/{foreign_org}/remediation/bulk",
                    headers=f,
                    json={"exposure_ids": [exposure_id], "transition": {"to_state": "in_progress"}},
                ).status_code,
            ]

            assert codes == [404, 404, 404, 404, 404, 404]
