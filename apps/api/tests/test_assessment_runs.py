from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import AssessmentRunRepository, apply_migrations
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient


def _downgrade_to_migration_five(connection: psycopg.Connection[Any]) -> None:
    connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 12")
    connection.execute("DROP TABLE assessment_run_exposure_passages")
    connection.execute("DROP TABLE assessment_run_exposure_evidence")
    connection.execute("DROP TABLE evidence_passages")
    connection.execute("DROP TABLE evidence_records")
    connection.execute("DROP TABLE sources")
    connection.execute("DROP FUNCTION reject_evidence_mutation")
    connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 9")
    connection.execute("DROP TABLE exposure_discoveries")
    connection.execute("DROP TABLE assessment_run_exposures")
    connection.execute("DROP TABLE exposures")
    connection.execute(
        "ALTER TABLE package_instances DROP CONSTRAINT package_instances_id_snapshot_key"
    )
    connection.execute("DROP TABLE vulnerability_aliases")
    connection.execute("DROP TABLE vulnerability_records")
    connection.execute("DROP FUNCTION reject_exposure_mutation")
    connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 8")
    connection.execute("DROP TABLE asset_capture_requests")
    connection.execute("DROP INDEX policy_decisions_one_request_per_run_idx")
    connection.execute("ALTER TABLE policy_decisions DROP COLUMN enforcement_point")
    connection.execute(
        "ALTER TABLE policy_decisions ADD CONSTRAINT "
        "policy_decisions_assessment_run_id_key UNIQUE (assessment_run_id)"
    )
    connection.execute(
        "ALTER TABLE assessment_runs DROP CONSTRAINT assessment_runs_asset_snapshot_check"
    )
    connection.execute(
        "ALTER TABLE assessment_runs ADD CONSTRAINT assessment_runs_asset_snapshot_check "
        "CHECK ((mode = 'synthetic' AND synthetic AND asset_snapshot_id IS NULL) OR "
        "(mode = 'repository' AND NOT synthetic AND asset_snapshot_id IS NOT NULL))"
    )
    connection.execute(
        "DROP TRIGGER sealed_asset_snapshot_packages_reject_inserts ON package_instances"
    )
    connection.execute(
        "DROP TRIGGER sealed_asset_snapshot_paths_reject_inserts ON dependency_paths"
    )
    connection.execute("DROP TRIGGER asset_snapshots_allow_only_seal ON asset_snapshots")
    connection.execute("DROP TRIGGER asset_snapshots_cannot_be_deleted ON asset_snapshots")
    connection.execute("DROP FUNCTION protect_asset_snapshot_package_membership")
    connection.execute("DROP FUNCTION protect_asset_snapshot_path_membership")
    connection.execute("ALTER TABLE package_instances ALTER COLUMN direct SET NOT NULL")
    connection.execute(
        "ALTER TABLE asset_snapshots DROP CONSTRAINT asset_snapshots_project_file_check"
    )
    connection.execute(
        "ALTER TABLE asset_snapshots DROP COLUMN project_file_path, "
        "DROP COLUMN project_file_digest, DROP COLUMN project_file_content"
    )
    connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 7")
    connection.execute("DROP FUNCTION allow_only_asset_snapshot_seal")
    connection.execute(
        "CREATE TRIGGER asset_snapshots_are_immutable "
        "BEFORE UPDATE OR DELETE ON asset_snapshots "
        "FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation()"
    )
    connection.execute("ALTER TABLE asset_snapshots DROP COLUMN sealed")
    connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 6")


def test_synthetic_assessment_survives_restart_and_replays_progress(
    database_url: str,
) -> None:
    settings = Settings(database_url=database_url)

    with TestClient(create_app(settings)) as client:
        create_response = client.post(
            "/api/v1/assessment-runs",
            json={"mode": "synthetic"},
        )

        assert create_response.status_code == 201
        created = create_response.json()
        assessment_id = UUID(created["id"])
        assert created["status"] == "queued"
        assert created["synthetic"] is True
        assert created["label"] == "Synthetic Assessment Run"
        assert created["policyDecision"] == {
            "id": created["policyDecision"]["id"],
            "assessmentRunId": created["id"],
            "standardVersion": "0.1",
            "assistanceClass": "C1",
            "actionLevel": "A1",
            "targetScope": "bundled synthetic fixture",
            "authorizationScope": "local operator",
            "result": "allowed",
            "ruleVersion": "assessment-request-v1",
            "reason": "C1 assistance at A1 is permitted for the confirmed target scope.",
            "createdAt": created["policyDecision"]["createdAt"],
            "enforcementPoint": "request",
        }

    assert process_next_assessment(database_url=database_url) is True

    with TestClient(create_app(settings)) as restarted_client:
        retrieval_response = restarted_client.get(f"/api/v1/assessment-runs/{assessment_id}")
        assert retrieval_response.status_code == 200
        assert retrieval_response.json() == {
            **created,
            "status": "completed",
            "startedAt": retrieval_response.json()["startedAt"],
            "completedAt": retrieval_response.json()["completedAt"],
        }
        assert retrieval_response.json()["startedAt"] is not None
        assert retrieval_response.json()["completedAt"] is not None

        list_response = restarted_client.get("/api/v1/assessment-runs")
        assert list_response.status_code == 200
        assert [item["id"] for item in list_response.json()["items"]] == [str(assessment_id)]

        replay_response = restarted_client.get(
            f"/api/v1/assessment-runs/{assessment_id}/events?follow=false"
        )
        assert replay_response.status_code == 200
        assert replay_response.headers["content-type"].startswith("text/event-stream")
        assert "id: 1\nevent: assessment.queued" in replay_response.text
        assert "event: assessment.started" in replay_response.text
        assert "event: assessment.synthetic_progress" in replay_response.text
        assert "event: assessment.completed" in replay_response.text

        resumed_response = restarted_client.get(
            f"/api/v1/assessment-runs/{assessment_id}/events?after=2&follow=false"
        )
        assert resumed_response.status_code == 200
        assert "id: 1\n" not in resumed_response.text
        assert "id: 2\n" not in resumed_response.text
        assert "id: 3\n" in resumed_response.text
        assert "id: 4\n" in resumed_response.text

        header_resumed_response = restarted_client.get(
            f"/api/v1/assessment-runs/{assessment_id}/events?follow=false",
            headers={"Last-Event-ID": "3"},
        )
        assert header_resumed_response.status_code == 200
        assert "id: 3\n" not in header_resumed_response.text
        assert "id: 4\n" in header_resumed_response.text

        missing_id = uuid4()
        missing_response = restarted_client.get(f"/api/v1/assessment-runs/{missing_id}")
        assert missing_response.status_code == 404
        assert missing_response.json() == {
            "detail": {
                "code": "assessment_run_not_found",
                "message": f"Assessment Run {missing_id} was not found.",
            }
        }

        failure_response = restarted_client.post(
            "/api/v1/assessment-runs",
            json={"mode": "synthetic", "scenario": "worker_failure"},
        )
        assert failure_response.status_code == 201
        failed_id = failure_response.json()["id"]

        assert process_next_assessment(database_url=database_url) is True

        failed_response = restarted_client.get(f"/api/v1/assessment-runs/{failed_id}")
        assert failed_response.status_code == 200
        assert failed_response.json()["status"] == "failed"
        assert failed_response.json()["errorCode"] == "synthetic_worker_failure"
        assert failed_response.json()["errorMessage"] == (
            "Synthetic worker failure requested for contract verification."
        )

        failed_events_response = restarted_client.get(
            f"/api/v1/assessment-runs/{failed_id}/events?follow=false"
        )
        assert failed_events_response.status_code == 200
        assert "event: assessment.failed" in failed_events_response.text
        assert '"code":"synthetic_worker_failure"' in failed_events_response.text

        interrupted_response = restarted_client.post(
            "/api/v1/assessment-runs",
            json={"mode": "synthetic"},
        )
        assert interrupted_response.status_code == 201
        interrupted_id = UUID(interrupted_response.json()["id"])
        claimed = AssessmentRunRepository(database_url).claim_next(stale_after_seconds=30)
        assert claimed is not None
        assert claimed.id == interrupted_id

        repository = AssessmentRunRepository(database_url)
        resumed = repository.claim_next(stale_after_seconds=0)
        assert resumed is not None
        assert resumed.id == interrupted_id
        assert repository.claim_next(stale_after_seconds=30) is None
        assert resumed.claim_id is not None
        assert repository.complete_synthetic(interrupted_id, claim_id=resumed.claim_id) is True
        assert claimed.claim_id is not None
        assert (
            repository.fail(
                interrupted_id,
                claim_id=claimed.claim_id,
                code="stale_worker",
                message="A stale worker must not be able to change the run.",
            )
            is False
        )

        resumed_events_response = restarted_client.get(
            f"/api/v1/assessment-runs/{interrupted_id}/events?follow=false"
        )
        assert resumed_events_response.status_code == 200
        assert "event: assessment.resumed" in resumed_events_response.text
        assert "event: assessment.completed" in resumed_events_response.text


@pytest.mark.parametrize(
    ("policy_context", "expected_result", "expected_reason"),
    [
        (
            {"operationChain": ["draft_dependency_patch"]},
            "restricted",
            "A2 actions are restricted pending the approved human-review milestone.",
        ),
        (
            {"operationChain": ["generate_exploit"]},
            "blocked",
            "C2 assistance is outside the first-release capability ceiling.",
        ),
        (
            {"operationChain": ["unrecognized_operation"]},
            "blocked",
            (
                "Assistance Class or Action Level is materially uncertain; the Assessment "
                "request is conservatively classified C3/A4 and blocked."
            ),
        ),
        (
            {
                "operationChain": ["scan_arbitrary_hosts"],
            },
            "blocked",
            (
                "C2 assistance and A4 action in the operation chain are outside the "
                "first-release capability ceiling."
            ),
        ),
    ],
)
def test_non_allowed_policy_decisions_are_visible_without_creating_worker_tasks(
    database_url: str,
    policy_context: dict[str, object],
    expected_result: str,
    expected_reason: str,
) -> None:
    settings = Settings(database_url=database_url)
    payload = {
        **policy_context,
    }

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={"mode": "synthetic", "policyContext": payload},
        )

        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["code"] == f"assessment_policy_{expected_result}"
        assert detail["message"] == expected_reason
        assert detail["policyDecision"]["result"] == expected_result
        assert detail["policyDecision"]["assessmentRunId"] is None
        if "unrecognized_operation" in payload.get("operationChain", []):
            assert detail["policyDecision"]["assistanceClass"] == "C3"
            assert detail["policyDecision"]["actionLevel"] == "A4"

        runs_response = client.get("/api/v1/assessment-runs")
        assert runs_response.status_code == 200
        assert runs_response.json()["items"] == []

        decisions_response = client.get("/api/v1/policy-decisions")
        assert decisions_response.status_code == 200
        assert decisions_response.json()["items"] == [detail["policyDecision"]]

    assert process_next_assessment(database_url=database_url) is False


def test_client_cannot_assert_its_own_authorization(database_url: str) -> None:
    settings = Settings(database_url=database_url)

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "synthetic",
                "policyContext": {"authorizationStatus": "confirmed"},
            },
        )

        assert response.status_code == 422
        assert client.get("/api/v1/assessment-runs").json()["items"] == []

    assert process_next_assessment(database_url=database_url) is False


def test_migration_fails_legacy_ungated_work_closed(database_url: str) -> None:
    legacy_id = uuid4()
    with psycopg.connect(database_url) as connection, connection.transaction():
        _downgrade_to_migration_five(connection)
        connection.execute(
            "ALTER TABLE assessment_runs DROP CONSTRAINT assessment_runs_asset_snapshot_check"
        )
        connection.execute("ALTER TABLE assessment_runs DROP COLUMN asset_snapshot_id")
        connection.execute("DROP TABLE dependency_paths")
        connection.execute("DROP TABLE package_instances")
        connection.execute("DROP TABLE asset_snapshots")
        connection.execute("DROP TABLE environment_profiles")
        connection.execute("DROP FUNCTION reject_asset_snapshot_mutation")
        connection.execute("DROP TABLE policy_decisions")
        connection.execute("DROP FUNCTION reject_policy_decision_mutation")
        connection.execute("ALTER TABLE assessment_runs DROP CONSTRAINT assessment_runs_mode_check")
        connection.execute(
            "ALTER TABLE assessment_runs ADD CONSTRAINT assessment_runs_mode_check "
            "CHECK (mode IN ('synthetic'))"
        )
        connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version IN (4, 5)")
        connection.execute(
            """
            INSERT INTO assessment_runs (
                id, mode, scenario, label, synthetic, status, created_at
            ) VALUES (%s, 'synthetic', 'complete', 'Synthetic Assessment Run', true,
                      'queued', %s)
            """,
            (legacy_id, datetime.now(UTC)),
        )

    apply_migrations(database_url)

    with TestClient(create_app(Settings(database_url=database_url))) as client:
        response = client.get(f"/api/v1/assessment-runs/{legacy_id}")

        assert response.status_code == 200
        assert response.json()["status"] == "failed"
        assert response.json()["errorCode"] == "policy_gate_unavailable"
        assert response.json()["policyDecision"]["result"] == "blocked"
        assert response.json()["policyDecision"]["assistanceClass"] == "C3"
        assert response.json()["policyDecision"]["actionLevel"] == "A4"

    assert process_next_assessment(database_url=database_url) is False


def test_migration_six_seals_existing_version_five_snapshots(database_url: str) -> None:
    environment_id = uuid4()
    snapshot_id = uuid4()
    with psycopg.connect(database_url) as connection, connection.transaction():
        _downgrade_to_migration_five(connection)
        connection.execute(
            """
            INSERT INTO environment_profiles (
                id, python_version, operating_system, architecture, selected_extras
            ) VALUES (%s, '3.12.2', 'linux', 'x86_64', '{}')
            """,
            (environment_id,),
        )
        connection.execute(
            """
            INSERT INTO asset_snapshots (
                id, repository, commit_sha, project_root, lockfile_path,
                lockfile_digest, lockfile_content, environment_profile_id,
                parser_version, captured_at
            ) VALUES (
                %s, 'https://github.com/example/project',
                '0123456789abcdef0123456789abcdef01234567', '.', 'uv.lock',
                'sha256:existing', 'version = 1', %s, 'uv-lock-v1', %s
            )
            """,
            (snapshot_id, environment_id, datetime.now(UTC)),
        )

    apply_migrations(database_url)

    with psycopg.connect(database_url) as connection:
        row = connection.execute(
            "SELECT sealed FROM asset_snapshots WHERE id = %s", (snapshot_id,)
        ).fetchone()
        versions = connection.execute(
            "SELECT version FROM exposure_ledger_schema_migrations ORDER BY version"
        ).fetchall()
        enforcement_point = connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'policy_decisions' AND column_name = 'enforcement_point'"
        ).fetchone()

    assert row == (True,)
    assert [version for (version,) in versions] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    assert enforcement_point == ("enforcement_point",)
