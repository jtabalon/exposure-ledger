from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from exposure_ledger import RepositoryArchive
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient

FIXTURE_ROOT = Path(__file__).parents[3] / "packages/domain/tests/fixtures/uv_repository"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class FixtureArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        assert repository == "https://github.com/example/exposure-fixture"
        assert commit == COMMIT
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in sorted(FIXTURE_ROOT.rglob("*")):
                if path.is_file():
                    archive.write(
                        path, f"exposure-fixture-{commit}/{path.relative_to(FIXTURE_ROOT)}"
                    )
        return RepositoryArchive(content=buffer.getvalue())


def test_asset_snapshot_is_captured_once_and_exposed_as_immutable_scope(
    database_url: str,
) -> None:
    payload = {
        "mode": "repository",
        "repository": "https://github.com/example/exposure-fixture",
        "commit": COMMIT,
        "projectRoot": "services/api",
        "lockfilePath": "services/api/uv.lock",
        "environmentProfile": {
            "pythonVersion": "3.12.2",
            "operatingSystem": "linux",
            "architecture": "x86_64",
            "selectedExtras": ["security"],
        },
    }
    app = create_app(Settings(database_url=database_url))

    with TestClient(app) as client:
        response = client.post("/api/v1/assessment-runs", json=payload)

        assert response.status_code == 201
        assessment = response.json()
        assert assessment["mode"] == "repository"
        assert assessment["synthetic"] is False
        assert assessment["status"] == "queued"
        assert assessment["assetSnapshotId"] is None
        assert assessment["policyDecision"]["targetScope"] == (
            f"https://github.com/example/exposure-fixture@{COMMIT}"
        )

    assert (
        process_next_assessment(database_url=database_url, archive_source=FixtureArchiveSource())
        is True
    )

    with TestClient(app) as client:
        completed = client.get(f"/api/v1/assessment-runs/{assessment['id']}")
        assert completed.status_code == 200
        assert completed.json()["status"] == "completed"
        snapshot_id = completed.json()["assetSnapshotId"]
        assert snapshot_id is not None
        snapshot_response = client.get(f"/api/v1/asset-snapshots/{snapshot_id}")
        assert snapshot_response.status_code == 200
        snapshot = snapshot_response.json()
        UUID(snapshot["id"])
        assert snapshot == {
            "id": snapshot["id"],
            "repository": "https://github.com/example/exposure-fixture",
            "commit": COMMIT,
            "projectRoot": "services/api",
            "lockfilePath": "services/api/uv.lock",
            "lockfileDigest": (
                "sha256:6f36f370f6f43bfe19c0082ef6ef5e51a8fe478f9f6226fbaa39863ec5f3894d"
            ),
            "environmentProfile": {
                "pythonVersion": "3.12.2",
                "operatingSystem": "linux",
                "architecture": "x86_64",
                "selectedExtras": ["security"],
            },
            "packages": [
                {
                    "name": "feature-lib",
                    "version": "5.1.0",
                    "direct": True,
                    "source": {"registry": "https://pypi.org/simple"},
                    "dependencyPaths": [["demo-app", "feature-lib"]],
                },
                {
                    "name": "http-x",
                    "version": "2.3.0",
                    "direct": True,
                    "source": {"registry": "https://pypi.org/simple"},
                    "dependencyPaths": [["demo-app", "http-x"]],
                },
                {
                    "name": "leaf-lib",
                    "version": "1.0.0",
                    "direct": False,
                    "source": {"registry": "https://pypi.org/simple"},
                    "dependencyPaths": [["demo-app", "http-x", "leaf-lib"]],
                },
                {
                    "name": "platform-only",
                    "version": "4.0.0",
                    "direct": True,
                    "source": {"registry": "https://pypi.org/simple"},
                    "dependencyPaths": [["demo-app", "platform-only"]],
                },
            ],
            "parserVersion": "uv-lock-v1",
            "capturedAt": snapshot["capturedAt"],
        }

        with (
            pytest.raises(psycopg.errors.RaiseException),
            psycopg.connect(database_url) as connection,
        ):
            connection.execute(
                """
                INSERT INTO package_instances (
                    id, asset_snapshot_id, name, version, direct, source
                ) VALUES (%s, %s, 'tampered', '1.0.0', false, '{}')
                """,
                (uuid4(), snapshot_id),
            )

        with psycopg.connect(database_url) as connection:
            package_id = connection.execute(
                "SELECT id FROM package_instances WHERE asset_snapshot_id = %s LIMIT 1",
                (snapshot_id,),
            ).fetchone()
        assert package_id is not None
        with (
            pytest.raises(psycopg.errors.RaiseException),
            psycopg.connect(database_url) as connection,
        ):
            connection.execute(
                "INSERT INTO dependency_paths (package_instance_id, path) VALUES (%s, %s)",
                (package_id[0], ["tampered", "path"]),
            )

        duplicate = client.post("/api/v1/assessment-runs", json=payload)
        assert duplicate.status_code == 201
        assert duplicate.json()["id"] != assessment["id"]
        assert duplicate.json()["assetSnapshotId"] is None

        retrieval = client.get(f"/api/v1/asset-snapshots/{snapshot['id']}")
        assert retrieval.status_code == 200
        assert retrieval.json() == snapshot

        listing = client.get("/api/v1/asset-snapshots")
        assert listing.status_code == 200
        assert listing.json() == {"items": [snapshot]}

        events = client.get(f"/api/v1/assessment-runs/{assessment['id']}/events?follow=false")
        assert "event: assessment.asset_snapshot_captured" in events.text
        assert "event: assessment.completed" in events.text
        decisions = client.get("/api/v1/policy-decisions").json()["items"]
        assert {decision["enforcementPoint"] for decision in decisions} == {
            "request",
            "tool_call",
        }

    assert (
        process_next_assessment(database_url=database_url, archive_source=FixtureArchiveSource())
        is True
    )

    with TestClient(app) as client:
        duplicate_completed = client.get(f"/api/v1/assessment-runs/{duplicate.json()['id']}")
        assert duplicate_completed.json()["assetSnapshotId"] == snapshot["id"]


def test_asset_snapshot_rejection_is_typed_and_does_not_persist(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "repository",
                "repository": "https://github.com/example/exposure-fixture/tree/main",
                "commit": COMMIT,
                "projectRoot": "services/api",
                "lockfilePath": "services/api/uv.lock",
                "environmentProfile": {
                    "pythonVersion": "3.12",
                    "operatingSystem": "linux",
                    "architecture": "x86_64",
                    "selectedExtras": [],
                },
            },
        )

        assert response.status_code == 422
        assert response.json() == {
            "detail": {
                "code": "invalid_repository",
                "message": "repository must identify a canonical public GitHub repository",
            }
        }
        assert client.get("/api/v1/asset-snapshots").json() == {"items": []}
        decisions = client.get("/api/v1/policy-decisions").json()["items"]
        assert len(decisions) == 1
        assert decisions[0]["targetScope"] == (
            f"https://github.com/example/exposure-fixture/tree/main@{COMMIT}"
        )
        assert decisions[0]["result"] == "blocked"
        assert decisions[0]["enforcementPoint"] == "request"


def test_policy_gate_runs_before_repository_retrieval(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "repository",
                "repository": "https://github.com/example/exposure-fixture",
                "commit": COMMIT,
                "projectRoot": "services/api",
                "lockfilePath": "services/api/uv.lock",
                "environmentProfile": {
                    "pythonVersion": "3.12",
                    "operatingSystem": "linux",
                    "architecture": "x86_64",
                },
                "policyContext": {"operationChain": ["generate_exploit"]},
            },
        )

        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["policyDecision"]["result"] == "blocked"
        assert client.get("/api/v1/assessment-runs").json() == {"items": []}
        assert client.get("/api/v1/asset-snapshots").json() == {"items": []}
