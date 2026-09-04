from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from exposure_ledger import RepositoryArchive, RepositoryArchiveUnavailable
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


class RedirectedArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        raise RepositoryArchiveUnavailable(
            "repository_redirect_rejected",
            "GitHub archive redirects are not accepted.",
        )


class ExcessiveFileCountArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("project-root/services/api/uv.lock", "version = 1")
            for index in range(5_000):
                archive.writestr(f"project-root/generated/{index}.txt", "")
        return RepositoryArchive(content=buffer.getvalue())


def repository_assessment_payload() -> dict[str, object]:
    return {
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
    }


class RequirementsArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                f"requirements-fixture-{commit}/requirements.txt",
                "http-x==2.3.0\nleaf-lib==1.0.0\n",
            )
        return RepositoryArchive(content=buffer.getvalue())


class UnpinnedRequirementsArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                f"requirements-fixture-{commit}/requirements.txt",
                "http-x>=2.3\n",
            )
        return RepositoryArchive(content=buffer.getvalue())


class PoetryArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                f"poetry-fixture-{commit}/pyproject.toml",
                """
[project]
name = "poetry-app"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["http-x>=2,<3"]
""",
            )
            archive.writestr(
                f"poetry-fixture-{commit}/poetry.lock",
                """
[[package]]
name = "http-x"
version = "2.3.0"
python-versions = ">=3.12"
groups = ["main"]

[package.dependencies]
leaf-lib = ">=1,<2"

[[package]]
name = "leaf-lib"
version = "1.0.0"
python-versions = ">=3.12"
groups = ["main"]

[metadata]
lock-version = "2.1"
python-versions = ">=3.12"
content-hash = "fixture"
""",
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
                "sha256:9ecd0209306e7e59e67eaf9f4aaed668726f42209685c974ca363345e18d9542"
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


def test_pinned_requirements_unknown_dependency_paths_are_visible_in_api(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "repository",
                "repository": "https://github.com/example/requirements-fixture",
                "commit": COMMIT,
                "projectRoot": ".",
                "lockfilePath": "requirements.txt",
                "environmentProfile": {
                    "pythonVersion": "3.12.2",
                    "operatingSystem": "linux",
                    "architecture": "x86_64",
                },
            },
        )
        assert response.status_code == 201
        assessment_id = response.json()["id"]

    assert process_next_assessment(
        database_url=database_url, archive_source=RequirementsArchiveSource()
    )

    with TestClient(app) as client:
        assessment = client.get(f"/api/v1/assessment-runs/{assessment_id}").json()
        assert assessment["status"] == "completed"
        snapshot = client.get(f"/api/v1/asset-snapshots/{assessment['assetSnapshotId']}").json()
        assert snapshot["parserVersion"] == "requirements-v1"
        assert snapshot["packages"] == [
            {
                "name": "http-x",
                "version": "2.3.0",
                "direct": None,
                "source": {"manifest": "requirements.txt"},
                "dependencyPaths": None,
            },
            {
                "name": "leaf-lib",
                "version": "1.0.0",
                "direct": None,
                "source": {"manifest": "requirements.txt"},
                "dependencyPaths": None,
            },
        ]


def test_unpinned_requirements_rejection_code_is_visible_in_api(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "repository",
                "repository": "https://github.com/example/requirements-fixture",
                "commit": COMMIT,
                "projectRoot": ".",
                "lockfilePath": "requirements.txt",
                "environmentProfile": {
                    "pythonVersion": "3.12.2",
                    "operatingSystem": "linux",
                    "architecture": "x86_64",
                },
            },
        )
        assessment_id = response.json()["id"]

    assert process_next_assessment(
        database_url=database_url, archive_source=UnpinnedRequirementsArchiveSource()
    )

    with TestClient(app) as client:
        assessment = client.get(f"/api/v1/assessment-runs/{assessment_id}").json()
        assert assessment["status"] == "failed"
        assert assessment["errorCode"] == "unpinned_requirement"
        assert (
            assessment["errorMessage"] == "requirement http-x must pin exactly one version with =="
        )
        events = client.get(f"/api/v1/assessment-runs/{assessment_id}/events?follow=false").text
        assert '"code":"unpinned_requirement"' in events


def test_poetry_lock_can_be_selected_through_the_assessment_flow(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/assessment-runs",
            json={
                "mode": "repository",
                "repository": "https://github.com/example/poetry-fixture",
                "commit": COMMIT,
                "projectRoot": ".",
                "lockfilePath": "poetry.lock",
                "environmentProfile": {
                    "pythonVersion": "3.12.2",
                    "operatingSystem": "linux",
                    "architecture": "x86_64",
                },
            },
        )
        assert response.status_code == 201
        assessment_id = response.json()["id"]

    assert process_next_assessment(database_url=database_url, archive_source=PoetryArchiveSource())

    with TestClient(app) as client:
        assessment = client.get(f"/api/v1/assessment-runs/{assessment_id}").json()
        assert assessment["status"] == "completed"
        snapshot = client.get(f"/api/v1/asset-snapshots/{assessment['assetSnapshotId']}").json()
        assert snapshot["parserVersion"] == "poetry-lock-v1"
        assert [
            (package["name"], package["direct"], package["dependencyPaths"])
            for package in snapshot["packages"]
        ] == [
            ("http-x", True, [["poetry-app", "http-x"]]),
            ("leaf-lib", False, [["poetry-app", "http-x", "leaf-lib"]]),
        ]


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


@pytest.mark.parametrize(
    "selection",
    [
        None,
        {"projectRoot": None, "lockfilePath": None},
        {"project_root": None, "lockfile_path": None},
    ],
)
def test_repository_assessment_requires_explicit_project_and_lockfile_selection(
    database_url: str,
    selection: dict[str, object] | None,
) -> None:
    app = create_app(Settings(database_url=database_url))
    payload = repository_assessment_payload()
    if selection is None:
        payload.pop("projectRoot")
        payload.pop("lockfilePath")
    else:
        payload.update(selection)

    with TestClient(app) as client:
        response = client.post("/api/v1/assessment-runs", json=payload)

        assert response.status_code == 422
        assert response.json() == {
            "detail": {
                "code": "asset_snapshot_selection_required",
                "message": (
                    "Select exactly one project root and one supported lockfile before "
                    "capturing an Asset Snapshot."
                ),
            }
        }
        assert client.get("/api/v1/assessment-runs").json() == {"items": []}
        assert client.get("/api/v1/asset-snapshots").json() == {"items": []}
        decisions = client.get("/api/v1/policy-decisions").json()["items"]
        assert len(decisions) == 1
        assert decisions[0]["result"] == "blocked"
        assert decisions[0]["enforcementPoint"] == "request"
        repository_schema = client.get("/openapi.json").json()["components"]["schemas"][
            "CreateRepositoryAssessmentRunRequest"
        ]
        assert {"projectRoot", "lockfilePath"} <= set(repository_schema["required"])


def test_repository_source_rejection_is_typed_and_does_not_create_a_partial_snapshot(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))

    with TestClient(app) as client:
        queued = client.post("/api/v1/assessment-runs", json=repository_assessment_payload())
        assert queued.status_code == 201

        assert (
            process_next_assessment(
                database_url=database_url,
                archive_source=RedirectedArchiveSource(),
            )
            is True
        )

        failed = client.get(f"/api/v1/assessment-runs/{queued.json()['id']}")
        assert failed.status_code == 200
        assert failed.json()["status"] == "failed"
        assert failed.json()["errorCode"] == "repository_redirect_rejected"
        assert failed.json()["errorMessage"] == "GitHub archive redirects are not accepted."
        assert failed.json()["assetSnapshotId"] is None
        assert client.get("/api/v1/asset-snapshots").json() == {"items": []}


def test_capture_ceiling_is_typed_and_does_not_create_a_partial_snapshot(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))

    with TestClient(app) as client:
        queued = client.post("/api/v1/assessment-runs", json=repository_assessment_payload())
        assert queued.status_code == 201

        assert (
            process_next_assessment(
                database_url=database_url,
                archive_source=ExcessiveFileCountArchiveSource(),
            )
            is True
        )

        failed = client.get(f"/api/v1/assessment-runs/{queued.json()['id']}")
        assert failed.status_code == 200
        assert failed.json()["status"] == "failed"
        assert failed.json()["errorCode"] == "archive_too_many_files"
        assert failed.json()["assetSnapshotId"] is None
        assert client.get("/api/v1/asset-snapshots").json() == {"items": []}


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
