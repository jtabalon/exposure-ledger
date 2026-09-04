from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from uuid import UUID

import psycopg
import pytest
from exposure_ledger import (
    AssessmentResult,
    CapturedSourcePayload,
    OsvBatchResponse,
    OsvPackageQuery,
    OsvSourceUnavailable,
    RepositoryArchive,
)
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import ExposureRepository
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient

FIXTURE_ROOT = Path(__file__).parents[3] / "packages/domain/tests/fixtures/uv_repository"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class FixtureArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in sorted(FIXTURE_ROOT.rglob("*")):
                if path.is_file():
                    archive.write(
                        path,
                        f"exposure-fixture-{commit}/{path.relative_to(FIXTURE_ROOT)}",
                    )
        return RepositoryArchive(content=buffer.getvalue())


class CapturedOsvSource:
    def __init__(self) -> None:
        self.batches: list[tuple[OsvPackageQuery, ...]] = []
        self._captured_at = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)

    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        self.batches.append(queries)
        assert queries == (
            OsvPackageQuery(name="feature-lib", version="5.1.0"),
            OsvPackageQuery(name="http-x", version="2.3.0"),
            OsvPackageQuery(name="leaf-lib", version="1.0.0"),
            OsvPackageQuery(name="platform-only", version="4.0.0"),
        )
        shared_aliases = ["CVE-2026-4000", "GHSA-4444-5555-6666"]
        payload = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-40",
                            "aliases": shared_aliases,
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {
                                        "ecosystem": "PyPI",
                                        "name": "feature_lib",
                                    },
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "5.0"},
                                                {"fixed": "5.2"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "GHSA-4444-5555-6666",
                            "aliases": ["CVE-2026-4000", "PYSEC-2026-40"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "http-x"},
                                    "versions": ["2.3.0"],
                                }
                            ],
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-99",
                            "aliases": [],
                            "affected": [
                                {
                                    "package": {
                                        "ecosystem": "PyPI",
                                        "name": "leaf-lib",
                                    },
                                    "versions": ["9.9.0"],
                                }
                            ],
                        }
                    ]
                },
                {},
            ]
        }
        captured_payloads = {
            str(vulnerability["id"]): CapturedSourcePayload(
                content=json.dumps(vulnerability, separators=(",", ":"), sort_keys=True),
                captured_at=self._captured_at,
            )
            for result in payload["results"]
            for vulnerability in result.get("vulns", [])
        }
        response = OsvBatchResponse.capture(
            payload,
            expected_results=len(queries),
            captured_payloads=captured_payloads,
        )
        self._captured_at += timedelta(minutes=1)
        return response


class UnavailableOsvSource:
    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        raise OsvSourceUnavailable("The public OSV API is unavailable.")


def repository_payload() -> dict[str, object]:
    return {
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


def test_assessment_exposures_are_package_specific_ranked_and_idempotent(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    osv_source = CapturedOsvSource()

    with TestClient(app) as client:
        first_run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=osv_source,
    )

    with TestClient(app) as client:
        first_response = client.get(f"/api/v1/assessment-runs/{first_run['id']}/exposures")
        assert first_response.status_code == 200
        first = first_response.json()["items"]

        assert [item["package"]["name"] for item in first] == ["feature-lib", "http-x"]
        assert [item["rank"] for item in first] == [1, 2]
        assert all(item["selectedForInvestigation"] for item in first)
        assert first[0]["vulnerabilityRecord"] == first[1]["vulnerabilityRecord"]
        assert first[0]["id"] != first[1]["id"]
        assert first[0]["vulnerabilityRecord"]["aliases"] == [
            "CVE-2026-4000",
            "GHSA-4444-5555-6666",
            "PYSEC-2026-40",
        ]
        assert first[0]["ranking"] == {
            "severity": "high",
            "directDependency": True,
            "dependencyDepth": 1,
            "fixedVersionAvailable": True,
            "score": 69,
        }
        assert first[1]["ranking"] == {
            "severity": "high",
            "directDependency": True,
            "dependencyDepth": 1,
            "fixedVersionAvailable": False,
            "score": 59,
        }
        feature_evidence = first[0]["evidenceRecords"]
        assert len(feature_evidence) == 1
        assert feature_evidence[0]["source"] == {
            "identity": "osv",
            "authority": "Open Source Vulnerabilities",
            "location": "https://api.osv.dev/v1/vulns/PYSEC-2026-40",
        }
        assert feature_evidence[0]["capturedAt"] == "2026-09-03T12:30:00Z"
        assert feature_evidence[0]["contentDigest"].startswith("sha256:")
        assert feature_evidence[0]["attribution"] == "Open Source Vulnerabilities (OSV)"
        assert feature_evidence[0]["aliases"] == [
            "CVE-2026-4000",
            "GHSA-4444-5555-6666",
            "PYSEC-2026-40",
        ]
        assert feature_evidence[0]["payloadIdentity"] == "PYSEC-2026-40"
        assert feature_evidence[0]["passages"] == [
            {
                "id": feature_evidence[0]["passages"][0]["id"],
                "identity": feature_evidence[0]["passages"][0]["identity"],
                "kind": "affected",
                "selector": "/affected/0",
                "content": (
                    '{"package":{"ecosystem":"PyPI","name":"feature_lib"},'
                    '"ranges":[{"events":[{"introduced":"5.0"},{"fixed":"5.2"}],'
                    '"type":"ECOSYSTEM"}]}'
                ),
            }
        ]
        with psycopg.connect(database_url) as connection:
            assert connection.execute("SELECT count(*) FROM evidence_records").fetchone() == (3,)
        with (
            psycopg.connect(database_url) as connection,
            pytest.raises(
                psycopg.errors.RaiseException,
                match="Evidence Records are immutable",
            ),
        ):
            connection.execute(
                "UPDATE evidence_records SET attribution = 'changed' WHERE id = %s",
                (feature_evidence[0]["id"],),
            )
        decisions = [
            item
            for item in client.get("/api/v1/policy-decisions").json()["items"]
            if item["assessmentRunId"] == first_run["id"]
        ]
        assert {item["targetScope"] for item in decisions} == {
            f"https://github.com/example/exposure-fixture@{COMMIT}",
            "https://api.osv.dev/v1",
        }
        assert all(item["result"] == "allowed" for item in decisions)

        replayed = ExposureRepository(database_url).record(
            assessment_run_id=UUID(first_run["id"]),
            asset_snapshot_id=UUID(first[0]["assetSnapshotId"]),
            result=AssessmentResult(vulnerability_records=(), exposures=()),
        )
        assert [str(item.id) for item in replayed] == [item["id"] for item in first]

        second_run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=osv_source,
    )

    with TestClient(app) as client:
        second = client.get(f"/api/v1/assessment-runs/{second_run['id']}/exposures").json()["items"]

    assert [item["id"] for item in second] == [item["id"] for item in first]
    assert [item["vulnerabilityRecord"]["id"] for item in second] == [
        item["vulnerabilityRecord"]["id"] for item in first
    ]
    assert [record["id"] for item in second for record in item["evidenceRecords"]] == [
        record["id"] for item in first for record in item["evidenceRecords"]
    ]
    assert second[0]["evidenceRecords"][0]["capturedAt"] == "2026-09-03T12:30:00Z"
    assert len(osv_source.batches) == 2


def test_osv_unavailability_is_visible_without_fabricated_evidence(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=UnavailableOsvSource(),
    )

    with TestClient(app) as client:
        failed = client.get(f"/api/v1/assessment-runs/{run['id']}").json()
        exposures = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"]

    assert failed["status"] == "failed"
    assert failed["errorCode"] == "osv_unavailable"
    assert failed["errorMessage"] == "The public OSV API is unavailable."
    assert exposures == []
    with psycopg.connect(database_url) as connection:
        assert connection.execute("SELECT count(*) FROM evidence_records").fetchone() == (0,)
