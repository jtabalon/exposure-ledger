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
    CisaKevCatalog,
    CisaKevSource,
    EpssResponseRejected,
    EpssSource,
    ExposureEvidence,
    FirstEpssResponse,
    KevSourceUnavailable,
    OsvBatchResponse,
    OsvPackageQuery,
    OsvQueryBatchSourceAdapter,
    OsvSourceUnavailable,
    RepositoryArchive,
)
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import ExposureRepository
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient

FIXTURE_ROOT = Path(__file__).parents[3] / "packages/domain/tests/fixtures/uv_repository"
LEXICAL_FIXTURE = Path(__file__).parent / "fixtures/lexical-retrieval-v1.json"
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
    def __init__(self, *, include_query_capture: bool = False) -> None:
        self.batches: list[tuple[OsvPackageQuery, ...]] = []
        self._captured_at = datetime(2026, 9, 3, 12, 30, tzinfo=UTC)
        self._include_query_capture = include_query_capture

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
        if self._include_query_capture:
            payload["results"][0]["vulns"][0]["affected"][0]["database_specific"] = {
                "remediation": "Upgrade feature-lib to 5.2 or later"
            }
        captured_payloads = {
            str(vulnerability["id"]): CapturedSourcePayload(
                content=json.dumps(vulnerability, separators=(",", ":"), sort_keys=True),
                captured_at=self._captured_at,
            )
            for result in payload["results"]
            for vulnerability in result.get("vulns", [])
        }
        capture_options: dict[str, object] = {}
        if self._include_query_capture:
            captured_content = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            query_record = OsvQueryBatchSourceAdapter(
                payload_identity="lexical-known-answer-page-v1"
            ).capture(
                payload,
                capture=CapturedSourcePayload(
                    content=captured_content,
                    captured_at=self._captured_at,
                ),
            )
            capture_options = {
                "additional_evidence_records": (query_record,),
                "query_evidence_by_vulnerability": {
                    (result_index, str(vulnerability["id"])): (
                        ExposureEvidence(
                            record_identity=query_record.identity,
                            passage_identities=(query_record.passages[result_index].identity,),
                        ),
                    )
                    for result_index, result in enumerate(payload["results"])
                    for vulnerability in result.get("vulns", [])
                },
            }
        response = OsvBatchResponse.capture(
            payload,
            expected_results=len(queries),
            captured_payloads=captured_payloads,
            **capture_options,
        )
        self._captured_at += timedelta(minutes=1)
        return response


class UnavailableOsvSource:
    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        raise OsvSourceUnavailable("The public OSV API is unavailable.")


class CapturedKevSource(CisaKevSource):
    def __init__(self) -> None:
        self.capture_count = 0

    def catalog(self) -> CisaKevCatalog:
        self.capture_count += 1
        payload = {
            "catalogVersion": "2026.09.03",
            "dateReleased": "2026-09-03T10:15:30Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-4000"}],
        }
        return CisaKevCatalog.capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 12, self.capture_count, tzinfo=UTC),
            ),
        )


class CapturedEpssSource(EpssSource):
    def __init__(self) -> None:
        self.capture_count = 0

    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        self.capture_count += 1
        assert cve_ids == ("CVE-2026-4000",)
        payload = {
            "status": "OK",
            "status-code": 200,
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": "CVE-2026-4000",
                    "epss": "0.420000000",
                    "percentile": "0.970000000",
                    "date": "2026-09-03",
                }
            ],
        }
        return FirstEpssResponse.capture(
            payload,
            cve_ids=cve_ids,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 13, self.capture_count, tzinfo=UTC),
            ),
        )


class UnavailableKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        raise KevSourceUnavailable("The public CISA KEV Source is unavailable.")


class MalformedEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        raise EpssResponseRejected("FIRST EPSS returned a malformed score.")


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
    kev_source = CapturedKevSource()
    epss_source = CapturedEpssSource()

    with TestClient(app) as client:
        first_run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=osv_source,
        kev_source=kev_source,
        epss_source=epss_source,
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
        assert first[0]["kev"] == {
            "state": "available",
            "listed": True,
            "observedAt": "2026-09-03T10:15:30Z",
            "detail": None,
        }
        assert first[0]["epss"] == {
            "state": "available",
            "score": 0.42,
            "percentile": 0.97,
            "observedAt": "2026-09-03T00:00:00Z",
            "detail": None,
        }
        assert first[1]["kev"] == first[0]["kev"]
        assert first[1]["epss"] == first[0]["epss"]
        feature_evidence = first[0]["evidenceRecords"]
        assert len(feature_evidence) == 3
        osv_evidence = next(
            record for record in feature_evidence if record["source"]["identity"] == "osv"
        )
        assert osv_evidence["source"] == {
            "identity": "osv",
            "authority": "Open Source Vulnerabilities",
            "location": "https://api.osv.dev/v1/vulns/PYSEC-2026-40",
        }
        assert osv_evidence["capturedAt"] == "2026-09-03T12:30:00Z"
        assert osv_evidence["contentDigest"].startswith("sha256:")
        assert osv_evidence["attribution"] == "Open Source Vulnerabilities (OSV)"
        assert osv_evidence["aliases"] == [
            "CVE-2026-4000",
            "GHSA-4444-5555-6666",
            "PYSEC-2026-40",
        ]
        assert osv_evidence["payloadIdentity"] == "PYSEC-2026-40"
        assert osv_evidence["passages"] == [
            {
                "id": osv_evidence["passages"][0]["id"],
                "identity": osv_evidence["passages"][0]["identity"],
                "kind": "affected",
                "selector": "/affected/0",
                "content": (
                    '{"package":{"ecosystem":"PyPI","name":"feature_lib"},'
                    '"ranges":[{"events":[{"introduced":"5.0"},{"fixed":"5.2"}],'
                    '"type":"ECOSYSTEM"}]}'
                ),
            }
        ]
        assert {record["source"]["identity"] for record in feature_evidence} == {
            "osv",
            "cisa-kev",
            "first-epss",
        }
        with psycopg.connect(database_url) as connection:
            assert connection.execute("SELECT count(*) FROM evidence_records").fetchone() == (5,)
        with (
            psycopg.connect(database_url) as connection,
            pytest.raises(
                psycopg.errors.RaiseException,
                match="Evidence Records are immutable",
            ),
        ):
            connection.execute(
                "UPDATE evidence_records SET attribution = 'changed' WHERE id = %s",
                (osv_evidence["id"],),
            )
        decisions = [
            item
            for item in client.get("/api/v1/policy-decisions").json()["items"]
            if item["assessmentRunId"] == first_run["id"]
        ]
        assert {item["targetScope"] for item in decisions} == {
            f"https://github.com/example/exposure-fixture@{COMMIT}",
            "https://api.osv.dev/v1",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://api.first.org/data/v1/epss",
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
        kev_source=kev_source,
        epss_source=epss_source,
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
    second_osv_evidence = next(
        record for record in second[0]["evidenceRecords"] if record["source"]["identity"] == "osv"
    )
    assert second_osv_evidence["capturedAt"] == "2026-09-03T12:30:00Z"
    assert len(osv_source.batches) == 2
    assert kev_source.capture_count == 2
    assert epss_source.capture_count == 2


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


def test_exposure_evidence_search_matches_versioned_lexical_known_answers(
    database_url: str,
) -> None:
    fixture = json.loads(LEXICAL_FIXTURE.read_text())
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(include_query_capture=True),
    )

    with TestClient(app) as client:
        exposures = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"]
        target, unrelated = exposures
        evidence_record_ids = {
            record["identity"]: record["id"] for record in target["evidenceRecords"]
        }

        for case in fixture["cases"]:
            response = client.get(
                f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
                params=[
                    ("query", case["query"]),
                    ("sourceIdentity", "osv"),
                    *[("evidenceType", item) for item in case["evidenceTypes"]],
                ],
            )
            assert response.status_code == 200
            result = response.json()
            assert result["queryContext"] == {
                "query": case["query"],
                "assessmentRunId": run["id"],
                "exposureId": target["id"],
                "sourcePolicy": {
                    "version": fixture["sourcePolicyVersion"],
                    "allowedSourceIdentities": ["osv"],
                },
                "evidenceTypes": case["evidenceTypes"],
                "retrievalConfigurationVersion": fixture["retrievalConfigurationVersion"],
                "limit": fixture["limit"],
            }
            assert len(result["items"]) == len(case["expectedPassages"])
            for rank, (item, passage_key) in enumerate(
                zip(result["items"], case["expectedPassages"], strict=True),
                start=1,
            ):
                expected = fixture["passages"][passage_key]
                assert item["lexicalRank"] == rank
                assert item["lexicalScore"] > 0
                assert {key: item["passage"][key] for key in ("identity", "kind", "selector")} == {
                    key: expected[key] for key in ("identity", "kind", "selector")
                }
                assert {
                    key: item["source"][key] for key in ("identity", "authority", "location")
                } == expected["source"]
                assert item["source"]["id"]
                assert item["capture"] == expected["capture"]
                assert (
                    item["evidenceRecordId"] == evidence_record_ids[expected["capture"]["identity"]]
                )
                assert item["exposureContext"] == fixture["exposureContext"]

        exposure_by_scope = {"target": target, "unrelated": unrelated}
        for case in fixture["emptyCases"]:
            scoped_exposure = exposure_by_scope[case["scope"]]
            response = client.get(
                f"/api/v1/assessment-runs/{run['id']}/exposures/{scoped_exposure['id']}"
                "/evidence-passages",
                params=[
                    ("query", case["query"]),
                    *[("sourceIdentity", item) for item in case["sourceIdentities"]],
                    *[("evidenceType", item) for item in case["evidenceTypes"]],
                ],
            )
            assert response.status_code == 200
            assert response.json()["items"] == []


def test_exposure_evidence_search_rejects_stale_configuration_and_wrong_scope(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
    )

    with TestClient(app) as client:
        exposure = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"][0]
        stale = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{exposure['id']}/evidence-passages",
            params={
                "query": "fixed",
                "sourceIdentity": "osv",
                "evidenceType": "affected",
                "retrievalConfigurationVersion": "postgres-lexical-v0",
            },
        )
        assert stale.status_code == 409
        assert stale.json()["detail"]["code"] == "retrieval_configuration_not_current"

        wrong_run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
        wrong_scope = client.get(
            f"/api/v1/assessment-runs/{wrong_run['id']}/exposures/{exposure['id']}"
            "/evidence-passages",
            params={
                "query": "fixed",
                "sourceIdentity": "osv",
                "evidenceType": "affected",
            },
        )
        assert wrong_scope.status_code == 404
        assert wrong_scope.json()["detail"]["code"] == "exposure_not_found"


def test_enrichment_failures_complete_with_explicit_partial_states(database_url: str) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        kev_source=UnavailableKevSource(),
        epss_source=MalformedEpssSource(),
    )

    with TestClient(app) as client:
        completed = client.get(f"/api/v1/assessment-runs/{run['id']}").json()
        exposures = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"]

    assert completed["status"] == "completed"
    assert exposures[0]["kev"] == {
        "state": "unavailable",
        "listed": None,
        "observedAt": None,
        "detail": "The public CISA KEV Source is unavailable.",
    }
    assert exposures[0]["epss"] == {
        "state": "malformed",
        "score": None,
        "percentile": None,
        "observedAt": None,
        "detail": "FIRST EPSS returned a malformed score.",
    }
    assert {record["source"]["identity"] for record in exposures[0]["evidenceRecords"]} == {"osv"}
