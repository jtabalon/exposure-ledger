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
    AssessmentOperation,
    AssessmentRequest,
    AssessmentResult,
    AuthorizationStatus,
    CapturedSourcePayload,
    CisaKevCatalog,
    CisaKevSource,
    CyberPolicy,
    EmbeddingSpace,
    EpssResponseRejected,
    EpssSource,
    EvidenceRecord,
    ExposureEvidence,
    FirstEpssResponse,
    GitHubAdvisorySourceUnavailable,
    GitHubAdvisoryTarget,
    GitHubRepositoryAdvisoryAdapter,
    KevSourceUnavailable,
    OsvBatchResponse,
    OsvPackageQuery,
    OsvQueryBatchSourceAdapter,
    OsvSourceUnavailable,
    RepositoryArchive,
)
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import (
    HYBRID_RETRIEVAL_CONFIGURATION_VERSION,
    AssessmentRunRepository,
    EmbeddingIndexUnavailable,
    EmbeddingProviderUnavailable,
    EmbeddingReadiness,
    EvidenceRetriever,
    ExposureRepository,
    build_exposure_retrieval_query,
    evaluate_retrieval_recall,
)
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient

FIXTURE_ROOT = Path(__file__).parents[3] / "packages/domain/tests/fixtures/uv_repository"
LEXICAL_FIXTURE = Path(__file__).parent / "fixtures/lexical-retrieval-v1.json"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class KnownAnswerEmbeddingProvider:
    def __init__(self, *, digest_character: str = "a", reverse: bool = False) -> None:
        self.space = EmbeddingSpace(
            provider="known-answer-local",
            model_artifact="known-answer-embedding-v1",
            artifact_digest="sha256:" + digest_character * 64,
            dimensions=3,
            retrieval_instruction="Represent this query for evidence passage retrieval: ",
            normalizer="l2-v1",
            passage_construction_version="source-aware-passage-v1",
        )
        self._reverse = reverse

    def check_readiness(self) -> EmbeddingReadiness:
        return EmbeddingReadiness(
            status="ready",
            code=None,
            message="Known-answer local provider is ready.",
            setup=None,
            space=self.space,
        )

    def require_space(self) -> EmbeddingSpace:
        return self.space

    def embed_query(self, text: str, space: EmbeddingSpace) -> tuple[float, ...]:
        assert space.identity == self.space.identity
        return (1.0, 0.0, 0.0)

    def embed_passages(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]:
        assert space.identity == self.space.identity
        vectors = []
        for text in texts:
            is_query_capture = '"vulns"' in text
            first = (0.0, 1.0, 0.0) if is_query_capture else (1.0, 0.0, 0.0)
            second = (1.0, 0.0, 0.0) if is_query_capture else (0.0, 1.0, 0.0)
            vectors.append(second if self._reverse else first)
        return tuple(vectors)


class UnavailableEmbeddingProvider:
    def check_readiness(self) -> EmbeddingReadiness:
        return EmbeddingReadiness(
            status="unavailable",
            code="embedding_runtime_unavailable",
            message="Local Ollama embedding runtime is unavailable.",
            setup="Start Ollama locally and run `make models`, then retry.",
            space=None,
        )

    def require_space(self) -> EmbeddingSpace:
        raise EmbeddingProviderUnavailable(self.check_readiness())

    def embed_query(self, text: str, space: EmbeddingSpace) -> tuple[float, ...]:
        raise AssertionError("Unavailable provider must not embed a query")

    def embed_passages(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]:
        raise AssertionError("Unavailable provider must not embed passages")


class InterruptOnceEmbeddingProvider(KnownAnswerEmbeddingProvider):
    def __init__(self) -> None:
        super().__init__()
        self._interrupted = False

    def embed_passages(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]:
        if not self._interrupted:
            self._interrupted = True
            raise KeyboardInterrupt("simulated worker interruption after evidence commit")
        return super().embed_passages(texts, space)


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


class AdvisoryLinkedOsvSource:
    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        payload = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-40",
                            "aliases": ["CVE-2026-4000", "GHSA-4444-5555-6666"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {
                                        "ecosystem": "PyPI",
                                        "name": "feature-lib",
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
                            "references": [
                                {
                                    "type": "ADVISORY",
                                    "url": (
                                        "https://github.com/acme/feature-lib/security/advisories/"
                                        "GHSA-4444-5555-6666"
                                    ),
                                }
                            ],
                        }
                    ]
                },
                {},
                {},
                {},
            ]
        }
        vulnerability = payload["results"][0]["vulns"][0]  # type: ignore[index]
        assert isinstance(vulnerability, dict)
        return OsvBatchResponse.capture(
            payload,
            expected_results=len(queries),
            captured_payloads={
                "PYSEC-2026-40": CapturedSourcePayload(
                    content=json.dumps(vulnerability, separators=(",", ":"), sort_keys=True),
                    captured_at=datetime(2026, 9, 4, 10, 0, tzinfo=UTC),
                )
            },
        )


class ConflictingAdvisorySource:
    def retrieve(self, targets: tuple[GitHubAdvisoryTarget, ...]) -> tuple[EvidenceRecord, ...]:
        assert len(targets) == 1
        target = targets[0]
        payload = {
            "ghsa_id": target.advisory_id,
            "cve_id": "CVE-2026-4000",
            "url": target.api_url,
            "html_url": target.publication_url,
            "summary": "Maintainer guidance for feature-lib.",
            "description": "Upgrade feature-lib.",
            "published_at": "2026-09-02T12:00:00Z",
            "updated_at": "2026-09-04T09:00:00Z",
            "withdrawn_at": None,
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "feature-lib"},
                    "vulnerable_version_range": ">= 5.0, < 5.1",
                    "patched_versions": "5.1",
                }
            ],
        }
        return (
            GitHubRepositoryAdvisoryAdapter(target).capture(
                payload,
                capture=CapturedSourcePayload(
                    content=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    captured_at=datetime(2026, 9, 4, 10, 1, tzinfo=UTC),
                ),
            ),
        )


class UnavailableAdvisorySource:
    def retrieve(self, targets: tuple[GitHubAdvisoryTarget, ...]) -> tuple[EvidenceRecord, ...]:
        raise GitHubAdvisorySourceUnavailable(
            "The GitHub repository advisory source is unavailable."
        )


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


def test_embedding_provider_outage_preserves_evidence_and_explicit_setup(
    database_url: str,
) -> None:
    provider = UnavailableEmbeddingProvider()
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        embedding_provider=provider,
    )

    with TestClient(app) as client:
        failed = client.get(f"/api/v1/assessment-runs/{run['id']}").json()
        exposures = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"]

    assert failed["status"] == "failed"
    assert failed["errorCode"] == "embedding_runtime_unavailable"
    assert failed["errorMessage"] == (
        "Local Ollama embedding runtime is unavailable. "
        "Start Ollama locally and run `make models`, then retry."
    )
    assert exposures
    assert exposures[0]["evidenceRecords"]


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
                    (
                        "retrievalConfigurationVersion",
                        fixture["retrievalConfigurationVersion"],
                    ),
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
                "embeddingSpace": None,
                "limit": fixture["limit"],
            }
            assert result["evaluation"] is None
            assert len(result["items"]) == len(case["expectedPassages"])
            for rank, (item, passage_key) in enumerate(
                zip(result["items"], case["expectedPassages"], strict=True),
                start=1,
            ):
                expected = fixture["passages"][passage_key]
                assert item["fullTextRank"] == rank
                assert item["fullTextScore"] > 0
                assert item["vectorRank"] is None
                assert item["fusedRank"] is None
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
                    (
                        "retrievalConfigurationVersion",
                        fixture["retrievalConfigurationVersion"],
                    ),
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


def test_hybrid_retrieval_is_deterministic_space_isolated_and_reports_recall(
    database_url: str,
) -> None:
    fixture = json.loads(LEXICAL_FIXTURE.read_text())
    first_provider = KnownAnswerEmbeddingProvider()
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(include_query_capture=True),
        embedding_provider=first_provider,
    )

    second_provider = KnownAnswerEmbeddingProvider(digest_character="b", reverse=True)
    with pytest.raises(EmbeddingIndexUnavailable, match="retrieved-content Policy Decision"):
        EvidenceRetriever(database_url, embedding_provider=second_provider).index_assessment(
            UUID(run["id"])
        )
    AssessmentRunRepository(database_url).record_retrieved_content_policy_decision(
        UUID(run["id"]),
        CyberPolicy.decide(
            AssessmentRequest(
                operation=AssessmentOperation.EMBED_RETRIEVED_EVIDENCE,
                target_scope=(
                    f"assessment:{run['id']};embedding-space:{second_provider.space.identity}"
                ),
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
            )
        ),
    )
    EvidenceRetriever(database_url, embedding_provider=second_provider).index_assessment(
        UUID(run["id"])
    )

    with TestClient(app) as client:
        target = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"][0]
        query_text = build_exposure_retrieval_query(
            target["package"]["name"],
            target["package"]["version"],
            tuple(target["vulnerabilityRecord"]["aliases"]),
        )
        assert target["retrievalQuery"] == query_text
        params = [
            ("query", query_text),
            ("sourceIdentity", "osv"),
            ("evidenceType", "affected"),
            ("evidenceType", "query_result"),
            ("retrievalConfigurationVersion", HYBRID_RETRIEVAL_CONFIGURATION_VERSION),
            ("embeddingSpaceIdentity", first_provider.space.identity),
            (
                "expectedPassageIdentity",
                fixture["passages"]["targetAffected"]["identity"],
            ),
            (
                "expectedPassageIdentity",
                fixture["passages"]["targetQueryResult"]["identity"],
            ),
            ("limit", "2"),
        ]
        first = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
            params=params,
        )
        replay = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
            params=params,
        )

        assert first.status_code == 200
        assert replay.json() == first.json()
        result = first.json()
        assert result["queryContext"]["embeddingSpace"] == {
            "identity": first_provider.space.identity,
            "provider": "known-answer-local",
            "modelArtifact": "known-answer-embedding-v1",
            "artifactDigest": "sha256:" + "a" * 64,
            "dimensions": 3,
            "retrievalInstruction": "Represent this query for evidence passage retrieval: ",
            "normalizer": "l2-v1",
            "passageConstructionVersion": "source-aware-passage-v1",
        }
        assert [item["fusedRank"] for item in result["items"]] == [1, 2]
        assert sorted(item["vectorRank"] for item in result["items"]) == [1, 2]
        assert all("fullTextRank" in item for item in result["items"])
        assert result["evaluation"] == {
            "k": 2,
            "expectedCount": 2,
            "retrievedCount": 2,
            "matchedPassageIdentities": [
                fixture["passages"]["targetAffected"]["identity"],
                fixture["passages"]["targetQueryResult"]["identity"],
            ],
            "recallAtK": 1.0,
        }
        first_vector_ranks = {
            item["passage"]["identity"]: item["vectorRank"] for item in result["items"]
        }
        assert first_vector_ranks == {
            fixture["passages"]["targetAffected"]["identity"]: 1,
            fixture["passages"]["targetQueryResult"]["identity"]: 2,
        }

        wrong_space = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
            params={
                "query": query_text,
                "sourceIdentity": "osv",
                "evidenceType": "affected",
                "embeddingSpaceIdentity": "sha256:" + "c" * 64,
            },
        )
        assert wrong_space.status_code == 409
        assert wrong_space.json()["detail"]["code"] == "embedding_space_not_current"

    with TestClient(app) as client:
        second = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
            params=[
                ("query", query_text),
                ("sourceIdentity", "osv"),
                ("evidenceType", "affected"),
                ("evidenceType", "query_result"),
                ("embeddingSpaceIdentity", second_provider.space.identity),
                ("limit", "2"),
            ],
        )
    assert second.status_code == 200
    assert second.json()["queryContext"]["embeddingSpace"]["identity"] == (
        second_provider.space.identity
    )
    assert {item["passage"]["identity"]: item["vectorRank"] for item in second.json()["items"]} == {
        fixture["passages"]["targetAffected"]["identity"]: 2,
        fixture["passages"]["targetQueryResult"]["identity"]: 1,
    }

    report = evaluate_retrieval_recall(
        retrieved_passage_identities=("expected-a", "other"),
        expected_passage_identities=("expected-a", "expected-b"),
        k=2,
    )
    assert report.recall_at_k == 0.5
    assert report.matched_passage_identities == ("expected-a",)

    with TestClient(app) as client:
        unavailable = client.get(
            f"/api/v1/assessment-runs/{run['id']}/exposures/{target['id']}/evidence-passages",
            params={
                "query": "not generated by the worker",
                "sourceIdentity": "osv",
                "evidenceType": "affected",
                "embeddingSpaceIdentity": first_provider.space.identity,
            },
        )
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == {
        "code": "embedding_index_unavailable",
        "message": (
            "No worker-generated query representation exists for this query and "
            "Embedding Space. Use the exposure's indexed retrieval query."
        ),
        "setup": "Run a new Assessment after `make models` succeeds.",
    }


def test_recovered_worker_indexes_existing_evidence_before_completion(
    database_url: str,
) -> None:
    provider = InterruptOnceEmbeddingProvider()
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    with pytest.raises(KeyboardInterrupt, match="simulated worker interruption"):
        process_next_assessment(
            database_url=database_url,
            archive_source=FixtureArchiveSource(),
            osv_source=CapturedOsvSource(include_query_capture=True),
            embedding_provider=provider,
        )

    with psycopg.connect(database_url) as connection:
        connection.execute(
            "UPDATE assessment_runs SET claimed_at = now() - interval '1 minute' WHERE id = %s",
            (run["id"],),
        )
        connection.commit()

    assert process_next_assessment(
        database_url=database_url,
        stale_after_seconds=1,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(include_query_capture=True),
        embedding_provider=provider,
    )

    with psycopg.connect(database_url) as connection:
        status_row = connection.execute(
            "SELECT status FROM assessment_runs WHERE id = %s", (run["id"],)
        ).fetchone()
        embedding_count = connection.execute("SELECT count(*) FROM passage_embeddings").fetchone()
        content_policy_count = connection.execute(
            """
            SELECT count(*) FROM policy_decisions
            WHERE assessment_run_id = %s AND enforcement_point = 'retrieved_content'
            """,
            (run["id"],),
        ).fetchone()

    assert status_row == ("completed",)
    assert embedding_count is not None and embedding_count[0] > 0
    assert content_policy_count == (2,)


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


def test_first_party_advisory_conflict_is_preserved_through_the_http_contract(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=AdvisoryLinkedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
        advisory_source=ConflictingAdvisorySource(),
    )

    with TestClient(app) as client:
        exposure = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"][0]
        decisions = [
            item
            for item in client.get("/api/v1/policy-decisions").json()["items"]
            if item["assessmentRunId"] == run["id"]
        ]

    assert exposure["authoritativeConflict"] is True
    assert exposure["kev"]["state"] == "available"
    assert exposure["epss"]["state"] == "available"
    evidence_by_source = {item["source"]["identity"]: item for item in exposure["evidenceRecords"]}
    assert evidence_by_source["osv"]["relationship"] == "contradicts"
    advisory = evidence_by_source["github_repository_security_advisory"]
    assert advisory["relationship"] == "contradicts"
    assert advisory["source"]["authority"] == "Repository maintainer"
    assert advisory["payloadIdentity"] == "GHSA-4444-5555-6666"
    assert [item["kind"] for item in advisory["passages"]] == [
        "publication",
        "affected_guidance",
    ]
    assert '"patched_versions":"5.1"' in advisory["passages"][1]["content"]
    assert {item["targetScope"] for item in decisions} == {
        f"https://github.com/example/exposure-fixture@{COMMIT}",
        "https://api.osv.dev/v1",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://api.first.org/data/v1/epss",
        ("https://api.github.com/repos/acme/feature-lib/security-advisories/GHSA-4444-5555-6666"),
    }


def test_unavailable_first_party_source_keeps_enriched_osv_evidence_visible(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=AdvisoryLinkedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
        advisory_source=UnavailableAdvisorySource(),
    )

    with TestClient(app) as client:
        failed = client.get(f"/api/v1/assessment-runs/{run['id']}").json()
        exposures = client.get(f"/api/v1/assessment-runs/{run['id']}/exposures").json()["items"]

    assert failed["status"] == "failed"
    assert failed["errorCode"] == "first_party_advisory_unavailable"
    assert exposures[0]["kev"]["state"] == "available"
    assert exposures[0]["epss"]["state"] == "available"
    assert {item["source"]["identity"] for item in exposures[0]["evidenceRecords"]} == {
        "osv",
        "cisa-kev",
        "first-epss",
    }
    assert all(
        item["source"]["identity"] != "github_repository_security_advisory"
        for exposure in exposures
        for item in exposure["evidenceRecords"]
    )
