from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from exposure_ledger import (
    AssessmentResult,
    CapturedSourcePayload,
    CisaKevCatalog,
    CisaKevSource,
    CisaKevSourceAdapter,
    EpssResponseRejected,
    EpssSource,
    Exposure,
    ExposureEnricher,
    ExposureRanking,
    ExposureSeverity,
    FirstEpssResponse,
    FirstEpssSourceAdapter,
    KevSourceUnavailable,
    PackageInstance,
    PackageSource,
    SourceAdapter,
    SourceObservationState,
    VulnerabilityRecord,
)


def test_cisa_kev_adapter_captures_catalog_provenance_and_matching_passages() -> None:
    adapter: SourceAdapter = CisaKevSourceAdapter()
    payload = {
        "catalogVersion": "2026.09.03",
        "dateReleased": "2026-09-03T10:15:30Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-5000",
                "vendorProject": "Example",
                "product": "Demo",
                "vulnerabilityName": "Example vulnerability",
                "dateAdded": "2026-09-03",
                "shortDescription": "Captured provider text.",
                "requiredAction": "Apply the vendor update.",
                "dueDate": "2026-09-24",
            }
        ],
    }
    content = (
        '{"catalogVersion":"2026.09.03","dateReleased":"2026-09-03T10:15:30Z",'
        '"count":1,"vulnerabilities":[{"cveID":"CVE-2026-5000",'
        '"vendorProject":"Example","product":"Demo","vulnerabilityName":'
        '"Example vulnerability","dateAdded":"2026-09-03","shortDescription":'
        '"Captured provider text.","requiredAction":"Apply the vendor update.",'
        '"dueDate":"2026-09-24"}]}'
    )

    evidence = adapter.capture(
        payload,
        capture=CapturedSourcePayload(
            content=content,
            captured_at=datetime(2026, 9, 3, 10, 16, tzinfo=UTC),
        ),
    )

    assert evidence.source.identity == "cisa-kev"
    assert evidence.source.authority == "Cybersecurity and Infrastructure Security Agency"
    assert evidence.source.location == (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    assert evidence.captured_at == datetime(2026, 9, 3, 10, 16, tzinfo=UTC)
    assert evidence.content_digest.startswith("sha256:")
    assert evidence.attribution == "CISA Known Exploited Vulnerabilities Catalog"
    assert evidence.aliases == ("CVE-2026-5000",)
    assert evidence.payload_identity == "catalog:2026.09.03"
    assert evidence.content == content
    assert len(evidence.passages) == 1
    assert evidence.passages[0].kind == "known_exploited_vulnerability"
    assert evidence.passages[0].selector == "/vulnerabilities/0"
    assert evidence.passages[0].content == (
        '{"cveID":"CVE-2026-5000","vendorProject":"Example","product":"Demo",'
        '"vulnerabilityName":"Example vulnerability","dateAdded":"2026-09-03",'
        '"shortDescription":"Captured provider text.","requiredAction":'
        '"Apply the vendor update.","dueDate":"2026-09-24"}'
    )


def test_first_epss_adapter_captures_query_provenance_and_score_passages() -> None:
    adapter: SourceAdapter = FirstEpssSourceAdapter(cve_ids=("CVE-2026-5000",))
    payload = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2026-5000",
                "epss": "0.125000000",
                "percentile": "0.910000000",
                "date": "2026-09-03",
            }
        ],
    }
    content = (
        '{"status":"OK","status-code":200,"version":"1.0","access":"public",'
        '"total":1,"offset":0,"limit":100,"data":[{"cve":"CVE-2026-5000",'
        '"epss":"0.125000000","percentile":"0.910000000","date":"2026-09-03"}]}'
    )

    evidence = adapter.capture(
        payload,
        capture=CapturedSourcePayload(
            content=content,
            captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
        ),
    )

    assert evidence.source.identity == "first-epss"
    assert evidence.source.authority == "Forum of Incident Response and Security Teams"
    assert evidence.source.location == (
        "https://api.first.org/data/v1/epss?cve=CVE-2026-5000&limit=100"
    )
    assert evidence.captured_at == datetime(2026, 9, 3, 11, 0, tzinfo=UTC)
    assert evidence.content_digest.startswith("sha256:")
    assert evidence.attribution == "FIRST Exploit Prediction Scoring System (EPSS)"
    assert evidence.aliases == ("CVE-2026-5000",)
    assert evidence.payload_identity.startswith("query:sha256:")
    assert evidence.content == content
    assert len(evidence.passages) == 1
    assert evidence.passages[0].kind == "epss_score"
    assert evidence.passages[0].selector == "/data/0"
    assert evidence.passages[0].content == (
        '{"cve":"CVE-2026-5000","epss":"0.125000000",'
        '"percentile":"0.910000000","date":"2026-09-03"}'
    )


def test_first_epss_adapter_rejects_an_out_of_range_score() -> None:
    payload = {
        "status": "OK",
        "status-code": 200,
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2026-5000",
                "epss": "1.100000000",
                "percentile": "0.910000000",
                "date": "2026-09-03",
            }
        ],
    }

    with pytest.raises(EpssResponseRejected, match="between zero and one"):
        FirstEpssSourceAdapter(cve_ids=("CVE-2026-5000",)).capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
            ),
        )


def test_first_epss_adapter_rejects_an_incomplete_response_page() -> None:
    payload = {
        "status": "OK",
        "status-code": 200,
        "total": 2,
        "offset": 0,
        "limit": 1,
        "data": [
            {
                "cve": "CVE-2026-5000",
                "epss": "0.125000000",
                "percentile": "0.910000000",
                "date": "2026-09-03",
            }
        ],
    }

    with pytest.raises(EpssResponseRejected, match="complete response page"):
        FirstEpssSourceAdapter(cve_ids=("CVE-2026-5000", "CVE-2026-6000")).capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
            ),
        )


class CapturedKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        payload = {
            "catalogVersion": "2026.09.03",
            "dateReleased": "2026-09-03T10:15:30Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-5000"}],
        }
        return CisaKevCatalog.capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 10, 16, tzinfo=UTC),
            ),
        )


class CapturedEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        assert cve_ids == ("CVE-2026-5000", "CVE-2026-6000")
        payload = {
            "status": "OK",
            "status-code": 200,
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": "CVE-2026-5000",
                    "epss": "0.125000000",
                    "percentile": "0.910000000",
                    "date": "2026-09-03",
                }
            ],
        }
        return FirstEpssResponse.capture(
            payload,
            cve_ids=cve_ids,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
            ),
        )


def _exposure(vulnerability_identity: str, package_name: str, rank: int) -> Exposure:
    return Exposure(
        vulnerability_identity=vulnerability_identity,
        package=PackageInstance(
            name=package_name,
            version="1.0",
            direct=True,
            source=PackageSource((("registry", "https://pypi.org/simple"),)),
            dependency_paths=(("project", package_name),),
        ),
        ranking=ExposureRanking(
            severity=ExposureSeverity.HIGH,
            direct_dependency=True,
            dependency_depth=1,
            fixed_version_available=True,
            score=69,
        ),
        rank=rank,
        selected_for_investigation=True,
        evidence=(),
    )


def test_enrichment_associates_fresh_matches_and_nonmatches_with_each_exposure() -> None:
    result = AssessmentResult(
        vulnerability_records=(
            VulnerabilityRecord("vulnerability-a", ("CVE-2026-5000", "GHSA-AAAA-BBBB-CCCC")),
            VulnerabilityRecord("vulnerability-b", ("CVE-2026-6000",)),
        ),
        exposures=(
            _exposure("vulnerability-a", "alpha", 1),
            _exposure("vulnerability-b", "beta", 2),
        ),
    )

    enriched = ExposureEnricher(
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
    ).enrich(result)

    matched, not_matched = enriched.exposures
    assert matched.kev.state is SourceObservationState.AVAILABLE
    assert matched.kev.listed is True
    assert matched.kev.observed_at == datetime(2026, 9, 3, 10, 15, 30, tzinfo=UTC)
    assert matched.epss.state is SourceObservationState.AVAILABLE
    assert matched.epss.score == Decimal("0.125000000")
    assert matched.epss.percentile == Decimal("0.910000000")
    assert matched.epss.observed_at == datetime(2026, 9, 3, tzinfo=UTC)

    assert not_matched.kev.state is SourceObservationState.AVAILABLE
    assert not_matched.kev.listed is False
    assert not_matched.kev.observed_at == datetime(2026, 9, 3, 10, 15, 30, tzinfo=UTC)
    assert not_matched.epss.state is SourceObservationState.MISSING
    assert not_matched.epss.score is None
    assert not_matched.epss.percentile is None
    assert not_matched.epss.observed_at is None

    assert {record.source.identity for record in enriched.evidence_records} == {
        "cisa-kev",
        "first-epss",
    }
    assert {record.source.identity for record in _evidence_for(enriched, matched)} == {
        "cisa-kev",
        "first-epss",
    }
    assert {record.source.identity for record in _evidence_for(enriched, not_matched)} == {
        "cisa-kev",
        "first-epss",
    }


def _evidence_for(result: AssessmentResult, exposure: Exposure):
    identities = {reference.record_identity for reference in exposure.evidence}
    return tuple(record for record in result.evidence_records if record.identity in identities)


class StaleKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        payload = {
            "catalogVersion": "2026.08.01",
            "dateReleased": "2026-08-01T10:15:30Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-5000"}],
        }
        return CisaKevCatalog.capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 10, 16, tzinfo=UTC),
            ),
        )


class StaleEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        payload = {
            "status": "OK",
            "status-code": 200,
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": cve_ids[0],
                    "epss": "0.125000000",
                    "percentile": "0.910000000",
                    "date": "2026-08-01",
                }
            ],
        }
        return FirstEpssResponse.capture(
            payload,
            cve_ids=cve_ids,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
            ),
        )


def test_enrichment_retains_stale_values_and_marks_them_partial() -> None:
    result = AssessmentResult(
        vulnerability_records=(VulnerabilityRecord("vulnerability-a", ("CVE-2026-5000",)),),
        exposures=(_exposure("vulnerability-a", "alpha", 1),),
    )

    exposure = (
        ExposureEnricher(
            kev_source=StaleKevSource(),
            epss_source=StaleEpssSource(),
        )
        .enrich(result)
        .exposures[0]
    )

    assert exposure.kev.state is SourceObservationState.STALE
    assert exposure.kev.listed is True
    assert exposure.kev.observed_at == datetime(2026, 8, 1, 10, 15, 30, tzinfo=UTC)
    assert exposure.epss.state is SourceObservationState.STALE
    assert exposure.epss.score == Decimal("0.125000000")
    assert exposure.epss.observed_at == datetime(2026, 8, 1, tzinfo=UTC)
    assert len(exposure.evidence) == 2


class UnavailableKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        raise KevSourceUnavailable("CISA KEV timed out.")


class MalformedEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        raise EpssResponseRejected("FIRST EPSS score was outside its valid range.")


class UnexpectedKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        raise AssertionError("CISA KEV must not be queried without a CVE alias")


class UnexpectedEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        raise AssertionError("FIRST EPSS must not be queried without a CVE alias")


def test_enrichment_marks_sources_missing_without_querying_when_no_cve_alias_exists() -> None:
    result = AssessmentResult(
        vulnerability_records=(VulnerabilityRecord("vulnerability-a", ("GHSA-AAAA-BBBB-CCCC",)),),
        exposures=(_exposure("vulnerability-a", "alpha", 1),),
    )

    enriched = ExposureEnricher(
        kev_source=UnexpectedKevSource(),
        epss_source=UnexpectedEpssSource(),
    ).enrich(result)

    exposure = enriched.exposures[0]
    assert exposure.kev.state is SourceObservationState.MISSING
    assert exposure.kev.listed is None
    assert exposure.epss.state is SourceObservationState.MISSING
    assert exposure.epss.score is None
    assert enriched.evidence_records == ()


def test_enrichment_preserves_independent_failure_states_without_fabricated_negatives() -> None:
    result = AssessmentResult(
        vulnerability_records=(VulnerabilityRecord("vulnerability-a", ("CVE-2026-5000",)),),
        exposures=(_exposure("vulnerability-a", "alpha", 1),),
    )

    enriched = ExposureEnricher(
        kev_source=UnavailableKevSource(),
        epss_source=MalformedEpssSource(),
    ).enrich(result)

    exposure = enriched.exposures[0]
    assert exposure.kev.state is SourceObservationState.UNAVAILABLE
    assert exposure.kev.listed is None
    assert exposure.kev.observed_at is None
    assert exposure.kev.detail == "CISA KEV timed out."
    assert exposure.epss.state is SourceObservationState.MALFORMED
    assert exposure.epss.score is None
    assert exposure.epss.percentile is None
    assert exposure.epss.observed_at is None
    assert enriched.evidence_records == ()


class FutureKevSource(CisaKevSource):
    def catalog(self) -> CisaKevCatalog:
        payload = {
            "catalogVersion": "2026.09.04",
            "dateReleased": "2026-09-04T10:15:30Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-5000"}],
        }
        return CisaKevCatalog.capture(
            payload,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 10, 16, tzinfo=UTC),
            ),
        )


class FutureEpssSource(EpssSource):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        payload = {
            "status": "OK",
            "status-code": 200,
            "total": 1,
            "offset": 0,
            "limit": 100,
            "data": [
                {
                    "cve": cve_ids[0],
                    "epss": "0.125000000",
                    "percentile": "0.910000000",
                    "date": "2026-09-04",
                }
            ],
        }
        return FirstEpssResponse.capture(
            payload,
            cve_ids=cve_ids,
            capture=CapturedSourcePayload(
                content=json.dumps(payload, separators=(",", ":")),
                captured_at=datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
            ),
        )


def test_enrichment_marks_materially_future_observations_as_malformed() -> None:
    result = AssessmentResult(
        vulnerability_records=(VulnerabilityRecord("vulnerability-a", ("CVE-2026-5000",)),),
        exposures=(_exposure("vulnerability-a", "alpha", 1),),
    )

    exposure = (
        ExposureEnricher(
            kev_source=FutureKevSource(),
            epss_source=FutureEpssSource(),
        )
        .enrich(result)
        .exposures[0]
    )

    assert exposure.kev.state is SourceObservationState.MALFORMED
    assert exposure.kev.listed is None
    assert exposure.kev.observed_at is None
    assert exposure.epss.state is SourceObservationState.MALFORMED
    assert exposure.epss.score is None
    assert exposure.epss.percentile is None
    assert exposure.epss.observed_at is None
    assert len(exposure.evidence) == 2
