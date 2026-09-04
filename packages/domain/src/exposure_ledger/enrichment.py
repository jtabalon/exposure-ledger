"""Deterministic KEV and EPSS enrichment for package-specific Exposures."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol
from urllib.parse import urlencode

from exposure_ledger.evidence import (
    CapturedJsonRejected,
    CapturedSourcePayload,
    EvidencePassage,
    EvidenceRecord,
    Source,
    load_captured_json,
)
from exposure_ledger.exposures import (
    AssessmentResult,
    EpssSignal,
    Exposure,
    ExposureEvidence,
    KevSignal,
    SourceObservationState,
)

CISA_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
_EPSS_BATCH_SIZE = 50


class KevResponseRejected(ValueError):
    """A captured CISA KEV response violates the provider contract."""


class EpssResponseRejected(ValueError):
    """A captured FIRST EPSS response violates the provider contract."""


class KevSourceUnavailable(RuntimeError):
    """The allowlisted public CISA KEV Source could not be captured."""


class EpssSourceUnavailable(RuntimeError):
    """The allowlisted public FIRST EPSS Source could not be captured."""


@dataclass(frozen=True, slots=True)
class KevCatalogEntry:
    cve_id: str
    evidence_passage_identity: str


@dataclass(frozen=True, slots=True)
class CisaKevCatalog:
    observed_at: datetime
    entries: tuple[KevCatalogEntry, ...]
    evidence_record: EvidenceRecord

    @classmethod
    def capture(
        cls,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> CisaKevCatalog:
        try:
            evidence = CisaKevSourceAdapter().capture(payload, capture=capture)
            observed_at = _parse_datetime(payload.get("dateReleased"), "CISA KEV dateReleased")
        except (TypeError, ValueError) as error:
            if isinstance(error, KevResponseRejected):
                raise
            raise KevResponseRejected(str(error)) from error
        return cls(
            observed_at=observed_at,
            entries=tuple(
                KevCatalogEntry(
                    cve_id=_kev_identifier(vulnerability),
                    evidence_passage_identity=evidence.passages[index].identity,
                )
                for index, vulnerability in enumerate(payload["vulnerabilities"])
            ),
            evidence_record=evidence,
        )


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve_id: str
    score: Decimal
    percentile: Decimal
    observed_at: datetime
    evidence_passage_identity: str


@dataclass(frozen=True, slots=True)
class FirstEpssResponse:
    scores: tuple[EpssScore, ...]
    evidence_record: EvidenceRecord

    @classmethod
    def capture(
        cls,
        payload: Mapping[str, Any],
        *,
        cve_ids: tuple[str, ...],
        capture: CapturedSourcePayload,
    ) -> FirstEpssResponse:
        try:
            evidence = FirstEpssSourceAdapter(cve_ids=cve_ids).capture(
                payload,
                capture=capture,
            )
            raw_scores = payload["data"]
            if not isinstance(raw_scores, Sequence) or isinstance(raw_scores, (str, bytes)):
                raise EpssResponseRejected("FIRST EPSS response must contain a data array")
            scores = tuple(
                _epss_score(
                    item,
                    evidence_passage_identity=evidence.passages[index].identity,
                )
                for index, item in enumerate(raw_scores)
            )
        except (KeyError, TypeError, ValueError) as error:
            if isinstance(error, EpssResponseRejected):
                raise
            raise EpssResponseRejected(str(error)) from error
        return cls(scores=scores, evidence_record=evidence)


class CisaKevSource(Protocol):
    def catalog(self) -> CisaKevCatalog: ...


class EpssSource(Protocol):
    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse: ...


@dataclass(frozen=True, slots=True)
class _CapturedEnrichment:
    kev_catalog: CisaKevCatalog | None
    kev_failure: tuple[SourceObservationState, str] | None
    epss_failures: Mapping[str, tuple[SourceObservationState, str]]
    epss_response_by_cve: Mapping[str, FirstEpssResponse]
    epss_score_by_cve: Mapping[str, tuple[EpssScore, FirstEpssResponse]]


class ExposureEnricher:
    """Associate independently captured KEV and EPSS observations with Exposures."""

    def __init__(
        self,
        *,
        kev_source: CisaKevSource,
        epss_source: EpssSource,
        kev_max_age: timedelta = timedelta(days=7),
        epss_max_age: timedelta = timedelta(days=2),
        future_tolerance: timedelta = timedelta(minutes=5),
    ) -> None:
        self._kev_source = kev_source
        self._epss_source = epss_source
        self._kev_max_age = kev_max_age
        self._epss_max_age = epss_max_age
        self._future_tolerance = future_tolerance

    def enrich(self, result: AssessmentResult) -> AssessmentResult:
        aliases_by_vulnerability = {
            record.identity: tuple(
                alias for alias in record.aliases if _CVE_PATTERN.fullmatch(alias)
            )
            for record in result.vulnerability_records
        }
        cve_ids = tuple(
            sorted({alias for aliases in aliases_by_vulnerability.values() for alias in aliases})
        )

        kev_catalog: CisaKevCatalog | None = None
        kev_failure: tuple[SourceObservationState, str] | None = None
        if cve_ids:
            try:
                kev_catalog = self._kev_source.catalog()
            except KevResponseRejected as error:
                kev_failure = (SourceObservationState.MALFORMED, str(error))
            except KevSourceUnavailable as error:
                kev_failure = (SourceObservationState.UNAVAILABLE, str(error))

        epss_responses: list[FirstEpssResponse] = []
        epss_failures: dict[str, tuple[SourceObservationState, str]] = {}
        epss_response_by_cve: dict[str, FirstEpssResponse] = {}
        epss_score_by_cve: dict[str, tuple[EpssScore, FirstEpssResponse]] = {}
        for start in range(0, len(cve_ids), _EPSS_BATCH_SIZE):
            batch = cve_ids[start : start + _EPSS_BATCH_SIZE]
            try:
                response = self._epss_source.query(batch)
            except EpssResponseRejected as error:
                epss_failures.update(
                    {cve_id: (SourceObservationState.MALFORMED, str(error)) for cve_id in batch}
                )
                continue
            except EpssSourceUnavailable as error:
                epss_failures.update(
                    {cve_id: (SourceObservationState.UNAVAILABLE, str(error)) for cve_id in batch}
                )
                continue
            epss_responses.append(response)
            for cve_id in batch:
                epss_response_by_cve[cve_id] = response
            for score in response.scores:
                epss_score_by_cve[score.cve_id] = (score, response)

        evidence_records = {record.identity: record for record in result.evidence_records}
        if kev_catalog is not None:
            evidence_records.setdefault(
                kev_catalog.evidence_record.identity,
                kev_catalog.evidence_record,
            )
        for response in epss_responses:
            evidence_records.setdefault(response.evidence_record.identity, response.evidence_record)

        captures = _CapturedEnrichment(
            kev_catalog=kev_catalog,
            kev_failure=kev_failure,
            epss_failures=epss_failures,
            epss_response_by_cve=epss_response_by_cve,
            epss_score_by_cve=epss_score_by_cve,
        )
        exposures = tuple(
            self._enrich_exposure(
                exposure,
                cve_ids=aliases_by_vulnerability[exposure.vulnerability_identity],
                captures=captures,
            )
            for exposure in result.exposures
        )
        return replace(
            result,
            exposures=exposures,
            evidence_records=tuple(
                sorted(evidence_records.values(), key=lambda item: item.identity)
            ),
        )

    def _enrich_exposure(
        self,
        exposure: Exposure,
        *,
        cve_ids: tuple[str, ...],
        captures: _CapturedEnrichment,
    ) -> Exposure:
        if not cve_ids:
            detail = "Vulnerability Record has no CVE alias for this Source."
            return replace(
                exposure,
                kev=KevSignal(SourceObservationState.MISSING, detail=detail),
                epss=EpssSignal(SourceObservationState.MISSING, detail=detail),
            )

        evidence = list(exposure.evidence)
        kev = self._kev_signal(
            cve_ids,
            kev_catalog=captures.kev_catalog,
            failure=captures.kev_failure,
        )
        if captures.kev_catalog is not None:
            kev_passages = tuple(
                entry.evidence_passage_identity
                for entry in captures.kev_catalog.entries
                if entry.cve_id in cve_ids
            )
            evidence.append(
                ExposureEvidence(captures.kev_catalog.evidence_record.identity, kev_passages)
            )

        scores = tuple(
            captures.epss_score_by_cve[cve_id]
            for cve_id in cve_ids
            if cve_id in captures.epss_score_by_cve
        )
        if scores:
            score, response = sorted(
                scores,
                key=lambda item: (item[0].observed_at, item[0].score, item[0].cve_id),
                reverse=True,
            )[0]
            state = self._freshness_state(
                score.observed_at,
                response.evidence_record.captured_at,
                self._epss_max_age,
            )
            if state is SourceObservationState.MALFORMED:
                epss = EpssSignal(
                    state,
                    detail="FIRST EPSS observation is materially future-dated.",
                )
            else:
                epss = EpssSignal(
                    state=state,
                    score=score.score,
                    percentile=score.percentile,
                    observed_at=score.observed_at,
                    detail=(
                        "FIRST EPSS observation is stale."
                        if state is SourceObservationState.STALE
                        else None
                    ),
                )
        else:
            failures = [
                captures.epss_failures[cve_id]
                for cve_id in cve_ids
                if cve_id in captures.epss_failures
            ]
            if failures:
                state, detail = failures[0]
                epss = EpssSignal(state, detail=detail)
            else:
                epss = EpssSignal(
                    SourceObservationState.MISSING,
                    detail=(
                        "FIRST EPSS returned no score for the Vulnerability Record's CVE aliases."
                    ),
                )
        for response in {
            captures.epss_response_by_cve[cve_id]
            for cve_id in cve_ids
            if cve_id in captures.epss_response_by_cve
        }:
            passages = tuple(
                score.evidence_passage_identity
                for score in response.scores
                if score.cve_id in cve_ids
            )
            evidence.append(ExposureEvidence(response.evidence_record.identity, passages))

        return replace(
            exposure,
            kev=kev,
            epss=epss,
            evidence=_merge_evidence(evidence),
        )

    def _kev_signal(
        self,
        cve_ids: tuple[str, ...],
        *,
        kev_catalog: CisaKevCatalog | None,
        failure: tuple[SourceObservationState, str] | None,
    ) -> KevSignal:
        if kev_catalog is None:
            state, detail = failure or (
                SourceObservationState.MISSING,
                "CISA KEV evidence was not collected.",
            )
            return KevSignal(state, detail=detail)
        state = self._freshness_state(
            kev_catalog.observed_at,
            kev_catalog.evidence_record.captured_at,
            self._kev_max_age,
        )
        listed = any(entry.cve_id in cve_ids for entry in kev_catalog.entries)
        if state is SourceObservationState.MALFORMED:
            return KevSignal(
                state,
                detail="CISA KEV catalog observation is materially future-dated.",
            )
        return KevSignal(
            state=state,
            listed=listed,
            observed_at=kev_catalog.observed_at,
            detail=(
                "CISA KEV catalog observation is stale."
                if state is SourceObservationState.STALE
                else None
            ),
        )

    def _freshness_state(
        self,
        observed_at: datetime,
        captured_at: datetime,
        maximum_age: timedelta,
    ) -> SourceObservationState:
        if observed_at > captured_at + self._future_tolerance:
            return SourceObservationState.MALFORMED
        if observed_at < captured_at - maximum_age:
            return SourceObservationState.STALE
        return SourceObservationState.AVAILABLE


def _kev_identifier(vulnerability: object) -> str:
    if not isinstance(vulnerability, Mapping):
        raise KevResponseRejected("Each CISA KEV vulnerability must be an object")
    identifier = vulnerability.get("cveID")
    if not isinstance(identifier, str) or not identifier.strip():
        raise KevResponseRejected("Each CISA KEV vulnerability must have a CVE identifier")
    normalized = identifier.strip().upper()
    if not _CVE_PATTERN.fullmatch(normalized):
        raise KevResponseRejected("CISA KEV vulnerability has an invalid CVE identifier")
    return normalized


def _epss_score(value: object, *, evidence_passage_identity: str) -> EpssScore:
    if not isinstance(value, Mapping):
        raise EpssResponseRejected("Each FIRST EPSS score must be an object")
    identifier = value.get("cve")
    if not isinstance(identifier, str):
        raise EpssResponseRejected("Each FIRST EPSS score must have a CVE identifier")
    try:
        score = Decimal(str(value["epss"]))
        percentile = Decimal(str(value["percentile"]))
    except (KeyError, InvalidOperation) as error:
        raise EpssResponseRejected("FIRST EPSS score and percentile must be decimals") from error
    if not score.is_finite() or not Decimal(0) <= score <= Decimal(1):
        raise EpssResponseRejected("FIRST EPSS score must be between zero and one")
    if not percentile.is_finite() or not Decimal(0) <= percentile <= Decimal(1):
        raise EpssResponseRejected("FIRST EPSS percentile must be between zero and one")
    return EpssScore(
        cve_id=identifier.strip().upper(),
        score=score,
        percentile=percentile,
        observed_at=_parse_date(value.get("date"), "FIRST EPSS date"),
        evidence_passage_identity=evidence_passage_identity,
    )


def _parse_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _parse_date(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO 8601 date") from error
    return datetime.combine(parsed, time.min, tzinfo=UTC)


def _merge_evidence(references: Sequence[ExposureEvidence]) -> tuple[ExposureEvidence, ...]:
    passages_by_record: dict[str, set[str]] = {}
    for reference in references:
        passages_by_record.setdefault(reference.record_identity, set()).update(
            reference.passage_identities
        )
    return tuple(
        ExposureEvidence(identity, tuple(sorted(passages)))
        for identity, passages in sorted(passages_by_record.items())
    )


class CisaKevSourceAdapter:
    """Capture one complete CISA KEV catalog under shared provenance rules."""

    version = "cisa-kev-v1"

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord:
        version = payload.get("catalogVersion")
        if not isinstance(version, str) or not version.strip():
            raise KevResponseRejected("CISA KEV catalog must have a version")
        try:
            _parse_datetime(payload.get("dateReleased"), "CISA KEV dateReleased")
        except ValueError as error:
            raise KevResponseRejected(str(error)) from error
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, Sequence) or isinstance(vulnerabilities, (str, bytes)):
            raise KevResponseRejected("CISA KEV catalog must contain a vulnerabilities array")
        if not all(isinstance(item, Mapping) for item in vulnerabilities):
            raise KevResponseRejected("Each CISA KEV vulnerability must be an object")
        count = payload.get("count")
        if not isinstance(count, int) or count != len(vulnerabilities):
            raise KevResponseRejected("CISA KEV catalog count must match its vulnerabilities")

        content, content_digest, captured_at = _validated_capture(payload, capture, "CISA KEV")
        passage_contents = _top_level_array_item_slices(content, "vulnerabilities", "CISA KEV")
        if len(passage_contents) != len(vulnerabilities):
            raise KevResponseRejected("Captured CISA KEV passages do not match the catalog")
        aliases = tuple(sorted(_kev_identifiers(vulnerabilities)))
        source = Source(
            identity="cisa-kev",
            authority="Cybersecurity and Infrastructure Security Agency",
            location=CISA_KEV_CATALOG_URL,
        )
        payload_identity = f"catalog:{version.strip()}"
        evidence_identity = _evidence_identity(
            source, payload_identity, content_digest, adapter_version=self.version
        )
        return EvidenceRecord(
            identity=evidence_identity,
            source=source,
            source_adapter_version=self.version,
            captured_at=captured_at,
            content_digest=content_digest,
            attribution="CISA Known Exploited Vulnerabilities Catalog",
            aliases=aliases,
            payload_identity=payload_identity,
            content=content,
            passages=tuple(
                _evidence_passage(
                    evidence_identity,
                    kind="known_exploited_vulnerability",
                    selector=f"/vulnerabilities/{index}",
                    content=passage,
                )
                for index, passage in enumerate(passage_contents)
            ),
        )


class FirstEpssSourceAdapter:
    """Capture one CVE-filtered FIRST EPSS response under shared provenance rules."""

    version = "first-epss-v1"

    def __init__(self, *, cve_ids: tuple[str, ...]) -> None:
        normalized = tuple(sorted({identifier.strip().upper() for identifier in cve_ids}))
        if not normalized or any(
            not _CVE_PATTERN.fullmatch(identifier) for identifier in normalized
        ):
            raise ValueError("FIRST EPSS queries require at least one CVE identifier")
        self._cve_ids = normalized

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord:
        if payload.get("status") != "OK" or payload.get("status-code") != 200:
            raise EpssResponseRejected("FIRST EPSS response status must be OK")
        data = payload.get("data")
        if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
            raise EpssResponseRejected("FIRST EPSS response must contain a data array")
        if not all(isinstance(item, Mapping) for item in data):
            raise EpssResponseRejected("Each FIRST EPSS score must be an object")
        total = payload.get("total")
        offset = payload.get("offset")
        limit = payload.get("limit")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or total != len(data)
            or offset != 0
            or limit < len(data)
        ):
            raise EpssResponseRejected("FIRST EPSS must return one complete response page")
        aliases = tuple(sorted(_epss_identifiers(data, requested=self._cve_ids)))
        content, content_digest, captured_at = _validated_capture(payload, capture, "FIRST EPSS")
        passage_contents = _top_level_array_item_slices(content, "data", "FIRST EPSS")
        if len(passage_contents) != len(data):
            raise EpssResponseRejected("Captured FIRST EPSS passages do not match the response")
        for score in data:
            _epss_score(score, evidence_passage_identity="")
        query = urlencode({"cve": ",".join(self._cve_ids), "limit": 100})
        source = Source(
            identity="first-epss",
            authority="Forum of Incident Response and Security Teams",
            location=f"{FIRST_EPSS_API_URL}?{query}",
        )
        query_digest = hashlib.sha256("\n".join(self._cve_ids).encode()).hexdigest()
        payload_identity = f"query:sha256:{query_digest}"
        evidence_identity = _evidence_identity(
            source, payload_identity, content_digest, adapter_version=self.version
        )
        return EvidenceRecord(
            identity=evidence_identity,
            source=source,
            source_adapter_version=self.version,
            captured_at=captured_at,
            content_digest=content_digest,
            attribution="FIRST Exploit Prediction Scoring System (EPSS)",
            aliases=aliases,
            payload_identity=payload_identity,
            content=content,
            passages=tuple(
                _evidence_passage(
                    evidence_identity,
                    kind="epss_score",
                    selector=f"/data/{index}",
                    content=passage,
                )
                for index, passage in enumerate(passage_contents)
            ),
        )


def _kev_identifiers(vulnerabilities: Sequence[object]) -> set[str]:
    identifiers: set[str] = set()
    for vulnerability in vulnerabilities:
        normalized = _kev_identifier(vulnerability)
        if normalized in identifiers:
            raise KevResponseRejected("CISA KEV catalog repeats a CVE identifier")
        identifiers.add(normalized)
    return identifiers


def _epss_identifiers(data: Sequence[object], *, requested: tuple[str, ...]) -> set[str]:
    identifiers: set[str] = set()
    for score in data:
        if not isinstance(score, Mapping):
            raise EpssResponseRejected("Each FIRST EPSS score must be an object")
        identifier = score.get("cve")
        if not isinstance(identifier, str) or not identifier.strip():
            raise EpssResponseRejected("Each FIRST EPSS score must have a CVE identifier")
        normalized = identifier.strip().upper()
        if not _CVE_PATTERN.fullmatch(normalized):
            raise EpssResponseRejected("FIRST EPSS score has an invalid CVE identifier")
        if normalized not in requested:
            raise EpssResponseRejected("FIRST EPSS returned an unrequested CVE identifier")
        if normalized in identifiers:
            raise EpssResponseRejected("FIRST EPSS response repeats a CVE identifier")
        identifiers.add(normalized)
    return identifiers


def _validated_capture(
    payload: Mapping[str, Any],
    capture: CapturedSourcePayload,
    provider: str,
) -> tuple[str, str, datetime]:
    if capture.captured_at.tzinfo is None or capture.captured_at.utcoffset() is None:
        raise ValueError("Evidence capture time must include a timezone")
    try:
        parsed_content = load_captured_json(capture.content)
    except CapturedJsonRejected as error:
        message = str(error).replace("Captured content", f"Captured {provider} content")
        raise ValueError(message) from error
    if parsed_content != payload:
        raise ValueError(f"Captured {provider} content does not match its parsed payload")
    return (
        capture.content,
        f"sha256:{hashlib.sha256(capture.content.encode()).hexdigest()}",
        capture.captured_at.astimezone(UTC),
    )


def _evidence_identity(
    source: Source,
    payload_identity: str,
    content_digest: str,
    *,
    adapter_version: str,
) -> str:
    material = "\n".join(
        (source.identity, source.location, adapter_version, payload_identity, content_digest)
    )
    return f"sha256:{hashlib.sha256(material.encode()).hexdigest()}"


def _evidence_passage(
    evidence_identity: str,
    *,
    kind: str,
    selector: str,
    content: str,
) -> EvidencePassage:
    material = f"{evidence_identity}\n{kind}\n{selector}\n{content}"
    return EvidencePassage(
        identity=f"sha256:{hashlib.sha256(material.encode()).hexdigest()}",
        kind=kind,
        selector=selector,
        content=content,
    )


def _top_level_array_item_slices(
    content: str,
    member: str,
    provider: str,
) -> tuple[str, ...]:
    decoder = json.JSONDecoder()
    index = _skip_json_whitespace(content, 0)
    if index >= len(content) or content[index] != "{":
        raise ValueError(f"Captured {provider} content must be a JSON object")
    index += 1
    while True:
        index = _skip_json_whitespace(content, index)
        if index >= len(content):
            raise ValueError(f"Captured {provider} content is incomplete")
        if content[index] == "}":
            return ()
        try:
            key, key_end = decoder.raw_decode(content, index)
            index = _skip_json_whitespace(content, key_end)
            if index >= len(content) or content[index] != ":":
                raise ValueError(f"Captured {provider} content has an invalid object member")
            value_start = _skip_json_whitespace(content, index + 1)
            _, value_end = decoder.raw_decode(content, value_start)
        except json.JSONDecodeError as error:
            raise ValueError(f"Captured {provider} content is invalid") from error
        if key == member:
            return _json_array_item_slices(content, value_start, provider)
        index = _skip_json_whitespace(content, value_end)
        if index >= len(content) or content[index] not in {",", "}"}:
            raise ValueError(f"Captured {provider} content has an invalid object separator")
        if content[index] == "}":
            return ()
        index += 1


def _json_array_item_slices(content: str, start: int, provider: str) -> tuple[str, ...]:
    if start >= len(content) or content[start] != "[":
        raise ValueError(f"Captured {provider} content member must be an array")
    decoder = json.JSONDecoder()
    index = start + 1
    slices: list[str] = []
    while True:
        index = _skip_json_whitespace(content, index)
        if index >= len(content):
            raise ValueError(f"Captured {provider} array is incomplete")
        if content[index] == "]":
            return tuple(slices)
        item_start = index
        try:
            _, item_end = decoder.raw_decode(content, item_start)
        except json.JSONDecodeError as error:
            raise ValueError(f"Captured {provider} array is invalid") from error
        slices.append(content[item_start:item_end])
        index = _skip_json_whitespace(content, item_end)
        if index >= len(content) or content[index] not in {",", "]"}:
            raise ValueError(f"Captured {provider} array has an invalid separator")
        if content[index] == "]":
            return tuple(slices)
        index += 1


def _skip_json_whitespace(content: str, index: int) -> int:
    while index < len(content) and content[index] in " \t\r\n":
        index += 1
    return index
