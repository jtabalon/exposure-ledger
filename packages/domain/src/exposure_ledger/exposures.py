"""Deterministic discovery and ranking of package-specific OSV Exposures."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import quote

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from exposure_ledger.asset_snapshots import AssetSnapshot, PackageInstance
from exposure_ledger.evidence import (
    CapturedJsonRejected,
    CapturedSourcePayload,
    EvidencePassage,
    EvidenceRecord,
    Source,
    SourceAdapter,
    load_captured_json,
)


@dataclass(frozen=True, slots=True, order=True)
class OsvPackageQuery:
    name: str
    version: str


class OsvEventKind(StrEnum):
    INTRODUCED = "introduced"
    FIXED = "fixed"
    LAST_AFFECTED = "last_affected"
    LIMIT = "limit"


@dataclass(frozen=True, slots=True)
class OsvRangeEvent:
    kind: OsvEventKind
    version: str


@dataclass(frozen=True, slots=True)
class OsvRange:
    range_type: str
    events: tuple[OsvRangeEvent, ...]


@dataclass(frozen=True, slots=True)
class OsvAffectedPackage:
    ecosystem: str
    name: str
    versions: tuple[str, ...]
    ranges: tuple[OsvRange, ...]
    evidence_passage_identity: str


@dataclass(frozen=True, slots=True)
class ExposureEvidence:
    record_identity: str
    passage_identities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OsvVulnerability:
    identifier: str
    aliases: tuple[str, ...]
    severity: str | None
    affected: tuple[OsvAffectedPackage, ...]
    evidence_identity: str
    query_evidence: tuple[ExposureEvidence, ...]


@dataclass(frozen=True, slots=True)
class OsvBatchResponse:
    results: tuple[tuple[OsvVulnerability, ...], ...]
    evidence_records: tuple[EvidenceRecord, ...] = ()

    @classmethod
    def capture(
        cls,
        payload: Mapping[str, Any],
        *,
        expected_results: int,
        adapter: SourceAdapter | None = None,
        captured_payloads: Mapping[str, CapturedSourcePayload] | None = None,
        additional_evidence_records: Sequence[EvidenceRecord] = (),
        query_evidence_by_vulnerability: Mapping[tuple[int, str], tuple[ExposureEvidence, ...]]
        | None = None,
    ) -> OsvBatchResponse:
        """Validate and freeze one provider response at the OSV source boundary."""
        results = payload.get("results")
        if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
            raise OsvResponseRejected("OSV batch response must contain a results array")
        if len(results) != expected_results:
            raise OsvResponseRejected("OSV batch response must align with the requested packages")
        evidence_adapter = adapter or OsvSourceAdapter()
        captured_results: list[tuple[OsvVulnerability, ...]] = []
        records = {record.identity: record for record in additional_evidence_records}
        for result_index, result in enumerate(results):
            vulnerabilities = _raw_osv_vulnerabilities(result)
            captured_vulnerabilities: list[OsvVulnerability] = []
            for vulnerability in vulnerabilities:
                identifier = vulnerability.get("id")
                capture = (
                    captured_payloads.get(identifier)
                    if captured_payloads is not None and isinstance(identifier, str)
                    else None
                )
                if capture is None:
                    raise OsvResponseRejected(
                        "Each OSV vulnerability must include captured Source content"
                    )
                evidence = evidence_adapter.capture(
                    vulnerability,
                    capture=capture,
                )
                records.setdefault(evidence.identity, evidence)
                captured_vulnerabilities.append(
                    _capture_osv_vulnerability(
                        vulnerability,
                        evidence=evidence,
                        query_evidence=(
                            query_evidence_by_vulnerability.get((result_index, str(identifier)), ())
                            if query_evidence_by_vulnerability is not None
                            else ()
                        ),
                    )
                )
            captured_results.append(tuple(captured_vulnerabilities))
        return cls(
            results=tuple(captured_results),
            evidence_records=tuple(sorted(records.values(), key=lambda item: item.identity)),
        )


class OsvSourceAdapter:
    """Capture one OSV vulnerability payload under shared provenance rules."""

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord:
        identifier = payload.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise OsvResponseRejected("Each OSV vulnerability must have an identifier")
        aliases = payload.get("aliases", [])
        if not isinstance(aliases, Sequence) or isinstance(aliases, (str, bytes)):
            raise OsvResponseRejected("OSV vulnerability aliases must be an array")
        normalized_aliases = tuple(
            sorted(
                {
                    identifier.strip().upper(),
                    *(
                        alias.strip().upper()
                        for alias in aliases
                        if isinstance(alias, str) and alias.strip()
                    ),
                }
            )
        )
        captured_content, content_digest, captured_at = _validated_capture(payload, capture)
        source = Source(
            identity="osv",
            authority="Open Source Vulnerabilities",
            location=f"https://api.osv.dev/v1/vulns/{quote(identifier, safe='')}",
        )
        evidence_identity = _evidence_identity(source, identifier, content_digest)
        affected = payload.get("affected", [])
        if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
            raise OsvResponseRejected("OSV affected packages must be an array")
        if not all(isinstance(item, Mapping) for item in affected):
            raise OsvResponseRejected("Each OSV affected package must be an object")
        passage_contents = _top_level_array_item_slices(captured_content, "affected")
        if len(passage_contents) != len(affected):
            raise OsvResponseRejected("Captured OSV affected passages do not match the payload")
        passages = tuple(
            _evidence_passage(
                evidence_identity,
                kind="affected",
                selector=f"/affected/{index}",
                content=passage_content,
            )
            for index, passage_content in enumerate(passage_contents)
        )
        return EvidenceRecord(
            identity=evidence_identity,
            source=source,
            captured_at=captured_at,
            content_digest=content_digest,
            attribution="Open Source Vulnerabilities (OSV)",
            aliases=normalized_aliases,
            payload_identity=identifier,
            content=captured_content,
            passages=passages,
        )


class OsvQueryBatchSourceAdapter:
    """Capture one OSV query-batch page and its package-aligned result passages."""

    def __init__(self, *, payload_identity: str) -> None:
        self._payload_identity = payload_identity

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord:
        captured_content, content_digest, captured_at = _validated_capture(payload, capture)
        results = payload.get("results")
        if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
            raise OsvResponseRejected("OSV batch response must contain a results array")
        passage_contents = _top_level_array_item_slices(captured_content, "results")
        if len(passage_contents) != len(results):
            raise OsvResponseRejected("Captured OSV query passages do not match the payload")
        source = Source(
            identity="osv",
            authority="Open Source Vulnerabilities",
            location="https://api.osv.dev/v1/querybatch",
        )
        evidence_identity = _evidence_identity(source, self._payload_identity, content_digest)
        aliases = tuple(sorted(_batch_vulnerability_identifiers(results)))
        return EvidenceRecord(
            identity=evidence_identity,
            source=source,
            captured_at=captured_at,
            content_digest=content_digest,
            attribution="Open Source Vulnerabilities (OSV)",
            aliases=aliases,
            payload_identity=self._payload_identity,
            content=captured_content,
            passages=tuple(
                _evidence_passage(
                    evidence_identity,
                    kind="query_result",
                    selector=f"/results/{index}",
                    content=passage_content,
                )
                for index, passage_content in enumerate(passage_contents)
            ),
        )


class OsvSource(Protocol):
    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse: ...


@dataclass(frozen=True, slots=True)
class VulnerabilityRecord:
    identity: str
    aliases: tuple[str, ...]


class ExposureSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ExposureRanking:
    severity: ExposureSeverity
    direct_dependency: bool | None
    dependency_depth: int | None
    fixed_version_available: bool
    score: int


class SourceObservationState(StrEnum):
    AVAILABLE = "available"
    STALE = "stale"
    MISSING = "missing"
    MALFORMED = "malformed"
    UNAVAILABLE = "unavailable"
    NOT_COLLECTED = "not_collected"


@dataclass(frozen=True, slots=True)
class KevSignal:
    state: SourceObservationState
    listed: bool | None = None
    observed_at: datetime | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class EpssSignal:
    state: SourceObservationState
    score: Decimal | None = None
    percentile: Decimal | None = None
    observed_at: datetime | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class Exposure:
    vulnerability_identity: str
    package: PackageInstance
    ranking: ExposureRanking
    rank: int
    selected_for_investigation: bool
    evidence: tuple[ExposureEvidence, ...]
    kev: KevSignal = field(default_factory=lambda: KevSignal(SourceObservationState.NOT_COLLECTED))
    epss: EpssSignal = field(
        default_factory=lambda: EpssSignal(SourceObservationState.NOT_COLLECTED)
    )


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    vulnerability_records: tuple[VulnerabilityRecord, ...]
    exposures: tuple[Exposure, ...]
    evidence_records: tuple[EvidenceRecord, ...] = ()


class OsvResponseRejected(ValueError):
    """A captured OSV batch response does not match the requested package batch."""


class OsvSourceUnavailable(RuntimeError):
    """The allowlisted public OSV source could not provide a complete batch."""


class ExposureDiscovery:
    """Turn one Asset Snapshot into a deterministic queue of OSV Exposures."""

    def __init__(self, source: OsvSource) -> None:
        self._source = source

    def discover(self, snapshot: AssetSnapshot) -> AssessmentResult:
        packages = tuple(
            sorted(
                (
                    replace(package, name=canonicalize_name(package.name))
                    for package in snapshot.packages
                    if _is_pypi_package(package)
                ),
                key=lambda item: (item.name, item.version),
            )
        )
        queries = tuple(
            OsvPackageQuery(name=canonicalize_name(package.name), version=package.version)
            for package in packages
        )
        response = self._source.query_batch(queries)
        if len(response.results) != len(queries):
            raise OsvResponseRejected("OSV batch response must align with the requested packages")

        raw_candidates: list[
            tuple[
                PackageInstance,
                tuple[str, ...],
                ExposureRanking,
                tuple[ExposureEvidence, ...],
            ]
        ] = []
        for package, vulnerabilities in zip(packages, response.results, strict=True):
            for vulnerability in vulnerabilities:
                matching_affected = tuple(
                    item
                    for item in _matching_affected_items(vulnerability, package)
                    if _affected_item_matches(item, package.version)
                )
                if not matching_affected:
                    continue
                aliases = _aliases(vulnerability)
                raw_candidates.append(
                    (
                        package,
                        aliases,
                        _ranking(vulnerability, package),
                        (
                            ExposureEvidence(
                                record_identity=vulnerability.evidence_identity,
                                passage_identities=tuple(
                                    item.evidence_passage_identity for item in matching_affected
                                ),
                            ),
                            *vulnerability.query_evidence,
                        ),
                    )
                )

        coalesced = _coalesced_aliases([aliases for _, aliases, _, _ in raw_candidates])
        records: dict[str, VulnerabilityRecord] = {}
        candidate_by_exposure: dict[
            tuple[PackageInstance, str],
            tuple[PackageInstance, VulnerabilityRecord, ExposureRanking, dict[str, set[str]]],
        ] = {}
        for package, aliases, ranking, evidence_references in raw_candidates:
            merged_aliases = coalesced[frozenset(aliases)]
            identity = _vulnerability_identity(merged_aliases)
            record = records.setdefault(
                identity,
                VulnerabilityRecord(identity=identity, aliases=merged_aliases),
            )
            exposure_key = (package, identity)
            previous = candidate_by_exposure.get(exposure_key)
            evidence_by_record = previous[3] if previous is not None else {}
            for evidence in evidence_references:
                evidence_by_record.setdefault(evidence.record_identity, set()).update(
                    evidence.passage_identities
                )
            selected_ranking = (
                ranking if previous is None or ranking.score > previous[2].score else previous[2]
            )
            candidate_by_exposure[exposure_key] = (
                package,
                record,
                selected_ranking,
                evidence_by_record,
            )

        candidates = list(candidate_by_exposure.values())

        candidates.sort(
            key=lambda item: (
                -item[2].score,
                item[1].aliases,
                item[0].name,
                Version(item[0].version),
            )
        )
        exposures = tuple(
            Exposure(
                vulnerability_identity=record.identity,
                package=package,
                ranking=ranking,
                rank=index,
                selected_for_investigation=index <= 5,
                evidence=tuple(
                    ExposureEvidence(
                        record_identity=record_identity,
                        passage_identities=tuple(sorted(passage_identities)),
                    )
                    for record_identity, passage_identities in sorted(evidence_by_record.items())
                ),
            )
            for index, (package, record, ranking, evidence_by_record) in enumerate(
                candidates, start=1
            )
        )
        return AssessmentResult(
            vulnerability_records=tuple(sorted(records.values(), key=lambda item: item.aliases)),
            exposures=exposures,
            evidence_records=response.evidence_records,
        )


def _is_pypi_package(package: PackageInstance) -> bool:
    source = package.source.as_dict()
    registry = source.get("registry")
    return (
        registry is not None and registry.rstrip("/") == "https://pypi.org/simple"
    ) or "manifest" in source


def _coalesced_aliases(
    alias_sets: Sequence[tuple[str, ...]],
) -> dict[frozenset[str], tuple[str, ...]]:
    components: list[set[str]] = []
    for aliases in alias_sets:
        current = set(aliases)
        overlapping = [component for component in components if component & current]
        for component in overlapping:
            current.update(component)
            components.remove(component)
        components.append(current)
    return {
        frozenset(aliases): tuple(sorted(component))
        for aliases in alias_sets
        for component in components
        if set(aliases) <= component
    }


def _raw_osv_vulnerabilities(result: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(result, Mapping):
        raise OsvResponseRejected("Each OSV batch result must be an object")
    vulnerabilities = result.get("vulns", [])
    if not isinstance(vulnerabilities, Sequence) or isinstance(vulnerabilities, (str, bytes)):
        raise OsvResponseRejected("OSV vulnerabilities must be an array")
    if not all(isinstance(item, Mapping) for item in vulnerabilities):
        raise OsvResponseRejected("Each OSV vulnerability must be an object")
    return tuple(item for item in vulnerabilities if isinstance(item, Mapping))


def _capture_osv_vulnerability(
    value: object,
    *,
    evidence: EvidenceRecord,
    query_evidence: tuple[ExposureEvidence, ...],
) -> OsvVulnerability:
    if not isinstance(value, Mapping):
        raise OsvResponseRejected("Each OSV vulnerability must be an object")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise OsvResponseRejected("Each OSV vulnerability must have an identifier")
    aliases = value.get("aliases", [])
    if not isinstance(aliases, Sequence) or isinstance(aliases, (str, bytes)):
        raise OsvResponseRejected("OSV vulnerability aliases must be an array")
    database_specific = value.get("database_specific")
    raw_severity = (
        database_specific.get("severity") if isinstance(database_specific, Mapping) else None
    )
    affected = value.get("affected", [])
    if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
        raise OsvResponseRejected("OSV affected packages must be an array")
    return OsvVulnerability(
        identifier=identifier,
        aliases=tuple(alias for alias in aliases if isinstance(alias, str)),
        severity=raw_severity if isinstance(raw_severity, str) else None,
        affected=tuple(
            _capture_osv_affected(item, passage=evidence.passages[index])
            for index, item in enumerate(affected)
        ),
        evidence_identity=evidence.identity,
        query_evidence=query_evidence,
    )


def _capture_osv_affected(value: object, *, passage: EvidencePassage) -> OsvAffectedPackage:
    if not isinstance(value, Mapping):
        raise OsvResponseRejected("Each OSV affected package must be an object")
    package = value.get("package")
    if not isinstance(package, Mapping):
        raise OsvResponseRejected("Each OSV affected package must identify its package")
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    if not isinstance(ecosystem, str) or not isinstance(name, str):
        raise OsvResponseRejected("Each OSV affected package must have an ecosystem and name")
    versions = value.get("versions", [])
    ranges = value.get("ranges", [])
    if not isinstance(versions, Sequence) or isinstance(versions, (str, bytes)):
        raise OsvResponseRejected("OSV affected versions must be an array")
    if not isinstance(ranges, Sequence) or isinstance(ranges, (str, bytes)):
        raise OsvResponseRejected("OSV affected ranges must be an array")
    return OsvAffectedPackage(
        ecosystem=ecosystem,
        name=name,
        versions=tuple(item for item in versions if isinstance(item, str)),
        ranges=tuple(_capture_osv_range(item) for item in ranges),
        evidence_passage_identity=passage.identity,
    )


def _evidence_passage(
    evidence_identity: str,
    *,
    kind: str,
    selector: str,
    content: str,
) -> EvidencePassage:
    identity_material = f"{evidence_identity}\n{kind}\n{selector}\n{content}"
    return EvidencePassage(
        identity=f"sha256:{hashlib.sha256(identity_material.encode()).hexdigest()}",
        kind=kind,
        selector=selector,
        content=content,
    )


def _top_level_array_item_slices(content: str, member: str) -> tuple[str, ...]:
    decoder = json.JSONDecoder()
    index = _skip_json_whitespace(content, 0)
    if index >= len(content) or content[index] != "{":
        raise OsvResponseRejected("Captured OSV content must be a JSON object")
    index += 1
    while True:
        index = _skip_json_whitespace(content, index)
        if index >= len(content):
            raise OsvResponseRejected("Captured OSV content is incomplete")
        if content[index] == "}":
            return ()
        try:
            key, key_end = decoder.raw_decode(content, index)
        except json.JSONDecodeError as error:
            raise OsvResponseRejected("Captured OSV content has an invalid object key") from error
        index = _skip_json_whitespace(content, key_end)
        if index >= len(content) or content[index] != ":":
            raise OsvResponseRejected("Captured OSV content has an invalid object member")
        value_start = _skip_json_whitespace(content, index + 1)
        try:
            _, value_end = decoder.raw_decode(content, value_start)
        except json.JSONDecodeError as error:
            raise OsvResponseRejected("Captured OSV content has an invalid object value") from error
        if key == member:
            return _json_array_item_slices(content, value_start)
        index = _skip_json_whitespace(content, value_end)
        if index >= len(content) or content[index] not in {",", "}"}:
            raise OsvResponseRejected("Captured OSV content has an invalid object separator")
        if content[index] == "}":
            return ()
        index += 1


def _json_array_item_slices(content: str, start: int) -> tuple[str, ...]:
    if start >= len(content) or content[start] != "[":
        raise OsvResponseRejected("Captured OSV affected content must be an array")
    decoder = json.JSONDecoder()
    index = start + 1
    slices: list[str] = []
    while True:
        index = _skip_json_whitespace(content, index)
        if index >= len(content):
            raise OsvResponseRejected("Captured OSV affected content is incomplete")
        if content[index] == "]":
            return tuple(slices)
        item_start = index
        try:
            _, item_end = decoder.raw_decode(content, item_start)
        except json.JSONDecodeError as error:
            raise OsvResponseRejected("Captured OSV affected content is invalid") from error
        slices.append(content[item_start:item_end])
        index = _skip_json_whitespace(content, item_end)
        if index >= len(content) or content[index] not in {",", "]"}:
            raise OsvResponseRejected("Captured OSV affected content has an invalid separator")
        if content[index] == "]":
            return tuple(slices)
        index += 1


def _skip_json_whitespace(content: str, index: int) -> int:
    while index < len(content) and content[index] in " \t\r\n":
        index += 1
    return index


def _validated_capture(
    payload: Mapping[str, Any], capture: CapturedSourcePayload
) -> tuple[str, str, datetime]:
    if capture.captured_at.tzinfo is None or capture.captured_at.utcoffset() is None:
        raise OsvResponseRejected("Evidence capture time must include a timezone")
    try:
        parsed_content = load_captured_json(capture.content)
    except CapturedJsonRejected as error:
        raise OsvResponseRejected(
            str(error).replace("Captured content", "Captured OSV content")
        ) from error
    if parsed_content != payload:
        raise OsvResponseRejected("Captured OSV content does not match its parsed payload")
    content_digest = f"sha256:{hashlib.sha256(capture.content.encode()).hexdigest()}"
    return capture.content, content_digest, capture.captured_at.astimezone(UTC)


def _evidence_identity(source: Source, payload_identity: str, content_digest: str) -> str:
    identity_material = "\n".join(
        (source.identity, source.location, payload_identity, content_digest)
    )
    return f"sha256:{hashlib.sha256(identity_material.encode()).hexdigest()}"


def _batch_vulnerability_identifiers(results: Sequence[object]) -> set[str]:
    identifiers: set[str] = set()
    for result in results:
        if not isinstance(result, Mapping):
            raise OsvResponseRejected("Each OSV batch result must be an object")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, Sequence) or isinstance(vulnerabilities, (str, bytes)):
            raise OsvResponseRejected("OSV vulnerabilities must be an array")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, Mapping):
                raise OsvResponseRejected("Each OSV vulnerability must be an object")
            identifier = vulnerability.get("id")
            if isinstance(identifier, str) and identifier:
                identifiers.add(identifier.upper())
    return identifiers


def _capture_osv_range(value: object) -> OsvRange:
    if not isinstance(value, Mapping):
        raise OsvResponseRejected("Each OSV affected range must be an object")
    range_type = value.get("type")
    events = value.get("events", [])
    if not isinstance(range_type, str):
        raise OsvResponseRejected("Each OSV affected range must have a type")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise OsvResponseRejected("OSV range events must be an array")
    return OsvRange(
        range_type=range_type,
        events=tuple(_capture_osv_event(item) for item in events),
    )


def _capture_osv_event(value: object) -> OsvRangeEvent:
    if not isinstance(value, Mapping):
        raise OsvResponseRejected("Each OSV range event must be an object")
    boundaries = [
        (OsvEventKind(kind), version)
        for kind in OsvEventKind
        if isinstance((version := value.get(kind)), str)
    ]
    if len(boundaries) != 1:
        raise OsvResponseRejected("OSV range events must contain one supported boundary")
    kind, version = boundaries[0]
    return OsvRangeEvent(kind=kind, version=version)


def _aliases(vulnerability: OsvVulnerability) -> tuple[str, ...]:
    values = [vulnerability.identifier, *vulnerability.aliases]
    normalized = tuple(sorted({value.strip().upper() for value in values if value.strip()}))
    if not normalized:
        raise OsvResponseRejected("Each OSV vulnerability must have an identifier")
    return normalized


def _vulnerability_identity(aliases: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\n".join(aliases).encode()).hexdigest()
    return f"sha256:{digest}"


def _matching_affected_items(
    vulnerability: OsvVulnerability, package: PackageInstance
) -> tuple[OsvAffectedPackage, ...]:
    matches: list[OsvAffectedPackage] = []
    normalized_name = canonicalize_name(package.name)
    for item in vulnerability.affected:
        if item.ecosystem != "PyPI" or (
            item.name != "*" and canonicalize_name(item.name) != normalized_name
        ):
            continue
        matches.append(item)
    return tuple(matches)


def _affected_item_matches(affected: OsvAffectedPackage, version: str) -> bool:
    candidate = _version(version)
    if any(_version(item) == candidate for item in affected.versions):
        return True
    return any(
        item.range_type == "ECOSYSTEM" and _range_matches(item, candidate)
        for item in affected.ranges
    )


def _range_matches(osv_range: OsvRange, candidate: Version) -> bool:
    limits = [event.version for event in osv_range.events if event.kind is OsvEventKind.LIMIT]
    if limits and not any(limit == "*" or candidate < _version(limit) for limit in limits):
        return False
    timeline = sorted(
        (event for event in osv_range.events if event.kind is not OsvEventKind.LIMIT),
        key=_event_sort_key,
    )
    active = False
    for event in timeline:
        if event.kind is OsvEventKind.INTRODUCED:
            if event.version == "0" or candidate >= _version(event.version):
                active = True
            continue
        if event.kind is OsvEventKind.FIXED:
            if candidate >= _version(event.version):
                active = False
            continue
        if event.kind is OsvEventKind.LAST_AFFECTED and candidate > _version(event.version):
            active = False
    return active


def _event_sort_key(event: OsvRangeEvent) -> tuple[Version, str]:
    return (_version(event.version), event.kind)


def _version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as error:
        raise OsvResponseRejected(f"OSV contains an invalid PyPI version: {value}") from error


def _ranking(vulnerability: OsvVulnerability, package: PackageInstance) -> ExposureRanking:
    severity = vulnerability.severity.lower() if vulnerability.severity else "unknown"
    if severity == "medium":
        severity = "moderate"
    if severity not in {"critical", "high", "moderate", "low"}:
        severity = "unknown"
    normalized_severity = ExposureSeverity(severity)
    severity_points = {
        ExposureSeverity.CRITICAL: 40,
        ExposureSeverity.HIGH: 30,
        ExposureSeverity.MODERATE: 20,
        ExposureSeverity.LOW: 10,
        ExposureSeverity.UNKNOWN: 0,
    }[normalized_severity]
    depth = (
        min((len(path) - 1 for path in package.dependency_paths), default=0)
        if package.dependency_paths is not None
        else None
    )
    fixed = _has_fixed_version(vulnerability, package)
    score = severity_points + (20 if package.direct else 0) + (10 if fixed else 0)
    if depth is not None:
        score += max(0, 10 - depth)
    return ExposureRanking(
        severity=normalized_severity,
        direct_dependency=package.direct,
        dependency_depth=depth,
        fixed_version_available=fixed,
        score=score,
    )


def _has_fixed_version(vulnerability: OsvVulnerability, package: PackageInstance) -> bool:
    installed_version = _version(package.version)
    for item in _matching_affected_items(vulnerability, package):
        for osv_range in item.ranges:
            if (
                osv_range.range_type == "ECOSYSTEM"
                and _range_matches(osv_range, installed_version)
                and _range_has_future_fix(osv_range, installed_version)
            ):
                return True
    return False


def _range_has_future_fix(osv_range: OsvRange, installed_version: Version) -> bool:
    return any(
        event.kind is OsvEventKind.FIXED and _version(event.version) > installed_version
        for event in osv_range.events
    )
