"""Deterministic discovery and ranking of package-specific OSV Exposures."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from exposure_ledger.asset_snapshots import AssetSnapshot, PackageInstance


@dataclass(frozen=True, slots=True, order=True)
class OsvPackageQuery:
    name: str
    version: str


class OsvSource(Protocol):
    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class VulnerabilityRecord:
    identity: str
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExposureRanking:
    severity: str
    direct_dependency: bool
    dependency_depth: int
    fixed_version_available: bool
    score: int


@dataclass(frozen=True, slots=True)
class Exposure:
    vulnerability_identity: str
    package: PackageInstance
    ranking: ExposureRanking
    rank: int
    selected_for_investigation: bool


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    vulnerability_records: tuple[VulnerabilityRecord, ...]
    exposures: tuple[Exposure, ...]


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
        payload = self._source.query_batch(queries)
        results = payload.get("results")
        if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
            raise OsvResponseRejected("OSV batch response must contain a results array")
        if len(results) != len(queries):
            raise OsvResponseRejected("OSV batch response must align with the requested packages")

        raw_candidates: list[tuple[PackageInstance, tuple[str, ...], ExposureRanking]] = []
        for package, result in zip(packages, results, strict=True):
            if not isinstance(result, Mapping):
                raise OsvResponseRejected("Each OSV batch result must be an object")
            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, Sequence) or isinstance(
                vulnerabilities, (str, bytes)
            ):
                raise OsvResponseRejected("OSV vulnerabilities must be an array")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, Mapping):
                    raise OsvResponseRejected("Each OSV vulnerability must be an object")
                if not _affects_package(vulnerability, package):
                    continue
                aliases = _aliases(vulnerability)
                raw_candidates.append((package, aliases, _ranking(vulnerability, package)))

        coalesced = _coalesced_aliases([aliases for _, aliases, _ in raw_candidates])
        records: dict[str, VulnerabilityRecord] = {}
        candidate_by_exposure: dict[
            tuple[PackageInstance, str],
            tuple[PackageInstance, VulnerabilityRecord, ExposureRanking],
        ] = {}
        for package, aliases, ranking in raw_candidates:
            merged_aliases = coalesced[frozenset(aliases)]
            identity = _vulnerability_identity(merged_aliases)
            record = records.setdefault(
                identity,
                VulnerabilityRecord(identity=identity, aliases=merged_aliases),
            )
            exposure_key = (package, identity)
            previous = candidate_by_exposure.get(exposure_key)
            if previous is None or ranking.score > previous[2].score:
                candidate_by_exposure[exposure_key] = (package, record, ranking)

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
            )
            for index, (package, record, ranking) in enumerate(candidates, start=1)
        )
        return AssessmentResult(
            vulnerability_records=tuple(sorted(records.values(), key=lambda item: item.aliases)),
            exposures=exposures,
        )


def _is_pypi_package(package: PackageInstance) -> bool:
    registry = package.source.as_dict().get("registry")
    return registry is not None and registry.rstrip("/") == "https://pypi.org/simple"


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


def _aliases(vulnerability: Mapping[str, Any]) -> tuple[str, ...]:
    identifier = vulnerability.get("id")
    aliases = vulnerability.get("aliases", [])
    values = [identifier] if isinstance(identifier, str) else []
    if isinstance(aliases, Sequence) and not isinstance(aliases, (str, bytes)):
        values.extend(alias for alias in aliases if isinstance(alias, str))
    normalized = tuple(sorted({value.strip().upper() for value in values if value.strip()}))
    if not normalized:
        raise OsvResponseRejected("Each OSV vulnerability must have an identifier")
    return normalized


def _vulnerability_identity(aliases: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\n".join(aliases).encode()).hexdigest()
    return f"sha256:{digest}"


def _affects_package(vulnerability: Mapping[str, Any], package: PackageInstance) -> bool:
    affected = vulnerability.get("affected", [])
    if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
        return False
    for item in affected:
        if not isinstance(item, Mapping):
            continue
        osv_package = item.get("package")
        if not isinstance(osv_package, Mapping):
            continue
        name = osv_package.get("name")
        if (
            osv_package.get("ecosystem") != "PyPI"
            or not isinstance(name, str)
            or (name != "*" and canonicalize_name(name) != canonicalize_name(package.name))
        ):
            continue
        if _affected_item_matches(item, package.version):
            return True
    return False


def _affected_item_matches(affected: Mapping[str, Any], version: str) -> bool:
    candidate = _version(version)
    versions = affected.get("versions", [])
    if (
        isinstance(versions, Sequence)
        and not isinstance(versions, (str, bytes))
        and any(_version(item) == candidate for item in versions if isinstance(item, str))
    ):
        return True
    ranges = affected.get("ranges", [])
    if not isinstance(ranges, Sequence) or isinstance(ranges, (str, bytes)):
        return False
    return any(
        isinstance(item, Mapping)
        and item.get("type") == "ECOSYSTEM"
        and _range_matches(item, candidate)
        for item in ranges
    )


def _range_matches(osv_range: Mapping[str, Any], candidate: Version) -> bool:
    events = osv_range.get("events", [])
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        return False
    limits = [
        limit
        for event in events
        if isinstance(event, Mapping) and isinstance((limit := event.get("limit")), str)
    ]
    if limits and not any(limit == "*" or candidate < _version(limit) for limit in limits):
        return False
    timeline = sorted(
        (event for event in events if isinstance(event, Mapping) and "limit" not in event),
        key=_event_sort_key,
    )
    active = False
    for event in timeline:
        introduced = event.get("introduced")
        if isinstance(introduced, str):
            if introduced == "0" or candidate >= _version(introduced):
                active = True
            continue
        fixed = event.get("fixed")
        if isinstance(fixed, str):
            if candidate >= _version(fixed):
                active = False
            continue
        last_affected = event.get("last_affected")
        if isinstance(last_affected, str) and candidate > _version(last_affected):
            active = False
    return active


def _event_sort_key(event: Mapping[str, Any]) -> tuple[Version, str]:
    for kind in ("introduced", "fixed", "last_affected"):
        value = event.get(kind)
        if isinstance(value, str):
            return (_version(value), kind)
    raise OsvResponseRejected("OSV range events must contain one supported boundary")


def _version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as error:
        raise OsvResponseRejected(f"OSV contains an invalid PyPI version: {value}") from error


def _ranking(vulnerability: Mapping[str, Any], package: PackageInstance) -> ExposureRanking:
    database_specific = vulnerability.get("database_specific")
    raw_severity = (
        database_specific.get("severity") if isinstance(database_specific, Mapping) else None
    )
    severity = str(raw_severity).lower() if isinstance(raw_severity, str) else "unknown"
    if severity == "medium":
        severity = "moderate"
    if severity not in {"critical", "high", "moderate", "low"}:
        severity = "unknown"
    severity_points = {
        "critical": 40,
        "high": 30,
        "moderate": 20,
        "low": 10,
    }.get(severity, 0)
    depth = min((len(path) - 1 for path in package.dependency_paths), default=0)
    fixed = _has_fixed_version(vulnerability, package)
    score = severity_points + (20 if package.direct else 0) + (10 if fixed else 0)
    score += max(0, 10 - depth)
    return ExposureRanking(
        severity=severity,
        direct_dependency=package.direct,
        dependency_depth=depth,
        fixed_version_available=fixed,
        score=score,
    )


def _has_fixed_version(vulnerability: Mapping[str, Any], package: PackageInstance) -> bool:
    affected = vulnerability.get("affected", [])
    if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
        return False
    normalized_name = canonicalize_name(package.name)
    installed_version = _version(package.version)
    for item in affected:
        if not isinstance(item, Mapping):
            continue
        osv_package = item.get("package")
        if not isinstance(osv_package, Mapping):
            continue
        name = osv_package.get("name")
        if (
            osv_package.get("ecosystem") != "PyPI"
            or not isinstance(name, str)
            or (name != "*" and canonicalize_name(name) != normalized_name)
        ):
            continue
        ranges = item.get("ranges", [])
        if isinstance(ranges, Sequence) and not isinstance(ranges, (str, bytes)):
            for osv_range in ranges:
                if not isinstance(osv_range, Mapping):
                    continue
                events = osv_range.get("events", [])
                if (
                    isinstance(events, Sequence)
                    and not isinstance(events, (str, bytes))
                    and any(
                        isinstance(event, Mapping)
                        and isinstance((fixed := event.get("fixed")), str)
                        and _version(fixed) > installed_version
                        for event in events
                    )
                ):
                    return True
    return False
