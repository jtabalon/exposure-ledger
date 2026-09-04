"""First-party advisory target and immutable capture contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from exposure_ledger.evidence import (
    CapturedJsonRejected,
    CapturedSourcePayload,
    EvidencePassage,
    EvidenceRecord,
    EvidenceRelationship,
    Source,
    load_captured_json,
)
from exposure_ledger.exposures import AssessmentResult, Exposure, ExposureEvidence

_GITHUB_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\Z")
_GHSA_ID = re.compile(
    r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-"
    r"[23456789CFGHJMPQRVWX]{4}\Z"
)


class GitHubAdvisoryTargetRejected(ValueError):
    """A proposed repository advisory target is outside the fixed allowlist."""


class GitHubAdvisoryResponseRejected(ValueError):
    """A captured repository advisory does not match its approved target."""


class GitHubAdvisorySourceUnavailable(RuntimeError):
    """The allowlisted GitHub advisory source could not be retrieved."""


@dataclass(frozen=True, slots=True, order=True)
class GitHubAdvisoryTarget:
    owner: str
    repository: str
    advisory_id: str
    derived_from_evidence: str

    def __post_init__(self) -> None:
        normalized_id = self.advisory_id.upper()
        if (
            not _GITHUB_NAME.fullmatch(self.owner)
            or not _GITHUB_NAME.fullmatch(self.repository)
            or self.owner in {".", ".."}
            or self.repository in {".", ".."}
            or not _GHSA_ID.fullmatch(normalized_id)
            or not self.derived_from_evidence.strip()
        ):
            raise GitHubAdvisoryTargetRejected(
                "GitHub advisory target is outside the approved repository advisory scope"
            )
        object.__setattr__(self, "advisory_id", normalized_id)

    @property
    def api_url(self) -> str:
        return (
            f"https://api.github.com/repos/{self.owner}/{self.repository}/"
            f"security-advisories/{self.advisory_id}"
        )

    @property
    def publication_url(self) -> str:
        return (
            f"https://github.com/{self.owner}/{self.repository}/security/advisories/"
            f"{self.advisory_id}"
        )

    @classmethod
    def from_osv_reference(
        cls,
        url: str,
        *,
        allowed_aliases: Sequence[str],
        derived_from_evidence: str,
    ) -> GitHubAdvisoryTarget:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise GitHubAdvisoryTargetRejected(
                "GitHub advisory reference contains an invalid port"
            ) from error
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise GitHubAdvisoryTargetRejected(
                "GitHub advisory reference is outside the approved HTTPS origin"
            )
        path = parsed.path.split("/")
        if len(path) != 6 or path[0] or path[3:5] != ["security", "advisories"]:
            raise GitHubAdvisoryTargetRejected(
                "GitHub advisory reference must identify one repository security advisory"
            )
        owner, repository, advisory_id = path[1], path[2], path[5].upper()
        aliases = {alias.strip().upper() for alias in allowed_aliases if alias.strip()}
        if advisory_id not in aliases:
            raise GitHubAdvisoryTargetRejected(
                "GitHub advisory reference is not an alias of the selected Vulnerability Record"
            )
        return cls(
            owner=owner,
            repository=repository,
            advisory_id=advisory_id,
            derived_from_evidence=derived_from_evidence,
        )


def derive_first_party_advisory_targets(
    evidence_records: Sequence[EvidenceRecord],
    *,
    allowed_aliases: Sequence[str],
) -> tuple[GitHubAdvisoryTarget, ...]:
    """Derive GitHub repository advisory targets from already captured OSV evidence."""
    by_target: dict[tuple[str, str, str], GitHubAdvisoryTarget] = {}
    for evidence in evidence_records:
        if evidence.source.identity != "osv":
            continue
        try:
            parsed_source = urlsplit(evidence.source.location)
            source_port = parsed_source.port
        except ValueError:
            continue
        if (
            parsed_source.scheme != "https"
            or parsed_source.hostname != "api.osv.dev"
            or source_port is not None
            or parsed_source.username is not None
            or parsed_source.password is not None
            or parsed_source.query
            or parsed_source.fragment
            or len(parsed_source.path.split("/")) != 4
            or not parsed_source.path.startswith("/v1/vulns/")
        ):
            continue
        try:
            payload = load_captured_json(evidence.content)
        except CapturedJsonRejected:
            continue
        if not isinstance(payload, Mapping):
            continue
        references = payload.get("references", [])
        if not isinstance(references, Sequence) or isinstance(references, (str, bytes)):
            continue
        for reference in references:
            if not isinstance(reference, Mapping) or reference.get("type") != "ADVISORY":
                continue
            url = reference.get("url")
            if not isinstance(url, str):
                continue
            try:
                target = GitHubAdvisoryTarget.from_osv_reference(
                    url,
                    allowed_aliases=allowed_aliases,
                    derived_from_evidence=evidence.identity,
                )
            except GitHubAdvisoryTargetRejected:
                continue
            key = (target.owner.lower(), target.repository.lower(), target.advisory_id)
            by_target.setdefault(key, target)
    return tuple(sorted(by_target.values()))


def derive_assessment_advisory_targets(
    result: AssessmentResult,
) -> tuple[GitHubAdvisoryTarget, ...]:
    """Derive only targets linked to an Exposure in this Assessment result."""
    records = {record.identity: record for record in result.evidence_records}
    vulnerabilities = {record.identity: record for record in result.vulnerability_records}
    by_target: dict[tuple[str, str, str], GitHubAdvisoryTarget] = {}
    for exposure in result.exposures:
        vulnerability = vulnerabilities[exposure.vulnerability_identity]
        referenced = tuple(
            records[reference.record_identity]
            for reference in exposure.evidence
            if reference.record_identity in records
        )
        for target in derive_first_party_advisory_targets(
            referenced, allowed_aliases=vulnerability.aliases
        ):
            key = (target.owner.lower(), target.repository.lower(), target.advisory_id)
            by_target.setdefault(key, target)
    return tuple(sorted(by_target.values()))


class FirstPartyAdvisorySource(Protocol):
    """Narrow source contract for approved repository advisory targets."""

    def retrieve(self, targets: tuple[GitHubAdvisoryTarget, ...]) -> tuple[EvidenceRecord, ...]: ...


class FirstPartyAdvisoryCollector:
    """Attach first-party guidance to Exposures without hiding disagreement."""

    def __init__(self, source: FirstPartyAdvisorySource) -> None:
        self._source = source

    def collect(self, result: AssessmentResult) -> AssessmentResult:
        records = {record.identity: record for record in result.evidence_records}
        vulnerabilities = {record.identity: record for record in result.vulnerability_records}
        targets_by_exposure: list[tuple[GitHubAdvisoryTarget, ...]] = []
        unique_targets: dict[tuple[str, str, str], GitHubAdvisoryTarget] = {}
        for exposure in result.exposures:
            vulnerability = vulnerabilities[exposure.vulnerability_identity]
            referenced = tuple(
                records[reference.record_identity]
                for reference in exposure.evidence
                if reference.record_identity in records
            )
            targets = derive_first_party_advisory_targets(
                referenced,
                allowed_aliases=vulnerability.aliases,
            )
            targets_by_exposure.append(targets)
            for target in targets:
                key = (target.owner.lower(), target.repository.lower(), target.advisory_id)
                unique_targets.setdefault(key, target)

        requested = tuple(sorted(unique_targets.values()))
        if not requested:
            return result
        captured = self._source.retrieve(requested)
        captured_by_location = {record.source.location: record for record in captured}
        expected_locations = {target.api_url for target in requested}
        if (
            len(captured) != len(expected_locations)
            or len(captured_by_location) != len(expected_locations)
            or set(captured_by_location) != expected_locations
        ):
            raise GitHubAdvisoryResponseRejected(
                "GitHub advisory source did not return exactly the approved targets"
            )
        records.update((record.identity, record) for record in captured)

        enriched_exposures = tuple(
            self._enrich_exposure(exposure, targets, records, captured_by_location)
            for exposure, targets in zip(result.exposures, targets_by_exposure, strict=True)
        )
        return replace(
            result,
            exposures=enriched_exposures,
            evidence_records=tuple(sorted(records.values(), key=lambda item: item.identity)),
        )

    @staticmethod
    def _enrich_exposure(
        exposure: Exposure,
        targets: tuple[GitHubAdvisoryTarget, ...],
        records: Mapping[str, EvidenceRecord],
        captured_by_location: Mapping[str, EvidenceRecord],
    ) -> Exposure:
        evidence = list(exposure.evidence)
        conflict = exposure.authoritative_conflict
        osv_records = tuple(
            records[reference.record_identity]
            for reference in exposure.evidence
            if records[reference.record_identity].source.identity == "osv"
        )
        for target in targets:
            advisory = captured_by_location[target.api_url]
            matching_passages = _matching_advisory_passages(advisory, exposure)
            advisory_conflicts = _guidance_conflicts(osv_records, advisory, exposure)
            conflict = conflict or advisory_conflicts
            evidence.append(
                ExposureEvidence(
                    record_identity=advisory.identity,
                    passage_identities=matching_passages,
                    relationship=(
                        EvidenceRelationship.CONTRADICTS
                        if advisory_conflicts
                        else EvidenceRelationship.SUPPORTS
                    ),
                )
            )
        return replace(
            exposure,
            evidence=tuple(evidence),
            authoritative_conflict=conflict,
        )


class GitHubRepositoryAdvisoryAdapter:
    """Capture one approved GitHub repository security advisory."""

    def __init__(self, target: GitHubAdvisoryTarget) -> None:
        self._target = target

    def capture(
        self,
        payload: Mapping[str, Any],
        *,
        capture: CapturedSourcePayload,
    ) -> EvidenceRecord:
        advisory_id = payload.get("ghsa_id")
        if not isinstance(advisory_id, str) or advisory_id.upper() != self._target.advisory_id:
            raise GitHubAdvisoryResponseRejected(
                "GitHub returned an advisory with a mismatched publication identity"
            )
        if not _matches_target_url(payload.get("url"), self._target, api=True):
            raise GitHubAdvisoryResponseRejected(
                "GitHub advisory API location does not match the approved target"
            )
        if not _matches_target_url(payload.get("html_url"), self._target, api=False):
            raise GitHubAdvisoryResponseRejected(
                "GitHub advisory publication location does not match the approved target"
            )
        published_at = payload.get("published_at")
        if not isinstance(published_at, str):
            raise GitHubAdvisoryResponseRejected(
                "GitHub advisory must include its publication time"
            )
        _timestamp(published_at, field="publication")
        updated_at = payload.get("updated_at")
        if not isinstance(updated_at, str):
            raise GitHubAdvisoryResponseRejected("GitHub advisory must include its update time")
        _timestamp(updated_at, field="update")
        withdrawn_at = payload.get("withdrawn_at")
        if withdrawn_at is not None:
            if not isinstance(withdrawn_at, str):
                raise GitHubAdvisoryResponseRejected(
                    "GitHub advisory withdrawal time must be a timestamp or null"
                )
            _timestamp(withdrawn_at, field="withdrawal")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, Sequence) or isinstance(vulnerabilities, (str, bytes)):
            raise GitHubAdvisoryResponseRejected("GitHub advisory vulnerabilities must be an array")
        for vulnerability in vulnerabilities:
            _validate_vulnerability(vulnerability)

        captured_content, content_digest, captured_at = _validated_capture(payload, capture)
        cve_id = payload.get("cve_id")
        aliases = tuple(
            sorted(
                {
                    self._target.advisory_id,
                    *(
                        [cve_id.strip().upper()]
                        if isinstance(cve_id, str) and cve_id.strip()
                        else []
                    ),
                }
            )
        )
        source = Source(
            identity="github_repository_security_advisory",
            authority="Repository maintainer",
            location=self._target.api_url,
        )
        evidence_identity = _evidence_identity(source, self._target.advisory_id, content_digest)
        publication = {
            key: payload.get(key)
            for key in (
                "ghsa_id",
                "cve_id",
                "html_url",
                "summary",
                "description",
                "published_at",
                "updated_at",
                "withdrawn_at",
            )
        }
        passages = [
            _passage(
                evidence_identity,
                kind="publication",
                selector="/",
                content=_canonical_json(publication),
            )
        ]
        passages.extend(
            _passage(
                evidence_identity,
                kind="affected_guidance",
                selector=f"/vulnerabilities/{index}",
                content=_canonical_json(vulnerability),
            )
            for index, vulnerability in enumerate(vulnerabilities)
        )
        return EvidenceRecord(
            identity=evidence_identity,
            source=source,
            captured_at=captured_at,
            content_digest=content_digest,
            attribution=(
                f"{self._target.owner}/{self._target.repository} maintainers via "
                "GitHub Security Advisory"
            ),
            aliases=aliases,
            payload_identity=self._target.advisory_id,
            content=captured_content,
            passages=tuple(passages),
        )


def _matching_advisory_passages(advisory: EvidenceRecord, exposure: Exposure) -> tuple[str, ...]:
    payload = _advisory_payload(advisory)
    vulnerabilities = payload["vulnerabilities"]
    matching = [
        index
        for index, vulnerability in enumerate(vulnerabilities)
        if _advisory_package_matches(vulnerability, exposure)
    ]
    if not matching:
        return tuple(passage.identity for passage in advisory.passages)
    passages_by_selector = {passage.selector: passage.identity for passage in advisory.passages}
    identities = [passages_by_selector["/"]]
    identities.extend(passages_by_selector[f"/vulnerabilities/{index}"] for index in matching)
    return tuple(identities)


def _guidance_conflicts(
    osv_records: tuple[EvidenceRecord, ...],
    advisory: EvidenceRecord,
    exposure: Exposure,
) -> bool:
    payload = _advisory_payload(advisory)
    guidance = tuple(
        vulnerability
        for vulnerability in payload["vulnerabilities"]
        if _advisory_package_matches(vulnerability, exposure)
    )
    if not guidance:
        return True
    installed = _version(exposure.package.version)
    if not any(
        SpecifierSet(str(item["vulnerable_version_range"])).contains(installed, prereleases=True)
        for item in guidance
    ):
        return True
    advisory_fixes = _advisory_fixed_versions(guidance)
    osv_fixes = _osv_fixed_versions(osv_records, exposure)
    return bool(advisory_fixes and osv_fixes and min(advisory_fixes) != min(osv_fixes))


def _advisory_payload(advisory: EvidenceRecord) -> Mapping[str, Any]:
    try:
        payload = load_captured_json(advisory.content)
    except CapturedJsonRejected as error:
        raise GitHubAdvisoryResponseRejected(
            "Captured GitHub advisory content is invalid"
        ) from error
    if not isinstance(payload, Mapping):
        raise GitHubAdvisoryResponseRejected("Captured GitHub advisory content must be an object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, Sequence) or isinstance(vulnerabilities, (str, bytes)):
        raise GitHubAdvisoryResponseRejected(
            "Captured GitHub advisory vulnerabilities must be an array"
        )
    if not all(isinstance(item, Mapping) for item in vulnerabilities):
        raise GitHubAdvisoryResponseRejected(
            "Captured GitHub advisory vulnerabilities must be objects"
        )
    return payload


def _advisory_package_matches(value: object, exposure: Exposure) -> bool:
    if not isinstance(value, Mapping):
        return False
    package = value.get("package")
    if not isinstance(package, Mapping):
        return False
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    return (
        isinstance(ecosystem, str)
        and ecosystem.lower() in {"pip", "pypi"}
        and isinstance(name, str)
        and canonicalize_name(name) == canonicalize_name(exposure.package.name)
    )


def _advisory_fixed_versions(guidance: Sequence[object]) -> set[Version]:
    versions: set[Version] = set()
    for item in guidance:
        if not isinstance(item, Mapping):
            continue
        fixed = item.get("patched_versions")
        if isinstance(fixed, str):
            versions.update(_version(value.strip()) for value in fixed.split(",") if value.strip())
    return versions


def _osv_fixed_versions(records: tuple[EvidenceRecord, ...], exposure: Exposure) -> set[Version]:
    versions: set[Version] = set()
    installed = _version(exposure.package.version)
    for record in records:
        try:
            payload = load_captured_json(record.content)
        except CapturedJsonRejected:
            continue
        if not isinstance(payload, Mapping):
            continue
        affected = payload.get("affected", [])
        if not isinstance(affected, Sequence) or isinstance(affected, (str, bytes)):
            continue
        for item in affected:
            if not _osv_package_matches(item, exposure):
                continue
            assert isinstance(item, Mapping)
            ranges = item.get("ranges", [])
            if not isinstance(ranges, Sequence) or isinstance(ranges, (str, bytes)):
                continue
            for affected_range in ranges:
                if not isinstance(affected_range, Mapping):
                    continue
                events = affected_range.get("events", [])
                if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
                    continue
                for event in events:
                    if isinstance(event, Mapping) and isinstance(event.get("fixed"), str):
                        fixed = _version(str(event["fixed"]))
                        if fixed > installed:
                            versions.add(fixed)
    return versions


def _osv_package_matches(value: object, exposure: Exposure) -> bool:
    if not isinstance(value, Mapping):
        return False
    package = value.get("package")
    if not isinstance(package, Mapping):
        return False
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    return (
        ecosystem == "PyPI"
        and isinstance(name, str)
        and canonicalize_name(name) == canonicalize_name(exposure.package.name)
    )


def _version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as error:
        raise GitHubAdvisoryResponseRejected(
            f"Advisory guidance contains an invalid PyPI version: {value}"
        ) from error


def _validate_vulnerability(value: object) -> None:
    if not isinstance(value, Mapping):
        raise GitHubAdvisoryResponseRejected("Each GitHub advisory vulnerability must be an object")
    package = value.get("package")
    if not isinstance(package, Mapping):
        raise GitHubAdvisoryResponseRejected(
            "Each GitHub advisory vulnerability must identify a package"
        )
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    if (
        not isinstance(ecosystem, str)
        or not ecosystem.strip()
        or not isinstance(name, str)
        or not name.strip()
    ):
        raise GitHubAdvisoryResponseRejected(
            "Each GitHub advisory vulnerability must include ecosystem and package name"
        )
    affected_range = value.get("vulnerable_version_range")
    if not isinstance(affected_range, str) or not affected_range.strip():
        raise GitHubAdvisoryResponseRejected(
            "Each GitHub advisory vulnerability must include an affected range"
        )
    try:
        SpecifierSet(affected_range)
    except InvalidSpecifier as error:
        raise GitHubAdvisoryResponseRejected(
            "GitHub advisory contains an invalid affected range"
        ) from error
    fixed = value.get("patched_versions")
    if fixed is not None and (not isinstance(fixed, str) or not fixed.strip()):
        raise GitHubAdvisoryResponseRejected(
            "GitHub advisory patched versions must be a non-empty string or null"
        )
    if isinstance(fixed, str):
        for version in fixed.split(","):
            if not version.strip():
                raise GitHubAdvisoryResponseRejected(
                    "GitHub advisory patched versions must identify complete versions"
                )
            _version(version.strip())


def _matches_target_url(value: object, target: GitHubAdvisoryTarget, *, api: bool) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    expected_host = "api.github.com" if api else "github.com"
    expected_parts = (
        ["", "repos", target.owner, target.repository, "security-advisories"]
        if api
        else ["", target.owner, target.repository, "security", "advisories"]
    )
    parts = parsed.path.split("/")
    return (
        parsed.scheme == "https"
        and parsed.hostname == expected_host
        and port is None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and len(parts) == 6
        and [part.lower() for part in parts[:5]] == [part.lower() for part in expected_parts]
        and parts[5].upper() == target.advisory_id
    )


def _timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GitHubAdvisoryResponseRejected(
            f"GitHub advisory {field} time must be an ISO 8601 timestamp"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GitHubAdvisoryResponseRejected(
            f"GitHub advisory {field} time must include a timezone"
        )
    return parsed.astimezone(UTC)


def _validated_capture(
    payload: Mapping[str, Any], capture: CapturedSourcePayload
) -> tuple[str, str, datetime]:
    if capture.captured_at.tzinfo is None or capture.captured_at.utcoffset() is None:
        raise GitHubAdvisoryResponseRejected("Evidence capture time must include a timezone")
    try:
        parsed_content = load_captured_json(capture.content)
    except CapturedJsonRejected as error:
        raise GitHubAdvisoryResponseRejected(str(error)) from error
    if parsed_content != payload:
        raise GitHubAdvisoryResponseRejected(
            "Captured GitHub advisory content does not match its parsed payload"
        )
    digest = f"sha256:{hashlib.sha256(capture.content.encode()).hexdigest()}"
    return capture.content, digest, capture.captured_at.astimezone(UTC)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as error:
        raise GitHubAdvisoryResponseRejected(
            "GitHub advisory payload must contain JSON values"
        ) from error


def _evidence_identity(source: Source, payload_identity: str, content_digest: str) -> str:
    material = "\n".join((source.identity, source.location, payload_identity, content_digest))
    return f"sha256:{hashlib.sha256(material.encode()).hexdigest()}"


def _passage(
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
