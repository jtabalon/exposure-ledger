from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from exposure_ledger import (
    AssessmentResult,
    CapturedSourcePayload,
    EvidenceRecord,
    EvidenceRelationship,
    Exposure,
    ExposureEvidence,
    ExposureRanking,
    ExposureSeverity,
    FirstPartyAdvisoryCollector,
    GitHubAdvisoryTarget,
    GitHubAdvisoryTargetRejected,
    GitHubRepositoryAdvisoryAdapter,
    OsvSourceAdapter,
    PackageInstance,
    PackageSource,
    VulnerabilityRecord,
    derive_first_party_advisory_targets,
)


def _osv_evidence(reference_url: str):
    payload = {
        "id": "PYSEC-2026-50",
        "aliases": ["CVE-2026-5000", "GHSA-2345-6789-cfgh"],
        "affected": [],
        "references": [{"type": "ADVISORY", "url": reference_url}],
    }
    return OsvSourceAdapter().capture(
        payload,
        capture=CapturedSourcePayload(
            content=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            captured_at=datetime(2026, 9, 4, 8, 0, tzinfo=UTC),
        ),
    )


def _advisory_payload(*, fixed_version: str = "1.4.2") -> dict[str, object]:
    return {
        "ghsa_id": "GHSA-2345-6789-CFGH",
        "cve_id": "CVE-2026-5000",
        "url": ("https://api.github.com/repos/acme/demo/security-advisories/GHSA-2345-6789-cfgh"),
        "html_url": ("https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh"),
        "summary": "Demo package accepts an unsafe token.",
        "description": "Upgrade the demo package to the first patched release.",
        "published_at": "2026-09-01T12:00:00Z",
        "updated_at": "2026-09-03T12:00:00Z",
        "withdrawn_at": None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "demo-pkg"},
                "vulnerable_version_range": ">= 1.0, < 1.4.2",
                "patched_versions": fixed_version,
            }
        ],
    }


def test_advisory_targets_are_derived_only_from_allowlisted_osv_evidence() -> None:
    evidence = _osv_evidence("https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh")

    targets = derive_first_party_advisory_targets(
        (evidence,),
        allowed_aliases=("CVE-2026-5000", "GHSA-2345-6789-CFGH"),
    )

    assert targets == (
        GitHubAdvisoryTarget.from_osv_reference(
            "https://github.com/acme/demo/security/advisories/GHSA-2345-6789-CFGH",
            allowed_aliases=("GHSA-2345-6789-CFGH",),
            derived_from_evidence=evidence.identity,
        ),
    )
    assert targets[0].api_url == (
        "https://api.github.com/repos/acme/demo/security-advisories/GHSA-2345-6789-CFGH"
    )


def test_advisory_target_accepts_the_complete_github_advisory_alphabet() -> None:
    target = GitHubAdvisoryTarget.from_osv_reference(
        "https://github.com/acme/demo/security/advisories/GHSA-2345-6789-CFGY",
        allowed_aliases=("GHSA-2345-6789-CFGY",),
        derived_from_evidence="sha256:osv-capture",
    )

    assert target.advisory_id == "GHSA-2345-6789-CFGY"


def test_advisory_target_cannot_bypass_allowlisted_reference_derivation() -> None:
    with pytest.raises(GitHubAdvisoryTargetRejected, match="allowlisted evidence"):
        GitHubAdvisoryTarget(
            owner="acme",
            repository="demo",
            advisory_id="GHSA-2345-6789-CFGH",
            derived_from_evidence="sha256:unverified",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh",
        "https://github.com.evil.test/acme/demo/security/advisories/GHSA-2345-6789-cfgh",
        "https://github.com/acme/demo/security/advisories/GHSA-9999-9999-9999",
        "https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh/extra",
        "https://user@github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh",
        "https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh?next=evil",
    ],
)
def test_advisory_target_rejects_scope_expansion(url: str) -> None:
    with pytest.raises(GitHubAdvisoryTargetRejected):
        GitHubAdvisoryTarget.from_osv_reference(
            url,
            allowed_aliases=("GHSA-2345-6789-CFGH",),
            derived_from_evidence="sha256:osv-capture",
        )


def test_advisory_adapter_captures_immutable_maintainer_guidance() -> None:
    target = GitHubAdvisoryTarget.from_osv_reference(
        "https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh",
        allowed_aliases=("CVE-2026-5000", "GHSA-2345-6789-CFGH"),
        derived_from_evidence="sha256:osv-capture",
    )
    payload = _advisory_payload()
    content = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    captured_at = datetime(2026, 9, 4, 8, 30, tzinfo=UTC)
    adapter = GitHubRepositoryAdvisoryAdapter(target)

    evidence = adapter.capture(
        payload,
        capture=CapturedSourcePayload(content=content, captured_at=captured_at),
    )
    replayed = adapter.capture(
        payload,
        capture=CapturedSourcePayload(
            content=content,
            captured_at=datetime(2026, 9, 4, 8, 31, tzinfo=UTC),
        ),
    )
    changed_payload = _advisory_payload(fixed_version="1.4.3")
    changed = adapter.capture(
        changed_payload,
        capture=CapturedSourcePayload(
            content=json.dumps(changed_payload, separators=(",", ":"), sort_keys=True),
            captured_at=datetime(2026, 9, 4, 8, 32, tzinfo=UTC),
        ),
    )

    assert evidence.source.identity == "github_repository_security_advisory"
    assert evidence.source.authority == "Repository maintainer"
    assert evidence.source.location == target.api_url
    assert evidence.captured_at == captured_at
    assert evidence.attribution == "acme/demo maintainers via GitHub Security Advisory"
    assert evidence.aliases == ("CVE-2026-5000", "GHSA-2345-6789-CFGH")
    assert evidence.payload_identity == "GHSA-2345-6789-CFGH"
    assert [(passage.kind, passage.selector) for passage in evidence.passages] == [
        ("publication", "/"),
        ("affected_guidance", "/vulnerabilities/0"),
    ]
    assert '"published_at":"2026-09-01T12:00:00Z"' in evidence.passages[0].content
    assert '"vulnerable_version_range":">= 1.0, < 1.4.2"' in (evidence.passages[1].content)
    assert '"patched_versions":"1.4.2"' in evidence.passages[1].content
    assert evidence.identity == replayed.identity
    assert evidence.content_digest == replayed.content_digest
    assert changed.identity != evidence.identity
    assert changed.content_digest != evidence.content_digest

    with pytest.raises(FrozenInstanceError):
        evidence.payload_identity = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("advisory_range", "advisory_fix", "expected_relationship", "expected_conflict"),
    [
        (">= 1.0, < 2.0", "2.0", EvidenceRelationship.SUPPORTS, False),
        (">= 1.0, < 1.4", "1.4", EvidenceRelationship.CONTRADICTS, True),
        (">= 1.4, < 2.0", "2.0", EvidenceRelationship.CONTRADICTS, True),
        (">= 1.0, < 2.0", "2.1", EvidenceRelationship.CONTRADICTS, True),
    ],
)
def test_advisory_collection_preserves_conflicting_authoritative_guidance(
    advisory_range: str,
    advisory_fix: str,
    expected_relationship: EvidenceRelationship,
    expected_conflict: bool,
) -> None:
    osv_payload = {
        "id": "PYSEC-2026-50",
        "aliases": ["CVE-2026-5000", "GHSA-2345-6789-CFGH"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "ADVISORY",
                "url": ("https://github.com/acme/demo/security/advisories/GHSA-2345-6789-cfgh"),
            }
        ],
    }
    osv_evidence = OsvSourceAdapter().capture(
        osv_payload,
        capture=CapturedSourcePayload(
            content=json.dumps(osv_payload, separators=(",", ":"), sort_keys=True),
            captured_at=datetime(2026, 9, 4, 8, 0, tzinfo=UTC),
        ),
    )
    advisory_payload = _advisory_payload(fixed_version=advisory_fix)
    advisory_payload["vulnerabilities"] = [
        {
            "package": {"ecosystem": "pip", "name": "demo-pkg"},
            "vulnerable_version_range": advisory_range,
            "patched_versions": advisory_fix,
        }
    ]
    target = derive_first_party_advisory_targets(
        (osv_evidence,), allowed_aliases=osv_evidence.aliases
    )[0]
    advisory_evidence = GitHubRepositoryAdvisoryAdapter(target).capture(
        advisory_payload,
        capture=CapturedSourcePayload(
            content=json.dumps(advisory_payload, separators=(",", ":"), sort_keys=True),
            captured_at=datetime(2026, 9, 4, 8, 30, tzinfo=UTC),
        ),
    )

    class Source:
        def retrieve(self, targets: tuple[GitHubAdvisoryTarget, ...]) -> tuple[EvidenceRecord, ...]:
            assert targets == (target,)
            return (advisory_evidence,)

    package = PackageInstance(
        name="demo-pkg",
        version="1.5",
        direct=True,
        source=PackageSource((("registry", "https://pypi.org/simple"),)),
        dependency_paths=(("demo", "demo-pkg"),),
    )
    result = AssessmentResult(
        vulnerability_records=(
            VulnerabilityRecord(identity="sha256:vulnerability", aliases=osv_evidence.aliases),
        ),
        exposures=(
            Exposure(
                vulnerability_identity="sha256:vulnerability",
                package=package,
                ranking=ExposureRanking(
                    severity=ExposureSeverity.HIGH,
                    direct_dependency=True,
                    dependency_depth=1,
                    fixed_version_available=True,
                    score=69,
                ),
                rank=1,
                selected_for_investigation=True,
                evidence=(
                    ExposureEvidence(
                        record_identity=osv_evidence.identity,
                        passage_identities=(osv_evidence.passages[0].identity,),
                        relationship=EvidenceRelationship.SUPPORTS,
                    ),
                ),
            ),
        ),
        evidence_records=(osv_evidence,),
    )

    enriched = FirstPartyAdvisoryCollector(Source()).collect(result)

    assert {record.identity for record in enriched.evidence_records} == {
        osv_evidence.identity,
        advisory_evidence.identity,
    }
    exposure = enriched.exposures[0]
    assert exposure.authoritative_conflict is expected_conflict
    osv_relationship = (
        EvidenceRelationship.CONTRADICTS if expected_conflict else EvidenceRelationship.SUPPORTS
    )
    assert [(item.record_identity, item.relationship) for item in exposure.evidence] == [
        (osv_evidence.identity, osv_relationship),
        (advisory_evidence.identity, expected_relationship),
    ]
    assert exposure.evidence[1].passage_identities == (
        advisory_evidence.passages[0].identity,
        advisory_evidence.passages[1].identity,
    )
