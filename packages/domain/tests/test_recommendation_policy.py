from exposure_ledger.recommendations import (
    EvidenceState,
    Recommendation,
    RecommendationPolicy,
)


def test_authoritative_conflict_forces_more_evidence() -> None:
    decision = RecommendationPolicy.validate(
        proposed=Recommendation.URGENT_REMEDIATION,
        evidence=EvidenceState(
            material_claims_supported=True,
            authoritative_conflict=True,
        ),
    )

    assert decision.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert decision.accepted is False
    assert decision.reason == "authoritative_evidence_conflict"


def test_unsupported_material_claims_force_more_evidence() -> None:
    decision = RecommendationPolicy.validate(
        proposed=Recommendation.PLANNED_REMEDIATION,
        evidence=EvidenceState(
            material_claims_supported=False,
            authoritative_conflict=False,
        ),
    )

    assert decision.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert decision.accepted is False
    assert decision.reason == "material_claims_unsupported"
