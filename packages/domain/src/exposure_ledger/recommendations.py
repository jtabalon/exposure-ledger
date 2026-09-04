"""Deterministic validation for evidence-backed Recommendations."""

from dataclasses import dataclass
from enum import StrEnum


class Recommendation(StrEnum):
    URGENT_REMEDIATION = "urgent_remediation"
    PLANNED_REMEDIATION = "planned_remediation"
    MONITOR = "monitor"
    NO_REMEDIATION_INDICATED = "no_remediation_indicated"
    MORE_EVIDENCE_REQUIRED = "more_evidence_required"


@dataclass(frozen=True, slots=True)
class EvidenceState:
    material_claims_supported: bool
    authoritative_conflict: bool


@dataclass(frozen=True, slots=True)
class RecommendationDecision:
    recommendation: Recommendation
    accepted: bool
    reason: str


class RecommendationPolicy:
    """Validate a proposed Recommendation without increasing its urgency."""

    @staticmethod
    def validate(*, proposed: Recommendation, evidence: EvidenceState) -> RecommendationDecision:
        if evidence.authoritative_conflict:
            return RecommendationDecision(
                recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
                accepted=False,
                reason="authoritative_evidence_conflict",
            )

        if not evidence.material_claims_supported:
            return RecommendationDecision(
                recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
                accepted=False,
                reason="material_claims_unsupported",
            )

        return RecommendationDecision(
            recommendation=proposed,
            accepted=True,
            reason="evidence_requirements_satisfied",
        )
