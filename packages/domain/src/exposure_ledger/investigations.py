"""Evidence-backed Claims and immutable Investigation Revision domain records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from exposure_ledger.cyber_policy import AssessmentOperation, PolicyDecision
from exposure_ledger.embeddings import EmbeddingSpace
from exposure_ledger.evidence import EvidenceRelationship
from exposure_ledger.recommendations import Recommendation

_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class ClaimKind(StrEnum):
    FACT = "fact"
    INFERENCE = "inference"


@dataclass(frozen=True, slots=True)
class AvailableEvidence:
    record_id: UUID
    record_identity: str
    content_digest: str
    source_identity: str
    source_adapter_version: str
    passage_identities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClaimEvidenceCitation:
    evidence_record_id: UUID
    passage_identities: tuple[str, ...]
    relationship: EvidenceRelationship


@dataclass(frozen=True, slots=True)
class ClaimDraft:
    identity: str
    kind: ClaimKind
    text: str
    material: bool
    limitation: str | None
    citations: tuple[ClaimEvidenceCitation, ...]


@dataclass(frozen=True, slots=True)
class ClaimEvidenceRelationship:
    evidence_record_id: UUID
    evidence_record_identity: str
    passage_identities: tuple[str, ...]
    relationship: EvidenceRelationship


@dataclass(frozen=True, slots=True)
class Claim:
    identity: str
    kind: ClaimKind
    text: str
    material: bool
    limitation: str | None
    supported: bool
    citations: tuple[ClaimEvidenceRelationship, ...]


@dataclass(frozen=True, slots=True)
class ClaimValidation:
    claims: tuple[Claim, ...]
    material_claims_supported: bool
    authoritative_conflict: bool
    issues: tuple[str, ...]


class ClaimValidator:
    """Validate model-drafted Claims against the retrieved immutable evidence scope."""

    @staticmethod
    def validate(
        *,
        claims: tuple[ClaimDraft, ...],
        available_evidence: tuple[AvailableEvidence, ...],
        authoritative_conflict: bool,
    ) -> ClaimValidation:
        evidence_by_id = {evidence.record_id: evidence for evidence in available_evidence}
        seen_identities: set[str] = set()
        validated: list[Claim] = []
        issues: list[str] = []

        for draft in claims:
            identity = draft.identity.strip()
            text = draft.text.strip()
            claim_issues: list[str] = []
            if not identity or identity in seen_identities:
                claim_issues.append("identity_not_unique")
            seen_identities.add(identity)
            if not text or "\n" in text or len(text) > 500:
                claim_issues.append("atomic_text_invalid")

            citations: list[ClaimEvidenceRelationship] = []
            for citation in draft.citations:
                evidence = evidence_by_id.get(citation.evidence_record_id)
                if evidence is None:
                    claim_issues.append("unknown_evidence_record")
                    continue
                if not citation.passage_identities or not set(citation.passage_identities).issubset(
                    evidence.passage_identities
                ):
                    claim_issues.append("unknown_evidence_passage")
                    continue
                citations.append(
                    ClaimEvidenceRelationship(
                        evidence_record_id=evidence.record_id,
                        evidence_record_identity=evidence.record_identity,
                        passage_identities=tuple(dict.fromkeys(citation.passage_identities)),
                        relationship=citation.relationship,
                    )
                )

            limitation = draft.limitation.strip() if draft.limitation else None
            if draft.kind is ClaimKind.INFERENCE:
                if limitation is None:
                    claim_issues.append("inference_limitation_required")
                if not citations:
                    claim_issues.append("inference_inputs_required")
                supported = limitation is not None and bool(citations)
            else:
                has_support = any(
                    citation.relationship is EvidenceRelationship.SUPPORTS for citation in citations
                )
                supported = bool(citations) and (not draft.material or has_support)
                if not citations:
                    claim_issues.append("claim_evidence_required")
                if draft.material and not has_support:
                    claim_issues.append("material_claim_missing_support")

            issues.extend(f"{identity or '<blank>'}:{issue}" for issue in claim_issues)
            validated.append(
                Claim(
                    identity=identity,
                    kind=draft.kind,
                    text=text,
                    material=draft.material,
                    limitation=limitation,
                    supported=supported
                    and not {
                        "identity_not_unique",
                        "atomic_text_invalid",
                    }.intersection(claim_issues),
                    citations=tuple(citations),
                )
            )

        material_claims_supported = bool(validated) and all(claim.supported for claim in validated)
        return ClaimValidation(
            claims=tuple(validated),
            material_claims_supported=material_claims_supported,
            authoritative_conflict=authoritative_conflict,
            issues=tuple(issues),
        )


@dataclass(frozen=True, slots=True)
class GenerationModel:
    provider: str
    model_artifact: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.model_artifact.strip():
            raise ValueError("Generation model fields must not be blank")
        if _SHA256_DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("Generation model requires an immutable sha256 digest")


@dataclass(frozen=True, slots=True)
class GenerationReadiness:
    status: Literal["ready", "unavailable"]
    code: str | None
    message: str
    setup: str | None
    model: GenerationModel | None


@dataclass(frozen=True, slots=True)
class InvestigationConfiguration:
    application_release: str
    graph_version: str
    prompt_version: str
    policy_version: str
    parser_version: str
    retrieval_configuration_version: str
    source_policy_version: str
    source_adapter_versions: tuple[str, ...]
    generation_model: GenerationModel
    embedding_space: EmbeddingSpace

    def __post_init__(self) -> None:
        values = (
            self.application_release,
            self.graph_version,
            self.prompt_version,
            self.policy_version,
            self.parser_version,
            self.retrieval_configuration_version,
            self.source_policy_version,
            *self.source_adapter_versions,
        )
        if not self.source_adapter_versions or any(not value.strip() for value in values):
            raise ValueError("Investigation configuration identities must not be blank")
        source_identities = [
            value.partition("=")[0] for value in self.source_adapter_versions if "=" in value
        ]
        if len(source_identities) != len(self.source_adapter_versions) or len(
            set(source_identities)
        ) != len(source_identities):
            raise ValueError("Source adapter versions must uniquely map Source identity to version")
        if any(
            not value.partition("=")[0].strip() or not value.partition("=")[2].strip()
            for value in self.source_adapter_versions
        ):
            raise ValueError("Source adapter versions must uniquely map Source identity to version")


@dataclass(frozen=True, slots=True)
class InvestigationBudget:
    max_generation_model_calls: int = 5
    max_tool_calls: int = 15
    max_graph_transitions: int = 12
    wall_time_seconds: float = 120

    def __post_init__(self) -> None:
        if (
            min(
                self.max_generation_model_calls,
                self.max_tool_calls,
                self.max_graph_transitions,
            )
            <= 0
            or self.wall_time_seconds <= 0
        ):
            raise ValueError("Investigation budgets must be positive")


@dataclass(frozen=True, slots=True)
class RunInvestigation:
    assessment_run_id: UUID
    exposure_id: UUID
    asset_snapshot_id: UUID
    configuration: InvestigationConfiguration
    budget: InvestigationBudget


@dataclass(frozen=True, slots=True)
class InvestigationExposure:
    assessment_run_id: UUID
    exposure_id: UUID
    asset_snapshot_id: UUID
    package_name: str
    package_version: str
    vulnerability_aliases: tuple[str, ...]
    authoritative_conflict: bool
    evidence: tuple[AvailableEvidence, ...]


@dataclass(frozen=True, slots=True)
class RetrievedInvestigationPassage:
    evidence_record_id: UUID
    evidence_record_identity: str
    evidence_record_digest: str
    passage_identity: str
    passage: str
    source_identity: str
    source_authority: str
    source_location: str
    captured_at: datetime
    full_text_rank: int | None
    full_text_score: float | None
    vector_rank: int | None
    vector_score: float | None
    fused_rank: int
    fused_score: float


@dataclass(frozen=True, slots=True)
class RetrievedInvestigationEvidence:
    query: str
    passages: tuple[RetrievedInvestigationPassage, ...]


@dataclass(frozen=True, slots=True)
class StructuredInvestigationDraft:
    operation: AssessmentOperation | str
    claims: tuple[ClaimDraft, ...]
    recommendation: Recommendation
    recommendation_summary: str
    recommendation_reasons: tuple[str, ...]
    recommendation_limitations: tuple[str, ...]


class InvestigationRevisionStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class InvestigationStage(StrEnum):
    LOAD_EXPOSURE = "load_exposure"
    ACQUIRE_EVIDENCE = "acquire_evidence"
    RETRIEVE_PASSAGES = "retrieve_passages"
    SYNTHESIZE_CLAIMS = "synthesize_claims"
    VALIDATE_CLAIMS = "validate_claims"
    RECOMMEND = "recommend"
    VALIDATE_POLICY = "validate_policy"
    PERSIST_REVISION = "persist_revision"


class InvestigationEventMode(StrEnum):
    DETERMINISTIC = "deterministic"
    RETRIEVAL = "retrieval"
    MODEL = "model"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class InvestigationEvidenceState:
    available: tuple[AvailableEvidence, ...]
    retrieved: RetrievedInvestigationEvidence
    material_claims_supported: bool
    authoritative_conflict: bool
    validation_issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RevisionRecommendation:
    recommendation: Recommendation
    accepted: bool
    reason: str
    summary: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InvestigationEvent:
    stage: InvestigationStage
    mode: InvestigationEventMode
    detail: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class InvestigationMeasurements:
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    generation_model_calls: int
    tool_calls: int
    graph_transitions: int


@dataclass(frozen=True, slots=True)
class InvestigationRevision:
    id: UUID
    assessment_run_id: UUID
    exposure_id: UUID
    asset_snapshot_id: UUID
    status: InvestigationRevisionStatus
    stopping_condition: str
    evidence_state: InvestigationEvidenceState
    claims: tuple[Claim, ...]
    recommendation: RevisionRecommendation
    output_policy_decision: PolicyDecision
    events: tuple[InvestigationEvent, ...]
    measurements: InvestigationMeasurements
    configuration: InvestigationConfiguration
    created_at: datetime
