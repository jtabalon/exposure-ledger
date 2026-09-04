"""FastAPI application entry point."""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from exposure_ledger import (
    ActionLevel,
    Architecture,
    AssessmentOperation,
    AssessmentRequest,
    AssetSnapshotRejected,
    AssistanceClass,
    AuthorizationStatus,
    CaptureAssetSnapshot,
    CyberPolicy,
    EmbeddingSpace,
    EnvironmentProfile,
    ExposureRanking,
    ExposureSeverity,
    OperatingSystem,
    PolicyDecision,
    PolicyResult,
    SourceObservationState,
    validate_asset_snapshot_request,
)
from exposure_ledger_storage import (
    HYBRID_RETRIEVAL_CONFIGURATION_VERSION,
    SOURCE_POLICY_VERSION,
    AssessmentEvent,
    AssessmentMode,
    AssessmentRun,
    AssessmentRunRepository,
    AssessmentScenario,
    AssessmentStatus,
    AssetSnapshotRecord,
    AssetSnapshotRepository,
    EmbeddingIndexUnavailable,
    EmbeddingReadiness,
    EmbeddingSpaceNotCurrent,
    EvidencePassageRecord,
    EvidenceRecordRecord,
    EvidenceRetriever,
    ExposureRecord,
    ExposureRepository,
    ExposureRetrievalScopeNotFound,
    InvestigationRepository,
    InvestigationRevisionRecord,
    PackageInstanceRecord,
    PolicyDecisionRecord,
    RetrievalConfigurationNotCurrent,
    RetrievalEvaluationReport,
    RetrievalQuery,
    RetrievalResult,
    RetrievedCapture,
    RetrievedEvidencePassage,
    RetrievedExposureContext,
    RetrievedPassageIdentity,
    RetrievedSource,
    SourcePolicy,
    build_exposure_retrieval_query,
)
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from exposure_ledger_api.settings import Settings

APP_VERSION = "0.1.0"


def _to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)


class EmbeddingSpaceResponse(ApiModel):
    identity: str
    provider: str
    model_artifact: str
    artifact_digest: str
    dimensions: int
    retrieval_instruction: str
    normalizer: str
    passage_construction_version: str

    @classmethod
    def from_domain(cls, space: EmbeddingSpace) -> "EmbeddingSpaceResponse":
        return cls(
            identity=space.identity,
            provider=space.provider,
            model_artifact=space.model_artifact,
            artifact_digest=space.artifact_digest,
            dimensions=space.dimensions,
            retrieval_instruction=space.retrieval_instruction,
            normalizer=space.normalizer,
            passage_construction_version=space.passage_construction_version,
        )


class GenerationModelResponse(ApiModel):
    provider: str
    model_artifact: str
    artifact_digest: str


class GenerationReadinessResponse(ApiModel):
    status: Literal["ready", "unavailable"]
    code: str | None
    message: str
    setup: str | None
    model: GenerationModelResponse | None


class EmbeddingReadinessResponse(ApiModel):
    status: Literal["ready", "unavailable"]
    code: str | None
    message: str
    setup: str | None
    space: EmbeddingSpaceResponse | None

    @classmethod
    def from_record(cls, readiness: EmbeddingReadiness) -> "EmbeddingReadinessResponse":
        return cls(
            status=readiness.status,
            code=readiness.code,
            message=readiness.message,
            setup=readiness.setup,
            space=(
                EmbeddingSpaceResponse.from_domain(readiness.space)
                if readiness.space is not None
                else None
            ),
        )


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: Literal["exposure-ledger-api"]
    version: str
    inference_mode: Literal["local"]
    embeddings: EmbeddingReadinessResponse
    generation: GenerationReadinessResponse


class AssessmentPolicyContext(ApiModel):
    model_config = ConfigDict(extra="forbid")

    operation_chain: list[str] = Field(default_factory=list)


class CreateSyntheticAssessmentRunRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["synthetic"]
    scenario: AssessmentScenario = AssessmentScenario.COMPLETE
    policy_context: AssessmentPolicyContext = Field(default_factory=AssessmentPolicyContext)


class PolicyDecisionResponse(ApiModel):
    id: UUID
    assessment_run_id: UUID | None
    standard_version: str
    assistance_class: AssistanceClass
    action_level: ActionLevel
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str
    created_at: datetime
    enforcement_point: str

    @classmethod
    def from_record(cls, record: PolicyDecisionRecord) -> "PolicyDecisionResponse":
        return cls.model_validate(record, from_attributes=True)


class AssessmentRunResponse(ApiModel):
    id: UUID
    mode: AssessmentMode
    scenario: AssessmentScenario
    label: str
    synthetic: bool
    status: AssessmentStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    asset_snapshot_id: UUID | None
    policy_decision: PolicyDecisionResponse

    @classmethod
    def from_record(
        cls,
        record: AssessmentRun,
        policy_decision: PolicyDecisionRecord,
    ) -> "AssessmentRunResponse":
        return cls.model_validate(
            {
                **asdict(record),
                "policy_decision": PolicyDecisionResponse.from_record(policy_decision),
            }
        )


class AssessmentRunListResponse(ApiModel):
    items: list[AssessmentRunResponse]


class PolicyDecisionListResponse(ApiModel):
    items: list[PolicyDecisionResponse]


class EnvironmentProfileRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    python_version: str
    operating_system: OperatingSystem
    architecture: Architecture
    selected_extras: list[str] = Field(default_factory=list)


class CreateRepositoryAssessmentRunRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["repository"]
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    environment_profile: EnvironmentProfileRequest
    policy_context: AssessmentPolicyContext = Field(default_factory=AssessmentPolicyContext)


CreateAssessmentRunRequest = Annotated[
    CreateSyntheticAssessmentRunRequest | CreateRepositoryAssessmentRunRequest,
    Field(discriminator="mode"),
]


class EnvironmentProfileResponse(ApiModel):
    python_version: str
    operating_system: OperatingSystem
    architecture: Architecture
    selected_extras: list[str]

    @classmethod
    def from_domain(cls, profile: EnvironmentProfile) -> "EnvironmentProfileResponse":
        return cls(
            python_version=profile.python_version,
            operating_system=profile.operating_system,
            architecture=profile.architecture,
            selected_extras=list(profile.selected_extras),
        )


class PackageInstanceResponse(ApiModel):
    name: str
    version: str
    direct: bool | None
    source: dict[str, object]
    dependency_paths: list[list[str]] | None

    @classmethod
    def from_record(cls, package: PackageInstanceRecord) -> "PackageInstanceResponse":
        return cls(
            name=package.name,
            version=package.version,
            direct=package.direct,
            source=package.source,
            dependency_paths=(
                [list(path) for path in package.dependency_paths]
                if package.dependency_paths is not None
                else None
            ),
        )


class AssetSnapshotResponse(ApiModel):
    id: UUID
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    lockfile_digest: str
    environment_profile: EnvironmentProfileResponse
    packages: list[PackageInstanceResponse]
    parser_version: str
    captured_at: datetime

    @classmethod
    def from_record(cls, snapshot: AssetSnapshotRecord) -> "AssetSnapshotResponse":
        return cls(
            id=snapshot.id,
            repository=snapshot.repository,
            commit=snapshot.commit,
            project_root=snapshot.project_root,
            lockfile_path=snapshot.lockfile_path,
            lockfile_digest=snapshot.lockfile_digest,
            environment_profile=EnvironmentProfileResponse.from_domain(
                snapshot.environment_profile
            ),
            packages=[PackageInstanceResponse.from_record(item) for item in snapshot.packages],
            parser_version=snapshot.parser_version,
            captured_at=snapshot.captured_at,
        )


class AssetSnapshotListResponse(ApiModel):
    items: list[AssetSnapshotResponse]


class VulnerabilityRecordResponse(ApiModel):
    id: UUID
    aliases: list[str]


class ExposureRankingResponse(ApiModel):
    severity: ExposureSeverity
    direct_dependency: bool | None
    dependency_depth: int | None
    fixed_version_available: bool
    score: int

    @classmethod
    def from_domain(cls, ranking: ExposureRanking) -> "ExposureRankingResponse":
        return cls.model_validate(ranking, from_attributes=True)


class SourceResponse(ApiModel):
    identity: str
    authority: str
    location: str


class EvidencePassageResponse(ApiModel):
    id: UUID
    identity: str
    kind: str
    selector: str
    content: str

    @classmethod
    def from_record(cls, passage: EvidencePassageRecord) -> "EvidencePassageResponse":
        return cls.model_validate(passage, from_attributes=True)


class EvidenceRecordResponse(ApiModel):
    id: UUID
    identity: str
    source: SourceResponse
    captured_at: datetime
    content_digest: str
    attribution: str
    aliases: list[str]
    payload_identity: str
    content: str
    passages: list[EvidencePassageResponse]
    relationship: str

    @classmethod
    def from_record(cls, evidence: EvidenceRecordRecord) -> "EvidenceRecordResponse":
        return cls(
            id=evidence.id,
            identity=evidence.identity,
            source=SourceResponse.model_validate(evidence.source, from_attributes=True),
            captured_at=evidence.captured_at,
            content_digest=evidence.content_digest,
            attribution=evidence.attribution,
            aliases=list(evidence.aliases),
            payload_identity=evidence.payload_identity,
            content=evidence.content,
            relationship=evidence.relationship,
            passages=[EvidencePassageResponse.from_record(item) for item in evidence.passages],
        )


class KevSignalResponse(ApiModel):
    state: SourceObservationState
    listed: bool | None
    observed_at: datetime | None
    detail: str | None


class EpssSignalResponse(ApiModel):
    state: SourceObservationState
    score: float | None
    percentile: float | None
    observed_at: datetime | None
    detail: str | None


class ExposureResponse(ApiModel):
    id: UUID
    assessment_run_id: UUID
    asset_snapshot_id: UUID
    vulnerability_record: VulnerabilityRecordResponse
    package: PackageInstanceResponse
    ranking: ExposureRankingResponse
    rank: int
    selected_for_investigation: bool
    authoritative_conflict: bool
    kev: KevSignalResponse
    epss: EpssSignalResponse
    evidence_records: list[EvidenceRecordResponse]
    retrieval_query: str

    @classmethod
    def from_record(cls, exposure: ExposureRecord) -> "ExposureResponse":
        return cls(
            id=exposure.id,
            assessment_run_id=exposure.assessment_run_id,
            asset_snapshot_id=exposure.asset_snapshot_id,
            vulnerability_record=VulnerabilityRecordResponse(
                id=exposure.vulnerability_record.id,
                aliases=list(exposure.vulnerability_record.aliases),
            ),
            package=PackageInstanceResponse.from_record(exposure.package),
            ranking=ExposureRankingResponse.from_domain(exposure.ranking),
            rank=exposure.rank,
            selected_for_investigation=exposure.selected_for_investigation,
            authoritative_conflict=exposure.authoritative_conflict,
            kev=KevSignalResponse.model_validate(exposure.kev, from_attributes=True),
            epss=EpssSignalResponse(
                state=exposure.epss.state,
                score=(float(exposure.epss.score) if exposure.epss.score is not None else None),
                percentile=(
                    float(exposure.epss.percentile)
                    if exposure.epss.percentile is not None
                    else None
                ),
                observed_at=exposure.epss.observed_at,
                detail=exposure.epss.detail,
            ),
            evidence_records=[
                EvidenceRecordResponse.from_record(item) for item in exposure.evidence_records
            ],
            retrieval_query=build_exposure_retrieval_query(
                exposure.package.name,
                exposure.package.version,
                exposure.vulnerability_record.aliases,
            ),
        )


class ExposureListResponse(ApiModel):
    items: list[ExposureResponse]


class RetrievalSourcePolicyResponse(ApiModel):
    version: str
    allowed_source_identities: list[str]


class RetrievalQueryContextResponse(ApiModel):
    query: str
    assessment_run_id: UUID
    exposure_id: UUID
    source_policy: RetrievalSourcePolicyResponse
    evidence_types: list[str]
    retrieval_configuration_version: str
    embedding_space: EmbeddingSpaceResponse | None
    limit: int


class RetrievedSourceResponse(ApiModel):
    id: UUID
    identity: str
    authority: str
    location: str

    @classmethod
    def from_record(cls, source: RetrievedSource) -> "RetrievedSourceResponse":
        return cls.model_validate(source, from_attributes=True)


class RetrievedCaptureResponse(ApiModel):
    identity: str
    captured_at: datetime
    content_digest: str
    payload_identity: str
    attribution: str

    @classmethod
    def from_record(cls, capture: RetrievedCapture) -> "RetrievedCaptureResponse":
        return cls.model_validate(capture, from_attributes=True)


class RetrievedPassageResponse(ApiModel):
    id: UUID
    identity: str
    kind: str
    selector: str
    content: str

    @classmethod
    def from_record(cls, passage: RetrievedPassageIdentity) -> "RetrievedPassageResponse":
        return cls.model_validate(passage, from_attributes=True)


class RetrievedEvidencePassageResponse(ApiModel):
    full_text_rank: int | None
    full_text_score: float | None
    vector_rank: int | None
    vector_score: float | None
    fused_rank: int | None
    fused_score: float | None
    passage: RetrievedPassageResponse
    source: RetrievedSourceResponse
    capture: RetrievedCaptureResponse
    exposure_context: "RetrievedExposureContextResponse"
    evidence_record_id: UUID

    @classmethod
    def from_record(cls, retrieved: RetrievedEvidencePassage) -> "RetrievedEvidencePassageResponse":
        return cls(
            full_text_rank=retrieved.full_text_rank,
            full_text_score=retrieved.full_text_score,
            vector_rank=retrieved.vector_rank,
            vector_score=retrieved.vector_score,
            fused_rank=retrieved.fused_rank,
            fused_score=retrieved.fused_score,
            passage=RetrievedPassageResponse.from_record(retrieved.passage),
            source=RetrievedSourceResponse.from_record(retrieved.source),
            capture=RetrievedCaptureResponse.from_record(retrieved.capture),
            exposure_context=RetrievedExposureContextResponse.from_record(
                retrieved.exposure_context
            ),
            evidence_record_id=retrieved.evidence_record_id,
        )


class RetrievedExposureContextResponse(ApiModel):
    package_name: str
    package_version: str
    vulnerability_aliases: list[str]

    @classmethod
    def from_record(cls, context: RetrievedExposureContext) -> "RetrievedExposureContextResponse":
        return cls(
            package_name=context.package_name,
            package_version=context.package_version,
            vulnerability_aliases=list(context.vulnerability_aliases),
        )


class RetrievalResponse(ApiModel):
    query_context: RetrievalQueryContextResponse
    items: list[RetrievedEvidencePassageResponse]
    evaluation: "RetrievalEvaluationResponse | None"

    @classmethod
    def from_result(cls, result: RetrievalResult) -> "RetrievalResponse":
        return cls(
            query_context=RetrievalQueryContextResponse(
                query=result.query.text,
                assessment_run_id=result.query.assessment_run_id,
                exposure_id=result.query.exposure_id,
                source_policy=RetrievalSourcePolicyResponse(
                    version=result.query.source_policy.version,
                    allowed_source_identities=list(
                        result.query.source_policy.allowed_source_identities
                    ),
                ),
                evidence_types=list(result.query.evidence_types),
                retrieval_configuration_version=(result.query.retrieval_configuration_version),
                embedding_space=(
                    EmbeddingSpaceResponse.from_domain(result.embedding_space)
                    if result.embedding_space is not None
                    else None
                ),
                limit=result.query.limit,
            ),
            items=[RetrievedEvidencePassageResponse.from_record(item) for item in result.passages],
            evaluation=(
                RetrievalEvaluationResponse.from_record(result.evaluation)
                if result.evaluation is not None
                else None
            ),
        )


class RetrievalEvaluationResponse(ApiModel):
    k: int
    expected_count: int
    retrieved_count: int
    matched_passage_identities: list[str]
    recall_at_k: float

    @classmethod
    def from_record(cls, report: RetrievalEvaluationReport) -> "RetrievalEvaluationResponse":
        return cls(
            k=report.k,
            expected_count=report.expected_count,
            retrieved_count=report.retrieved_count,
            matched_passage_identities=list(report.matched_passage_identities),
            recall_at_k=report.recall_at_k,
        )


class ClaimCitationResponse(ApiModel):
    evidence_record_id: UUID
    evidence_record_identity: str
    passage_identities: list[str]
    relationship: str


class InvestigationClaimResponse(ApiModel):
    identity: str
    kind: str
    text: str
    material: bool
    limitation: str | None
    supported: bool
    citations: list[ClaimCitationResponse]


class RevisionEvidenceRecordResponse(ApiModel):
    record_id: UUID
    record_identity: str
    content_digest: str
    source_identity: str
    source_adapter_version: str
    passage_identities: list[str]


class RevisionRetrievedPassageResponse(ApiModel):
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


class RevisionRetrievedEvidenceResponse(ApiModel):
    query: str
    passages: list[RevisionRetrievedPassageResponse]


class RevisionEvidenceStateResponse(ApiModel):
    available: list[RevisionEvidenceRecordResponse]
    retrieved: RevisionRetrievedEvidenceResponse
    material_claims_supported: bool
    authoritative_conflict: bool | None
    validation_issues: list[str]


class RevisionRecommendationResponse(ApiModel):
    value: str
    accepted: bool
    reason: str
    summary: str
    reasons: list[str]
    limitations: list[str]


class RevisionPolicyDecisionResponse(ApiModel):
    standard_version: str
    assistance_class: AssistanceClass
    action_level: ActionLevel
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str
    enforcement_point: Literal["structured_output", "tool_call"]

    @classmethod
    def from_domain(
        cls,
        decision: PolicyDecision,
        *,
        enforcement_point: Literal["structured_output", "tool_call"] = "structured_output",
    ) -> "RevisionPolicyDecisionResponse":
        return cls(
            standard_version=decision.standard_version,
            assistance_class=decision.assistance_class,
            action_level=decision.action_level,
            target_scope=decision.target_scope,
            authorization_scope=decision.authorization_scope,
            result=decision.result,
            rule_version=decision.rule_version,
            reason=decision.reason,
            enforcement_point=enforcement_point,
        )


class EvidenceGapResponse(ApiModel):
    identity: str
    kind: str
    description: str


class EvidenceFollowUpArgumentsResponse(ApiModel):
    source_identity: str
    evidence_type: str


class EvidenceFollowUpProposalResponse(ApiModel):
    tool: str
    target: str
    arguments: EvidenceFollowUpArgumentsResponse
    assistance_class: str
    action_level: str


class EvidenceFollowUpAuthorizationResponse(ApiModel):
    authorized: bool
    executed: bool
    reason: str
    issues: list[str]
    policy_decision: RevisionPolicyDecisionResponse


class EvidenceFollowUpResponse(ApiModel):
    proposal: EvidenceFollowUpProposalResponse
    authorization: EvidenceFollowUpAuthorizationResponse


class InvestigationEventResponse(ApiModel):
    stage: str
    mode: str
    detail: str
    occurred_at: datetime


class InvestigationMeasurementsResponse(ApiModel):
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    generation_model_calls: int
    tool_calls: int
    graph_transitions: int


class InvestigationConfigurationResponse(ApiModel):
    application_release: str
    graph_version: str
    prompt_version: str
    policy_version: str
    parser_version: str
    retrieval_configuration_version: str
    source_policy_version: str
    source_adapter_versions: list[str]
    generation_model: GenerationModelResponse
    embedding_space: EmbeddingSpaceResponse


class InvestigationRevisionResponse(ApiModel):
    investigation_id: UUID
    revision_number: int
    id: UUID
    assessment_run_id: UUID
    exposure_id: UUID
    asset_snapshot_id: UUID
    status: str
    stopping_condition: str
    stopping_reason: str | None
    evidence_gap: EvidenceGapResponse | None
    follow_up: EvidenceFollowUpResponse | None
    evidence_state: RevisionEvidenceStateResponse
    claims: list[InvestigationClaimResponse]
    recommendation: RevisionRecommendationResponse
    output_policy_decision: RevisionPolicyDecisionResponse
    events: list[InvestigationEventResponse]
    measurements: InvestigationMeasurementsResponse
    configuration: InvestigationConfigurationResponse
    created_at: datetime

    @classmethod
    def from_record(cls, record: InvestigationRevisionRecord) -> "InvestigationRevisionResponse":
        revision = record.revision
        return cls(
            investigation_id=record.investigation_id,
            revision_number=record.revision_number,
            id=revision.id,
            assessment_run_id=revision.assessment_run_id,
            exposure_id=revision.exposure_id,
            asset_snapshot_id=revision.asset_snapshot_id,
            status=revision.status,
            stopping_condition=revision.stopping_condition,
            stopping_reason=revision.stopping_reason,
            evidence_gap=(
                EvidenceGapResponse.model_validate(revision.evidence_gap, from_attributes=True)
                if revision.evidence_gap is not None
                else None
            ),
            follow_up=(
                EvidenceFollowUpResponse(
                    proposal=EvidenceFollowUpProposalResponse(
                        tool=revision.follow_up.proposal.tool,
                        target=revision.follow_up.proposal.target,
                        arguments=EvidenceFollowUpArgumentsResponse.model_validate(
                            revision.follow_up.proposal.arguments, from_attributes=True
                        ),
                        assistance_class=revision.follow_up.proposal.assistance_class,
                        action_level=revision.follow_up.proposal.action_level,
                    ),
                    authorization=EvidenceFollowUpAuthorizationResponse(
                        authorized=revision.follow_up.authorized,
                        executed=revision.follow_up.executed,
                        reason=revision.follow_up.reason,
                        issues=list(revision.follow_up.issues),
                        policy_decision=RevisionPolicyDecisionResponse.from_domain(
                            revision.follow_up.policy_decision,
                            enforcement_point="tool_call",
                        ),
                    ),
                )
                if revision.follow_up is not None
                else None
            ),
            evidence_state=RevisionEvidenceStateResponse(
                available=[
                    RevisionEvidenceRecordResponse(
                        record_id=item.record_id,
                        record_identity=item.record_identity,
                        content_digest=item.content_digest,
                        source_identity=item.source_identity,
                        source_adapter_version=item.source_adapter_version,
                        passage_identities=list(item.passage_identities),
                    )
                    for item in revision.evidence_state.available
                ],
                retrieved=RevisionRetrievedEvidenceResponse(
                    query=revision.evidence_state.retrieved.query,
                    passages=[
                        RevisionRetrievedPassageResponse.model_validate(item, from_attributes=True)
                        for item in revision.evidence_state.retrieved.passages
                    ],
                ),
                material_claims_supported=(revision.evidence_state.material_claims_supported),
                authoritative_conflict=revision.evidence_state.authoritative_conflict,
                validation_issues=list(revision.evidence_state.validation_issues),
            ),
            claims=[
                InvestigationClaimResponse(
                    identity=claim.identity,
                    kind=claim.kind,
                    text=claim.text,
                    material=claim.material,
                    limitation=claim.limitation,
                    supported=claim.supported,
                    citations=[
                        ClaimCitationResponse(
                            evidence_record_id=citation.evidence_record_id,
                            evidence_record_identity=citation.evidence_record_identity,
                            passage_identities=list(citation.passage_identities),
                            relationship=citation.relationship,
                        )
                        for citation in claim.citations
                    ],
                )
                for claim in revision.claims
            ],
            recommendation=RevisionRecommendationResponse(
                value=revision.recommendation.recommendation,
                accepted=revision.recommendation.accepted,
                reason=revision.recommendation.reason,
                summary=revision.recommendation.summary,
                reasons=list(revision.recommendation.reasons),
                limitations=list(revision.recommendation.limitations),
            ),
            output_policy_decision=RevisionPolicyDecisionResponse.from_domain(
                revision.output_policy_decision
            ),
            events=[
                InvestigationEventResponse.model_validate(item, from_attributes=True)
                for item in revision.events
            ],
            measurements=InvestigationMeasurementsResponse.model_validate(
                revision.measurements, from_attributes=True
            ),
            configuration=InvestigationConfigurationResponse(
                application_release=revision.configuration.application_release,
                graph_version=revision.configuration.graph_version,
                prompt_version=revision.configuration.prompt_version,
                policy_version=revision.configuration.policy_version,
                parser_version=revision.configuration.parser_version,
                retrieval_configuration_version=(
                    revision.configuration.retrieval_configuration_version
                ),
                source_policy_version=revision.configuration.source_policy_version,
                source_adapter_versions=list(revision.configuration.source_adapter_versions),
                generation_model=GenerationModelResponse.model_validate(
                    revision.configuration.generation_model, from_attributes=True
                ),
                embedding_space=EmbeddingSpaceResponse.from_domain(
                    revision.configuration.embedding_space
                ),
            ),
            created_at=revision.created_at,
        )


class InvestigationRevisionListResponse(ApiModel):
    items: list[InvestigationRevisionResponse]


def _not_found(assessment_run_id: UUID) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "code": "assessment_run_not_found",
            "message": f"Assessment Run {assessment_run_id} was not found.",
        },
    )


def _assessment_response(
    repository: AssessmentRunRepository,
    assessment_run: AssessmentRun,
) -> AssessmentRunResponse:
    policy_decision = repository.get_policy_decision(assessment_run.id)
    if policy_decision is None:
        raise RuntimeError(f"Assessment Run {assessment_run.id} has no request Policy Decision.")
    return AssessmentRunResponse.from_record(assessment_run, policy_decision)


def _encode_sse(event: AssessmentEvent) -> str:
    body = {
        "assessmentRunId": str(event.assessment_run_id),
        "sequence": event.sequence,
        "type": event.event_type,
        "occurredAt": event.occurred_at.isoformat(),
        **event.payload,
    }
    return (
        f"id: {event.sequence}\n"
        f"event: {event.event_type}\n"
        f"data: {json.dumps(body, separators=(',', ':'))}\n\n"
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    configured_settings = settings or Settings()
    repository = AssessmentRunRepository(configured_settings.database_url)
    snapshot_repository = AssetSnapshotRepository(configured_settings.database_url)
    exposure_repository = ExposureRepository(configured_settings.database_url)
    investigation_repository = InvestigationRepository(configured_settings.database_url)
    evidence_retriever = EvidenceRetriever(configured_settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        repository.check_ready()
        snapshot_repository.check_ready()
        exposure_repository.check_ready()
        investigation_repository.check_ready()
        evidence_retriever.check_ready()
        yield

    application = FastAPI(
        title="Exposure Ledger API",
        summary="Evidence-led software exposure investigations",
        version=APP_VERSION,
        lifespan=lifespan,
    )

    @application.exception_handler(RequestValidationError)
    async def typed_request_validation(
        request: Request,
        error: RequestValidationError,
    ) -> Response:
        body = error.body
        selection_error_fields = {
            str(item["loc"][-1])
            for item in error.errors()
            if item.get("loc")
            and item["loc"][-1] in {"projectRoot", "lockfilePath", "project_root", "lockfile_path"}
        }
        if isinstance(body, dict) and body.get("mode") == "repository" and selection_error_fields:
            raw_context = body.get("policyContext", body.get("policy_context", {}))
            raw_chain = (
                raw_context.get("operationChain", raw_context.get("operation_chain", []))
                if isinstance(raw_context, dict)
                else []
            )
            operation_chain = (
                tuple(raw_chain)
                if isinstance(raw_chain, list)
                and all(isinstance(operation, str) for operation in raw_chain)
                else ("unrecognized_operation",)
            )
            raw_repository = body.get("repository")
            raw_commit = body.get("commit")
            target_scope = (
                f"{raw_repository}@{raw_commit}"
                if isinstance(raw_repository, str) and isinstance(raw_commit, str)
                else None
            )
            decision = CyberPolicy.decide(
                AssessmentRequest(
                    operation=AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT,
                    target_scope=target_scope,
                    authorization_scope="local operator",
                    authorization_status=AuthorizationStatus.UNCERTAIN,
                    operation_chain=operation_chain,
                )
            )
            repository.record_policy_decision(
                replace(
                    decision,
                    result=PolicyResult.BLOCKED,
                    reason=(
                        "Asset Snapshot project and lockfile selection is materially uncertain; "
                        "the Assessment request is blocked."
                    ),
                )
            )
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                content={
                    "detail": {
                        "code": "asset_snapshot_selection_required",
                        "message": (
                            "Select exactly one project root and one supported lockfile before "
                            "capturing an Asset Snapshot."
                        ),
                    }
                },
            )
        return await request_validation_exception_handler(request, error)

    @application.get("/health", response_model=HealthResponse, tags=["operations"])
    def health() -> HealthResponse:
        embedding_readiness = evidence_retriever.embedding_readiness()
        generation_readiness = investigation_repository.generation_readiness()
        return HealthResponse(
            status=(
                "ok"
                if embedding_readiness.status == generation_readiness.status == "ready"
                else "degraded"
            ),
            service="exposure-ledger-api",
            version=APP_VERSION,
            inference_mode="local",
            embeddings=EmbeddingReadinessResponse.from_record(embedding_readiness),
            generation=GenerationReadinessResponse(
                status=generation_readiness.status,
                code=generation_readiness.code,
                message=generation_readiness.message,
                setup=generation_readiness.setup,
                model=(
                    GenerationModelResponse.model_validate(
                        generation_readiness.model, from_attributes=True
                    )
                    if generation_readiness.model is not None
                    else None
                ),
            ),
        )

    @application.get(
        "/api/v1/asset-snapshots",
        response_model=AssetSnapshotListResponse,
        response_model_by_alias=True,
        tags=["asset-snapshots"],
    )
    def list_asset_snapshots() -> AssetSnapshotListResponse:
        return AssetSnapshotListResponse(
            items=[AssetSnapshotResponse.from_record(item) for item in snapshot_repository.list()]
        )

    @application.get(
        "/api/v1/asset-snapshots/{snapshot_id}",
        response_model=AssetSnapshotResponse,
        response_model_by_alias=True,
        tags=["asset-snapshots"],
    )
    def get_asset_snapshot(snapshot_id: UUID) -> AssetSnapshotResponse:
        snapshot = snapshot_repository.get(snapshot_id)
        if snapshot is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "asset_snapshot_not_found",
                    "message": f"Asset Snapshot {snapshot_id} was not found.",
                },
            )
        return AssetSnapshotResponse.from_record(snapshot)

    @application.post(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunResponse,
        response_model_by_alias=True,
        status_code=status.HTTP_201_CREATED,
        tags=["assessment-runs"],
    )
    def create_assessment_run(request: CreateAssessmentRunRequest) -> AssessmentRunResponse:
        context = request.policy_context
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            operation = AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT
            target_scope = f"{request.repository}@{request.commit}"
        else:
            operation = AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT
            target_scope = "bundled synthetic fixture"
        decision = CyberPolicy.decide(
            AssessmentRequest(
                operation=operation,
                target_scope=target_scope,
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
                operation_chain=tuple(context.operation_chain),
            )
        )
        if decision.result is not PolicyResult.ALLOWED:
            policy_record = repository.record_policy_decision(decision)
            response = PolicyDecisionResponse.from_record(policy_record)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": f"assessment_policy_{decision.result}",
                    "message": decision.reason,
                    "policyDecision": response.model_dump(mode="json", by_alias=True),
                },
            )
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            try:
                profile = EnvironmentProfile(
                    python_version=request.environment_profile.python_version,
                    operating_system=request.environment_profile.operating_system,
                    architecture=request.environment_profile.architecture,
                    selected_extras=tuple(request.environment_profile.selected_extras),
                )
                capture_request = validate_asset_snapshot_request(
                    CaptureAssetSnapshot(
                        repository=request.repository,
                        commit=request.commit,
                        project_root=request.project_root,
                        lockfile_path=request.lockfile_path,
                        environment_profile=profile,
                    )
                )
            except AssetSnapshotRejected as error:
                repository.record_policy_decision(
                    replace(
                        decision,
                        result=PolicyResult.BLOCKED,
                        reason=(
                            f"Target scope is invalid; the Assessment request is blocked: {error}"
                        ),
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={"code": error.code, "message": str(error)},
                ) from error
            except ValueError as error:
                repository.record_policy_decision(
                    replace(
                        decision,
                        result=PolicyResult.BLOCKED,
                        reason=(
                            "Environment Profile is invalid; the Assessment request is blocked: "
                            f"{error}"
                        ),
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={"code": "invalid_environment_profile", "message": str(error)},
                ) from error
            target_scope = f"{capture_request.repository}@{capture_request.commit}"
            decision = CyberPolicy.decide(
                AssessmentRequest(
                    operation=operation,
                    target_scope=target_scope,
                    authorization_scope="local operator",
                    authorization_status=AuthorizationStatus.CONFIRMED,
                    operation_chain=tuple(context.operation_chain),
                )
            )
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            assessment_run = repository.create_repository(
                capture_request=capture_request,
                label=(
                    f"{capture_request.repository.removeprefix('https://github.com/')}"
                    f"@{capture_request.commit[:12]}"
                ),
                policy_decision=decision,
            )
        else:
            assessment_run = repository.create_synthetic(
                scenario=request.scenario,
                policy_decision=decision,
            )
        return _assessment_response(repository, assessment_run)

    @application.get(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunListResponse,
        response_model_by_alias=True,
        tags=["assessment-runs"],
    )
    def list_assessment_runs() -> AssessmentRunListResponse:
        return AssessmentRunListResponse(
            items=[_assessment_response(repository, item) for item in repository.list_runs()]
        )

    @application.get(
        "/api/v1/policy-decisions",
        response_model=PolicyDecisionListResponse,
        response_model_by_alias=True,
        tags=["policy-decisions"],
    )
    def list_policy_decisions() -> PolicyDecisionListResponse:
        return PolicyDecisionListResponse(
            items=[
                PolicyDecisionResponse.from_record(item)
                for item in repository.list_policy_decisions()
            ]
        )

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}",
        response_model=AssessmentRunResponse,
        response_model_by_alias=True,
        tags=["assessment-runs"],
    )
    def get_assessment_run(assessment_run_id: UUID) -> AssessmentRunResponse:
        assessment_run = repository.get(assessment_run_id)
        if assessment_run is None:
            raise _not_found(assessment_run_id)
        return _assessment_response(repository, assessment_run)

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/exposures",
        response_model=ExposureListResponse,
        response_model_by_alias=True,
        tags=["exposures"],
    )
    def list_assessment_exposures(assessment_run_id: UUID) -> ExposureListResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)
        return ExposureListResponse(
            items=[
                ExposureResponse.from_record(item)
                for item in exposure_repository.list_for_assessment(assessment_run_id)
            ]
        )

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/investigation-revisions",
        response_model=InvestigationRevisionListResponse,
        response_model_by_alias=True,
        tags=["investigations"],
    )
    def list_assessment_investigation_revisions(
        assessment_run_id: UUID,
    ) -> InvestigationRevisionListResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)
        return InvestigationRevisionListResponse(
            items=[
                InvestigationRevisionResponse.from_record(item)
                for item in investigation_repository.list_for_assessment(assessment_run_id)
            ]
        )

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/exposures/{exposure_id}/evidence-passages",
        response_model=RetrievalResponse,
        response_model_by_alias=True,
        tags=["exposures"],
    )
    def retrieve_exposure_evidence_passages(
        assessment_run_id: UUID,
        exposure_id: UUID,
        query: Annotated[str, Query(min_length=1, max_length=500)],
        source_identity: Annotated[list[str], Query(alias="sourceIdentity", min_length=1)],
        evidence_type: Annotated[list[str], Query(alias="evidenceType", min_length=1)],
        retrieval_configuration_version: Annotated[
            str, Query(alias="retrievalConfigurationVersion")
        ] = HYBRID_RETRIEVAL_CONFIGURATION_VERSION,
        embedding_space_identity: Annotated[
            str | None, Query(alias="embeddingSpaceIdentity")
        ] = None,
        expected_passage_identity: Annotated[
            list[str] | None, Query(alias="expectedPassageIdentity")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 10,
    ) -> RetrievalResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)
        retrieval_query = RetrievalQuery(
            assessment_run_id=assessment_run_id,
            exposure_id=exposure_id,
            text=query,
            source_policy=SourcePolicy(
                version=SOURCE_POLICY_VERSION,
                allowed_source_identities=tuple(source_identity),
            ),
            evidence_types=tuple(evidence_type),
            retrieval_configuration_version=retrieval_configuration_version,
            embedding_space_identity=embedding_space_identity,
            expected_passage_identities=tuple(expected_passage_identity or ()),
            limit=limit,
        )
        try:
            result = evidence_retriever.retrieve(retrieval_query)
        except RetrievalConfigurationNotCurrent as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "retrieval_configuration_not_current",
                    "message": str(error),
                    "currentVersion": HYBRID_RETRIEVAL_CONFIGURATION_VERSION,
                },
            ) from error
        except ExposureRetrievalScopeNotFound as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "exposure_not_found",
                    "message": str(error),
                },
            ) from error
        except EmbeddingSpaceNotCurrent as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": "embedding_space_not_current",
                    "message": str(error),
                    "currentEmbeddingSpaceIdentity": None,
                },
            ) from error
        except EmbeddingIndexUnavailable as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "embedding_index_unavailable",
                    "message": str(error),
                    "setup": "Run a new Assessment after `make models` succeeds.",
                },
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "invalid_retrieval_query", "message": str(error)},
            ) from error
        return RetrievalResponse.from_result(result)

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/events",
        response_class=StreamingResponse,
        tags=["assessment-runs"],
        responses={200: {"content": {"text/event-stream": {}}}},
    )
    async def stream_assessment_events(
        assessment_run_id: UUID,
        request: Request,
        after: Annotated[int | None, Query(ge=0)] = None,
        follow: bool = True,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)

        cursor = after if after is not None else _parse_last_event_id(last_event_id)

        async def event_stream() -> AsyncIterator[str]:
            current = cursor
            while True:
                events = repository.list_events(assessment_run_id, after=current)
                for event in events:
                    current = event.sequence
                    yield _encode_sse(event)

                assessment_run = repository.get(assessment_run_id)
                finished = assessment_run is None or assessment_run.status in {
                    AssessmentStatus.COMPLETED,
                    AssessmentStatus.FAILED,
                }
                if not follow or finished or await request.is_disconnected():
                    break
                await asyncio.sleep(configured_settings.event_poll_seconds)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    return application


def _parse_last_event_id(value: str | None) -> int:
    if value is None:
        return 0
    try:
        parsed = int(value)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_event_cursor",
                "message": "Last-Event-ID must be a non-negative integer.",
            },
        ) from error
    if parsed < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_event_cursor",
                "message": "Last-Event-ID must be a non-negative integer.",
            },
        )
    return parsed


app = create_app()
