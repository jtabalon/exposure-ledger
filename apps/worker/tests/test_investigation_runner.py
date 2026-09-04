from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest
from exposure_ledger import (
    ActionLevel,
    AssessmentOperation,
    AssistanceClass,
    AvailableEvidence,
    ClaimDraft,
    ClaimEvidenceCitation,
    ClaimKind,
    EmbeddingSpace,
    EvidenceRelationship,
    GenerationModel,
    InvestigationBudget,
    InvestigationConfiguration,
    InvestigationExposure,
    InvestigationRevision,
    InvestigationRevisionStatus,
    PolicyResult,
    Recommendation,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
    RunInvestigation,
    StructuredInvestigationDraft,
)
from exposure_ledger_worker.investigations import BoundedInvestigationRunner
from exposure_ledger_worker.local_generation import GenerationReadiness

ASSESSMENT_ID = UUID("00000000-0000-0000-0000-000000000013")
EXPOSURE_ID = UUID("00000000-0000-0000-0000-000000000042")
SNAPSHOT_ID = UUID("00000000-0000-0000-0000-000000000007")
EVIDENCE_ID = UUID("00000000-0000-0000-0000-000000000081")
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _embedding_space() -> EmbeddingSpace:
    return EmbeddingSpace(
        provider="known-answer-local",
        model_artifact="known-answer-embedding-v1",
        artifact_digest="sha256:" + "a" * 64,
        dimensions=3,
        retrieval_instruction="Represent this query for evidence retrieval: ",
        normalizer="l2-v1",
        passage_construction_version="source-aware-passage-v1",
    )


def _generation_model() -> GenerationModel:
    return GenerationModel(
        provider="controlled-local",
        model_artifact="controlled-generation-v1",
        artifact_digest="sha256:" + "b" * 64,
    )


def _command() -> RunInvestigation:
    return RunInvestigation(
        assessment_run_id=ASSESSMENT_ID,
        exposure_id=EXPOSURE_ID,
        asset_snapshot_id=SNAPSHOT_ID,
        configuration=InvestigationConfiguration(
            application_release="0.1.0",
            graph_version="bounded-investigation-v1",
            prompt_version="claims-recommendation-v1",
            policy_version="0.1",
            parser_version="uv-lock-v1",
            retrieval_configuration_version="postgres-hybrid-rrf-v1",
            source_policy_version="explicit-source-allowlist-v1",
            source_adapter_versions=("osv=osv-v1",),
            generation_model=_generation_model(),
            embedding_space=_embedding_space(),
        ),
        budget=InvestigationBudget(),
    )


class ControlledEvidenceAcquirer:
    def __init__(self) -> None:
        self.calls = 0

    def acquire(
        self, command: RunInvestigation, *, timeout_seconds: float
    ) -> InvestigationExposure:
        self.calls += 1
        assert timeout_seconds > 0
        assert command.exposure_id == EXPOSURE_ID
        return InvestigationExposure(
            assessment_run_id=ASSESSMENT_ID,
            exposure_id=EXPOSURE_ID,
            asset_snapshot_id=SNAPSHOT_ID,
            package_name="feature-lib",
            package_version="5.1.0",
            vulnerability_aliases=("CVE-2026-4000", "GHSA-4444-5555-6666"),
            authoritative_conflict=False,
            evidence=(
                AvailableEvidence(
                    record_id=EVIDENCE_ID,
                    record_identity="sha256:evidence",
                    content_digest="sha256:" + "c" * 64,
                    source_identity="osv",
                    source_adapter_version="osv-v1",
                    passage_identities=("osv:affected",),
                ),
            ),
        )


class ControlledRetriever:
    def __init__(self) -> None:
        self.calls = 0

    def retrieve(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
        *,
        timeout_seconds: float,
    ) -> RetrievedInvestigationEvidence:
        self.calls += 1
        assert timeout_seconds > 0
        assert exposure.exposure_id == command.exposure_id
        return RetrievedInvestigationEvidence(
            query="feature-lib 5.1.0 CVE-2026-4000 affected fixed upgrade",
            passages=(
                RetrievedInvestigationPassage(
                    evidence_record_id=EVIDENCE_ID,
                    evidence_record_identity="sha256:evidence",
                    evidence_record_digest="sha256:" + "c" * 64,
                    passage_identity="osv:affected",
                    passage="feature-lib releases before 5.2 are affected.",
                    source_identity="osv",
                    source_authority="Open Source Vulnerabilities",
                    source_location="https://api.osv.dev/v1/vulns/PYSEC-2026-40",
                    captured_at=NOW,
                    full_text_rank=1,
                    full_text_score=0.9,
                    vector_rank=1,
                    vector_score=0.8,
                    fused_rank=1,
                    fused_score=0.03,
                ),
            ),
        )


class ControlledGenerator:
    def __init__(self, draft: StructuredInvestigationDraft) -> None:
        self._draft = draft
        self.calls = 0

    def check_readiness(self, *, timeout_seconds: float | None = None) -> GenerationReadiness:
        assert timeout_seconds is None or timeout_seconds > 0
        return GenerationReadiness(
            status="ready",
            code=None,
            message="Controlled local generation is ready.",
            setup=None,
            model=_generation_model(),
        )

    async def check_readiness_bounded(self, *, timeout_seconds: float) -> GenerationReadiness:
        return self.check_readiness(timeout_seconds=timeout_seconds)

    def generate(
        self,
        exposure: InvestigationExposure,
        evidence: RetrievedInvestigationEvidence,
        configuration: InvestigationConfiguration,
        *,
        timeout_seconds: float,
    ) -> StructuredInvestigationDraft:
        self.calls += 1
        assert timeout_seconds > 0
        assert exposure.exposure_id == EXPOSURE_ID
        assert evidence.passages[0].evidence_record_id == EVIDENCE_ID
        assert configuration.generation_model == _generation_model()
        return self._draft

    async def generate_bounded(
        self,
        exposure: InvestigationExposure,
        evidence: RetrievedInvestigationEvidence,
        configuration: InvestigationConfiguration,
        *,
        timeout_seconds: float,
    ) -> StructuredInvestigationDraft:
        return self.generate(
            exposure,
            evidence,
            configuration,
            timeout_seconds=timeout_seconds,
        )


class InMemoryRevisionHistory:
    def __init__(self) -> None:
        self.revisions: list[InvestigationRevision] = []

    def append(self, revision: InvestigationRevision) -> InvestigationRevision:
        self.revisions.append(revision)
        return revision


def _supported_draft() -> StructuredInvestigationDraft:
    return StructuredInvestigationDraft(
        operation=AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION,
        claims=(
            ClaimDraft(
                identity="claim-affected",
                kind=ClaimKind.FACT,
                text="Feature-lib 5.1.0 is within the published affected range.",
                material=True,
                limitation=None,
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=EVIDENCE_ID,
                        passage_identities=("osv:affected",),
                        relationship=EvidenceRelationship.SUPPORTS,
                    ),
                ),
            ),
        ),
        recommendation=Recommendation.PLANNED_REMEDIATION,
        recommendation_summary="Upgrade to the first published fixed version.",
        recommendation_reasons=("The installed package is in the affected range.",),
        recommendation_limitations=("Static analysis does not prove runtime reachability.",),
    )


@pytest.mark.asyncio
async def test_runner_persists_one_complete_evidence_backed_revision() -> None:
    history = InMemoryRevisionHistory()
    generator = ControlledGenerator(_supported_draft())
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=generator,
        revision_history=history,
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.status is InvestigationRevisionStatus.COMPLETE
    assert revision.stopping_condition == "completed"
    assert revision.exposure_id == EXPOSURE_ID
    assert revision.asset_snapshot_id == SNAPSHOT_ID
    assert revision.claims[0].supported is True
    assert revision.claims[0].citations[0].relationship is EvidenceRelationship.SUPPORTS
    assert revision.recommendation.recommendation is Recommendation.PLANNED_REMEDIATION
    assert revision.recommendation.accepted is True
    assert revision.output_policy_decision.result is PolicyResult.ALLOWED
    assert revision.output_policy_decision.assistance_class is AssistanceClass.C1
    assert revision.output_policy_decision.action_level is ActionLevel.A0
    assert [event.stage for event in revision.events] == [
        "load_exposure",
        "acquire_evidence",
        "retrieve_passages",
        "synthesize_claims",
        "validate_claims",
        "recommend",
        "validate_policy",
        "persist_revision",
    ]
    assert revision.measurements.generation_model_calls == 1
    assert revision.measurements.tool_calls == 2
    assert revision.measurements.graph_transitions == 8
    assert revision.configuration == _command().configuration
    assert history.revisions == [revision]
    assert generator.calls == 1


@pytest.mark.asyncio
async def test_unsupported_claim_is_preserved_and_recommendation_is_downgraded() -> None:
    draft = _supported_draft()
    unsupported = StructuredInvestigationDraft(
        operation=draft.operation,
        claims=(
            ClaimDraft(
                identity="claim-reachability",
                kind=ClaimKind.FACT,
                text="The vulnerable behavior is reachable at runtime.",
                material=True,
                limitation=None,
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=EVIDENCE_ID,
                        passage_identities=("osv:affected",),
                        relationship=EvidenceRelationship.CONTEXTUAL,
                    ),
                ),
            ),
        ),
        recommendation=Recommendation.URGENT_REMEDIATION,
        recommendation_summary=draft.recommendation_summary,
        recommendation_reasons=draft.recommendation_reasons,
        recommendation_limitations=draft.recommendation_limitations,
    )
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=ControlledGenerator(unsupported),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.status is InvestigationRevisionStatus.COMPLETE
    assert revision.claims[0].supported is False
    assert revision.evidence_state.validation_issues == (
        "claim-reachability:material_claim_missing_support",
    )
    assert revision.recommendation.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert revision.recommendation.accepted is False
    assert revision.recommendation.reason == "material_claims_unsupported"
    assert revision.recommendation.reasons == (
        "material_claims_unsupported",
        "claim-reachability:material_claim_missing_support",
    )


class ConflictingEvidenceAcquirer(ControlledEvidenceAcquirer):
    def acquire(
        self, command: RunInvestigation, *, timeout_seconds: float
    ) -> InvestigationExposure:
        return replace(
            super().acquire(command, timeout_seconds=timeout_seconds),
            authoritative_conflict=True,
        )


@pytest.mark.asyncio
async def test_authoritative_conflict_forces_more_evidence_required() -> None:
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ConflictingEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=ControlledGenerator(_supported_draft()),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.evidence_state.authoritative_conflict is True
    assert revision.recommendation.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert revision.recommendation.accepted is False
    assert revision.recommendation.reason == "authoritative_evidence_conflict"


@pytest.mark.asyncio
async def test_unsafe_structured_operation_is_blocked_before_revision_completion() -> None:
    unsafe_draft = replace(
        _supported_draft(),
        operation=AssessmentOperation.GENERATE_EXPLOIT,
    )
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=ControlledGenerator(unsafe_draft),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "structured_output_policy_blocked"
    assert revision.output_policy_decision.result is PolicyResult.BLOCKED
    assert revision.recommendation.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert revision.recommendation.accepted is False


@pytest.mark.asyncio
async def test_wall_time_budget_stops_model_use_and_persists_incomplete_revision() -> None:
    monotonic_values = iter((0.0, 2.0))
    generator = ControlledGenerator(_supported_draft())
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=generator,
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
        monotonic_clock=lambda: next(monotonic_values, 2.0),
    )
    command = replace(_command(), budget=InvestigationBudget(wall_time_seconds=1))

    revision = await runner.run(command)

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "wall_time_budget_exhausted"
    assert revision.measurements.generation_model_calls == 0
    assert revision.measurements.tool_calls == 0
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_transition_budget_stops_before_retrieval_call() -> None:
    retriever = ControlledRetriever()
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=retriever,
        generator=ControlledGenerator(_supported_draft()),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )
    command = replace(_command(), budget=InvestigationBudget(max_graph_transitions=2))

    revision = await runner.run(command)

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "graph_transition_budget_exhausted"
    assert revision.measurements.tool_calls == 1
    assert retriever.calls == 0


@pytest.mark.asyncio
async def test_transition_budget_stops_before_evidence_acquisition() -> None:
    acquirer = ControlledEvidenceAcquirer()
    runner = BoundedInvestigationRunner(
        evidence_acquirer=acquirer,
        retriever=ControlledRetriever(),
        generator=ControlledGenerator(_supported_draft()),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )
    command = replace(_command(), budget=InvestigationBudget(max_graph_transitions=1))

    revision = await runner.run(command)

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "graph_transition_budget_exhausted"
    assert revision.asset_snapshot_id == SNAPSHOT_ID
    assert revision.evidence_state.authoritative_conflict is None
    assert revision.measurements.tool_calls == 0
    assert acquirer.calls == 0


@pytest.mark.asyncio
async def test_transition_budget_stops_before_generation_call() -> None:
    generator = ControlledGenerator(_supported_draft())
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=generator,
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )
    command = replace(_command(), budget=InvestigationBudget(max_graph_transitions=3))

    revision = await runner.run(command)

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "graph_transition_budget_exhausted"
    assert revision.measurements.tool_calls == 2
    assert generator.calls == 0


@pytest.mark.asyncio
async def test_tool_budget_does_not_record_unperformed_retrieval() -> None:
    retriever = ControlledRetriever()
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=retriever,
        generator=ControlledGenerator(_supported_draft()),
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )
    command = replace(_command(), budget=InvestigationBudget(max_tool_calls=1))

    revision = await runner.run(command)

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "tool_call_budget_exhausted"
    assert revision.measurements.tool_calls == 1
    assert retriever.calls == 0
    assert [event.stage for event in revision.events] == [
        "load_exposure",
        "acquire_evidence",
    ]


class TimedOutRetriever(ControlledRetriever):
    def retrieve(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
        *,
        timeout_seconds: float,
    ) -> RetrievedInvestigationEvidence:
        assert timeout_seconds > 0
        raise TimeoutError("controlled retrieval timeout")


@pytest.mark.asyncio
async def test_active_retrieval_timeout_persists_an_incomplete_revision() -> None:
    generator = ControlledGenerator(_supported_draft())
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=TimedOutRetriever(),
        generator=generator,
        revision_history=InMemoryRevisionHistory(),
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "wall_time_budget_exhausted"
    assert revision.evidence_state.retrieved.passages == ()
    assert revision.measurements.generation_model_calls == 0
    assert revision.measurements.tool_calls == 2
    assert generator.calls == 0


class UnavailableGenerator(ControlledGenerator):
    def check_readiness(self, *, timeout_seconds: float | None = None) -> GenerationReadiness:
        assert timeout_seconds is None or timeout_seconds > 0
        return GenerationReadiness(
            status="unavailable",
            code="generation_model_not_installed",
            message="Local generation artifact controlled-generation-v1 is not installed.",
            setup="Run `ollama pull controlled-generation-v1`, then retry.",
            model=None,
        )

    def generate(
        self,
        exposure: InvestigationExposure,
        evidence: RetrievedInvestigationEvidence,
        configuration: InvestigationConfiguration,
        *,
        timeout_seconds: float,
    ) -> StructuredInvestigationDraft:
        raise AssertionError("Unavailable local generation must not invoke any provider")


@pytest.mark.asyncio
async def test_missing_local_generation_artifact_persists_an_incomplete_revision() -> None:
    history = InMemoryRevisionHistory()
    runner = BoundedInvestigationRunner(
        evidence_acquirer=ControlledEvidenceAcquirer(),
        retriever=ControlledRetriever(),
        generator=UnavailableGenerator(_supported_draft()),
        revision_history=history,
        clock=lambda: NOW,
    )

    revision = await runner.run(_command())

    assert revision.status is InvestigationRevisionStatus.INCOMPLETE
    assert revision.stopping_condition == "generation_model_not_installed"
    assert revision.claims == ()
    assert revision.recommendation.recommendation is Recommendation.MORE_EVIDENCE_REQUIRED
    assert revision.measurements.generation_model_calls == 0
    assert history.revisions == [revision]
