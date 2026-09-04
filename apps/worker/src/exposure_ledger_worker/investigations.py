"""Bounded LangGraph orchestration for one evidence-backed Investigation Revision."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from time import monotonic
from typing import Protocol, TypedDict, cast
from uuid import UUID, uuid4

from exposure_ledger import (
    AssessmentOperation,
    AssessmentRequest,
    AuthorizationStatus,
    AvailableEvidence,
    ClaimValidation,
    ClaimValidator,
    CyberPolicy,
    EvidenceState,
    InvestigationEvent,
    InvestigationEventMode,
    InvestigationEvidenceState,
    InvestigationExposure,
    InvestigationMeasurements,
    InvestigationRevision,
    InvestigationRevisionStatus,
    InvestigationStage,
    InvestigationStoppingCondition,
    PolicyDecision,
    PolicyResult,
    Recommendation,
    RecommendationPolicy,
    RetrievedInvestigationEvidence,
    RevisionRecommendation,
    RunInvestigation,
    StructuredInvestigationDraft,
)
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from exposure_ledger_worker.local_generation import (
    GenerationProvider,
    GenerationProviderUnavailable,
)


class EvidenceAcquirer(Protocol):
    def acquire(
        self, command: RunInvestigation, *, timeout_seconds: float
    ) -> InvestigationExposure: ...


class InvestigationRetriever(Protocol):
    def retrieve(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
        *,
        timeout_seconds: float,
    ) -> RetrievedInvestigationEvidence: ...


class RevisionHistory(Protocol):
    def append(self, revision: InvestigationRevision) -> InvestigationRevision: ...


class _GraphState(TypedDict, total=False):
    command: RunInvestigation
    started_at: datetime
    deadline_monotonic: float
    exposure: InvestigationExposure
    retrieved: RetrievedInvestigationEvidence
    draft: StructuredInvestigationDraft
    validation: ClaimValidation
    recommendation: RevisionRecommendation
    policy_decision: PolicyDecision
    status: InvestigationRevisionStatus
    stopping_condition: InvestigationStoppingCondition
    events: tuple[InvestigationEvent, ...]
    generation_model_calls: int
    tool_calls: int
    graph_transitions: int
    revision: InvestigationRevision


_STAGES: tuple[tuple[InvestigationStage, InvestigationEventMode, str], ...] = (
    (
        InvestigationStage.LOAD_EXPOSURE,
        InvestigationEventMode.DETERMINISTIC,
        "Load the pinned package-specific Exposure.",
    ),
    (
        InvestigationStage.ACQUIRE_EVIDENCE,
        InvestigationEventMode.DETERMINISTIC,
        "Acquire immutable Evidence Records.",
    ),
    (
        InvestigationStage.RETRIEVE_PASSAGES,
        InvestigationEventMode.RETRIEVAL,
        "Run Exposure-scoped hybrid retrieval.",
    ),
    (
        InvestigationStage.SYNTHESIZE_CLAIMS,
        InvestigationEventMode.MODEL,
        "Synthesize structured Claims locally.",
    ),
    (
        InvestigationStage.VALIDATE_CLAIMS,
        InvestigationEventMode.DETERMINISTIC,
        "Validate Claim citations and limitations.",
    ),
    (
        InvestigationStage.RECOMMEND,
        InvestigationEventMode.DETERMINISTIC,
        "Apply the Recommendation evidence policy.",
    ),
    (
        InvestigationStage.VALIDATE_POLICY,
        InvestigationEventMode.POLICY,
        "Apply the structured-output cyber policy.",
    ),
    (
        InvestigationStage.PERSIST_REVISION,
        InvestigationEventMode.DETERMINISTIC,
        "Persist the immutable Investigation Revision.",
    ),
)


class BoundedInvestigationRunner:
    """Run one fixed graph pass; Evidence Gap follow-ups and resumption are later seams."""

    def __init__(
        self,
        *,
        evidence_acquirer: EvidenceAcquirer,
        retriever: InvestigationRetriever,
        generator: GenerationProvider,
        revision_history: RevisionHistory,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self._evidence_acquirer = evidence_acquirer
        self._retriever = retriever
        self._generator = generator
        self._revision_history = revision_history
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock or monotonic
        self._graph = self._build_graph()

    async def run(self, command: RunInvestigation) -> InvestigationRevision:
        started_at = self._clock()
        state = cast(
            _GraphState,
            await self._graph.ainvoke(
                {
                    "command": command,
                    "started_at": started_at,
                    "deadline_monotonic": self._monotonic() + command.budget.wall_time_seconds,
                    "events": (),
                    "generation_model_calls": 0,
                    "tool_calls": 0,
                    "graph_transitions": 0,
                    "status": InvestigationRevisionStatus.COMPLETE,
                    "stopping_condition": InvestigationStoppingCondition.COMPLETED,
                }
            ),
        )
        return state["revision"]

    def _build_graph(
        self,
    ) -> CompiledStateGraph[_GraphState, None, _GraphState, _GraphState]:
        graph = StateGraph(_GraphState)
        nodes = (
            self._load_exposure,
            self._acquire_evidence,
            self._retrieve_passages,
            self._synthesize_claims,
            self._validate_claims,
            self._recommend,
            self._validate_policy,
            self._persist_revision,
        )
        for (stage, _, _), node in zip(_STAGES, nodes, strict=True):
            graph.add_node(stage, node)
        graph.add_edge(START, _STAGES[0][0])
        for current, following in zip(_STAGES, _STAGES[1:], strict=False):
            graph.add_edge(current[0], following[0])
        graph.add_edge(_STAGES[-1][0], END)
        return graph.compile()

    def _event(self, state: _GraphState, stage: InvestigationStage) -> dict[str, object]:
        if state["status"] is InvestigationRevisionStatus.INCOMPLETE:
            return {}
        _, mode, detail = next(item for item in _STAGES if item[0] == stage)
        command = state["command"]
        occurred_at = self._clock()
        if self._remaining_seconds(state) <= 0:
            return {
                "status": InvestigationRevisionStatus.INCOMPLETE,
                "stopping_condition": InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
            }
        if state["graph_transitions"] >= command.budget.max_graph_transitions:
            return {
                "status": InvestigationRevisionStatus.INCOMPLETE,
                "stopping_condition": (
                    InvestigationStoppingCondition.GRAPH_TRANSITION_BUDGET_EXHAUSTED
                ),
            }
        return {
            "events": (*state["events"], InvestigationEvent(stage, mode, detail, occurred_at)),
            "graph_transitions": state["graph_transitions"] + 1,
        }

    @staticmethod
    def _stopped(state: _GraphState, updates: dict[str, object]) -> bool:
        return updates.get("status", state["status"]) is InvestigationRevisionStatus.INCOMPLETE

    def _remaining_seconds(self, state: _GraphState) -> float:
        return max(0.0, state["deadline_monotonic"] - self._monotonic())

    def _load_exposure(self, state: _GraphState) -> dict[str, object]:
        return self._event(state, InvestigationStage.LOAD_EXPOSURE)

    def _acquire_evidence(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.ACQUIRE_EVIDENCE)
        if self._stopped(state, updates):
            return updates
        timeout_seconds = self._remaining_seconds(state)
        updates["tool_calls"] = state["tool_calls"] + 1
        try:
            exposure = self._evidence_acquirer.acquire(
                state["command"], timeout_seconds=timeout_seconds
            )
        except TimeoutError:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
            )
            return updates
        if (
            exposure.assessment_run_id != state["command"].assessment_run_id
            or exposure.exposure_id != state["command"].exposure_id
            or exposure.asset_snapshot_id != state["command"].asset_snapshot_id
        ):
            raise ValueError("Acquired Exposure does not match the Investigation command")
        updates["exposure"] = exposure
        return updates

    def _retrieve_passages(self, state: _GraphState) -> dict[str, object]:
        if state["tool_calls"] >= state["command"].budget.max_tool_calls:
            return dict(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.TOOL_CALL_BUDGET_EXHAUSTED,
                retrieved=RetrievedInvestigationEvidence(query="", passages=()),
            )
        updates = self._event(state, InvestigationStage.RETRIEVE_PASSAGES)
        if self._stopped(state, updates):
            updates["retrieved"] = RetrievedInvestigationEvidence(query="", passages=())
            return updates
        timeout_seconds = self._remaining_seconds(state)
        updates["tool_calls"] = state["tool_calls"] + 1
        try:
            updates["retrieved"] = self._retriever.retrieve(
                state["exposure"],
                state["command"],
                timeout_seconds=timeout_seconds,
            )
        except TimeoutError:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
                retrieved=RetrievedInvestigationEvidence(query="", passages=()),
            )
            return updates
        return updates

    async def _synthesize_claims(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.SYNTHESIZE_CLAIMS)
        if self._stopped(state, updates):
            return updates
        timeout_seconds = self._remaining_seconds(state)
        try:
            readiness = await self._generator.check_readiness_bounded(
                timeout_seconds=timeout_seconds
            )
        except TimeoutError:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
            )
            return updates
        configured = state["command"].configuration.generation_model
        if readiness.model is None:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=_generation_stopping_condition(readiness.code),
            )
            return updates
        if readiness.model != configured:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.GENERATION_MODEL_NOT_CURRENT,
            )
            return updates
        if state["generation_model_calls"] >= state["command"].budget.max_generation_model_calls:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=(
                    InvestigationStoppingCondition.GENERATION_MODEL_CALL_BUDGET_EXHAUSTED
                ),
            )
            return updates
        try:
            timeout_seconds = self._remaining_seconds(state)
            updates["generation_model_calls"] = state["generation_model_calls"] + 1
            updates["draft"] = await self._generator.generate_bounded(
                state["exposure"],
                state["retrieved"],
                state["command"].configuration,
                timeout_seconds=timeout_seconds,
            )
        except GenerationProviderUnavailable as error:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=_generation_stopping_condition(error.readiness.code),
            )
        except TimeoutError:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
            )
        return updates

    def _validate_claims(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.VALIDATE_CLAIMS)
        draft = state.get("draft")
        retrieved = state["retrieved"]
        exposure = state.get("exposure")
        available = _retrieved_evidence_scope(
            retrieved, exposure.evidence if exposure is not None else ()
        )
        updates["validation"] = ClaimValidator.validate(
            claims=draft.claims if draft is not None else (),
            available_evidence=available,
            authoritative_conflict=(
                exposure.authoritative_conflict if exposure is not None else False
            ),
        )
        return updates

    def _recommend(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.RECOMMEND)
        draft = state.get("draft")
        validation = state["validation"]
        decision = RecommendationPolicy.validate(
            proposed=(
                draft.recommendation if draft is not None else Recommendation.MORE_EVIDENCE_REQUIRED
            ),
            evidence=EvidenceState(
                material_claims_supported=validation.material_claims_supported,
                authoritative_conflict=validation.authoritative_conflict,
            ),
        )
        accepted = decision.accepted and state["status"] is InvestigationRevisionStatus.COMPLETE
        recommendation = decision.recommendation
        reason = decision.reason
        if state["status"] is InvestigationRevisionStatus.INCOMPLETE:
            accepted = False
            recommendation = Recommendation.MORE_EVIDENCE_REQUIRED
            reason = state["stopping_condition"]
        reasons = (
            draft.recommendation_reasons
            if draft is not None and accepted
            else tuple(dict.fromkeys((reason, *validation.issues)))
        )
        updates["recommendation"] = RevisionRecommendation(
            recommendation=recommendation,
            accepted=accepted,
            reason=reason,
            summary=(
                draft.recommendation_summary
                if draft is not None and accepted
                else (
                    "More evidence is required before a remediation Recommendation can be "
                    "supported."
                )
            ),
            reasons=reasons,
            limitations=(draft.recommendation_limitations if draft is not None else ()),
        )
        return updates

    def _validate_policy(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.VALIDATE_POLICY)
        draft = state.get("draft")
        decision = CyberPolicy.decide(
            AssessmentRequest(
                operation=(
                    draft.operation
                    if draft is not None
                    else AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION
                ),
                target_scope=f"exposure:{state['command'].exposure_id}",
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
            )
        )
        updates["policy_decision"] = decision
        if decision.result is not PolicyResult.ALLOWED:
            updates["status"] = InvestigationRevisionStatus.INCOMPLETE
            updates["stopping_condition"] = (
                InvestigationStoppingCondition.STRUCTURED_OUTPUT_POLICY_BLOCKED
            )
            updates["recommendation"] = replace(
                state["recommendation"],
                recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
                accepted=False,
                reason=InvestigationStoppingCondition.STRUCTURED_OUTPUT_POLICY_BLOCKED,
                summary="Structured model output was blocked by the Cyber Policy.",
            )
        return updates

    def _persist_revision(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.PERSIST_REVISION)
        events = cast(tuple[InvestigationEvent, ...], updates.get("events", state["events"]))
        completed_at = self._clock()
        duration_ms = max(
            0,
            int((completed_at - state["started_at"]).total_seconds() * 1000),
        )
        validation = state["validation"]
        status = cast(InvestigationRevisionStatus, updates.get("status", state["status"]))
        stopping_condition = cast(
            InvestigationStoppingCondition,
            updates.get("stopping_condition", state["stopping_condition"]),
        )
        recommendation = state["recommendation"]
        if status is InvestigationRevisionStatus.INCOMPLETE and recommendation.accepted:
            recommendation = replace(
                recommendation,
                recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
                accepted=False,
                reason=stopping_condition,
                summary=(
                    "More evidence is required before a remediation Recommendation can be "
                    "supported."
                ),
                reasons=(stopping_condition,),
            )
        revision = InvestigationRevision(
            id=uuid4(),
            assessment_run_id=state["command"].assessment_run_id,
            exposure_id=state["command"].exposure_id,
            asset_snapshot_id=state["command"].asset_snapshot_id,
            status=status,
            stopping_condition=stopping_condition,
            evidence_state=InvestigationEvidenceState(
                available=(state["exposure"].evidence if "exposure" in state else ()),
                retrieved=state["retrieved"],
                material_claims_supported=validation.material_claims_supported,
                authoritative_conflict=(
                    validation.authoritative_conflict if "exposure" in state else None
                ),
                validation_issues=validation.issues,
            ),
            claims=validation.claims,
            recommendation=recommendation,
            output_policy_decision=state["policy_decision"],
            events=events,
            measurements=InvestigationMeasurements(
                started_at=state["started_at"],
                completed_at=completed_at,
                duration_ms=duration_ms,
                generation_model_calls=state["generation_model_calls"],
                tool_calls=state["tool_calls"],
                graph_transitions=cast(
                    int, updates.get("graph_transitions", state["graph_transitions"])
                ),
            ),
            configuration=state["command"].configuration,
            created_at=completed_at,
        )
        persisted = self._revision_history.append(revision)
        return {**updates, "revision": persisted}


def _retrieved_evidence_scope(
    retrieved: RetrievedInvestigationEvidence,
    exposure_evidence: tuple[AvailableEvidence, ...],
) -> tuple[AvailableEvidence, ...]:
    available_by_id = {item.record_id: item for item in exposure_evidence}
    grouped: dict[UUID, tuple[str, str, str, str, list[str]]] = {}
    for passage in retrieved.passages:
        source_evidence = available_by_id.get(passage.evidence_record_id)
        if source_evidence is None or source_evidence.source_identity != passage.source_identity:
            raise ValueError("Retrieved Evidence Record changed Source identity")
        current = grouped.setdefault(
            passage.evidence_record_id,
            (
                passage.evidence_record_identity,
                passage.evidence_record_digest,
                source_evidence.source_identity,
                source_evidence.source_adapter_version,
                [],
            ),
        )
        if current[:2] != (
            passage.evidence_record_identity,
            passage.evidence_record_digest,
        ):
            raise ValueError("Retrieved Evidence Record identity changed within one result")
        current[4].append(passage.passage_identity)
    return tuple(
        AvailableEvidence(
            record_id=record_id,
            record_identity=identity,
            content_digest=digest,
            source_identity=source_identity,
            source_adapter_version=source_adapter_version,
            passage_identities=tuple(dict.fromkeys(passages)),
        )
        for record_id, (
            identity,
            digest,
            source_identity,
            source_adapter_version,
            passages,
        ) in sorted(grouped.items(), key=lambda item: str(item[0]))
    )


def _generation_stopping_condition(code: str | None) -> InvestigationStoppingCondition:
    if code == "generation_wall_time_budget_exhausted":
        return InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED
    try:
        return InvestigationStoppingCondition(
            code or InvestigationStoppingCondition.GENERATION_PROVIDER_UNAVAILABLE
        )
    except ValueError:
        return InvestigationStoppingCondition.GENERATION_PROVIDER_UNAVAILABLE
