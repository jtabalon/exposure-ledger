"""Bounded LangGraph orchestration for one evidence-backed Investigation Revision."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
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
    InvestigationEvidenceState,
    InvestigationExposure,
    InvestigationMeasurements,
    InvestigationRevision,
    InvestigationRevisionStatus,
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
    def acquire(self, command: RunInvestigation) -> InvestigationExposure: ...


class InvestigationRetriever(Protocol):
    def retrieve(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
    ) -> RetrievedInvestigationEvidence: ...


class RevisionHistory(Protocol):
    def append(self, revision: InvestigationRevision) -> InvestigationRevision: ...


class _GraphState(TypedDict, total=False):
    command: RunInvestigation
    started_at: datetime
    exposure: InvestigationExposure
    retrieved: RetrievedInvestigationEvidence
    draft: StructuredInvestigationDraft
    validation: ClaimValidation
    recommendation: RevisionRecommendation
    policy_decision: PolicyDecision
    status: InvestigationRevisionStatus
    stopping_condition: str
    events: tuple[InvestigationEvent, ...]
    generation_model_calls: int
    tool_calls: int
    graph_transitions: int
    revision: InvestigationRevision


_STAGES: tuple[tuple[str, str, str], ...] = (
    ("load_exposure", "deterministic", "Pinned package-specific Exposure loaded."),
    ("acquire_evidence", "deterministic", "Immutable Evidence Records acquired."),
    ("retrieve_passages", "retrieval", "Exposure-scoped hybrid retrieval completed."),
    ("synthesize_claims", "model", "Structured Claims synthesized locally."),
    ("validate_claims", "deterministic", "Claim citations and limitations validated."),
    ("recommend", "deterministic", "Recommendation evidence policy applied."),
    ("validate_policy", "policy", "Structured output cyber policy applied."),
    ("persist_revision", "deterministic", "Immutable Investigation Revision persisted."),
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
    ) -> None:
        self._evidence_acquirer = evidence_acquirer
        self._retriever = retriever
        self._generator = generator
        self._revision_history = revision_history
        self._clock = clock or (lambda: datetime.now(UTC))
        self._graph = self._build_graph()

    async def run(self, command: RunInvestigation) -> InvestigationRevision:
        state = cast(
            _GraphState,
            await self._graph.ainvoke(
                {
                    "command": command,
                    "started_at": self._clock(),
                    "events": (),
                    "generation_model_calls": 0,
                    "tool_calls": 0,
                    "graph_transitions": 0,
                    "status": InvestigationRevisionStatus.COMPLETE,
                    "stopping_condition": "completed",
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

    def _event(self, state: _GraphState, stage: str) -> dict[str, object]:
        _, mode, detail = next(item for item in _STAGES if item[0] == stage)
        command = state["command"]
        transitions = state["graph_transitions"] + 1
        occurred_at = self._clock()
        updates: dict[str, object] = {
            "events": (*state["events"], InvestigationEvent(stage, mode, detail, occurred_at)),
            "graph_transitions": transitions,
        }
        if state["status"] is InvestigationRevisionStatus.INCOMPLETE:
            return updates
        elapsed_seconds = (occurred_at - state["started_at"]).total_seconds()
        if elapsed_seconds > command.budget.wall_time_seconds:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition="wall_time_budget_exhausted",
            )
        elif transitions > command.budget.max_graph_transitions:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition="graph_transition_budget_exhausted",
            )
        return updates

    def _load_exposure(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "load_exposure")
        exposure = self._evidence_acquirer.acquire(state["command"])
        if (
            exposure.assessment_run_id != state["command"].assessment_run_id
            or exposure.exposure_id != state["command"].exposure_id
        ):
            raise ValueError("Acquired Exposure does not match the Investigation command")
        updates["exposure"] = exposure
        return updates

    def _acquire_evidence(self, state: _GraphState) -> dict[str, object]:
        return self._event(state, "acquire_evidence")

    def _retrieve_passages(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "retrieve_passages")
        if state["status"] is InvestigationRevisionStatus.INCOMPLETE:
            updates["retrieved"] = RetrievedInvestigationEvidence(query="", passages=())
            return updates
        if state["tool_calls"] >= state["command"].budget.max_tool_calls:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition="tool_call_budget_exhausted",
                retrieved=RetrievedInvestigationEvidence(query="", passages=()),
            )
            return updates
        updates["retrieved"] = self._retriever.retrieve(state["exposure"], state["command"])
        updates["tool_calls"] = state["tool_calls"] + 1
        return updates

    def _synthesize_claims(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "synthesize_claims")
        if state["status"] is InvestigationRevisionStatus.INCOMPLETE:
            return updates
        readiness = self._generator.check_readiness()
        configured = state["command"].configuration.generation_model
        if readiness.model is None:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=readiness.code or "generation_provider_unavailable",
            )
            return updates
        if readiness.model != configured:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition="generation_model_not_current",
            )
            return updates
        if state["generation_model_calls"] >= state["command"].budget.max_generation_model_calls:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition="generation_model_call_budget_exhausted",
            )
            return updates
        try:
            updates["draft"] = self._generator.generate(
                state["exposure"],
                state["retrieved"],
                state["command"].configuration,
            )
            updates["generation_model_calls"] = state["generation_model_calls"] + 1
        except GenerationProviderUnavailable as error:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=error.readiness.code or "generation_provider_unavailable",
            )
        return updates

    def _validate_claims(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "validate_claims")
        draft = state.get("draft")
        retrieved = state["retrieved"]
        available = _retrieved_evidence_scope(retrieved)
        updates["validation"] = ClaimValidator.validate(
            claims=draft.claims if draft is not None else (),
            available_evidence=available,
            authoritative_conflict=state["exposure"].authoritative_conflict,
        )
        return updates

    def _recommend(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "recommend")
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
        updates = self._event(state, "validate_policy")
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
            updates["stopping_condition"] = "structured_output_policy_blocked"
            updates["recommendation"] = replace(
                state["recommendation"],
                recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
                accepted=False,
                reason="structured_output_policy_blocked",
                summary="Structured model output was blocked by the Cyber Policy.",
            )
        return updates

    def _persist_revision(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, "persist_revision")
        events = cast(tuple[InvestigationEvent, ...], updates["events"])
        completed_at = self._clock()
        duration_ms = max(
            0,
            int((completed_at - state["started_at"]).total_seconds() * 1000),
        )
        validation = state["validation"]
        status = cast(InvestigationRevisionStatus, updates.get("status", state["status"]))
        stopping_condition = cast(
            str, updates.get("stopping_condition", state["stopping_condition"])
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
            asset_snapshot_id=state["exposure"].asset_snapshot_id,
            status=status,
            stopping_condition=stopping_condition,
            evidence_state=InvestigationEvidenceState(
                available=state["exposure"].evidence,
                retrieved=state["retrieved"],
                material_claims_supported=validation.material_claims_supported,
                authoritative_conflict=validation.authoritative_conflict,
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
                graph_transitions=cast(int, updates["graph_transitions"]),
            ),
            configuration=state["command"].configuration,
            created_at=completed_at,
        )
        persisted = self._revision_history.append(revision)
        return {**updates, "revision": persisted}


def _retrieved_evidence_scope(
    retrieved: RetrievedInvestigationEvidence,
) -> tuple[AvailableEvidence, ...]:
    grouped: dict[UUID, tuple[str, str, list[str]]] = {}
    for passage in retrieved.passages:
        current = grouped.setdefault(
            passage.evidence_record_id,
            (
                passage.evidence_record_identity,
                passage.evidence_record_digest,
                [],
            ),
        )
        if current[:2] != (
            passage.evidence_record_identity,
            passage.evidence_record_digest,
        ):
            raise ValueError("Retrieved Evidence Record identity changed within one result")
        current[2].append(passage.passage_identity)
    return tuple(
        AvailableEvidence(
            record_id=record_id,
            record_identity=identity,
            content_digest=digest,
            passage_identities=tuple(dict.fromkeys(passages)),
        )
        for record_id, (identity, digest, passages) in sorted(
            grouped.items(), key=lambda item: str(item[0])
        )
    )
