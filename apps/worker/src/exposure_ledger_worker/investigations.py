"""Bounded LangGraph orchestration for one evidence-backed Investigation Revision."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, TypedDict, cast
from uuid import UUID

from exposure_ledger import (
    AssessmentOperation,
    AssessmentRequest,
    AuthorizationStatus,
    AvailableEvidence,
    ClaimValidation,
    ClaimValidator,
    CyberPolicy,
    EvidenceFollowUpAuthorization,
    EvidenceFollowUpProposal,
    EvidenceFollowUpUnavailable,
    EvidenceGap,
    EvidenceState,
    FollowUpAuthorizationContext,
    FollowUpValidator,
    InvestigationConfiguration,
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
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
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

    def follow_up(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
        proposal: EvidenceFollowUpProposal,
        *,
        timeout_seconds: float,
    ) -> RetrievedInvestigationEvidence: ...


class RevisionHistory(Protocol):
    def append(self, revision: InvestigationRevision) -> InvestigationRevision: ...

    def get(self, revision_id: UUID) -> InvestigationRevision | None: ...


class ProgressHistory(Protocol):
    def record(
        self, command: RunInvestigation, event: InvestigationEvent
    ) -> InvestigationEvent: ...


class InvalidInvestigationCheckpoint(RuntimeError):
    """A persisted graph checkpoint cannot safely resume the requested operation."""


class _GraphState(TypedDict, total=False):
    command: RunInvestigation
    started_at: datetime
    deadline_at: datetime
    exposure: InvestigationExposure
    retrieved: RetrievedInvestigationEvidence
    draft: StructuredInvestigationDraft
    validation: ClaimValidation
    recommendation: RevisionRecommendation
    policy_decision: PolicyDecision
    evidence_gap: EvidenceGap
    follow_up: EvidenceFollowUpAuthorization
    status: InvestigationRevisionStatus
    stopping_condition: InvestigationStoppingCondition
    stopping_reason: str
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
        "Model proposed structured Claims and at most one Evidence Gap follow-up.",
    ),
    (
        InvestigationStage.AUTHORIZE_FOLLOW_UP,
        InvestigationEventMode.POLICY,
        "Deterministically validate the proposed follow-up target, arguments, policy, and budgets.",
    ),
    (
        InvestigationStage.EXECUTE_FOLLOW_UP,
        InvestigationEventMode.RETRIEVAL,
        "Execute one authorized search over captured Exposure evidence.",
    ),
    (
        InvestigationStage.SYNTHESIZE_FOLLOW_UP,
        InvestigationEventMode.MODEL,
        "Synthesize final Claims from the untrusted follow-up result.",
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
    """Run one bounded graph pass with at most one authorized Evidence Gap follow-up."""

    def __init__(
        self,
        *,
        evidence_acquirer: EvidenceAcquirer,
        retriever: InvestigationRetriever,
        generator: GenerationProvider,
        revision_history: RevisionHistory,
        checkpointer: BaseCheckpointSaver[Any] | None = None,
        progress_history: ProgressHistory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._evidence_acquirer = evidence_acquirer
        self._retriever = retriever
        self._generator = generator
        self._revision_history = revision_history
        self._checkpointer = checkpointer
        self._progress_history = progress_history
        self._clock = clock or (lambda: datetime.now(UTC))
        self._graph = self._build_graph()

    async def run(self, command: RunInvestigation) -> InvestigationRevision:
        started_at = self._clock()
        config: RunnableConfig = {"configurable": {"thread_id": str(command.operation_id)}}
        resume = False
        if self._checkpointer is not None:
            try:
                checkpoint = await self._checkpointer.aget_tuple(config)
            except (KeyError, TypeError, ValueError) as error:
                raise InvalidInvestigationCheckpoint(
                    f"Investigation checkpoint {command.operation_id} is invalid."
                ) from error
            if checkpoint is not None:
                channel_values = checkpoint.checkpoint.get("channel_values", {})
                stored_command = channel_values.get("command")
                if not _same_operation(stored_command, command):
                    raise InvalidInvestigationCheckpoint(
                        f"Investigation checkpoint {command.operation_id} does not match its scope."
                    )
                checkpoint_revision = channel_values.get("revision")
                if checkpoint_revision is not None:
                    revision = self._revision_history.get(command.operation_id)
                    if revision is None:
                        raise InvalidInvestigationCheckpoint(
                            f"Investigation checkpoint {command.operation_id} has no Revision."
                        )
                    return revision
                resume = True
        state = cast(
            _GraphState,
            await self._graph.ainvoke(
                None
                if resume
                else {
                    "command": command,
                    "started_at": started_at,
                    "deadline_at": started_at + timedelta(seconds=command.budget.wall_time_seconds),
                    "events": (),
                    "generation_model_calls": 0,
                    "tool_calls": 0,
                    "graph_transitions": 0,
                    "status": InvestigationRevisionStatus.COMPLETE,
                    "stopping_condition": InvestigationStoppingCondition.COMPLETED,
                },
                config if self._checkpointer is not None else None,
                durability="sync" if self._checkpointer is not None else None,
            ),
        )
        return state["revision"]

    def _build_graph(
        self,
    ) -> CompiledStateGraph[_GraphState, None, _GraphState, _GraphState]:
        graph = StateGraph(_GraphState)
        nodes = {
            InvestigationStage.LOAD_EXPOSURE: self._load_exposure,
            InvestigationStage.ACQUIRE_EVIDENCE: self._acquire_evidence,
            InvestigationStage.RETRIEVE_PASSAGES: self._retrieve_passages,
            InvestigationStage.SYNTHESIZE_CLAIMS: self._synthesize_claims,
            InvestigationStage.AUTHORIZE_FOLLOW_UP: self._authorize_follow_up,
            InvestigationStage.EXECUTE_FOLLOW_UP: self._execute_follow_up,
            InvestigationStage.SYNTHESIZE_FOLLOW_UP: self._synthesize_follow_up,
            InvestigationStage.VALIDATE_CLAIMS: self._validate_claims,
            InvestigationStage.RECOMMEND: self._recommend,
            InvestigationStage.VALIDATE_POLICY: self._validate_policy,
            InvestigationStage.PERSIST_REVISION: self._persist_revision,
        }
        for stage, node in nodes.items():
            graph.add_node(stage, node)
        graph.add_edge(START, InvestigationStage.LOAD_EXPOSURE)
        graph.add_edge(InvestigationStage.LOAD_EXPOSURE, InvestigationStage.ACQUIRE_EVIDENCE)
        graph.add_edge(InvestigationStage.ACQUIRE_EVIDENCE, InvestigationStage.RETRIEVE_PASSAGES)
        graph.add_edge(InvestigationStage.RETRIEVE_PASSAGES, InvestigationStage.SYNTHESIZE_CLAIMS)
        graph.add_conditional_edges(
            InvestigationStage.SYNTHESIZE_CLAIMS,
            self._route_after_initial_synthesis,
            {
                "authorize": InvestigationStage.AUTHORIZE_FOLLOW_UP,
                "validate": InvestigationStage.VALIDATE_CLAIMS,
            },
        )
        graph.add_conditional_edges(
            InvestigationStage.AUTHORIZE_FOLLOW_UP,
            self._route_after_authorization,
            {
                "execute": InvestigationStage.EXECUTE_FOLLOW_UP,
                "validate": InvestigationStage.VALIDATE_CLAIMS,
            },
        )
        graph.add_conditional_edges(
            InvestigationStage.EXECUTE_FOLLOW_UP,
            self._route_after_execution,
            {
                "synthesize": InvestigationStage.SYNTHESIZE_FOLLOW_UP,
                "validate": InvestigationStage.VALIDATE_CLAIMS,
            },
        )
        graph.add_edge(InvestigationStage.SYNTHESIZE_FOLLOW_UP, InvestigationStage.VALIDATE_CLAIMS)
        graph.add_edge(InvestigationStage.VALIDATE_CLAIMS, InvestigationStage.RECOMMEND)
        graph.add_edge(InvestigationStage.RECOMMEND, InvestigationStage.VALIDATE_POLICY)
        graph.add_edge(InvestigationStage.VALIDATE_POLICY, InvestigationStage.PERSIST_REVISION)
        graph.add_edge(InvestigationStage.PERSIST_REVISION, END)
        return graph.compile(checkpointer=self._checkpointer)

    @staticmethod
    def _route_after_initial_synthesis(state: _GraphState) -> str:
        draft = state.get("draft")
        return "authorize" if draft is not None and draft.follow_up is not None else "validate"

    @staticmethod
    def _route_after_authorization(state: _GraphState) -> str:
        follow_up = state.get("follow_up")
        return (
            "execute"
            if follow_up is not None
            and follow_up.authorized
            and state["status"] is InvestigationRevisionStatus.COMPLETE
            else "validate"
        )

    @staticmethod
    def _route_after_execution(state: _GraphState) -> str:
        follow_up = state.get("follow_up")
        return (
            "synthesize"
            if follow_up is not None
            and follow_up.executed
            and state["status"] is InvestigationRevisionStatus.COMPLETE
            else "validate"
        )

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
        event = InvestigationEvent(stage, mode, detail, occurred_at)
        if self._progress_history is not None:
            event = self._progress_history.record(command, event)
        return {
            "events": (*state["events"], event),
            "graph_transitions": state["graph_transitions"] + 1,
        }

    @staticmethod
    def _stopped(state: _GraphState, updates: dict[str, object]) -> bool:
        return updates.get("status", state["status"]) is InvestigationRevisionStatus.INCOMPLETE

    def _remaining_seconds(self, state: _GraphState) -> float:
        return max(0.0, (state["deadline_at"] - self._clock()).total_seconds())

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
        updates = await self._synthesize(state, InvestigationStage.SYNTHESIZE_CLAIMS)
        draft = cast(StructuredInvestigationDraft | None, updates.get("draft"))
        if draft is not None and draft.evidence_gap is not None:
            updates["evidence_gap"] = draft.evidence_gap
            if draft.follow_up is None and FollowUpValidator.validate_gap(draft.evidence_gap):
                updates.update(
                    status=InvestigationRevisionStatus.INCOMPLETE,
                    stopping_condition=(
                        InvestigationStoppingCondition.GENERATION_INVALID_STRUCTURED_OUTPUT
                    ),
                    stopping_reason=(
                        "The model returned an invalid structured Evidence Gap without a "
                        "follow-up proposal."
                    ),
                )
        return updates

    async def _synthesize_follow_up(self, state: _GraphState) -> dict[str, object]:
        updates = await self._synthesize(state, InvestigationStage.SYNTHESIZE_FOLLOW_UP)
        draft = cast(StructuredInvestigationDraft | None, updates.get("draft"))
        if draft is not None and draft.follow_up is not None:
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=InvestigationStoppingCondition.FOLLOW_UP_LIMIT_REACHED,
                stopping_reason=(
                    "The final model response proposed another follow-up after the single "
                    "authorized follow-up had already been used."
                ),
            )
        return updates

    async def _synthesize(self, state: _GraphState, stage: InvestigationStage) -> dict[str, object]:
        updates = self._event(state, stage)
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

    def _authorize_follow_up(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.AUTHORIZE_FOLLOW_UP)
        draft = state["draft"]
        proposal = draft.follow_up
        assert proposal is not None
        exposure = state["exposure"]
        authorization = FollowUpValidator.authorize(
            gap=draft.evidence_gap,
            proposal=proposal,
            context=FollowUpAuthorizationContext(
                exposure_id=state["command"].exposure_id,
                allowed_source_identities=tuple(
                    sorted({item.source_identity for item in exposure.evidence})
                ),
                generation_model_calls=state["generation_model_calls"],
                tool_calls=state["tool_calls"],
                graph_transitions=cast(
                    int, updates.get("graph_transitions", state["graph_transitions"])
                ),
                remaining_wall_time_seconds=self._remaining_seconds(state),
                budget=state["command"].budget,
            ),
        )
        updates["evidence_gap"] = draft.evidence_gap
        updates["follow_up"] = authorization
        if not authorization.authorized:
            stopping_condition = _follow_up_stopping_condition(authorization.reason)
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=stopping_condition,
                stopping_reason=_stopping_reason(stopping_condition, authorization.reason),
            )
        return updates

    def _execute_follow_up(self, state: _GraphState) -> dict[str, object]:
        updates = self._event(state, InvestigationStage.EXECUTE_FOLLOW_UP)
        authorization = state["follow_up"]
        if self._stopped(state, updates):
            stopping_condition = cast(
                InvestigationStoppingCondition,
                updates.get("stopping_condition", state["stopping_condition"]),
            )
            updates["follow_up"] = authorization
            updates["stopping_reason"] = _stopping_reason(stopping_condition)
            return updates
        if state["tool_calls"] >= state["command"].budget.max_tool_calls:
            stopping_condition = InvestigationStoppingCondition.TOOL_CALL_BUDGET_EXHAUSTED
            return {
                **updates,
                "status": InvestigationRevisionStatus.INCOMPLETE,
                "stopping_condition": stopping_condition,
                "stopping_reason": _stopping_reason(stopping_condition),
                "follow_up": authorization,
            }
        updates["tool_calls"] = state["tool_calls"] + 1
        try:
            follow_up_evidence = self._retriever.follow_up(
                state["exposure"],
                state["command"],
                authorization.proposal,
                timeout_seconds=self._remaining_seconds(state),
            )
            updates["retrieved"] = _merge_retrieved_evidence(state["retrieved"], follow_up_evidence)
            updates["follow_up"] = replace(authorization, executed=True)
        except TimeoutError:
            stopping_condition = InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=stopping_condition,
                stopping_reason=_stopping_reason(stopping_condition),
            )
        except EvidenceFollowUpUnavailable as error:
            stopping_condition = InvestigationStoppingCondition.FOLLOW_UP_UNAVAILABLE
            updates.update(
                status=InvestigationRevisionStatus.INCOMPLETE,
                stopping_condition=stopping_condition,
                stopping_reason=_stopping_reason(stopping_condition, str(error)),
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
        command = state["command"]
        existing = self._revision_history.get(command.operation_id)
        if existing is not None:
            if (
                existing.assessment_run_id != command.assessment_run_id
                or existing.exposure_id != command.exposure_id
                or existing.asset_snapshot_id != command.asset_snapshot_id
                or not _same_configuration(existing.configuration, command.configuration)
            ):
                raise InvalidInvestigationCheckpoint(
                    f"Investigation Revision {command.operation_id} does not match its operation."
                )
            return {"revision": existing}
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
            id=state["command"].operation_id,
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
            evidence_gap=state.get("evidence_gap"),
            follow_up=state.get("follow_up"),
            stopping_reason=(
                None
                if status is InvestigationRevisionStatus.COMPLETE
                else state.get("stopping_reason") or _stopping_reason(stopping_condition)
            ),
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


def _merge_retrieved_evidence(
    initial: RetrievedInvestigationEvidence,
    follow_up: RetrievedInvestigationEvidence,
) -> RetrievedInvestigationEvidence:
    passages = {(item.evidence_record_id, item.passage_identity): item for item in initial.passages}
    passages.update(
        {(item.evidence_record_id, item.passage_identity): item for item in follow_up.passages}
    )
    return RetrievedInvestigationEvidence(
        query=follow_up.query,
        passages=tuple(passages.values()),
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


def _follow_up_stopping_condition(reason: str) -> InvestigationStoppingCondition:
    try:
        return InvestigationStoppingCondition(reason)
    except ValueError:
        if reason == "follow_up_policy_blocked":
            return InvestigationStoppingCondition.FOLLOW_UP_POLICY_BLOCKED
        return InvestigationStoppingCondition.FOLLOW_UP_INVALID


def _stopping_reason(
    condition: InvestigationStoppingCondition,
    detail: str | None = None,
) -> str:
    reasons = {
        InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED: (
            "The two-minute Investigation wall-time budget was exhausted."
        ),
        InvestigationStoppingCondition.GRAPH_TRANSITION_BUDGET_EXHAUSTED: (
            "The Investigation graph-transition budget was exhausted."
        ),
        InvestigationStoppingCondition.TOOL_CALL_BUDGET_EXHAUSTED: (
            "The Investigation tool-call budget was exhausted."
        ),
        InvestigationStoppingCondition.GENERATION_MODEL_CALL_BUDGET_EXHAUSTED: (
            "The Investigation generation-model-call budget was exhausted."
        ),
        InvestigationStoppingCondition.FOLLOW_UP_INVALID: (
            "The proposed Evidence Gap follow-up failed deterministic validation."
        ),
        InvestigationStoppingCondition.FOLLOW_UP_POLICY_BLOCKED: (
            "The proposed Evidence Gap follow-up was blocked by the Cyber Policy."
        ),
        InvestigationStoppingCondition.FOLLOW_UP_UNAVAILABLE: (
            "The authorized Evidence Gap follow-up was unavailable."
        ),
        InvestigationStoppingCondition.FOLLOW_UP_LIMIT_REACHED: (
            "A second Evidence Gap follow-up was rejected because only one is permitted."
        ),
    }
    base = reasons.get(condition, f"The Investigation stopped: {condition.value}.")
    return f"{base} ({detail})" if detail and detail != condition else base


def _same_operation(stored: object, requested: RunInvestigation) -> bool:
    if not isinstance(stored, RunInvestigation):
        return False
    stored_configuration = stored.configuration
    requested_configuration = requested.configuration
    return (
        stored.operation_id == requested.operation_id
        and stored.assessment_run_id == requested.assessment_run_id
        and stored.exposure_id == requested.exposure_id
        and stored.asset_snapshot_id == requested.asset_snapshot_id
        and stored.budget == requested.budget
        and _same_configuration(stored_configuration, requested_configuration)
    )


def _same_configuration(
    stored: InvestigationConfiguration,
    requested: InvestigationConfiguration,
) -> bool:
    return (
        stored.application_release == requested.application_release
        and stored.graph_version == requested.graph_version
        and stored.prompt_version == requested.prompt_version
        and stored.policy_version == requested.policy_version
        and stored.parser_version == requested.parser_version
        and stored.retrieval_configuration_version == requested.retrieval_configuration_version
        and stored.source_policy_version == requested.source_policy_version
        and tuple(stored.source_adapter_versions) == tuple(requested.source_adapter_versions)
        and stored.generation_model == requested.generation_model
        and stored.embedding_space == requested.embedding_space
    )
