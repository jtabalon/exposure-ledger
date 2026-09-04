"""PostgreSQL authority for immutable Investigation Revisions and Claims."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import (
    ActionLevel,
    AssistanceClass,
    AvailableEvidence,
    Claim,
    ClaimEvidenceRelationship,
    ClaimKind,
    EmbeddingSpace,
    EvidenceRelationship,
    GenerationModel,
    GenerationReadiness,
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
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
    RevisionRecommendation,
    RunInvestigation,
)
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from exposure_ledger_storage.exposures import ExposureRepository
from exposure_ledger_storage.postgres_deadline import (
    connect_with_deadline,
    deadline_after,
    set_statement_deadline,
)
from exposure_ledger_storage.retrieval import (
    EvidenceRetriever,
    RetrievalQuery,
    SourcePolicy,
    build_exposure_retrieval_query,
)

GENERATION_READINESS_MAX_AGE_SECONDS = 30


@dataclass(frozen=True, slots=True)
class InvestigationRevisionRecord:
    investigation_id: UUID
    revision_number: int
    revision: InvestigationRevision


class InvestigationRepository:
    """Append and load complete immutable Revision aggregates transactionally."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url) as connection:
                connection.execute("SELECT EXISTS (SELECT 1 FROM investigation_revisions)")
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error

    def record_generation_readiness(self, readiness: GenerationReadiness) -> None:
        with psycopg.connect(self._database_url) as connection:
            connection.execute(
                """
                INSERT INTO generation_provider_observations (
                    singleton, observed_at, status, code, message, setup,
                    provider, model_artifact, artifact_digest
                ) VALUES (true, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (singleton) DO UPDATE SET
                    observed_at = EXCLUDED.observed_at,
                    status = EXCLUDED.status,
                    code = EXCLUDED.code,
                    message = EXCLUDED.message,
                    setup = EXCLUDED.setup,
                    provider = EXCLUDED.provider,
                    model_artifact = EXCLUDED.model_artifact,
                    artifact_digest = EXCLUDED.artifact_digest
                """,
                (
                    datetime.now(UTC),
                    readiness.status,
                    readiness.code,
                    readiness.message,
                    readiness.setup,
                    readiness.model.provider if readiness.model is not None else None,
                    readiness.model.model_artifact if readiness.model is not None else None,
                    readiness.model.artifact_digest if readiness.model is not None else None,
                ),
            )

    def generation_readiness(self) -> GenerationReadiness:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                SELECT observed_at, status, code, message, setup,
                       provider, model_artifact, artifact_digest
                FROM generation_provider_observations WHERE singleton
                """
            ).fetchone()
        if row is None:
            return GenerationReadiness(
                status="unavailable",
                code="generation_readiness_unavailable",
                message="No local generation readiness observation has been recorded.",
                setup="Check that the worker and Ollama are running, then retry.",
                model=None,
            )
        if cast(datetime, row["observed_at"]) < datetime.now(UTC) - timedelta(
            seconds=GENERATION_READINESS_MAX_AGE_SECONDS
        ):
            previous_setup = str(row["setup"]) if row["setup"] is not None else None
            return GenerationReadiness(
                status="unavailable",
                code="generation_readiness_stale",
                message=(
                    "The worker's local generation readiness observation is stale. "
                    f"Last observation: {row['message']}"
                ),
                setup=(
                    f"{previous_setup} Then restart the worker."
                    if previous_setup is not None
                    else "Check that the worker and Ollama are running, then retry."
                ),
                model=None,
            )
        model = (
            GenerationModel(
                provider=str(row["provider"]),
                model_artifact=str(row["model_artifact"]),
                artifact_digest=str(row["artifact_digest"]),
            )
            if row["status"] == "ready"
            else None
        )
        return GenerationReadiness(
            status=cast(Any, row["status"]),
            code=str(row["code"]) if row["code"] is not None else None,
            message=str(row["message"]),
            setup=str(row["setup"]) if row["setup"] is not None else None,
            model=model,
        )

    def acquire(
        self, command: RunInvestigation, *, timeout_seconds: float
    ) -> InvestigationExposure:
        """Load one selected package-specific Exposure and its immutable evidence state."""
        deadline_monotonic = deadline_after(timeout_seconds)
        try:
            exposure = next(
                (
                    item
                    for item in ExposureRepository(self._database_url).list_for_assessment(
                        command.assessment_run_id,
                        deadline_monotonic=deadline_monotonic,
                    )
                    if item.id == command.exposure_id
                ),
                None,
            )
        except psycopg.errors.QueryCanceled as error:
            raise TimeoutError("Evidence acquisition exceeded its wall-time budget") from error
        if exposure is None or not exposure.selected_for_investigation:
            raise ValueError("Investigation command does not identify a selected Exposure")
        if exposure.asset_snapshot_id != command.asset_snapshot_id:
            raise ValueError("Pinned Asset Snapshot does not match the Exposure")
        with connect_with_deadline(self._database_url, deadline_monotonic) as connection:
            try:
                set_statement_deadline(connection, deadline_monotonic)
                snapshot = connection.execute(
                    "SELECT parser_version FROM asset_snapshots WHERE id = %s",
                    (exposure.asset_snapshot_id,),
                ).fetchone()
            except psycopg.errors.QueryCanceled as error:
                raise TimeoutError("Evidence acquisition exceeded its wall-time budget") from error
        if snapshot is None or snapshot["parser_version"] != command.configuration.parser_version:
            raise ValueError("Pinned parser version does not match the Asset Snapshot")
        return InvestigationExposure(
            assessment_run_id=exposure.assessment_run_id,
            exposure_id=exposure.id,
            asset_snapshot_id=exposure.asset_snapshot_id,
            package_name=exposure.package.name,
            package_version=exposure.package.version,
            vulnerability_aliases=exposure.vulnerability_record.aliases,
            authoritative_conflict=exposure.authoritative_conflict,
            evidence=tuple(
                AvailableEvidence(
                    record_id=evidence.id,
                    record_identity=evidence.identity,
                    content_digest=evidence.content_digest,
                    source_identity=evidence.source.identity,
                    source_adapter_version=evidence.source_adapter_version,
                    passage_identities=tuple(passage.identity for passage in evidence.passages),
                )
                for evidence in exposure.evidence_records
            ),
        )

    def retrieve(
        self,
        exposure: InvestigationExposure,
        command: RunInvestigation,
        *,
        timeout_seconds: float,
    ) -> RetrievedInvestigationEvidence:
        """Run the pinned hybrid retrieval configuration inside the Exposure scope."""
        deadline_monotonic = deadline_after(timeout_seconds)
        if command.configuration.source_policy_version != "explicit-source-allowlist-v1":
            raise ValueError("Pinned Source policy version is not current")
        try:
            records = ExposureRepository(self._database_url).list_for_assessment(
                command.assessment_run_id,
                deadline_monotonic=deadline_monotonic,
            )
        except psycopg.errors.QueryCanceled as error:
            raise TimeoutError("Evidence retrieval exceeded its wall-time budget") from error
        record = next((item for item in records if item.id == exposure.exposure_id), None)
        if record is None:
            raise ValueError("Exposure is no longer available in the Assessment scope")
        source_identities = tuple(
            sorted({evidence.source.identity for evidence in record.evidence_records})
        )
        evidence_types = tuple(
            sorted(
                {
                    passage.kind
                    for evidence in record.evidence_records
                    for passage in evidence.passages
                }
            )
        )
        try:
            result = EvidenceRetriever(self._database_url).retrieve(
                RetrievalQuery(
                    assessment_run_id=command.assessment_run_id,
                    exposure_id=command.exposure_id,
                    text=build_exposure_retrieval_query(
                        exposure.package_name,
                        exposure.package_version,
                        exposure.vulnerability_aliases,
                    ),
                    source_policy=SourcePolicy(
                        version=command.configuration.source_policy_version,
                        allowed_source_identities=source_identities,
                    ),
                    evidence_types=evidence_types,
                    retrieval_configuration_version=(
                        command.configuration.retrieval_configuration_version
                    ),
                    embedding_space_identity=command.configuration.embedding_space.identity,
                    limit=10,
                ),
                deadline_monotonic=deadline_monotonic,
            )
        except psycopg.errors.QueryCanceled as error:
            raise TimeoutError("Evidence retrieval exceeded its wall-time budget") from error
        if result.embedding_space != command.configuration.embedding_space:
            raise ValueError("Retrieved evidence used a different Embedding Space")
        return RetrievedInvestigationEvidence(
            query=result.query.text,
            passages=tuple(
                RetrievedInvestigationPassage(
                    evidence_record_id=item.evidence_record_id,
                    evidence_record_identity=item.capture.identity,
                    evidence_record_digest=item.capture.content_digest,
                    passage_identity=item.passage.identity,
                    passage=item.passage.content,
                    source_identity=item.source.identity,
                    source_authority=item.source.authority,
                    source_location=item.source.location,
                    captured_at=item.capture.captured_at,
                    full_text_rank=item.full_text_rank,
                    full_text_score=item.full_text_score,
                    vector_rank=item.vector_rank,
                    vector_score=item.vector_score,
                    fused_rank=item.fused_rank or 0,
                    fused_score=item.fused_score or 0.0,
                )
                for item in result.passages
            ),
        )

    def append(self, revision: InvestigationRevision) -> InvestigationRevision:
        with (
            psycopg.connect(self._database_url, row_factory=dict_row) as connection,
            connection.transaction(),
        ):
            self._validate_scope(connection, revision)
            embedding_space_id = self._store_embedding_space(
                connection, revision.configuration.embedding_space
            )
            assert embedding_space_id
            investigation_id = self._investigation_id(connection, revision)
            revision_number = self._next_revision_number(connection, investigation_id)
            policy_decision_id = self._insert_output_policy_decision(connection, revision)
            connection.execute(
                """
                INSERT INTO investigation_revisions (
                    id, investigation_id, revision_number, assessment_run_id, exposure_id,
                    asset_snapshot_id, status, stopping_condition,
                    material_claims_supported, authoritative_conflict, validation_issues,
                    retrieval_query, retrieved_passages,
                    recommendation, recommendation_accepted, recommendation_reason,
                    recommendation_summary, recommendation_reasons,
                    recommendation_limitations, output_policy_decision_id, events, measurements,
                    application_release, graph_version, prompt_version, policy_version,
                    parser_version, retrieval_configuration_version, source_policy_version,
                    source_adapter_versions, generation_provider, generation_model_artifact,
                    generation_artifact_digest, embedding_space_identity, created_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    revision.id,
                    investigation_id,
                    revision_number,
                    revision.assessment_run_id,
                    revision.exposure_id,
                    revision.asset_snapshot_id,
                    revision.status,
                    revision.stopping_condition,
                    revision.evidence_state.material_claims_supported,
                    revision.evidence_state.authoritative_conflict,
                    list(revision.evidence_state.validation_issues),
                    revision.evidence_state.retrieved.query,
                    Jsonb(_retrieved_passages_json(revision.evidence_state.retrieved)),
                    revision.recommendation.recommendation,
                    revision.recommendation.accepted,
                    revision.recommendation.reason,
                    revision.recommendation.summary,
                    list(revision.recommendation.reasons),
                    list(revision.recommendation.limitations),
                    policy_decision_id,
                    Jsonb(_events_json(revision.events)),
                    Jsonb(_measurements_json(revision.measurements)),
                    revision.configuration.application_release,
                    revision.configuration.graph_version,
                    revision.configuration.prompt_version,
                    revision.configuration.policy_version,
                    revision.configuration.parser_version,
                    revision.configuration.retrieval_configuration_version,
                    revision.configuration.source_policy_version,
                    list(revision.configuration.source_adapter_versions),
                    revision.configuration.generation_model.provider,
                    revision.configuration.generation_model.model_artifact,
                    revision.configuration.generation_model.artifact_digest,
                    revision.configuration.embedding_space.identity,
                    revision.created_at,
                ),
            )
            retrieved_by_record: dict[UUID, list[str]] = {}
            for passage in revision.evidence_state.retrieved.passages:
                retrieved_by_record.setdefault(passage.evidence_record_id, []).append(
                    passage.passage_identity
                )
            for evidence in revision.evidence_state.available:
                connection.execute(
                    """
                    INSERT INTO investigation_revision_evidence (
                        revision_id, evidence_record_id, content_digest,
                        available_passage_identities, retrieved_passage_identities
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        revision.id,
                        evidence.record_id,
                        evidence.content_digest,
                        list(evidence.passage_identities),
                        list(dict.fromkeys(retrieved_by_record.get(evidence.record_id, []))),
                    ),
                )
            for ordinal, claim in enumerate(revision.claims, start=1):
                claim_id = uuid4()
                connection.execute(
                    """
                    INSERT INTO claims (
                        id, revision_id, identity_key, ordinal, kind, claim_text,
                        material, limitation, supported
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        claim_id,
                        revision.id,
                        claim.identity,
                        ordinal,
                        claim.kind,
                        claim.text,
                        claim.material,
                        claim.limitation,
                        claim.supported,
                    ),
                )
                for citation in claim.citations:
                    connection.execute(
                        """
                        INSERT INTO claim_evidence_relationships (
                            claim_id, evidence_record_id, relationship, passage_identities
                        ) VALUES (%s, %s, %s, %s)
                        """,
                        (
                            claim_id,
                            citation.evidence_record_id,
                            citation.relationship,
                            list(citation.passage_identities),
                        ),
                    )
            connection.execute(
                "UPDATE investigation_revisions SET sealed = true WHERE id = %s",
                (revision.id,),
            )
        return revision

    def list_for_exposure(self, exposure_id: UUID) -> list[InvestigationRevisionRecord]:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT investigation_revisions.*, investigations.id AS investigation_identity,
                       embedding_spaces.provider AS embedding_provider,
                       embedding_spaces.model_artifact AS embedding_model_artifact,
                       embedding_spaces.artifact_digest AS embedding_artifact_digest,
                       embedding_spaces.dimensions AS embedding_dimensions,
                       embedding_spaces.retrieval_instruction,
                       embedding_spaces.normalizer,
                       embedding_spaces.passage_construction_version,
                       policy_decisions.standard_version AS output_standard_version,
                       policy_decisions.assistance_class AS output_assistance_class,
                       policy_decisions.action_level AS output_action_level,
                       policy_decisions.target_scope AS output_target_scope,
                       policy_decisions.authorization_scope AS output_authorization_scope,
                       policy_decisions.result AS output_result,
                       policy_decisions.rule_version AS output_rule_version,
                       policy_decisions.reason AS output_reason
                FROM investigation_revisions
                JOIN investigations
                  ON investigations.id = investigation_revisions.investigation_id
                JOIN embedding_spaces
                  ON embedding_spaces.identity_key =
                     investigation_revisions.embedding_space_identity
                JOIN policy_decisions
                  ON policy_decisions.id =
                     investigation_revisions.output_policy_decision_id
                WHERE investigation_revisions.exposure_id = %s
                ORDER BY investigation_revisions.revision_number DESC
                """,
                (exposure_id,),
            ).fetchall()
            return [self._from_row(connection, row) for row in rows]

    def list_for_assessment(self, assessment_run_id: UUID) -> list[InvestigationRevisionRecord]:
        assessment_run_id = UUID(str(assessment_run_id))
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            exposure_ids = [
                UUID(str(row["exposure_id"]))
                for row in connection.execute(
                    """
                    SELECT DISTINCT exposure_id FROM investigation_revisions
                    WHERE assessment_run_id = %s ORDER BY exposure_id
                    """,
                    (assessment_run_id,),
                ).fetchall()
            ]
        records = [
            record
            for exposure_id in exposure_ids
            for record in self.list_for_exposure(exposure_id)
            if record.revision.assessment_run_id == assessment_run_id
        ]
        return sorted(
            records,
            key=lambda record: (record.revision.created_at, str(record.revision.id)),
            reverse=True,
        )

    @staticmethod
    def _validate_scope(
        connection: psycopg.Connection[dict[str, Any]], revision: InvestigationRevision
    ) -> None:
        belongs = connection.execute(
            """
            SELECT 1
            FROM assessment_run_exposures
            JOIN exposures ON exposures.id = assessment_run_exposures.exposure_id
            WHERE assessment_run_exposures.assessment_run_id = %s
              AND assessment_run_exposures.exposure_id = %s
              AND exposures.asset_snapshot_id = %s
              AND assessment_run_exposures.selected_for_investigation
            """,
            (
                revision.assessment_run_id,
                revision.exposure_id,
                revision.asset_snapshot_id,
            ),
        ).fetchone()
        if belongs is None:
            raise ValueError("Investigation Revision is outside the selected Exposure scope")

        available_by_id = {item.record_id: item for item in revision.evidence_state.available}
        if len(available_by_id) != len(revision.evidence_state.available):
            raise ValueError("Investigation evidence contains duplicate Evidence Records")
        stored_rows = connection.execute(
            """
            SELECT evidence_records.id, evidence_records.identity_key,
                   evidence_records.content_digest,
                   evidence_records.source_adapter_version,
                   sources.identity_key AS source_identity,
                   array_agg(evidence_passages.identity_key
                             ORDER BY evidence_passages.identity_key) AS passages
            FROM assessment_run_exposure_evidence
            JOIN evidence_records
              ON evidence_records.id = assessment_run_exposure_evidence.evidence_record_id
            JOIN sources ON sources.id = evidence_records.source_id
            JOIN evidence_passages
              ON evidence_passages.evidence_record_id = evidence_records.id
            JOIN assessment_run_exposure_passages
              ON assessment_run_exposure_passages.assessment_run_id =
                 assessment_run_exposure_evidence.assessment_run_id
             AND assessment_run_exposure_passages.exposure_id =
                 assessment_run_exposure_evidence.exposure_id
             AND assessment_run_exposure_passages.evidence_record_id = evidence_records.id
             AND assessment_run_exposure_passages.passage_id = evidence_passages.id
            WHERE assessment_run_exposure_evidence.assessment_run_id = %s
              AND assessment_run_exposure_evidence.exposure_id = %s
            GROUP BY evidence_records.id, evidence_records.identity_key,
                     evidence_records.content_digest,
                     evidence_records.source_adapter_version, sources.identity_key
            """,
            (revision.assessment_run_id, revision.exposure_id),
        ).fetchall()
        stored = {
            UUID(str(row["id"])): (
                str(row["identity_key"]),
                str(row["content_digest"]),
                str(row["source_identity"]),
                str(row["source_adapter_version"]),
                tuple(str(item) for item in row["passages"]),
            )
            for row in stored_rows
        }
        for record_id, available in available_by_id.items():
            expected = stored.get(record_id)
            if (
                expected is None
                or expected[:4]
                != (
                    available.record_identity,
                    available.content_digest,
                    available.source_identity,
                    available.source_adapter_version,
                )
                or not set(available.passage_identities).issubset(expected[4])
            ):
                raise ValueError("Investigation Revision is outside the Exposure evidence scope")

        for passage in revision.evidence_state.retrieved.passages:
            retrieved_available = available_by_id.get(passage.evidence_record_id)
            if (
                retrieved_available is None
                or (
                    passage.evidence_record_identity,
                    passage.evidence_record_digest,
                )
                != (retrieved_available.record_identity, retrieved_available.content_digest)
                or (passage.passage_identity not in retrieved_available.passage_identities)
            ):
                raise ValueError("Retrieved passage is outside the Exposure evidence scope")
        retrieved_passages = {
            (passage.evidence_record_id, passage.passage_identity)
            for passage in revision.evidence_state.retrieved.passages
        }
        for claim in revision.claims:
            if not claim.citations:
                raise ValueError("Claim support state is inconsistent with its citations")
            expected_supported = (
                bool(claim.limitation and claim.limitation.strip())
                if claim.kind is ClaimKind.INFERENCE
                else (
                    not claim.material
                    or any(
                        citation.relationship is EvidenceRelationship.SUPPORTS
                        for citation in claim.citations
                    )
                )
            )
            if claim.supported != expected_supported:
                raise ValueError("Claim support state is inconsistent with its citations")
            for citation in claim.citations:
                cited_available = available_by_id.get(citation.evidence_record_id)
                if cited_available is None or not set(citation.passage_identities).issubset(
                    cited_available.passage_identities
                ):
                    raise ValueError("Claim citation is outside the Exposure evidence scope")
                if citation.evidence_record_identity != cited_available.record_identity:
                    raise ValueError("Claim citation conflicts with immutable Evidence identity")
                if any(
                    (citation.evidence_record_id, passage_identity) not in retrieved_passages
                    for passage_identity in citation.passage_identities
                ):
                    raise ValueError("Claim citation is outside the retrieved evidence scope")
        expected_material_support = bool(revision.claims) and all(
            claim.supported for claim in revision.claims
        )
        if revision.evidence_state.material_claims_supported != expected_material_support:
            raise ValueError("Revision evidence support state is inconsistent with its Claims")
        adapter_versions = _source_adapter_versions(revision.configuration.source_adapter_versions)
        expected_adapter_versions = {
            item.source_identity: item.source_adapter_version
            for item in revision.evidence_state.available
        }
        evidence_was_skipped_by_budget = (
            revision.status is InvestigationRevisionStatus.INCOMPLETE
            and not revision.evidence_state.available
            and revision.stopping_condition
            in {
                InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
                InvestigationStoppingCondition.GRAPH_TRANSITION_BUDGET_EXHAUSTED,
            }
        )
        if evidence_was_skipped_by_budget:
            if revision.evidence_state.authoritative_conflict is not None:
                raise ValueError(
                    "Authoritative conflict must be unknown when evidence acquisition was skipped"
                )
        elif revision.evidence_state.authoritative_conflict is None:
            raise ValueError(
                "Authoritative conflict may be unknown only when evidence acquisition was skipped"
            )
        if adapter_versions != expected_adapter_versions and not evidence_was_skipped_by_budget:
            raise ValueError("Revision does not pin the exact Evidence Source adapter versions")
        if (
            revision.configuration.policy_version
            != revision.output_policy_decision.standard_version
        ):
            raise ValueError("Pinned policy version does not match the output Policy Decision")

    @staticmethod
    def _store_embedding_space(
        connection: psycopg.Connection[dict[str, Any]], space: EmbeddingSpace
    ) -> UUID:
        inserted = connection.execute(
            """
            INSERT INTO embedding_spaces (
                id, identity_key, provider, model_artifact, artifact_digest, dimensions,
                retrieval_instruction, normalizer, passage_construction_version
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING RETURNING id
            """,
            (
                uuid4(),
                space.identity,
                space.provider,
                space.model_artifact,
                space.artifact_digest,
                space.dimensions,
                space.retrieval_instruction,
                space.normalizer,
                space.passage_construction_version,
            ),
        ).fetchone()
        if inserted is not None:
            return UUID(str(inserted["id"]))
        existing = connection.execute(
            """
            SELECT id, provider, model_artifact, artifact_digest, dimensions,
                   retrieval_instruction, normalizer, passage_construction_version
            FROM embedding_spaces WHERE identity_key = %s
            """,
            (space.identity,),
        ).fetchone()
        if existing is None or (
            existing["provider"],
            existing["model_artifact"],
            existing["artifact_digest"],
            existing["dimensions"],
            existing["retrieval_instruction"],
            existing["normalizer"],
            existing["passage_construction_version"],
        ) != (
            space.provider,
            space.model_artifact,
            space.artifact_digest,
            space.dimensions,
            space.retrieval_instruction,
            space.normalizer,
            space.passage_construction_version,
        ):
            raise ValueError("Embedding Space identity conflicts with stored inputs")
        return UUID(str(existing["id"]))

    @staticmethod
    def _investigation_id(
        connection: psycopg.Connection[dict[str, Any]], revision: InvestigationRevision
    ) -> UUID:
        inserted = connection.execute(
            """
            INSERT INTO investigations (id, exposure_id, created_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (exposure_id) DO NOTHING RETURNING id
            """,
            (uuid4(), revision.exposure_id, revision.created_at),
        ).fetchone()
        if inserted is not None:
            investigation_id = UUID(str(inserted["id"]))
        else:
            existing = connection.execute(
                "SELECT id FROM investigations WHERE exposure_id = %s",
                (revision.exposure_id,),
            ).fetchone()
            assert existing is not None
            investigation_id = UUID(str(existing["id"]))
        connection.execute(
            "SELECT id FROM investigations WHERE id = %s FOR UPDATE",
            (investigation_id,),
        )
        return investigation_id

    @staticmethod
    def _next_revision_number(
        connection: psycopg.Connection[dict[str, Any]], investigation_id: UUID
    ) -> int:
        row = connection.execute(
            """
            SELECT COALESCE(MAX(revision_number), 0) + 1 AS next_number
            FROM investigation_revisions WHERE investigation_id = %s
            """,
            (investigation_id,),
        ).fetchone()
        assert row is not None
        return int(row["next_number"])

    @staticmethod
    def _insert_output_policy_decision(
        connection: psycopg.Connection[dict[str, Any]], revision: InvestigationRevision
    ) -> UUID:
        decision = revision.output_policy_decision
        decision_id = uuid4()
        connection.execute(
            """
            INSERT INTO policy_decisions (
                id, assessment_run_id, standard_version, assistance_class, action_level,
                target_scope, authorization_scope, result, rule_version, reason, created_at,
                enforcement_point
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'structured_output')
            """,
            (
                decision_id,
                revision.assessment_run_id,
                decision.standard_version,
                decision.assistance_class,
                decision.action_level,
                decision.target_scope,
                decision.authorization_scope,
                decision.result,
                decision.rule_version,
                decision.reason,
                revision.created_at,
            ),
        )
        return decision_id

    @staticmethod
    def _from_row(
        connection: psycopg.Connection[dict[str, Any]], row: dict[str, Any]
    ) -> InvestigationRevisionRecord:
        available_rows = connection.execute(
            """
            SELECT investigation_revision_evidence.evidence_record_id,
                   evidence_records.identity_key,
                   evidence_records.source_adapter_version,
                   sources.identity_key AS source_identity,
                   investigation_revision_evidence.content_digest,
                   investigation_revision_evidence.available_passage_identities
            FROM investigation_revision_evidence
            JOIN evidence_records
              ON evidence_records.id = investigation_revision_evidence.evidence_record_id
            JOIN sources ON sources.id = evidence_records.source_id
            WHERE investigation_revision_evidence.revision_id = %s
            ORDER BY evidence_records.identity_key
            """,
            (row["id"],),
        ).fetchall()
        claims_rows = connection.execute(
            """
            SELECT * FROM claims WHERE revision_id = %s ORDER BY ordinal
            """,
            (row["id"],),
        ).fetchall()
        claims: list[Claim] = []
        for claim_row in claims_rows:
            citation_rows = connection.execute(
                """
                SELECT claim_evidence_relationships.evidence_record_id,
                       evidence_records.identity_key, relationship, passage_identities
                FROM claim_evidence_relationships
                JOIN evidence_records
                  ON evidence_records.id = claim_evidence_relationships.evidence_record_id
                WHERE claim_id = %s
                ORDER BY evidence_records.identity_key, relationship
                """,
                (claim_row["id"],),
            ).fetchall()
            claims.append(
                Claim(
                    identity=str(claim_row["identity_key"]),
                    kind=ClaimKind(str(claim_row["kind"])),
                    text=str(claim_row["claim_text"]),
                    material=bool(claim_row["material"]),
                    limitation=(
                        str(claim_row["limitation"])
                        if claim_row["limitation"] is not None
                        else None
                    ),
                    supported=bool(claim_row["supported"]),
                    citations=tuple(
                        ClaimEvidenceRelationship(
                            evidence_record_id=UUID(str(item["evidence_record_id"])),
                            evidence_record_identity=str(item["identity_key"]),
                            passage_identities=tuple(
                                str(value) for value in item["passage_identities"]
                            ),
                            relationship=EvidenceRelationship(str(item["relationship"])),
                        )
                        for item in citation_rows
                    ),
                )
            )
        configuration = InvestigationConfiguration(
            application_release=str(row["application_release"]),
            graph_version=str(row["graph_version"]),
            prompt_version=str(row["prompt_version"]),
            policy_version=str(row["policy_version"]),
            parser_version=str(row["parser_version"]),
            retrieval_configuration_version=str(row["retrieval_configuration_version"]),
            source_policy_version=str(row["source_policy_version"]),
            source_adapter_versions=tuple(str(item) for item in row["source_adapter_versions"]),
            generation_model=GenerationModel(
                provider=str(row["generation_provider"]),
                model_artifact=str(row["generation_model_artifact"]),
                artifact_digest=str(row["generation_artifact_digest"]),
            ),
            embedding_space=EmbeddingSpace(
                provider=str(row["embedding_provider"]),
                model_artifact=str(row["embedding_model_artifact"]),
                artifact_digest=str(row["embedding_artifact_digest"]),
                dimensions=int(row["embedding_dimensions"]),
                retrieval_instruction=str(row["retrieval_instruction"]),
                normalizer=str(row["normalizer"]),
                passage_construction_version=str(row["passage_construction_version"]),
            ),
        )
        evidence_state = InvestigationEvidenceState(
            available=tuple(
                AvailableEvidence(
                    record_id=UUID(str(item["evidence_record_id"])),
                    record_identity=str(item["identity_key"]),
                    content_digest=str(item["content_digest"]),
                    source_identity=str(item["source_identity"]),
                    source_adapter_version=str(item["source_adapter_version"]),
                    passage_identities=tuple(
                        str(value) for value in item["available_passage_identities"]
                    ),
                )
                for item in available_rows
            ),
            retrieved=RetrievedInvestigationEvidence(
                query=str(row["retrieval_query"]),
                passages=_retrieved_passages_from_json(row["retrieved_passages"]),
            ),
            material_claims_supported=bool(row["material_claims_supported"]),
            authoritative_conflict=(
                bool(row["authoritative_conflict"])
                if row["authoritative_conflict"] is not None
                else None
            ),
            validation_issues=tuple(str(item) for item in row["validation_issues"]),
        )
        revision = InvestigationRevision(
            id=UUID(str(row["id"])),
            assessment_run_id=UUID(str(row["assessment_run_id"])),
            exposure_id=UUID(str(row["exposure_id"])),
            asset_snapshot_id=UUID(str(row["asset_snapshot_id"])),
            status=InvestigationRevisionStatus(str(row["status"])),
            stopping_condition=InvestigationStoppingCondition(str(row["stopping_condition"])),
            evidence_state=evidence_state,
            claims=tuple(claims),
            recommendation=RevisionRecommendation(
                recommendation=Recommendation(str(row["recommendation"])),
                accepted=bool(row["recommendation_accepted"]),
                reason=str(row["recommendation_reason"]),
                summary=str(row["recommendation_summary"]),
                reasons=tuple(str(item) for item in row["recommendation_reasons"]),
                limitations=tuple(str(item) for item in row["recommendation_limitations"]),
            ),
            output_policy_decision=PolicyDecision(
                standard_version=str(row["output_standard_version"]),
                assistance_class=AssistanceClass(str(row["output_assistance_class"])),
                action_level=ActionLevel(str(row["output_action_level"])),
                target_scope=(
                    str(row["output_target_scope"])
                    if row["output_target_scope"] is not None
                    else None
                ),
                authorization_scope=(
                    str(row["output_authorization_scope"])
                    if row["output_authorization_scope"] is not None
                    else None
                ),
                result=PolicyResult(str(row["output_result"])),
                rule_version=str(row["output_rule_version"]),
                reason=str(row["output_reason"]),
            ),
            events=_events_from_json(row["events"]),
            measurements=_measurements_from_json(row["measurements"]),
            configuration=configuration,
            created_at=cast(datetime, row["created_at"]),
        )
        return InvestigationRevisionRecord(
            investigation_id=UUID(str(row["investigation_identity"])),
            revision_number=int(row["revision_number"]),
            revision=revision,
        )


def _retrieved_passages_json(evidence: RetrievedInvestigationEvidence) -> list[dict[str, object]]:
    return [
        {
            "evidenceRecordId": str(item.evidence_record_id),
            "evidenceRecordIdentity": item.evidence_record_identity,
            "evidenceRecordDigest": item.evidence_record_digest,
            "passageIdentity": item.passage_identity,
            "passage": item.passage,
            "sourceIdentity": item.source_identity,
            "sourceAuthority": item.source_authority,
            "sourceLocation": item.source_location,
            "capturedAt": item.captured_at.isoformat(),
            "fullTextRank": item.full_text_rank,
            "fullTextScore": item.full_text_score,
            "vectorRank": item.vector_rank,
            "vectorScore": item.vector_score,
            "fusedRank": item.fused_rank,
            "fusedScore": item.fused_score,
        }
        for item in evidence.passages
    ]


def _retrieved_passages_from_json(value: object) -> tuple[RetrievedInvestigationPassage, ...]:
    items = cast(list[dict[str, object]], value)
    return tuple(
        RetrievedInvestigationPassage(
            evidence_record_id=UUID(str(item["evidenceRecordId"])),
            evidence_record_identity=str(item["evidenceRecordIdentity"]),
            evidence_record_digest=str(item["evidenceRecordDigest"]),
            passage_identity=str(item["passageIdentity"]),
            passage=str(item["passage"]),
            source_identity=str(item["sourceIdentity"]),
            source_authority=str(item["sourceAuthority"]),
            source_location=str(item["sourceLocation"]),
            captured_at=datetime.fromisoformat(str(item["capturedAt"])),
            full_text_rank=_optional_int(item["fullTextRank"]),
            full_text_score=_optional_float(item["fullTextScore"]),
            vector_rank=_optional_int(item["vectorRank"]),
            vector_score=_optional_float(item["vectorScore"]),
            fused_rank=int(str(item["fusedRank"])),
            fused_score=float(str(item["fusedScore"])),
        )
        for item in items
    )


def _events_json(events: tuple[InvestigationEvent, ...]) -> list[dict[str, object]]:
    return [
        {
            "stage": event.stage,
            "mode": event.mode,
            "detail": event.detail,
            "occurredAt": event.occurred_at.isoformat(),
        }
        for event in events
    ]


def _events_from_json(value: object) -> tuple[InvestigationEvent, ...]:
    return tuple(
        InvestigationEvent(
            stage=InvestigationStage(str(item["stage"])),
            mode=InvestigationEventMode(str(item["mode"])),
            detail=str(item["detail"]),
            occurred_at=datetime.fromisoformat(str(item["occurredAt"])),
        )
        for item in cast(list[dict[str, object]], value)
    )


def _measurements_json(measurements: InvestigationMeasurements) -> dict[str, object]:
    return {
        "startedAt": measurements.started_at.isoformat(),
        "completedAt": measurements.completed_at.isoformat(),
        "durationMs": measurements.duration_ms,
        "generationModelCalls": measurements.generation_model_calls,
        "toolCalls": measurements.tool_calls,
        "graphTransitions": measurements.graph_transitions,
    }


def _measurements_from_json(value: object) -> InvestigationMeasurements:
    item = cast(dict[str, object], value)
    return InvestigationMeasurements(
        started_at=datetime.fromisoformat(str(item["startedAt"])),
        completed_at=datetime.fromisoformat(str(item["completedAt"])),
        duration_ms=int(str(item["durationMs"])),
        generation_model_calls=int(str(item["generationModelCalls"])),
        tool_calls=int(str(item["toolCalls"])),
        graph_transitions=int(str(item["graphTransitions"])),
    )


def _optional_int(value: object) -> int | None:
    return int(str(value)) if value is not None else None


def _optional_float(value: object) -> float | None:
    return float(str(value)) if value is not None else None


def _source_adapter_versions(values: tuple[str, ...]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for value in values:
        source_identity, separator, version = value.partition("=")
        if (
            not separator
            or not source_identity.strip()
            or not version.strip()
            or source_identity in versions
        ):
            raise ValueError("Source adapter versions must uniquely map Source identity to version")
        versions[source_identity] = version
    return versions
