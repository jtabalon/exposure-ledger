from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest
from exposure_ledger import (
    AssessmentOperation,
    AssessmentRequest,
    AuthorizationStatus,
    AvailableEvidence,
    Claim,
    ClaimDraft,
    ClaimEvidenceCitation,
    ClaimEvidenceRelationship,
    ClaimKind,
    CyberPolicy,
    EmbeddingSpace,
    EvidenceRelationship,
    GenerationModel,
    InvestigationConfiguration,
    InvestigationEvent,
    InvestigationEvidenceState,
    InvestigationMeasurements,
    InvestigationRevision,
    InvestigationRevisionStatus,
    Recommendation,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
    RevisionRecommendation,
    StructuredInvestigationDraft,
)
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import ExposureRepository, InvestigationRepository
from exposure_ledger_worker.local_generation import GenerationReadiness
from exposure_ledger_worker.main import process_next_assessment
from fastapi.testclient import TestClient
from test_exposures_http import (
    CapturedEpssSource,
    CapturedKevSource,
    CapturedOsvSource,
    FixtureArchiveSource,
    KnownAnswerEmbeddingProvider,
    repository_payload,
)

NOW = datetime(2026, 9, 4, 14, 0, tzinfo=UTC)


class ControlledGenerationProvider:
    model = GenerationModel(
        provider="controlled-local",
        model_artifact="controlled-generation-v1",
        artifact_digest="sha256:" + "d" * 64,
    )

    def check_readiness(self) -> GenerationReadiness:
        return GenerationReadiness(
            status="ready",
            code=None,
            message="Controlled local generation is ready.",
            setup=None,
            model=self.model,
        )

    def generate(self, exposure, evidence, configuration):  # type: ignore[no-untyped-def]
        assert configuration.generation_model == self.model
        passage = evidence.passages[0]
        return StructuredInvestigationDraft(
            operation=AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION,
            claims=(
                ClaimDraft(
                    identity="claim-affected",
                    kind=ClaimKind.FACT,
                    text=(
                        f"{exposure.package_name} {exposure.package_version} is associated "
                        "with the captured public vulnerability evidence."
                    ),
                    material=True,
                    limitation=None,
                    citations=(
                        ClaimEvidenceCitation(
                            evidence_record_id=passage.evidence_record_id,
                            passage_identities=(passage.passage_identity,),
                            relationship=EvidenceRelationship.SUPPORTS,
                        ),
                    ),
                ),
            ),
            recommendation=Recommendation.PLANNED_REMEDIATION,
            recommendation_summary="Review and apply the published fixed version.",
            recommendation_reasons=("The captured evidence supports package applicability.",),
            recommendation_limitations=("Static analysis does not prove runtime reachability.",),
        )


def _seed_exposure(database_url: str):  # type: ignore[no-untyped-def]
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
    )
    return ExposureRepository(database_url).list_for_assessment(run["id"])[0]


def _revision(exposure, *, created_at: datetime = NOW) -> InvestigationRevision:  # type: ignore[no-untyped-def]
    evidence = exposure.evidence_records[0]
    passage = evidence.passages[0]
    available = AvailableEvidence(
        record_id=evidence.id,
        record_identity=evidence.identity,
        content_digest=evidence.content_digest,
        source_identity=evidence.source.identity,
        source_adapter_version=evidence.source_adapter_version,
        passage_identities=(passage.identity,),
    )
    retrieved = RetrievedInvestigationEvidence(
        query="feature-lib 5.1.0 affected fixed upgrade",
        passages=(
            RetrievedInvestigationPassage(
                evidence_record_id=evidence.id,
                evidence_record_identity=evidence.identity,
                evidence_record_digest=evidence.content_digest,
                passage_identity=passage.identity,
                passage=passage.content,
                source_identity=evidence.source.identity,
                source_authority=evidence.source.authority,
                source_location=evidence.source.location,
                captured_at=evidence.captured_at,
                full_text_rank=1,
                full_text_score=0.9,
                vector_rank=1,
                vector_score=0.8,
                fused_rank=1,
                fused_score=0.03,
            ),
        ),
    )
    policy = CyberPolicy.decide(
        AssessmentRequest(
            operation=AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION,
            target_scope=f"exposure:{exposure.id}",
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )
    return InvestigationRevision(
        id=uuid4(),
        assessment_run_id=exposure.assessment_run_id,
        exposure_id=exposure.id,
        asset_snapshot_id=exposure.asset_snapshot_id,
        status=InvestigationRevisionStatus.COMPLETE,
        stopping_condition="completed",
        evidence_state=InvestigationEvidenceState(
            available=(available,),
            retrieved=retrieved,
            material_claims_supported=True,
            authoritative_conflict=False,
            validation_issues=(),
        ),
        claims=(
            Claim(
                identity="claim-affected",
                kind=ClaimKind.FACT,
                text="Feature-lib 5.1.0 is within the published affected range.",
                material=True,
                limitation=None,
                supported=True,
                citations=(
                    ClaimEvidenceRelationship(
                        evidence_record_id=evidence.id,
                        evidence_record_identity=evidence.identity,
                        passage_identities=(passage.identity,),
                        relationship=EvidenceRelationship.SUPPORTS,
                    ),
                ),
            ),
        ),
        recommendation=RevisionRecommendation(
            recommendation=Recommendation.PLANNED_REMEDIATION,
            accepted=True,
            reason="evidence_requirements_satisfied",
            summary="Upgrade to the first published fixed version.",
            reasons=("The installed package is in the affected range.",),
            limitations=("Static analysis does not prove runtime reachability.",),
        ),
        output_policy_decision=policy,
        events=(
            InvestigationEvent(
                stage="persist_revision",
                mode="deterministic",
                detail="Immutable Investigation Revision persisted.",
                occurred_at=created_at,
            ),
        ),
        measurements=InvestigationMeasurements(
            started_at=created_at,
            completed_at=created_at,
            duration_ms=0,
            generation_model_calls=1,
            tool_calls=1,
            graph_transitions=8,
        ),
        configuration=InvestigationConfiguration(
            application_release="0.1.0",
            graph_version="bounded-investigation-v1",
            prompt_version="claims-recommendation-v1",
            policy_version="0.1",
            parser_version="uv-lock-v1",
            retrieval_configuration_version="postgres-hybrid-rrf-v1",
            source_policy_version="explicit-source-allowlist-v1",
            source_adapter_versions=(
                f"{evidence.source.identity}={evidence.source_adapter_version}",
            ),
            generation_model=GenerationModel(
                provider="controlled-local",
                model_artifact="controlled-generation-v1",
                artifact_digest="sha256:" + "d" * 64,
            ),
            embedding_space=EmbeddingSpace(
                provider="known-answer-local",
                model_artifact="known-answer-embedding-v1",
                artifact_digest="sha256:" + "e" * 64,
                dimensions=3,
                retrieval_instruction="Represent this query: ",
                normalizer="l2-v1",
                passage_construction_version="source-aware-passage-v1",
            ),
        ),
        created_at=created_at,
    )


def test_revision_history_appends_and_reloads_complete_immutable_revisions(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    first = _revision(exposure)

    assert repository.append(first) == first
    second = replace(first, id=uuid4(), created_at=NOW.replace(minute=1))
    assert repository.append(second) == second

    records = repository.list_for_exposure(exposure.id)
    assert [record.revision_number for record in records] == [2, 1]
    assert records[0].revision == second
    assert records[1].revision == first
    assert records[0].investigation_id == records[1].investigation_id
    assert records[0].revision.claims[0].citations[0].relationship is EvidenceRelationship.SUPPORTS
    assert records[0].revision.configuration.generation_model.artifact_digest == (
        "sha256:" + "d" * 64
    )
    assert records[0].revision.configuration.embedding_space.identity == (
        first.configuration.embedding_space.identity
    )

    with (
        psycopg.connect(database_url) as connection,
        pytest.raises(psycopg.errors.RaiseException, match="Investigation history is immutable"),
    ):
        connection.execute(
            "UPDATE investigation_revisions SET stopping_condition = 'changed' WHERE id = %s",
            (first.id,),
        )

    with (
        psycopg.connect(database_url) as connection,
        pytest.raises(psycopg.errors.RaiseException, match="Investigation history is immutable"),
    ):
        connection.execute(
            """
            INSERT INTO claims (
                id, revision_id, identity_key, ordinal, kind, claim_text,
                material, limitation, supported
            ) VALUES (%s, %s, 'late-claim', 2, 'fact', 'Late mutation.', true, NULL, false)
            """,
            (uuid4(), first.id),
        )


def test_revision_rejects_evidence_outside_the_exposure_scope(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    unknown = uuid4()
    invalid_claim = replace(
        revision.claims[0],
        citations=(replace(revision.claims[0].citations[0], evidence_record_id=unknown),),
    )

    with pytest.raises(ValueError, match="Exposure evidence scope"):
        InvestigationRepository(database_url).append(replace(revision, claims=(invalid_claim,)))


def test_revision_rejects_a_forged_supported_claim(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    forged = replace(revision.claims[0], citations=())

    with pytest.raises(ValueError, match="support state is inconsistent"):
        InvestigationRepository(database_url).append(replace(revision, claims=(forged,)))


def test_revision_rejects_an_unverified_source_adapter_pin(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    source_identity = revision.evidence_state.available[0].source_identity
    unverified_configuration = replace(
        revision.configuration,
        source_adapter_versions=(f"{source_identity}=unverified-v99",),
    )

    with pytest.raises(ValueError, match="exact Evidence Source adapter versions"):
        InvestigationRepository(database_url).append(
            replace(revision, configuration=unverified_configuration)
        )


def test_controlled_adapters_exercise_the_complete_investigation_path(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
        embedding_provider=KnownAnswerEmbeddingProvider(),
        generation_provider=ControlledGenerationProvider(),
    )

    revisions = InvestigationRepository(database_url).list_for_assessment(run["id"])
    assert len(revisions) == 2
    assert all(item.revision.status is InvestigationRevisionStatus.COMPLETE for item in revisions)
    assert all(item.revision.claims[0].supported for item in revisions)
    assert all(
        item.revision.recommendation.recommendation is Recommendation.PLANNED_REMEDIATION
        for item in revisions
    )
    assert all(
        item.revision.configuration.generation_model == ControlledGenerationProvider.model
        for item in revisions
    )
    assert all(item.revision.measurements.graph_transitions == 8 for item in revisions)
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM policy_decisions
            WHERE assessment_run_id = %s AND enforcement_point = 'structured_output'
            """,
            (run["id"],),
        ).fetchone() == (2,)

    with TestClient(app) as client:
        response = client.get(f"/api/v1/assessment-runs/{run['id']}/investigation-revisions")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 2
    first = payload["items"][0]
    assert first["revisionNumber"] == 1
    assert first["status"] == "complete"
    assert first["stoppingCondition"] == "completed"
    assert first["claims"][0]["kind"] == "fact"
    assert first["claims"][0]["supported"] is True
    assert first["claims"][0]["citations"][0]["relationship"] == "supports"
    assert first["evidenceState"]["available"][0]["sourceAdapterVersion"]
    assert first["recommendation"]["value"] == "planned_remediation"
    assert first["outputPolicyDecision"]["enforcementPoint"] == "structured_output"
    assert first["configuration"]["generationModel"] == {
        "provider": "controlled-local",
        "modelArtifact": "controlled-generation-v1",
        "artifactDigest": "sha256:" + "d" * 64,
    }
    assert first["configuration"]["embeddingSpace"]["identity"].startswith("sha256:")
    assert first["events"][-1]["stage"] == "persist_revision"
    assert first["measurements"]["graphTransitions"] == 8
    assert "thinking" not in json.dumps(payload).lower()
    assert "chain-of-thought" not in json.dumps(payload).lower()
