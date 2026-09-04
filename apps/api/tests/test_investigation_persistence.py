from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID, uuid4

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
    Disposition,
    DispositionKind,
    EmbeddingSpace,
    EvidenceFollowUpArguments,
    EvidenceFollowUpAuthorization,
    EvidenceFollowUpProposal,
    EvidenceFollowUpTool,
    EvidenceGap,
    EvidenceGapKind,
    EvidenceRelationship,
    EvidenceType,
    GenerationModel,
    InvestigationBudget,
    InvestigationConfiguration,
    InvestigationEvent,
    InvestigationEvidenceState,
    InvestigationMeasurements,
    InvestigationRevision,
    InvestigationRevisionStatus,
    InvestigationStoppingCondition,
    Recommendation,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
    RevisionRecommendation,
    RunInvestigation,
    StructuredInvestigationDraft,
)
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import (
    AssessmentRunRepository,
    ExposureRepository,
    InvalidInvestigationOperation,
    InvestigationRepository,
    apply_migrations,
)
from exposure_ledger_storage.postgres_deadline import connect_with_deadline
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


def test_bounded_database_connections_reject_unenforceable_deadlines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TimeoutError, match="Insufficient wall-time"):
        connect_with_deadline(
            "postgresql://localhost/exposure_ledger",
            monotonic() + 1.5,
        )
    with pytest.raises(ValueError, match="one explicit PostgreSQL host"):
        connect_with_deadline(
            "postgresql://host-a:5432,host-b:5432/exposure_ledger",
            monotonic() + 10,
        )
    monkeypatch.setenv("PGHOST", "host-a,host-b")
    with pytest.raises(ValueError, match="explicit PostgreSQL host"):
        connect_with_deadline(
            "postgresql:///exposure_ledger",
            monotonic() + 10,
        )
    monkeypatch.delenv("PGHOST")
    monkeypatch.setenv("PGSERVICE", "production")
    with pytest.raises(ValueError, match="PGSERVICE"):
        connect_with_deadline(
            "postgresql://127.0.0.1/exposure_ledger",
            monotonic() + 10,
        )
    monkeypatch.delenv("PGSERVICE")
    with pytest.raises(ValueError, match="explicit PostgreSQL address"):
        connect_with_deadline(
            "postgresql://database.internal/exposure_ledger",
            monotonic() + 10,
        )

    def connection_timeout(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise psycopg.errors.ConnectionTimeout("connection timed out")

    monkeypatch.setattr(psycopg, "connect", connection_timeout)
    with pytest.raises(TimeoutError, match="wall-time budget"):
        connect_with_deadline(
            "postgresql://127.0.0.1/exposure_ledger",
            monotonic() + 10,
        )


class ControlledGenerationProvider:
    model = GenerationModel(
        provider="controlled-local",
        model_artifact="controlled-generation-v1",
        artifact_digest="sha256:" + "d" * 64,
    )

    def check_readiness(self, *, timeout_seconds: float | None = None) -> GenerationReadiness:
        return GenerationReadiness(
            status="ready",
            code=None,
            message="Controlled local generation is ready.",
            setup=None,
            model=self.model,
        )

    async def check_readiness_bounded(self, *, timeout_seconds: float) -> GenerationReadiness:
        return self.check_readiness(timeout_seconds=timeout_seconds)

    def generate(  # type: ignore[no-untyped-def]
        self, exposure, evidence, configuration, *, timeout_seconds: float
    ):
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

    async def generate_bounded(  # type: ignore[no-untyped-def]
        self, exposure, evidence, configuration, *, timeout_seconds: float
    ):
        return self.generate(
            exposure,
            evidence,
            configuration,
            timeout_seconds=timeout_seconds,
        )


class ControlledFollowUpGenerationProvider(ControlledGenerationProvider):
    def __init__(self) -> None:
        self._calls_by_exposure: dict[object, int] = {}

    def generate(  # type: ignore[no-untyped-def]
        self, exposure, evidence, configuration, *, timeout_seconds: float
    ):
        draft = super().generate(
            exposure,
            evidence,
            configuration,
            timeout_seconds=timeout_seconds,
        )
        count = self._calls_by_exposure.get(exposure.exposure_id, 0) + 1
        self._calls_by_exposure[exposure.exposure_id] = count
        if count > 1:
            return draft
        return replace(
            draft,
            recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
            evidence_gap=EvidenceGap(
                identity="gap-affected-range",
                kind=EvidenceGapKind.INSUFFICIENT,
                description="A focused affected-range passage is required.",
            ),
            follow_up=EvidenceFollowUpProposal(
                tool=EvidenceFollowUpTool.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
                target=f"exposure:{exposure.exposure_id}",
                arguments=EvidenceFollowUpArguments(
                    source_identity="osv",
                    evidence_type=EvidenceType.AFFECTED,
                ),
                assistance_class="C1",
                action_level="A1",
            ),
        )


class InterruptDuringFollowUpGenerationProvider(ControlledFollowUpGenerationProvider):
    def generate(  # type: ignore[no-untyped-def]
        self, exposure, evidence, configuration, *, timeout_seconds: float
    ):
        draft = super().generate(
            exposure,
            evidence,
            configuration,
            timeout_seconds=timeout_seconds,
        )
        if self._calls_by_exposure[exposure.exposure_id] == 2:
            raise KeyboardInterrupt("simulated worker interruption at a graph checkpoint")
        return draft


class CountingArchiveSource(FixtureArchiveSource):
    def __init__(self) -> None:
        self.calls = 0

    def fetch(self, repository: str, commit: str):  # type: ignore[no-untyped-def]
        self.calls += 1
        return super().fetch(repository, commit)


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
        evidence_gap=None,
        follow_up=None,
        stopping_reason=None,
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
            prompt_version="claims-recommendation-follow-up-v2",
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


def test_retrying_the_same_revision_is_idempotent(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    revision = _revision(exposure)

    first = repository.append(revision)
    retried = repository.append(revision)

    assert retried == first
    assert [record.revision.id for record in repository.list_for_exposure(exposure.id)] == [
        revision.id
    ]


def test_operation_identity_rejects_changed_pinned_configuration(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    command = RunInvestigation(
        operation_id=uuid4(),
        assessment_run_id=exposure.assessment_run_id,
        exposure_id=exposure.id,
        asset_snapshot_id=exposure.asset_snapshot_id,
        configuration=revision.configuration,
        budget=InvestigationBudget(),
    )
    repository = InvestigationRepository(database_url)

    repository.begin_operation(command)

    with pytest.raises(InvalidInvestigationOperation, match="configuration changed"):
        repository.begin_operation(
            replace(
                command,
                configuration=replace(command.configuration, prompt_version="changed-v2"),
            )
        )


def test_follow_up_migration_preserves_legacy_incomplete_revisions(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    legacy_revision = replace(
        _revision(exposure),
        status=InvestigationRevisionStatus.INCOMPLETE,
        stopping_condition=InvestigationStoppingCondition.WALL_TIME_BUDGET_EXHAUSTED,
        stopping_reason="The Investigation wall-time budget was exhausted.",
    )
    repository.append(legacy_revision)
    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute(
            """
            ALTER TABLE investigation_revisions
                DROP CONSTRAINT investigation_revisions_stopping_reason_check,
                DROP CONSTRAINT investigation_revisions_follow_up_check,
                DROP COLUMN stopping_reason,
                DROP COLUMN evidence_gap,
                DROP COLUMN follow_up,
                DROP COLUMN follow_up_policy_decision_id
            """
        )
        connection.execute("DELETE FROM exposure_ledger_schema_migrations WHERE version = 17")

    apply_migrations(database_url)

    loaded = repository.list_for_exposure(exposure.id)[0].revision
    with psycopg.connect(database_url) as connection:
        stored_reason = connection.execute(
            "SELECT stopping_reason FROM investigation_revisions WHERE id = %s",
            (legacy_revision.id,),
        ).fetchone()
    assert stored_reason == (None,)
    assert loaded.status is InvestigationRevisionStatus.INCOMPLETE
    assert loaded.stopping_reason is not None
    assert "legacy Investigation Revision" in loaded.stopping_reason


def test_revision_persists_the_model_proposal_and_deterministic_follow_up_authorization(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    proposal = EvidenceFollowUpProposal(
        tool=EvidenceFollowUpTool.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
        target=f"exposure:{exposure.id}",
        arguments=EvidenceFollowUpArguments(
            source_identity=revision.evidence_state.available[0].source_identity,
            evidence_type=EvidenceType.AFFECTED,
        ),
        assistance_class="C1",
        action_level="A1",
    )
    policy = CyberPolicy.decide(
        AssessmentRequest(
            operation=AssessmentOperation.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
            target_scope=proposal.target,
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )
    followed = replace(
        revision,
        evidence_gap=EvidenceGap(
            identity="gap-affected-range",
            kind=EvidenceGapKind.INSUFFICIENT,
            description="A focused affected-range passage was required.",
        ),
        follow_up=EvidenceFollowUpAuthorization(
            proposal=proposal,
            authorized=True,
            executed=True,
            reason="follow_up_authorized",
            issues=(),
            policy_decision=policy,
        ),
    )

    repository = InvestigationRepository(database_url)
    repository.append(followed)
    loaded = repository.list_for_exposure(exposure.id)[0].revision

    assert loaded.evidence_gap == followed.evidence_gap
    assert loaded.follow_up == followed.follow_up

    with TestClient(create_app(Settings(database_url=database_url))) as client:
        payload = client.get(
            f"/api/v1/assessment-runs/{exposure.assessment_run_id}/investigation-revisions"
        ).json()["items"][0]

    assert payload["evidenceGap"]["kind"] == "insufficient"
    assert payload["followUp"]["proposal"]["tool"] == "search_captured_exposure_evidence"
    assert payload["followUp"]["authorization"]["authorized"] is True
    assert payload["followUp"]["authorization"]["executed"] is True
    assert payload["followUp"]["authorization"]["policyDecision"]["enforcementPoint"] == (
        "tool_call"
    )


def test_risk_acceptance_requires_rationale_and_an_expiration_or_review_date(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    repository = InvestigationRepository(database_url)
    repository.append(revision)
    investigation_id = repository.list_for_exposure(exposure.id)[0].investigation_id
    app = create_app(
        Settings(
            database_url=database_url,
            enable_local_dispositions=True,
            local_operator="AppSec reviewer",
        )
    )
    request = {
        "investigationRevisionId": str(revision.id),
        "kind": "accept_risk",
    }

    with TestClient(create_app(Settings(database_url=database_url))) as client:
        disabled = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={**request, "reviewDate": (NOW + timedelta(days=30)).date().isoformat()},
        )
    assert disabled.status_code == 403
    assert disabled.json()["detail"]["code"] == "local_dispositions_disabled"

    with TestClient(app) as remote_client:
        remote = remote_client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={
                **request,
                "rationale": "Compensating controls reduce the immediate risk.",
                "reviewDate": (NOW + timedelta(days=30)).date().isoformat(),
            },
        )
    assert remote.status_code == 403
    assert remote.json()["detail"]["code"] == "local_dispositions_loopback_required"

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        missing_rationale = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={**request, "reviewDate": (NOW + timedelta(days=30)).date().isoformat()},
        )
        missing_date = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={**request, "rationale": "Compensating controls reduce the immediate risk."},
        )
        blank_rationale = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={
                **request,
                "rationale": "   ",
                "expirationDate": (NOW + timedelta(days=30)).date().isoformat(),
            },
        )
        accepted = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={
                **request,
                "rationale": "Compensating controls reduce the immediate risk.",
                "reviewDate": (NOW + timedelta(days=30)).date().isoformat(),
            },
        )

    assert missing_rationale.status_code == 422
    assert missing_rationale.json()["detail"]["code"] == "invalid_disposition"
    assert missing_date.status_code == 422
    assert missing_date.json()["detail"]["code"] == "invalid_disposition"
    assert blank_rationale.status_code == 422
    assert blank_rationale.json()["detail"]["code"] == "invalid_disposition"
    assert accepted.status_code == 201
    assert accepted.json() == {
        "id": accepted.json()["id"],
        "investigationId": str(investigation_id),
        "investigationRevisionId": str(revision.id),
        "exposureId": str(exposure.id),
        "assetSnapshotId": str(exposure.asset_snapshot_id),
        "kind": "accept_risk",
        "author": "AppSec reviewer",
        "rationale": "Compensating controls reduce the immediate risk.",
        "expirationDate": None,
        "reviewDate": (NOW + timedelta(days=30)).date().isoformat(),
        "createdAt": accepted.json()["createdAt"],
    }

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        other_kinds = [
            client.post(
                f"/api/v1/investigations/{investigation_id}/dispositions",
                json={
                    **request,
                    "kind": kind,
                    "rationale": "Human review completed.",
                    "reviewDate": (NOW + timedelta(days=30)).date().isoformat(),
                },
            )
            for kind in ("remediate", "monitor", "not_affected", "request_more_evidence")
        ]

    assert [response.status_code for response in other_kinds] == [201, 201, 201, 201]
    assert [response.json()["kind"] for response in other_kinds] == [
        "remediate",
        "monitor",
        "not_affected",
        "request_more_evidence",
    ]
    assert all(response.json()["reviewDate"] is not None for response in other_kinds)


def test_investigation_history_keeps_recommendations_and_dispositions_distinct(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    first = _revision(exposure)
    repository.append(first)
    second = replace(
        first,
        id=uuid4(),
        recommendation=replace(
            first.recommendation,
            recommendation=Recommendation.MONITOR,
            summary="Monitor the captured Exposure for updated maintainer guidance.",
        ),
        configuration=replace(first.configuration, prompt_version="claims-recommendation-v2"),
        created_at=NOW + timedelta(minutes=1),
    )
    repository.append(second)
    investigation_id = repository.list_for_exposure(exposure.id)[0].investigation_id
    app = create_app(
        Settings(
            database_url=database_url,
            enable_local_dispositions=True,
            local_operator="AppSec reviewer",
        )
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        disposition = client.post(
            f"/api/v1/investigations/{investigation_id}/dispositions",
            json={
                "investigationRevisionId": str(first.id),
                "kind": "remediate",
                "rationale": "The published fixed version is approved for rollout.",
            },
        )
        history = client.get(f"/api/v1/exposures/{exposure.id}/investigation")

    assert disposition.status_code == 201
    assert history.status_code == 200
    payload = history.json()
    assert payload["investigationId"] == str(investigation_id)
    assert payload["exposureId"] == str(exposure.id)
    assert payload["assetSnapshotId"] == str(exposure.asset_snapshot_id)
    assert [item["revisionNumber"] for item in payload["revisions"]] == [2, 1]
    assert [item["recommendation"]["value"] for item in payload["revisions"]] == [
        "monitor",
        "planned_remediation",
    ]
    assert payload["revisions"][0]["configuration"]["promptVersion"] == ("claims-recommendation-v2")
    assert payload["dispositions"][0]["kind"] == "remediate"
    assert "recommendation" not in payload["dispositions"][0]


def test_concurrent_dispositions_append_without_mutating_prior_decisions(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    revision = _revision(exposure)
    repository.append(revision)
    investigation_id = repository.list_for_exposure(exposure.id)[0].investigation_id
    dispositions = tuple(
        Disposition(
            id=uuid4(),
            investigation_id=investigation_id,
            investigation_revision_id=revision.id,
            exposure_id=exposure.id,
            asset_snapshot_id=exposure.asset_snapshot_id,
            kind=kind,
            author=author,
            rationale=rationale,
            expiration_date=None,
            review_date=None,
            created_at=NOW + timedelta(seconds=offset),
        )
        for offset, kind, author, rationale in (
            (1, DispositionKind.REMEDIATE, "Reviewer A", "Schedule the fixed release."),
            (2, DispositionKind.MONITOR, "Reviewer B", "Watch for updated guidance."),
        )
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        appended = tuple(executor.map(repository.append_disposition, dispositions))

    assert set(appended) == set(dispositions)
    assert {item.id for item in repository.list_dispositions(investigation_id)} == {
        item.id for item in dispositions
    }
    with (
        psycopg.connect(database_url) as connection,
        pytest.raises(psycopg.errors.RaiseException, match="Dispositions are append-only"),
    ):
        connection.execute(
            "UPDATE dispositions SET rationale = 'changed' WHERE id = %s",
            (dispositions[0].id,),
        )


def test_concurrent_reassessments_append_separate_revision_numbers(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    revisions = (
        _revision(exposure, created_at=NOW),
        _revision(exposure, created_at=NOW + timedelta(seconds=1)),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        appended = tuple(executor.map(repository.append, revisions))

    assert set(appended) == set(revisions)
    records = repository.list_for_exposure(exposure.id)
    assert {record.revision.id for record in records} == {revision.id for revision in revisions}
    assert {record.revision_number for record in records} == {1, 2}


def test_dispositions_do_not_carry_to_a_new_environment_profile(database_url: str) -> None:
    first_exposure = _seed_exposure(database_url)
    repository = InvestigationRepository(database_url)
    first_revision = _revision(first_exposure)
    repository.append(first_revision)
    first_investigation_id = repository.list_for_exposure(first_exposure.id)[0].investigation_id
    repository.append_disposition(
        Disposition(
            id=uuid4(),
            investigation_id=first_investigation_id,
            investigation_revision_id=first_revision.id,
            exposure_id=first_exposure.id,
            asset_snapshot_id=first_exposure.asset_snapshot_id,
            kind=DispositionKind.NOT_AFFECTED,
            author="AppSec reviewer",
            rationale="The affected feature is not enabled in this Environment Profile.",
            expiration_date=None,
            review_date=None,
            created_at=NOW,
        )
    )

    next_request = repository_payload()
    next_request["environmentProfile"] = {
        **next_request["environmentProfile"],  # type: ignore[dict-item]
        "architecture": "aarch64",
    }
    app = create_app(
        Settings(
            database_url=database_url,
            enable_local_dispositions=True,
            local_operator="AppSec reviewer",
        )
    )
    with TestClient(app) as client:
        next_run = client.post("/api/v1/assessment-runs", json=next_request).json()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
    )
    next_exposure = ExposureRepository(database_url).list_for_assessment(next_run["id"])[0]
    next_revision = _revision(next_exposure, created_at=NOW + timedelta(minutes=1))
    repository.append(next_revision)

    with TestClient(app) as client:
        history = client.get(f"/api/v1/exposures/{next_exposure.id}/investigation")

    assert next_exposure.asset_snapshot_id != first_exposure.asset_snapshot_id
    assert next_exposure.id != first_exposure.id
    assert history.status_code == 200
    assert history.json()["dispositions"] == []

    with TestClient(app) as client:
        carried = client.post(
            f"/api/v1/investigations/{history.json()['investigationId']}/dispositions",
            json={
                "investigationRevisionId": str(next_revision.id),
                "assetSnapshotId": str(first_exposure.asset_snapshot_id),
                "kind": "not_affected",
                "rationale": "Attempted carry-forward.",
            },
        )
    assert carried.status_code == 422
    assert carried.json()["detail"][0]["type"] == "extra_forbidden"
    with (
        psycopg.connect(database_url) as connection,
        pytest.raises(
            psycopg.errors.RaiseException,
            match="Disposition is outside the reviewed Revision scope",
        ),
    ):
        connection.execute(
            """
            INSERT INTO dispositions (
                id, investigation_id, investigation_revision_id, exposure_id,
                asset_snapshot_id, kind, author, rationale, created_at
            ) VALUES (%s, %s, %s, %s, %s, 'monitor', 'Reviewer', NULL, %s)
            """,
            (
                uuid4(),
                UUID(history.json()["investigationId"]),
                next_revision.id,
                next_exposure.id,
                first_exposure.asset_snapshot_id,
                NOW,
            ),
        )


def test_revision_append_is_fenced_by_the_current_assessment_claim(database_url: str) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    current_claim = uuid4()
    stale_claim = uuid4()
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            UPDATE assessment_runs
            SET status = 'running', completed_at = NULL,
                claimed_at = %s, claim_id = %s
            WHERE id = %s
            """,
            (NOW, current_claim, exposure.assessment_run_id),
        )

    with pytest.raises(RuntimeError, match="claim was lost"):
        InvestigationRepository(
            database_url,
            assessment_claim_id=stale_claim,
        ).append(revision)

    assert InvestigationRepository(database_url).list_for_exposure(exposure.id) == []
    assert (
        InvestigationRepository(
            database_url,
            assessment_claim_id=current_claim,
        ).append(revision)
        == revision
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


def test_revision_rejects_contradictory_status_and_stopping_condition(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)

    with pytest.raises(ValueError, match="Complete Revision status"):
        replace(revision, status=InvestigationRevisionStatus.INCOMPLETE)


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


def test_revision_persists_when_budget_expires_before_evidence_acquisition(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    incomplete = replace(
        revision,
        status=InvestigationRevisionStatus.INCOMPLETE,
        stopping_condition="wall_time_budget_exhausted",
        stopping_reason="The Investigation wall-time budget was exhausted.",
        evidence_state=InvestigationEvidenceState(
            available=(),
            retrieved=RetrievedInvestigationEvidence(query="", passages=()),
            material_claims_supported=False,
            authoritative_conflict=None,
            validation_issues=(),
        ),
        claims=(),
        recommendation=RevisionRecommendation(
            recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
            accepted=False,
            reason="wall_time_budget_exhausted",
            summary="More evidence is required before a Recommendation can be supported.",
            reasons=("wall_time_budget_exhausted",),
            limitations=(),
        ),
        measurements=replace(
            revision.measurements,
            generation_model_calls=0,
            tool_calls=0,
            graph_transitions=0,
        ),
    )

    repository = InvestigationRepository(database_url)
    assert repository.append(incomplete) == incomplete
    assert repository.list_for_exposure(exposure.id)[0].revision == incomplete


def test_revision_rejects_unknown_conflict_after_evidence_acquisition(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)

    with pytest.raises(ValueError, match="unknown only when evidence acquisition was skipped"):
        InvestigationRepository(database_url).append(
            replace(
                revision,
                evidence_state=replace(
                    revision.evidence_state,
                    authoritative_conflict=None,
                ),
            )
        )


def test_revision_rejects_known_conflict_when_evidence_acquisition_was_skipped(
    database_url: str,
) -> None:
    exposure = _seed_exposure(database_url)
    revision = _revision(exposure)
    skipped = replace(
        revision,
        status=InvestigationRevisionStatus.INCOMPLETE,
        stopping_condition="graph_transition_budget_exhausted",
        stopping_reason="The graph-transition budget was exhausted.",
        evidence_state=InvestigationEvidenceState(
            available=(),
            retrieved=RetrievedInvestigationEvidence(query="", passages=()),
            material_claims_supported=False,
            authoritative_conflict=False,
            validation_issues=(),
        ),
        claims=(),
        recommendation=replace(
            revision.recommendation,
            recommendation=Recommendation.MORE_EVIDENCE_REQUIRED,
            accepted=False,
            reason="graph_transition_budget_exhausted",
        ),
    )

    with pytest.raises(ValueError, match="must be unknown"):
        InvestigationRepository(database_url).append(skipped)


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


def test_controlled_adapters_execute_one_persisted_follow_up_per_exposure(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    provider = ControlledFollowUpGenerationProvider()
    assert process_next_assessment(
        database_url=database_url,
        archive_source=FixtureArchiveSource(),
        osv_source=CapturedOsvSource(),
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
        embedding_provider=KnownAnswerEmbeddingProvider(),
        generation_provider=provider,
    )

    revisions = InvestigationRepository(database_url).list_for_assessment(run["id"])
    assert len(revisions) == 2
    assert all(item.revision.follow_up is not None for item in revisions)
    assert all(item.revision.follow_up and item.revision.follow_up.executed for item in revisions)
    assert all(item.revision.measurements.generation_model_calls == 2 for item in revisions)
    assert all(item.revision.measurements.tool_calls == 3 for item in revisions)
    assert all(item.revision.measurements.graph_transitions == 11 for item in revisions)
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            """
            SELECT count(*) FROM policy_decisions
            WHERE assessment_run_id = %s
              AND enforcement_point = 'tool_call'
              AND target_scope LIKE 'exposure:%%'
            """,
            (run["id"],),
        ).fetchone() == (2,)


def test_worker_and_api_restart_resume_investigations_from_postgres_checkpoints(
    database_url: str,
) -> None:
    app = create_app(Settings(database_url=database_url))
    with TestClient(app) as client:
        run = client.post("/api/v1/assessment-runs", json=repository_payload()).json()

    archive_source = CountingArchiveSource()
    osv_source = CapturedOsvSource()
    interrupted_provider = InterruptDuringFollowUpGenerationProvider()
    with pytest.raises(
        KeyboardInterrupt,
        match="simulated worker interruption at a graph checkpoint",
    ):
        process_next_assessment(
            database_url=database_url,
            archive_source=archive_source,
            osv_source=osv_source,
            kev_source=CapturedKevSource(),
            epss_source=CapturedEpssSource(),
            embedding_provider=KnownAnswerEmbeddingProvider(),
            generation_provider=interrupted_provider,
        )

    with psycopg.connect(database_url) as connection:
        connection.execute(
            "UPDATE assessment_runs SET claimed_at = now() - interval '1 minute' WHERE id = %s",
            (run["id"],),
        )
        connection.commit()

    with TestClient(create_app(Settings(database_url=database_url))) as interrupted_client:
        interrupted_events = interrupted_client.get(
            f"/api/v1/assessment-runs/{run['id']}/events?follow=false"
        )
    interrupted_ids = [
        int(line.removeprefix("id: "))
        for line in interrupted_events.text.splitlines()
        if line.startswith("id: ")
    ]
    assert interrupted_ids
    reconnect_after = interrupted_ids[-1]

    resumed_provider = ControlledFollowUpGenerationProvider()
    assert process_next_assessment(
        database_url=database_url,
        stale_after_seconds=1,
        archive_source=archive_source,
        osv_source=osv_source,
        kev_source=CapturedKevSource(),
        epss_source=CapturedEpssSource(),
        embedding_provider=KnownAnswerEmbeddingProvider(),
        generation_provider=resumed_provider,
    )

    with psycopg.connect(database_url) as connection:
        operation_states = connection.execute(
            "SELECT status, error_code, error_message FROM investigation_operations "
            "WHERE assessment_run_id = %s ORDER BY exposure_id",
            (run["id"],),
        ).fetchall()
    assert operation_states == [("completed", None, None), ("completed", None, None)]
    assert archive_source.calls == 1
    assert len(osv_source.batches) == 1
    assert sorted(resumed_provider._calls_by_exposure.values()) == [1, 2]
    revisions = InvestigationRepository(database_url).list_for_assessment(run["id"])
    assert len(revisions) == 2
    assert {record.revision.stopping_condition for record in revisions} == {
        InvestigationStoppingCondition.COMPLETED,
        InvestigationStoppingCondition.FOLLOW_UP_LIMIT_REACHED,
    }
    progress_events = [
        event
        for event in AssessmentRunRepository(database_url).list_events(UUID(run["id"]), after=0)
        if event.event_type == "investigation.progress"
    ]
    assert len(progress_events) == sum(len(record.revision.events) for record in revisions)
    progress_by_operation_and_stage = {
        (event.payload["operationId"], event.payload["stage"]): event for event in progress_events
    }
    for record in revisions:
        for event in record.revision.events:
            persisted = progress_by_operation_and_stage[(str(record.revision.id), event.stage)]
            assert persisted.occurred_at == event.occurred_at
    with psycopg.connect(database_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM investigation_operations WHERE assessment_run_id = %s "
            "AND status = 'completed'",
            (run["id"],),
        ).fetchone() == (2,)
        assert connection.execute("SELECT count(*) FROM checkpoints").fetchone()[0] > 0

    with TestClient(create_app(Settings(database_url=database_url))) as restarted_client:
        response = restarted_client.get(
            f"/api/v1/assessment-runs/{run['id']}/events?follow=false",
            headers={"Last-Event-ID": str(reconnect_after)},
        )

    assert response.status_code == 200
    resumed_ids = [
        int(line.removeprefix("id: "))
        for line in response.text.splitlines()
        if line.startswith("id: ")
    ]
    assert resumed_ids
    assert interrupted_ids + resumed_ids == list(range(1, resumed_ids[-1] + 1))
    assert all(event_id > reconnect_after for event_id in resumed_ids)
