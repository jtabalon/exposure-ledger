"""Opt-in contract check for the explicitly installed local generation artifact."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID

import pytest
from exposure_ledger import (
    AssessmentOperation,
    AvailableEvidence,
    ClaimValidator,
    EmbeddingSpace,
    InvestigationConfiguration,
    InvestigationExposure,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
)
from exposure_ledger_worker.local_generation import OllamaGenerationProvider

pytestmark = pytest.mark.real_model


def test_installed_local_generation_model_satisfies_structured_claim_contract() -> None:
    if os.environ.get("EXPOSURE_LEDGER_RUN_REAL_MODEL_CHECK") != "1":
        pytest.skip("run `make check-real-model` after the explicit `make models` setup step")

    provider = OllamaGenerationProvider(
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        model_artifact=os.environ.get("GENERATION_MODEL", "gpt-oss:20b"),
    )
    readiness = provider.check_readiness()
    if readiness.model is None:
        pytest.fail(f"{readiness.message} {readiness.setup or ''}".strip())

    evidence_id = UUID("00000000-0000-0000-0000-000000000081")
    evidence = AvailableEvidence(
        record_id=evidence_id,
        record_identity="sha256:real-model-contract-evidence",
        content_digest="sha256:" + "c" * 64,
        source_identity="controlled-contract-source",
        source_adapter_version="controlled-contract-v1",
        passage_identities=("contract:affected",),
    )
    exposure = InvestigationExposure(
        assessment_run_id=UUID("00000000-0000-0000-0000-000000000013"),
        exposure_id=UUID("00000000-0000-0000-0000-000000000042"),
        asset_snapshot_id=UUID("00000000-0000-0000-0000-000000000007"),
        package_name="contract-fixture",
        package_version="1.0.0",
        vulnerability_aliases=("CVE-2099-0001",),
        authoritative_conflict=False,
        evidence=(evidence,),
    )
    retrieved = RetrievedInvestigationEvidence(
        query="contract-fixture 1.0.0 affected range",
        passages=(
            RetrievedInvestigationPassage(
                evidence_record_id=evidence_id,
                evidence_record_identity=evidence.record_identity,
                evidence_record_digest=evidence.content_digest,
                passage_identity="contract:affected",
                passage="Contract-fixture version 1.0.0 is in the published affected range.",
                source_identity="controlled-contract-source",
                source_authority="controlled authoritative fixture",
                source_location="fixture://real-model-contract",
                captured_at=datetime(2099, 1, 1, tzinfo=UTC),
                full_text_rank=1,
                full_text_score=1.0,
                vector_rank=1,
                vector_score=1.0,
                fused_rank=1,
                fused_score=1.0,
            ),
        ),
    )
    configuration = InvestigationConfiguration(
        application_release="0.1.0",
        graph_version="bounded-investigation-v1",
        prompt_version="claims-recommendation-follow-up-v2",
        policy_version="0.1",
        parser_version="uv-lock-v1",
        retrieval_configuration_version="postgres-hybrid-rrf-v1",
        source_policy_version="explicit-source-allowlist-v1",
        source_adapter_versions=("controlled-contract-source=controlled-contract-v1",),
        generation_model=readiness.model,
        embedding_space=EmbeddingSpace(
            provider="controlled-contract-local",
            model_artifact="controlled-contract-embedding-v1",
            artifact_digest="sha256:" + "a" * 64,
            dimensions=3,
            retrieval_instruction="Represent this query: ",
            normalizer="l2-v1",
            passage_construction_version="source-aware-passage-v1",
        ),
    )

    draft = provider.generate(exposure, retrieved, configuration)
    validation = ClaimValidator.validate(
        claims=draft.claims,
        available_evidence=(evidence,),
        authoritative_conflict=False,
    )

    assert draft.operation == AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION
    assert draft.claims
    assert validation.claims
