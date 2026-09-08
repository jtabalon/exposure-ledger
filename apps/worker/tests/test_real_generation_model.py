"""Opt-in contract check for the explicitly installed local generation artifact."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from time import monotonic
from uuid import UUID

import httpx
import pytest
from exposure_ledger import (
    AssessmentOperation,
    AvailableEvidence,
    ClaimValidator,
    EmbeddingSpace,
    GenerationModel,
    InvestigationBudget,
    InvestigationConfiguration,
    InvestigationExposure,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
)
from exposure_ledger_worker.local_generation import (
    GENERATION_PROMPT_VERSION,
    GenerationProviderUnavailable,
    OllamaGenerationProvider,
)
from exposure_ledger_worker.main import WorkerSettings

pytestmark = pytest.mark.real_model


def _model_residency(base_url: str, model: GenerationModel) -> str:
    """Observe residency without loading, unloading, or retaining generation content."""
    try:
        with httpx.Client(base_url=base_url, timeout=5, follow_redirects=False) as client:
            response = client.get("/api/ps")
            response.raise_for_status()
            inventory = response.json()
        if not isinstance(inventory, dict) or not isinstance(inventory.get("models"), list):
            return "unknown"
        for item in inventory["models"]:
            if not isinstance(item, dict):
                return "unknown"
            if model.model_artifact in (item.get("name"), item.get("model")):
                return (
                    "loaded"
                    if item.get("digest") == model.artifact_digest.removeprefix("sha256:")
                    else "unknown"
                )
        return "unloaded"
    except (httpx.HTTPError, ValueError):
        return "unknown"


def test_installed_local_generation_model_satisfies_structured_claim_contract() -> None:
    if os.environ.get("EXPOSURE_LEDGER_RUN_REAL_MODEL_CHECK") != "1":
        pytest.skip("run `make check-real-model` after the explicit `make models` setup step")

    settings = WorkerSettings()
    budget_seconds = InvestigationBudget().wall_time_seconds
    provider = OllamaGenerationProvider(
        base_url=settings.ollama_base_url,
        model_artifact=settings.generation_model,
    )
    started = monotonic()
    readiness = provider.check_readiness(timeout_seconds=budget_seconds)
    print(
        json.dumps(
            {
                "phase": "readiness",
                "model_artifact": settings.generation_model,
                "prompt_version": GENERATION_PROMPT_VERSION,
                "wall_seconds": round(monotonic() - started, 3),
                "outcome": readiness.code or readiness.status,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if readiness.model is None:
        pytest.fail(f"{readiness.code}: {readiness.setup or ''}".strip(), pytrace=False)

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
        graph_version="bounded-investigation-v2",
        prompt_version=GENERATION_PROMPT_VERSION,
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

    # Stop the configured model explicitly before running this check to observe a cold
    # candidate. Residency is sampled, not guaranteed: other local clients may load or
    # evict it. Each generation has its own unchanged absolute Investigation limit.
    for phase in ("cold_candidate", "warm_candidate"):
        residency = _model_residency(settings.ollama_base_url, readiness.model)
        started = monotonic()
        outcome = "generation_failed"
        generation_wall_seconds: float | None = None
        try:
            draft = provider.generate(
                exposure, retrieved, configuration, timeout_seconds=budget_seconds
            )
        except GenerationProviderUnavailable as error:
            outcome = error.readiness.code or "generation_unavailable"
            # Adapter diagnostics can contain rejected model content. Report only the
            # typed outcome; never print exceptions, responses, drafts, or reasoning.
            pytest.fail(f"{phase}: {outcome}", pytrace=False)
        else:
            generation_wall_seconds = monotonic() - started
            validation = ClaimValidator.validate(
                claims=draft.claims,
                available_evidence=(evidence,),
                authoritative_conflict=False,
            )
            if draft.operation != AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION:
                outcome = "generation_operation_invalid"
            # A nonempty validation result alone can retain unsupported Claims and discard
            # invalid citations. Require every original citation and Claim to be accepted.
            elif (
                not draft.claims
                or not all(claim.citations for claim in draft.claims)
                or validation.issues
                or not validation.material_claims_supported
            ):
                outcome = "generation_claim_validation_failed"
            elif any(
                len(original.citations) != len(validated.citations)
                for original, validated in zip(draft.claims, validation.claims, strict=True)
            ):
                outcome = "generation_citation_discarded"
            else:
                outcome = "contract_passed"
            if outcome != "contract_passed":
                pytest.fail(f"{phase}: {outcome}", pytrace=False)
        finally:
            if generation_wall_seconds is None:
                generation_wall_seconds = monotonic() - started
            print(
                json.dumps(
                    {
                        "phase": phase,
                        "model_artifact": readiness.model.model_artifact,
                        "artifact_digest": readiness.model.artifact_digest,
                        "prompt_version": configuration.prompt_version,
                        "residency_before": residency,
                        "generation_wall_seconds": round(generation_wall_seconds, 3),
                        "budget_seconds": budget_seconds,
                        "outcome": outcome,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
