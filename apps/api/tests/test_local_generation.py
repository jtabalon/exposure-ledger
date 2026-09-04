from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest
from exposure_ledger import (
    EmbeddingSpace,
    GenerationModel,
    InvestigationConfiguration,
    InvestigationExposure,
    Recommendation,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
)
from exposure_ledger_worker.local_generation import (
    GenerationProviderUnavailable,
    OllamaGenerationProvider,
)

MODEL = "gpt-oss:20b"
DIGEST = "a" * 64
EVIDENCE_ID = UUID("00000000-0000-0000-0000-000000000081")


def _configuration() -> InvestigationConfiguration:
    return InvestigationConfiguration(
        application_release="0.1.0",
        graph_version="bounded-investigation-v1",
        prompt_version="claims-recommendation-v1",
        policy_version="0.1",
        parser_version="uv-lock-v1",
        retrieval_configuration_version="postgres-hybrid-rrf-v1",
        source_policy_version="explicit-source-allowlist-v1",
        source_adapter_versions=("osv=osv-v1",),
        generation_model=GenerationModel(
            provider="ollama-local",
            model_artifact=MODEL,
            artifact_digest=f"sha256:{DIGEST}",
        ),
        embedding_space=EmbeddingSpace(
            provider="known-answer-local",
            model_artifact="known-answer-embedding-v1",
            artifact_digest="sha256:" + "b" * 64,
            dimensions=3,
            retrieval_instruction="Represent this query: ",
            normalizer="l2-v1",
            passage_construction_version="source-aware-passage-v1",
        ),
    )


def _exposure() -> InvestigationExposure:
    return InvestigationExposure(
        assessment_run_id=UUID("00000000-0000-0000-0000-000000000013"),
        exposure_id=UUID("00000000-0000-0000-0000-000000000042"),
        asset_snapshot_id=UUID("00000000-0000-0000-0000-000000000007"),
        package_name="feature-lib",
        package_version="5.1.0",
        vulnerability_aliases=("CVE-2026-4000",),
        authoritative_conflict=False,
        evidence=(),
    )


def _evidence() -> RetrievedInvestigationEvidence:
    return RetrievedInvestigationEvidence(
        query="feature-lib 5.1.0 affected fixed upgrade",
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
                captured_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
                full_text_rank=1,
                full_text_score=0.9,
                vector_rank=1,
                vector_score=0.8,
                fused_rank=1,
                fused_score=0.03,
            ),
        ),
    )


def _show_response(digest: str = DIGEST) -> dict[str, object]:
    return {
        "details": {"family": "gptoss"},
        "capabilities": ["completion"],
        "model_info": {},
        "digest": digest,
    }


def test_generation_readiness_requires_an_explicitly_installed_local_artifact() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"models": []})

    readiness = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    ).check_readiness()

    assert readiness.status == "unavailable"
    assert readiness.code == "generation_model_not_installed"
    assert readiness.setup == f"Run `ollama pull {MODEL}`, then retry."
    assert readiness.model is None
    assert [(request.method, request.url.path) for request in requests] == [("GET", "/api/tags")]


def test_generation_returns_only_validated_structured_output_without_reasoning() -> None:
    chat_requests: list[dict[str, object]] = []
    structured = {
        "operation": "produce_exposure_recommendation",
        "claims": [
            {
                "identity": "claim-affected",
                "kind": "fact",
                "text": "Feature-lib 5.1.0 is within the published affected range.",
                "material": True,
                "limitation": None,
                "citations": [
                    {
                        "evidenceRecordId": str(EVIDENCE_ID),
                        "passageIdentities": ["osv:affected"],
                        "relationship": "supports",
                    }
                ],
            }
        ],
        "recommendation": "planned_remediation",
        "recommendationSummary": "Upgrade to the first published fixed version.",
        "recommendationReasons": ["The installed package is in the affected range."],
        "recommendationLimitations": ["Static analysis does not prove runtime reachability."],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        assert request.url.path == "/api/chat"
        payload = json.loads(request.content)
        chat_requests.append(payload)
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": json.dumps(structured),
                    "thinking": "private reasoning must be discarded",
                },
                "done": True,
            },
        )

    provider = OllamaGenerationProvider(
        base_url="http://127.0.0.1:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    draft = provider.generate(_exposure(), _evidence(), _configuration())

    assert draft.recommendation is Recommendation.PLANNED_REMEDIATION
    assert draft.claims[0].citations[0].evidence_record_id == EVIDENCE_ID
    assert not hasattr(draft, "thinking")
    assert len(chat_requests) == 1
    request = chat_requests[0]
    assert request["model"] == MODEL
    assert request["stream"] is False
    assert request["think"] is False
    assert request["format"] == OllamaGenerationProvider.output_schema()
    assert "tools" not in request
    messages = request["messages"]
    assert isinstance(messages, list)
    assert "untrusted data" in str(messages[0]).lower()


def test_invalid_structured_output_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": '{"claims":[]}'}, "done": True},
        )

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GenerationProviderUnavailable) as caught:
        provider.generate(_exposure(), _evidence(), _configuration())

    assert caught.value.readiness.code == "generation_invalid_structured_output"


@pytest.mark.parametrize(
    "base_url",
    ["https://localhost:11434", "http://ollama.example.com", "http://user@localhost:11434"],
)
def test_generation_rejects_nonlocal_or_authenticated_runtimes(base_url: str) -> None:
    with pytest.raises(ValueError, match="unauthenticated HTTP loopback"):
        OllamaGenerationProvider(base_url=base_url, model_artifact=MODEL)
