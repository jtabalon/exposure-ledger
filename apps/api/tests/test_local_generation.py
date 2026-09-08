from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest
from exposure_ledger import (
    AvailableEvidence,
    EmbeddingSpace,
    GenerationModel,
    InvestigationConfiguration,
    InvestigationExposure,
    Recommendation,
    RetrievedInvestigationEvidence,
    RetrievedInvestigationPassage,
)
from exposure_ledger_worker.local_generation import (
    GENERATION_PROMPT_VERSION,
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
        prompt_version=GENERATION_PROMPT_VERSION,
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


def _structured_output(evidence_record_id: str = str(EVIDENCE_ID)) -> dict[str, object]:
    return {
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
                        "evidenceRecordId": evidence_record_id,
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


def test_generation_requests_use_the_remaining_investigation_timeout() -> None:
    request_timeouts: list[float] = []
    now = 10.0

    def monotonic() -> float:
        nonlocal now
        current = now
        now = 10.25
        return current

    def handler(request: httpx.Request) -> httpx.Response:
        timeout = request.extensions["timeout"]
        assert isinstance(timeout, dict)
        request_timeouts.append(float(timeout["read"]))
        return httpx.Response(200, json={"models": []})

    readiness = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
        monotonic=monotonic,
    ).check_readiness(timeout_seconds=1)

    assert readiness.code == "generation_model_not_installed"
    assert request_timeouts == [0.75]


@pytest.mark.asyncio
async def test_generation_readiness_cancels_at_the_absolute_wall_time() -> None:
    cancelled = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        try:
            await asyncio.sleep(1)
        finally:
            cancelled.set()
        return httpx.Response(200, json={"models": []})

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    readiness = await provider.check_readiness_bounded(timeout_seconds=0.01)

    assert readiness.code == "generation_wall_time_budget_exhausted"
    assert cancelled.is_set()


def test_generation_returns_only_validated_structured_output_without_reasoning() -> None:
    chat_requests: list[dict[str, object]] = []
    structured = _structured_output()

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
    assert GENERATION_PROMPT_VERSION == "claims-recommendation-follow-up-v4-gptoss-low"
    assert request["think"] == "low"
    assert request["options"] == {"temperature": 0, "seed": 0}
    assert request["format"] == OllamaGenerationProvider.output_schema()
    assert "tools" not in request
    messages = request["messages"]
    assert isinstance(messages, list)
    assert "untrusted data" in str(messages[0]).lower()


@pytest.mark.parametrize(
    "content",
    [
        '{"claims":[]}',
        json.dumps(_structured_output("not-a-uuid")),
        json.dumps({**_structured_output(), "operation": "exposure_recommendation"}),
        json.dumps({**_structured_output(), "thinking": "unexpected extra field"}),
    ],
    ids=["missing-fields", "invalid-evidence-uuid", "invalid-operation", "extra-field"],
)
def test_invalid_structured_output_fails_closed(content: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": content}, "done": True},
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
    "prior_version",
    ["claims-recommendation-follow-up-v2", "claims-recommendation-follow-up-v3-gptoss-low"],
)
def test_generation_rejects_the_prior_prompt_version_before_chat(prior_version: str) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        assert request.url.path == "/api/show"
        return httpx.Response(200, json=_show_response())

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )
    configuration = replace(_configuration(), prompt_version=prior_version)

    with pytest.raises(GenerationProviderUnavailable) as caught:
        provider.generate(_exposure(), _evidence(), configuration)

    assert caught.value.readiness.code == "generation_prompt_not_current"
    assert paths == ["/api/tags", "/api/show"]


@pytest.mark.parametrize(
    ("changed_inventory", "expected_code", "expected_paths"),
    [
        (1, "generation_model_not_current", ["/api/tags", "/api/show"]),
        (
            2,
            "generation_artifact_changed",
            ["/api/tags", "/api/show", "/api/chat", "/api/tags", "/api/show"],
        ),
    ],
    ids=["before-generation", "during-generation"],
)
def test_generation_enforces_the_pinned_digest(
    changed_inventory: int, expected_code: str, expected_paths: list[str]
) -> None:
    inventory_count = 0
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal inventory_count
        paths.append(request.url.path)
        if request.url.path == "/api/tags":
            inventory_count += 1
            digest = "d" * 64 if inventory_count >= changed_inventory else DIGEST
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": digest}]})
        if request.url.path == "/api/show":
            digest = "d" * 64 if inventory_count >= changed_inventory else DIGEST
            return httpx.Response(200, json=_show_response(digest))
        assert request.url.path == "/api/chat"
        return httpx.Response(
            200, json={"message": {"content": json.dumps(_structured_output())}, "done": True}
        )

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GenerationProviderUnavailable) as caught:
        provider.generate(_exposure(), _evidence(), _configuration())

    assert caught.value.readiness.code == expected_code
    assert caught.value.readiness.model is None
    assert paths == expected_paths


def test_generation_shares_one_deadline_with_preflight_and_postflight_inventory() -> None:
    now = 10.0
    requests: list[tuple[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal now
        timeout = request.extensions["timeout"]
        assert isinstance(timeout, dict)
        requests.append((request.url.path, float(timeout["read"])))
        now += 0.125
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        assert request.url.path == "/api/chat"
        return httpx.Response(
            200, json={"message": {"content": json.dumps(_structured_output())}, "done": True}
        )

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
        monotonic=lambda: now,
    )

    draft = provider.generate(_exposure(), _evidence(), _configuration(), timeout_seconds=1)

    assert draft.recommendation is Recommendation.PLANNED_REMEDIATION
    assert requests == [
        ("/api/tags", 1.0),
        ("/api/show", 0.875),
        ("/api/chat", 0.75),
        ("/api/tags", 0.625),
        ("/api/show", 0.5),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_request", [0, 2, 4], ids=["preflight", "chat", "postflight"])
async def test_generation_cancels_before_returning_output_when_the_deadline_expires(
    blocked_request: int,
) -> None:
    cancelled = asyncio.Event()
    paths: list[str] = []
    expected_paths = ["/api/tags", "/api/show", "/api/chat", "/api/tags", "/api/show"]

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if len(paths) - 1 == blocked_request:
            try:
                await asyncio.sleep(1)
            finally:
                cancelled.set()
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        assert request.url.path == "/api/chat"
        return httpx.Response(
            200, json={"message": {"content": json.dumps(_structured_output())}, "done": True}
        )

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GenerationProviderUnavailable) as caught:
        await provider.generate_bounded(
            _exposure(), _evidence(), _configuration(), timeout_seconds=0.05
        )

    assert caught.value.readiness.code == "generation_wall_time_budget_exhausted"
    assert cancelled.is_set()
    assert paths == expected_paths[: blocked_request + 1]


def test_generation_with_an_exhausted_budget_fails_before_any_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("No runtime request is permitted after the Investigation deadline.")

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(GenerationProviderUnavailable) as caught:
        provider.generate(_exposure(), _evidence(), _configuration(), timeout_seconds=0)

    assert caught.value.readiness.code == "generation_wall_time_budget_exhausted"


def test_generation_parses_one_enumerated_evidence_gap_follow_up() -> None:
    structured = {
        "operation": "produce_exposure_recommendation",
        "claims": [
            {
                "identity": "claim-affected",
                "kind": "fact",
                "text": "Feature-lib 5.1.0 may be inside the affected range.",
                "material": True,
                "limitation": None,
                "citations": [
                    {
                        "evidenceRecordId": str(EVIDENCE_ID),
                        "passageIdentities": ["osv:affected"],
                        "relationship": "contextual",
                    }
                ],
            }
        ],
        "recommendation": "more_evidence_required",
        "recommendationSummary": "Retrieve a focused affected-range passage.",
        "recommendationReasons": ["Affected-range support is insufficient."],
        "recommendationLimitations": [],
        "evidenceGap": {
            "identity": "gap-affected-range",
            "kind": "insufficient",
            "description": "The affected range needs focused support.",
        },
        "followUp": {
            "tool": "search_captured_exposure_evidence",
            "target": "exposure:00000000-0000-0000-0000-000000000042",
            "arguments": {"sourceIdentity": "osv", "evidenceType": "affected"},
            "assistanceClass": "C1",
            "actionLevel": "A1",
        },
    }
    chat_payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": MODEL, "digest": DIGEST}]})
        if request.url.path == "/api/show":
            return httpx.Response(200, json=_show_response())
        chat_payloads.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": json.dumps(structured)}},
        )

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )
    exposure = replace(
        _exposure(),
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

    draft = provider.generate(exposure, _evidence(), _configuration())

    assert draft.evidence_gap is not None
    assert draft.evidence_gap.kind == "insufficient"
    assert draft.follow_up is not None
    assert draft.follow_up.tool == "search_captured_exposure_evidence"
    messages = chat_payloads[0]["messages"]
    assert isinstance(messages, list)
    user_payload = json.loads(messages[1]["content"])
    assert user_payload["allowedFollowUp"] == {
        "actionLevel": "A1",
        "assistanceClass": "C1",
        "evidenceGapKinds": ["missing", "insufficient", "stale", "conflicting"],
        "evidenceTypes": [
            "affected",
            "affected_guidance",
            "epss_score",
            "known_exploited_vulnerability",
            "publication",
            "query_result",
        ],
        "maximumProposals": 1,
        "sourceIdentities": ["osv"],
        "target": "exposure:00000000-0000-0000-0000-000000000042",
        "tool": "search_captured_exposure_evidence",
    }


@pytest.mark.parametrize(
    "base_url",
    ["https://localhost:11434", "http://ollama.example.com", "http://user@localhost:11434"],
)
def test_generation_rejects_nonlocal_or_authenticated_runtimes(base_url: str) -> None:
    with pytest.raises(ValueError, match="unauthenticated HTTP loopback"):
        OllamaGenerationProvider(base_url=base_url, model_artifact=MODEL)


@pytest.mark.parametrize("model_artifact", ["gpt-oss:20b-cloud", "gpt-oss:cloud"])
def test_generation_rejects_explicit_cloud_artifacts(model_artifact: str) -> None:
    with pytest.raises(ValueError, match="must not select an Ollama cloud model"):
        OllamaGenerationProvider(base_url="http://localhost:11434", model_artifact=model_artifact)


@pytest.mark.parametrize("remote_field", ["remote_model", "remote_host"])
@pytest.mark.parametrize("remote_location", ["/api/tags", "/api/show"])
def test_generation_readiness_rejects_remote_inventory_before_chat(
    remote_field: str, remote_location: str
) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        remote = {remote_field: "remote-artifact"} if request.url.path == remote_location else {}
        if request.url.path == "/api/tags":
            return httpx.Response(
                200, json={"models": [{"name": MODEL, "digest": DIGEST, **remote}]}
            )
        assert request.url.path == "/api/show"
        return httpx.Response(200, json={**_show_response(), **remote})

    provider = OllamaGenerationProvider(
        base_url="http://localhost:11434",
        model_artifact=MODEL,
        transport=httpx.MockTransport(handler),
    )

    readiness = provider.check_readiness()

    assert readiness.code == "generation_cloud_model_rejected"
    assert readiness.model is None
    assert paths == (
        ["/api/tags"] if remote_location == "/api/tags" else ["/api/tags", "/api/show"]
    )
