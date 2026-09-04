from __future__ import annotations

import json

import httpx
import pytest
from exposure_ledger_storage import (
    EmbeddingProviderUnavailable,
    OllamaEmbeddingProvider,
)


def test_local_provider_pins_space_and_applies_the_versioned_query_instruction() -> None:
    requests: list[tuple[str, str, dict[str, object] | None]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content) if request.content else None
        requests.append((request.method, request.url.path, payload))
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "qwen3-embedding:0.6b",
                            "digest": "a" * 64,
                        }
                    ]
                },
            )
        if request.url.path == "/api/show":
            return httpx.Response(
                200,
                json={
                    "capabilities": ["embedding"],
                    "model_info": {"qwen3embedding.embedding_length": 3},
                },
            )
        if request.url.path == "/api/embed":
            return httpx.Response(200, json={"embeddings": [[3.0, 0.0, 4.0]]})
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = OllamaEmbeddingProvider(
        base_url="http://localhost:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(respond),
    )

    readiness = provider.check_readiness()
    assert readiness.status == "ready"
    assert readiness.space is not None
    assert readiness.space.provider == "ollama-local"
    assert readiness.space.model_artifact == "qwen3-embedding:0.6b"
    assert readiness.space.artifact_digest == "sha256:" + "a" * 64
    assert readiness.space.dimensions == 3
    assert readiness.space.normalizer == "l2-v1"
    assert readiness.space.passage_construction_version == "source-aware-passage-v1"

    assert provider.embed_query("patched release", readiness.space) == (0.6, 0.0, 0.8)
    embed_payload = next(payload for _, path, payload in requests if path == "/api/embed")
    assert embed_payload == {
        "model": "qwen3-embedding:0.6b",
        "input": readiness.space.retrieval_instruction + "patched release",
        "truncate": False,
        "dimensions": 3,
    }


def test_missing_local_artifact_has_explicit_setup_and_never_calls_embed() -> None:
    paths: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"models": []})

    provider = OllamaEmbeddingProvider(
        base_url="http://127.0.0.1:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(respond),
    )

    readiness = provider.check_readiness()
    assert readiness.status == "unavailable"
    assert readiness.code == "embedding_model_not_installed"
    assert readiness.setup == "Run `ollama pull qwen3-embedding:0.6b`, then retry."
    assert readiness.space is None
    with pytest.raises(EmbeddingProviderUnavailable, match="not installed"):
        provider.require_space()
    assert paths == ["/api/tags", "/api/tags"]


def test_local_provider_rejects_hosted_or_cloud_configuration() -> None:
    with pytest.raises(ValueError, match="loopback"):
        OllamaEmbeddingProvider(
            base_url="https://ollama.com",
            model_artifact="qwen3-embedding:0.6b",
        )
    with pytest.raises(ValueError, match="cloud model"):
        OllamaEmbeddingProvider(
            base_url="http://localhost:11434",
            model_artifact="qwen3-embedding:cloud",
        )
    with pytest.raises(ValueError, match="cloud model"):
        OllamaEmbeddingProvider(
            base_url="http://localhost:11434",
            model_artifact="gpt-oss:120b-cloud",
        )


def test_local_provider_rejects_remote_inventory_entries() -> None:
    provider = OllamaEmbeddingProvider(
        base_url="http://localhost:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "qwen3-embedding:0.6b",
                            "digest": "a" * 64,
                            "remote_model": "qwen3-embedding:0.6b",
                            "remote_host": "https://ollama.com",
                        }
                    ]
                },
            )
        ),
    )

    readiness = provider.check_readiness()

    assert readiness.status == "unavailable"
    assert readiness.code == "embedding_cloud_model_rejected"
    assert readiness.space is None


def test_local_provider_discards_vectors_when_artifact_digest_changes_during_generation() -> None:
    tag_calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal tag_calls
        if request.url.path == "/api/tags":
            tag_calls += 1
            digest = ("a" if tag_calls < 3 else "b") * 64
            return httpx.Response(
                200,
                json={"models": [{"name": "qwen3-embedding:0.6b", "digest": digest}]},
            )
        if request.url.path == "/api/show":
            return httpx.Response(
                200,
                json={
                    "capabilities": ["embedding"],
                    "model_info": {"qwen3embedding.embedding_length": 3},
                },
            )
        if request.url.path == "/api/embed":
            return httpx.Response(200, json={"embeddings": [[1.0, 0.0, 0.0]]})
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = OllamaEmbeddingProvider(
        base_url="http://localhost:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(respond),
    )
    space = provider.require_space()

    with pytest.raises(EmbeddingProviderUnavailable, match="changed during embedding generation"):
        provider.embed_query("patched release", space)
