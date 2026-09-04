import httpx
from exposure_ledger_api.main import create_app
from exposure_ledger_storage import OllamaEmbeddingProvider
from fastapi.testclient import TestClient


def test_health_gives_explicit_local_embedding_setup_when_artifact_is_missing() -> None:
    provider = OllamaEmbeddingProvider(
        base_url="http://localhost:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"models": []})),
    )

    response = TestClient(create_app(embedding_provider=provider)).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "service": "exposure-ledger-api",
        "version": "0.1.0",
        "inference_mode": "local",
        "embeddings": {
            "status": "unavailable",
            "code": "embedding_model_not_installed",
            "message": "Local embedding artifact qwen3-embedding:0.6b is not installed.",
            "setup": "Run `ollama pull qwen3-embedding:0.6b`, then retry.",
            "space": None,
        },
    }
