import httpx
import psycopg
from exposure_ledger import GenerationModel, GenerationReadiness
from exposure_ledger_api.main import create_app
from exposure_ledger_api.settings import Settings
from exposure_ledger_storage import (
    EvidenceRetriever,
    InvestigationRepository,
    OllamaEmbeddingProvider,
)
from fastapi.testclient import TestClient


def test_health_gives_worker_observed_local_embedding_setup_when_artifact_is_missing(
    database_url: str,
) -> None:
    provider = OllamaEmbeddingProvider(
        base_url="http://localhost:11434",
        model_artifact="qwen3-embedding:0.6b",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"models": []})),
    )

    EvidenceRetriever(database_url).record_embedding_readiness(provider.check_readiness())
    InvestigationRepository(database_url).record_generation_readiness(
        GenerationReadiness(
            status="ready",
            code=None,
            message="The explicitly configured local generation artifact is ready.",
            setup=None,
            model=GenerationModel(
                provider="ollama-local",
                model_artifact="gpt-oss:20b",
                artifact_digest="sha256:" + "a" * 64,
            ),
        )
    )

    response = TestClient(create_app(Settings(database_url=database_url))).get("/health")

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
        "generation": {
            "status": "ready",
            "code": None,
            "message": "The explicitly configured local generation artifact is ready.",
            "setup": None,
            "model": {
                "provider": "ollama-local",
                "modelArtifact": "gpt-oss:20b",
                "artifactDigest": "sha256:" + "a" * 64,
            },
        },
    }


def test_health_rejects_stale_worker_embedding_observations(database_url: str) -> None:
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO embedding_provider_observations (
                singleton, observed_at, status, code, message, setup, embedding_space_id
            ) VALUES (
                true, now() - interval '1 hour', 'unavailable',
                'embedding_runtime_unavailable', 'old observation', 'old setup', NULL
            )
            """
        )
        connection.commit()

    response = TestClient(create_app(Settings(database_url=database_url))).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["embeddings"] == {
        "status": "unavailable",
        "code": "embedding_readiness_stale",
        "message": "The worker's local embedding readiness observation is stale.",
        "setup": "Check that the worker and Ollama are running, then retry.",
        "space": None,
    }


def test_health_reports_missing_local_generation_without_hosted_fallback(
    database_url: str,
) -> None:
    InvestigationRepository(database_url).record_generation_readiness(
        GenerationReadiness(
            status="unavailable",
            code="generation_model_not_installed",
            message="Local generation artifact gpt-oss:20b is not installed.",
            setup="Run `ollama pull gpt-oss:20b`, then retry.",
            model=None,
        )
    )

    response = TestClient(create_app(Settings(database_url=database_url))).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["inference_mode"] == "local"
    assert response.json()["generation"] == {
        "status": "unavailable",
        "code": "generation_model_not_installed",
        "message": "Local generation artifact gpt-oss:20b is not installed.",
        "setup": "Run `ollama pull gpt-oss:20b`, then retry.",
        "model": None,
    }


def test_health_preserves_missing_generation_setup_when_worker_observation_is_stale(
    database_url: str,
) -> None:
    InvestigationRepository(database_url).record_generation_readiness(
        GenerationReadiness(
            status="unavailable",
            code="generation_model_not_installed",
            message="Local generation artifact gpt-oss:20b is not installed.",
            setup="Run `ollama pull gpt-oss:20b`, then retry.",
            model=None,
        )
    )
    with psycopg.connect(database_url) as connection:
        connection.execute(
            "UPDATE generation_provider_observations SET observed_at = now() - interval '1 hour'"
        )
        connection.commit()

    response = TestClient(create_app(Settings(database_url=database_url))).get("/health")

    assert response.json()["generation"]["code"] == "generation_readiness_stale"
    assert "gpt-oss:20b is not installed" in response.json()["generation"]["message"]
    assert "ollama pull gpt-oss:20b" in response.json()["generation"]["setup"]
