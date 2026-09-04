"""Explicitly configured local Ollama embeddings for the retrieval boundary."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlparse

import httpx
from exposure_ledger import EmbeddingSpace

EMBEDDING_PROVIDER = "ollama-local"
EMBEDDING_NORMALIZER = "l2-v1"
EMBEDDING_PASSAGE_CONSTRUCTION_VERSION = "source-aware-passage-v1"
EMBEDDING_RETRIEVAL_INSTRUCTION = (
    "Represent this cybersecurity query for evidence passage retrieval: "
)
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class EmbeddingReadiness:
    status: Literal["ready", "unavailable"]
    code: str | None
    message: str
    setup: str | None
    space: EmbeddingSpace | None


class EmbeddingProviderUnavailable(RuntimeError):
    """The explicitly configured local embedding provider cannot serve the requested space."""

    def __init__(self, readiness: EmbeddingReadiness) -> None:
        super().__init__(readiness.message)
        self.readiness = readiness


class OllamaEmbeddingProvider:
    """Resolve and use one installed local Ollama artifact without downloading or fallback."""

    def __init__(
        self,
        *,
        base_url: str,
        model_artifact: str,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 10,
    ) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("OLLAMA_BASE_URL must be an unauthenticated HTTP loopback URL")
        if not model_artifact.strip():
            raise ValueError("EMBEDDING_MODEL must not be blank")
        if re.search(r"(?:^|[:_-])cloud$", model_artifact.casefold()) is not None:
            raise ValueError("EMBEDDING_MODEL must not select an Ollama cloud model")
        self._base_url = base_url.rstrip("/")
        self._model_artifact = model_artifact
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    def check_readiness(self) -> EmbeddingReadiness:
        try:
            tags = self._request_json("GET", "/api/tags")
            models = tags.get("models")
            if not isinstance(models, list):
                return self._invalid_response("Ollama returned no model inventory.")
            installed = next(
                (
                    item
                    for item in models
                    if isinstance(item, dict)
                    and self._model_artifact in {item.get("name"), item.get("model")}
                ),
                None,
            )
            if installed is None:
                return EmbeddingReadiness(
                    status="unavailable",
                    code="embedding_model_not_installed",
                    message=(f"Local embedding artifact {self._model_artifact} is not installed."),
                    setup=f"Run `ollama pull {self._model_artifact}`, then retry.",
                    space=None,
                )
            if (
                installed.get("remote_model") is not None
                or installed.get("remote_host") is not None
            ):
                return EmbeddingReadiness(
                    status="unavailable",
                    code="embedding_cloud_model_rejected",
                    message=(
                        f"Configured artifact {self._model_artifact} is remote; "
                        "only an installed local artifact is permitted."
                    ),
                    setup=(
                        "Configure a non-cloud Ollama embedding artifact, run `make models`, "
                        "then retry."
                    ),
                    space=None,
                )
            digest = installed.get("digest")
            if not isinstance(digest, str) or _HEX_DIGEST.fullmatch(digest) is None:
                return self._invalid_response("Ollama returned an invalid model artifact digest.")

            details = self._request_json(
                "POST", "/api/show", json={"model": self._model_artifact, "verbose": False}
            )
            if details.get("remote_model") is not None or details.get("remote_host") is not None:
                return EmbeddingReadiness(
                    status="unavailable",
                    code="embedding_cloud_model_rejected",
                    message=(
                        f"Configured artifact {self._model_artifact} resolves remotely; "
                        "only an installed local artifact is permitted."
                    ),
                    setup=(
                        "Configure a non-cloud Ollama embedding artifact, run `make models`, "
                        "then retry."
                    ),
                    space=None,
                )
            capabilities = details.get("capabilities")
            if not isinstance(capabilities, list) or "embedding" not in capabilities:
                return self._invalid_response(
                    f"Local artifact {self._model_artifact} does not advertise embedding support."
                )
            model_info = details.get("model_info")
            if not isinstance(model_info, dict):
                return self._invalid_response("Ollama returned no embedding dimensions.")
            dimensions = {
                value
                for key, value in model_info.items()
                if isinstance(key, str)
                and key.endswith(".embedding_length")
                and isinstance(value, int)
                and value > 0
            }
            if len(dimensions) != 1:
                return self._invalid_response("Ollama returned ambiguous embedding dimensions.")
            space = EmbeddingSpace(
                provider=EMBEDDING_PROVIDER,
                model_artifact=self._model_artifact,
                artifact_digest=f"sha256:{digest.lower()}",
                dimensions=dimensions.pop(),
                retrieval_instruction=EMBEDDING_RETRIEVAL_INSTRUCTION,
                normalizer=EMBEDDING_NORMALIZER,
                passage_construction_version=EMBEDDING_PASSAGE_CONSTRUCTION_VERSION,
            )
            return EmbeddingReadiness(
                status="ready",
                code=None,
                message="The explicitly configured local embedding artifact is ready.",
                setup=None,
                space=space,
            )
        except (httpx.HTTPError, ValueError) as error:
            return EmbeddingReadiness(
                status="unavailable",
                code="embedding_runtime_unavailable",
                message=f"Local Ollama embedding runtime is unavailable: {error}",
                setup="Start Ollama locally and run `make models`, then retry.",
                space=None,
            )

    def require_space(self) -> EmbeddingSpace:
        readiness = self.check_readiness()
        if readiness.space is None:
            raise EmbeddingProviderUnavailable(readiness)
        return readiness.space

    def embed_query(self, text: str, space: EmbeddingSpace) -> tuple[float, ...]:
        return self._embed((space.retrieval_instruction + text,), space)[0]

    def embed_passages(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]:
        return self._embed(texts, space)

    def _embed(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]:
        if not texts:
            return ()
        current_space = self.require_space()
        if current_space.identity != space.identity:
            raise EmbeddingProviderUnavailable(
                EmbeddingReadiness(
                    status="unavailable",
                    code="embedding_space_not_current",
                    message=(
                        "The installed local artifact does not match the requested Embedding Space."
                    ),
                    setup=(
                        f"Install the artifact pinned by Embedding Space {space.identity} "
                        "or re-embed into the current space."
                    ),
                    space=None,
                )
            )
        try:
            response = self._request_json(
                "POST",
                "/api/embed",
                json={
                    "model": space.model_artifact,
                    "input": texts[0] if len(texts) == 1 else list(texts),
                    "truncate": False,
                    "dimensions": space.dimensions,
                },
            )
            raw_embeddings = response.get("embeddings")
            if not isinstance(raw_embeddings, list) or len(raw_embeddings) != len(texts):
                raise ValueError("Ollama returned the wrong number of embeddings")
            if any(not isinstance(vector, list) for vector in raw_embeddings):
                raise ValueError("Ollama returned an invalid embedding collection")
            normalized = tuple(
                self._normalize(cast(list[object], vector), dimensions=space.dimensions)
                for vector in raw_embeddings
            )
            final_space = self.require_space()
            if final_space.identity != space.identity:
                raise EmbeddingProviderUnavailable(
                    EmbeddingReadiness(
                        status="unavailable",
                        code="embedding_artifact_changed",
                        message=(
                            "The local embedding artifact changed during embedding generation; "
                            "the generated representations were discarded."
                        ),
                        setup=(
                            "Restore the artifact pinned by the requested Embedding Space or "
                            "retry in a new space."
                        ),
                        space=None,
                    )
                )
            return normalized
        except EmbeddingProviderUnavailable:
            raise
        except (httpx.HTTPError, ValueError) as error:
            raise EmbeddingProviderUnavailable(
                EmbeddingReadiness(
                    status="unavailable",
                    code="embedding_provider_unavailable",
                    message=f"Local embedding generation failed: {error}",
                    setup="Verify Ollama is running with the pinned artifact, then retry.",
                    space=None,
                )
            ) from error

    @staticmethod
    def _normalize(vector: list[object], *, dimensions: int) -> tuple[float, ...]:
        if len(vector) != dimensions:
            raise ValueError("Ollama returned an embedding with unexpected dimensions")
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in vector):
            raise ValueError("Ollama returned a non-numeric embedding")
        values = tuple(float(cast(int | float, value)) for value in vector)
        if any(not math.isfinite(value) for value in values):
            raise ValueError("Ollama returned a non-finite embedding")
        magnitude = math.sqrt(sum(value * value for value in values))
        if magnitude == 0:
            raise ValueError("Ollama returned a zero-length embedding")
        return tuple(value / magnitude for value in values)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, object] | None = None,
    ) -> dict[str, object]:
        with httpx.Client(
            base_url=self._base_url,
            transport=self._transport,
            timeout=self._timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = client.request(method, path, json=json)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Ollama returned a non-object response")
        return cast(dict[str, object], payload)

    @staticmethod
    def _invalid_response(message: str) -> EmbeddingReadiness:
        return EmbeddingReadiness(
            status="unavailable",
            code="embedding_provider_invalid_response",
            message=message,
            setup="Verify the installed Ollama artifact and runtime version, then retry.",
            space=None,
        )
