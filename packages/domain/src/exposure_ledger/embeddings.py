"""Versioned identities for mutually comparable semantic representations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class EmbeddingSpace:
    """All inputs that determine whether two embedding vectors are comparable."""

    provider: str
    model_artifact: str
    artifact_digest: str
    dimensions: int
    retrieval_instruction: str
    normalizer: str
    passage_construction_version: str

    def __post_init__(self) -> None:
        text_fields = (
            self.provider,
            self.model_artifact,
            self.retrieval_instruction,
            self.normalizer,
            self.passage_construction_version,
        )
        if any(not value.strip() for value in text_fields):
            raise ValueError("Embedding Space fields must not be blank")
        if _SHA256_DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("Embedding Space requires an immutable sha256 digest")
        if self.dimensions <= 0:
            raise ValueError("Embedding Space dimensions must be positive")

    @property
    def identity(self) -> str:
        material = json.dumps(
            {
                "artifactDigest": self.artifact_digest,
                "dimensions": self.dimensions,
                "modelArtifact": self.model_artifact,
                "normalizer": self.normalizer,
                "passageConstructionVersion": self.passage_construction_version,
                "provider": self.provider,
                "retrievalInstruction": self.retrieval_instruction,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return f"sha256:{hashlib.sha256(material.encode()).hexdigest()}"
