from dataclasses import FrozenInstanceError

import pytest
from exposure_ledger import EmbeddingSpace


def _space(**changes: object) -> EmbeddingSpace:
    values: dict[str, object] = {
        "provider": "ollama-local",
        "model_artifact": "qwen3-embedding:0.6b",
        "artifact_digest": "sha256:" + "a" * 64,
        "dimensions": 3,
        "retrieval_instruction": "Represent this query for evidence retrieval: ",
        "normalizer": "l2-v1",
        "passage_construction_version": "source-aware-passage-v1",
    }
    values.update(changes)
    return EmbeddingSpace(**values)  # type: ignore[arg-type]


def test_embedding_space_identity_covers_every_comparability_input() -> None:
    original = _space()

    assert original.identity == _space().identity
    for field, changed in (
        ("provider", "another-local-provider"),
        ("model_artifact", "qwen3-embedding:4b"),
        ("artifact_digest", "sha256:" + "b" * 64),
        ("dimensions", 4),
        ("retrieval_instruction", "Represent another retrieval task: "),
        ("normalizer", "unit-length-v2"),
        ("passage_construction_version", "source-aware-passage-v2"),
    ):
        assert _space(**{field: changed}).identity != original.identity


def test_embedding_space_is_immutable_and_rejects_unpinned_artifacts() -> None:
    space = _space()

    with pytest.raises(FrozenInstanceError):
        space.dimensions = 4  # type: ignore[misc]
    with pytest.raises(ValueError, match="immutable sha256 digest"):
        _space(artifact_digest="latest")
