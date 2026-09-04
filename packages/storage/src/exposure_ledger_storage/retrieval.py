"""Metadata-isolated PostgreSQL hybrid retrieval for Exposure evidence passages."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import EmbeddingSpace
from psycopg.rows import dict_row

from exposure_ledger_storage.local_embeddings import EmbeddingReadiness

LEXICAL_RETRIEVAL_CONFIGURATION_VERSION = "postgres-lexical-v1"
HYBRID_RETRIEVAL_CONFIGURATION_VERSION = "postgres-hybrid-rrf-v1"
SOURCE_POLICY_VERSION = "explicit-source-allowlist-v1"
_EXPECTED_CONFIGURATIONS: dict[str, dict[str, object]] = {
    LEXICAL_RETRIEVAL_CONFIGURATION_VERSION: {
        "text_search_configuration": "simple",
        "ranking_algorithm": "ts_rank_cd-32",
        "passage_construction_version": "source-aware-passage-v1",
        "fusion_algorithm": "none",
        "rrf_rank_constant": 60,
        "full_text_candidate_limit": 100,
        "vector_candidate_limit": 100,
    },
    HYBRID_RETRIEVAL_CONFIGURATION_VERSION: {
        "text_search_configuration": "simple",
        "ranking_algorithm": "ts_rank_cd-32",
        "passage_construction_version": "source-aware-passage-v1",
        "fusion_algorithm": "reciprocal-rank-fusion-v1",
        "rrf_rank_constant": 60,
        "full_text_candidate_limit": 100,
        "vector_candidate_limit": 100,
    },
}


class RetrievalConfigurationNotCurrent(ValueError):
    """The caller requested a retrieval configuration other than a supported current one."""


class ExposureRetrievalScopeNotFound(LookupError):
    """The Exposure does not belong to the requested Assessment Run."""


class EmbeddingSpaceNotCurrent(ValueError):
    """The caller requested an Embedding Space other than the configured local space."""


class EmbeddingIndexUnavailable(RuntimeError):
    """The requested metadata scope is not fully represented in one Embedding Space."""


class EmbeddingProvider(Protocol):
    def check_readiness(self) -> EmbeddingReadiness: ...

    def require_space(self) -> EmbeddingSpace: ...

    def embed_query(self, text: str, space: EmbeddingSpace) -> tuple[float, ...]: ...

    def embed_passages(
        self, texts: tuple[str, ...], space: EmbeddingSpace
    ) -> tuple[tuple[float, ...], ...]: ...


@dataclass(frozen=True, slots=True)
class SourcePolicy:
    version: str
    allowed_source_identities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    assessment_run_id: UUID
    exposure_id: UUID
    text: str
    source_policy: SourcePolicy
    evidence_types: tuple[str, ...]
    retrieval_configuration_version: str = HYBRID_RETRIEVAL_CONFIGURATION_VERSION
    embedding_space_identity: str | None = None
    expected_passage_identities: tuple[str, ...] = ()
    limit: int = 10


@dataclass(frozen=True, slots=True)
class RetrievedSource:
    id: UUID
    identity: str
    authority: str
    location: str


@dataclass(frozen=True, slots=True)
class RetrievedCapture:
    identity: str
    captured_at: datetime
    content_digest: str
    payload_identity: str
    attribution: str


@dataclass(frozen=True, slots=True)
class RetrievedPassageIdentity:
    id: UUID
    identity: str
    kind: str
    selector: str
    content: str


@dataclass(frozen=True, slots=True)
class RetrievedExposureContext:
    package_name: str
    package_version: str
    vulnerability_aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetrievedEvidencePassage:
    full_text_rank: int | None
    full_text_score: float | None
    vector_rank: int | None
    vector_score: float | None
    fused_rank: int | None
    fused_score: float | None
    passage: RetrievedPassageIdentity
    source: RetrievedSource
    capture: RetrievedCapture
    exposure_context: RetrievedExposureContext
    evidence_record_id: UUID


@dataclass(frozen=True, slots=True)
class RetrievalEvaluationReport:
    k: int
    expected_count: int
    retrieved_count: int
    matched_passage_identities: tuple[str, ...]
    recall_at_k: float


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    query: RetrievalQuery
    passages: tuple[RetrievedEvidencePassage, ...]
    embedding_space: EmbeddingSpace | None
    evaluation: RetrievalEvaluationReport | None


def evaluate_retrieval_recall(
    *,
    retrieved_passage_identities: tuple[str, ...],
    expected_passage_identities: tuple[str, ...],
    k: int,
) -> RetrievalEvaluationReport:
    """Report recall@k without changing retrieval ordering."""
    if k <= 0:
        raise ValueError("Recall cutoff k must be positive")
    expected = tuple(dict.fromkeys(expected_passage_identities))
    if not expected:
        raise ValueError("Recall reporting requires at least one known-answer passage")
    retrieved = tuple(dict.fromkeys(retrieved_passage_identities[:k]))
    retrieved_set = set(retrieved)
    matched = tuple(identity for identity in expected if identity in retrieved_set)
    return RetrievalEvaluationReport(
        k=k,
        expected_count=len(expected),
        retrieved_count=len(retrieved),
        matched_passage_identities=matched,
        recall_at_k=len(matched) / len(expected),
    )


class EvidenceRetriever:
    """Retrieve ranked passages without crossing Exposure or Embedding Space boundaries."""

    def __init__(
        self,
        database_url: str,
        *,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self._database_url = database_url
        self._embedding_provider = embedding_provider

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
                available = self._configuration_is_current(
                    connection, HYBRID_RETRIEVAL_CONFIGURATION_VERSION
                )
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error
        if not available:
            raise RuntimeError("The current hybrid retrieval configuration is unavailable.")

    def index_assessment(self, assessment_run_id: UUID) -> EmbeddingSpace:
        """Create every missing passage representation for one Assessment Run and one space."""
        if self._embedding_provider is None:
            raise EmbeddingIndexUnavailable("No local embedding provider is configured.")
        space = self._embedding_provider.require_space()
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            space_id = self._store_space(connection, space)
            rows = connection.execute(
                """
                SELECT DISTINCT evidence_passages.id, evidence_passages.content
                FROM assessment_run_exposure_passages
                JOIN evidence_passages
                  ON evidence_passages.id = assessment_run_exposure_passages.passage_id
                LEFT JOIN passage_embeddings
                  ON passage_embeddings.passage_id = evidence_passages.id
                 AND passage_embeddings.embedding_space_id = %s
                WHERE assessment_run_exposure_passages.assessment_run_id = %s
                  AND passage_embeddings.passage_id IS NULL
                ORDER BY evidence_passages.id
                """,
                (space_id, assessment_run_id),
            ).fetchall()
        if not rows:
            return space

        representations = self._embedding_provider.embed_passages(
            tuple(str(row["content"]) for row in rows), space
        )
        if len(representations) != len(rows):
            raise ValueError("Embedding provider returned the wrong number of representations")
        vectors = tuple(self._validate_vector(vector, space) for vector in representations)
        with (
            psycopg.connect(self._database_url) as insert_connection,
            insert_connection.transaction(),
            insert_connection.cursor() as cursor,
        ):
            cursor.executemany(
                """
                INSERT INTO passage_embeddings (
                    passage_id, embedding_space_id, representation
                ) VALUES (%s, %s, %s::vector)
                ON CONFLICT DO NOTHING
                """,
                [
                    (row["id"], space_id, self._vector_literal(vector))
                    for row, vector in zip(rows, vectors, strict=True)
                ],
            )
        return space

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        self._validate_query(query)
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            if not self._configuration_is_current(
                connection, query.retrieval_configuration_version
            ):
                raise RetrievalConfigurationNotCurrent(
                    "The requested retrieval configuration is not current"
                )
            self._require_exposure_scope(connection, query)
            if query.retrieval_configuration_version == LEXICAL_RETRIEVAL_CONFIGURATION_VERSION:
                passages = self._retrieve_full_text(connection, query)
                return self._result(query, passages, embedding_space=None)

        if self._embedding_provider is None:
            raise EmbeddingIndexUnavailable(
                "Hybrid retrieval requires the explicitly configured local embedding provider."
            )
        space = self._embedding_provider.require_space()
        if (
            query.embedding_space_identity is not None
            and query.embedding_space_identity != space.identity
        ):
            raise EmbeddingSpaceNotCurrent(
                "The requested Embedding Space is not the configured local Embedding Space."
            )
        vector = self._validate_vector(
            self._embedding_provider.embed_query(query.text.strip(), space), space
        )
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            stored_space_id = self._stored_space_id(connection, space)
            if stored_space_id is None:
                raise EmbeddingIndexUnavailable(
                    "No passage representations exist in the configured Embedding Space. "
                    "Run a new Assessment after local embedding setup is ready."
                )
            self._require_complete_index(connection, query, stored_space_id)
            passages = self._retrieve_hybrid(connection, query, stored_space_id, vector)
        return self._result(query, passages, embedding_space=space)

    def _result(
        self,
        query: RetrievalQuery,
        passages: tuple[RetrievedEvidencePassage, ...],
        *,
        embedding_space: EmbeddingSpace | None,
    ) -> RetrievalResult:
        evaluation = None
        if query.expected_passage_identities:
            evaluation = evaluate_retrieval_recall(
                retrieved_passage_identities=tuple(item.passage.identity for item in passages),
                expected_passage_identities=query.expected_passage_identities,
                k=query.limit,
            )
        return RetrievalResult(
            query=query,
            passages=passages,
            embedding_space=embedding_space,
            evaluation=evaluation,
        )

    @staticmethod
    def _validate_query(query: RetrievalQuery) -> None:
        if not query.text.strip():
            raise ValueError("Retrieval query text must not be blank")
        if not query.source_policy.allowed_source_identities:
            raise ValueError("Source policy must allow at least one Source identity")
        if query.source_policy.version != SOURCE_POLICY_VERSION:
            raise ValueError("Source policy version is not current")
        if any(not identity.strip() for identity in query.source_policy.allowed_source_identities):
            raise ValueError("Source policy identities must not be blank")
        if not query.evidence_types:
            raise ValueError("Retrieval must select at least one evidence type")
        if any(not evidence_type.strip() for evidence_type in query.evidence_types):
            raise ValueError("Evidence types must not be blank")
        if not 1 <= query.limit <= 100:
            raise ValueError("Retrieval limit must be between 1 and 100")
        if query.retrieval_configuration_version not in _EXPECTED_CONFIGURATIONS:
            raise RetrievalConfigurationNotCurrent(
                "Only a current retrieval configuration can be queried"
            )

    @staticmethod
    def _require_exposure_scope(
        connection: psycopg.Connection[dict[str, Any]], query: RetrievalQuery
    ) -> None:
        belongs_to_run = connection.execute(
            """
            SELECT 1 FROM assessment_run_exposures
            WHERE assessment_run_id = %s AND exposure_id = %s
            """,
            (query.assessment_run_id, query.exposure_id),
        ).fetchone()
        if belongs_to_run is None:
            raise ExposureRetrievalScopeNotFound(
                "Exposure does not belong to the requested Assessment Run"
            )

    def _retrieve_full_text(
        self,
        connection: psycopg.Connection[dict[str, Any]],
        query: RetrievalQuery,
    ) -> tuple[RetrievedEvidencePassage, ...]:
        rows = connection.execute(
            self._candidate_cte()
            + """
            , matches AS (
                SELECT *, ts_rank_cd(search_document, query, 32) AS full_text_score
                FROM candidates WHERE search_document @@ query
            ), ranked AS (
                SELECT *, row_number() OVER (
                    ORDER BY full_text_score DESC, capture_identity, passage_identity
                ) AS full_text_rank
                FROM matches
            )
            SELECT *, NULL::bigint AS vector_rank, NULL::double precision AS vector_score,
                   NULL::bigint AS fused_rank, NULL::double precision AS fused_score
            FROM ranked WHERE full_text_rank <= %s ORDER BY full_text_rank
            """,
            self._candidate_parameters(query) + (query.limit,),
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def _retrieve_hybrid(
        self,
        connection: psycopg.Connection[dict[str, Any]],
        query: RetrievalQuery,
        space_id: UUID,
        vector: tuple[float, ...],
    ) -> tuple[RetrievedEvidencePassage, ...]:
        configuration = _EXPECTED_CONFIGURATIONS[HYBRID_RETRIEVAL_CONFIGURATION_VERSION]
        rank_constant = cast(int, configuration["rrf_rank_constant"])
        full_text_limit = cast(int, configuration["full_text_candidate_limit"])
        vector_limit = cast(int, configuration["vector_candidate_limit"])
        vector_literal = self._vector_literal(vector)
        rows = connection.execute(
            self._candidate_cte(include_embeddings=True)
            + """
            , full_text_scored AS (
                SELECT passage_id, ts_rank_cd(search_document, query, 32) AS full_text_score,
                       row_number() OVER (
                           ORDER BY ts_rank_cd(search_document, query, 32) DESC,
                                    capture_identity, passage_identity
                       ) AS full_text_rank
                FROM candidates WHERE search_document @@ query
            ), full_text_top AS (
                SELECT * FROM full_text_scored WHERE full_text_rank <= %s
            ), vector_scored AS (
                SELECT passage_id, 1 - (representation <=> %s::vector) AS vector_score,
                       row_number() OVER (
                           ORDER BY representation <=> %s::vector,
                                    capture_identity, passage_identity
                       ) AS vector_rank
                FROM candidates
            ), vector_top AS (
                SELECT * FROM vector_scored WHERE vector_rank <= %s
            ), selected AS (
                SELECT passage_id FROM full_text_top
                UNION
                SELECT passage_id FROM vector_top
            ), combined AS (
                SELECT candidates.*, full_text_top.full_text_rank,
                       full_text_top.full_text_score, vector_top.vector_rank,
                       vector_top.vector_score,
                       COALESCE(1.0 / (%s + full_text_top.full_text_rank), 0.0)
                       + COALESCE(1.0 / (%s + vector_top.vector_rank), 0.0) AS fused_score
                FROM selected
                JOIN candidates USING (passage_id)
                LEFT JOIN full_text_top USING (passage_id)
                LEFT JOIN vector_top USING (passage_id)
            ), fused AS (
                SELECT *, row_number() OVER (
                    ORDER BY fused_score DESC, full_text_rank NULLS LAST,
                             vector_rank NULLS LAST, capture_identity, passage_identity
                ) AS fused_rank
                FROM combined
            )
            SELECT * FROM fused WHERE fused_rank <= %s ORDER BY fused_rank
            """,
            self._candidate_parameters(query, space_id=space_id)
            + (
                full_text_limit,
                vector_literal,
                vector_literal,
                vector_limit,
                rank_constant,
                rank_constant,
                query.limit,
            ),
        ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    @staticmethod
    def _candidate_cte(*, include_embeddings: bool = False) -> str:
        embedding_column = ", passage_embeddings.representation" if include_embeddings else ""
        embedding_join = (
            "JOIN passage_embeddings ON passage_embeddings.passage_id = evidence_passages.id "
            "AND passage_embeddings.embedding_space_id = %s"
            if include_embeddings
            else ""
        )
        return f"""
            WITH requested AS (
                SELECT plainto_tsquery('simple'::regconfig, %s) AS query
            ), candidates AS (
                SELECT evidence_passages.id AS passage_id,
                       evidence_passages.identity_key AS passage_identity,
                       evidence_passages.kind, evidence_passages.selector,
                       evidence_passages.content AS passage_content,
                       evidence_records.id AS evidence_record_id,
                       evidence_records.identity_key AS capture_identity,
                       evidence_records.captured_at, evidence_records.content_digest,
                       evidence_records.payload_identity, evidence_records.attribution,
                       sources.id AS source_id, sources.identity_key AS source_identity,
                       sources.authority, sources.location,
                       package_instances.name AS package_name,
                       package_instances.version AS package_version,
                       exposure_metadata.vulnerability_aliases,
                       (setweight(evidence_passages.search_vector, 'A')
                        || setweight(to_tsvector('simple'::regconfig, concat_ws(
                            ' ', evidence_records.payload_identity, evidence_records.attribution
                        )), 'B')
                        || setweight(to_tsvector('simple'::regconfig, concat_ws(
                            ' ', package_instances.name, package_instances.version,
                            array_to_string(exposure_metadata.vulnerability_aliases, ' ')
                        )), 'C')
                        || setweight(to_tsvector('simple'::regconfig, concat_ws(
                            ' ', sources.identity_key, sources.authority, sources.location
                        )), 'D')) AS search_document,
                       requested.query{embedding_column}
                FROM assessment_run_exposure_passages
                JOIN evidence_passages
                  ON evidence_passages.id = assessment_run_exposure_passages.passage_id
                 AND evidence_passages.evidence_record_id =
                     assessment_run_exposure_passages.evidence_record_id
                {embedding_join}
                JOIN evidence_records
                  ON evidence_records.id = assessment_run_exposure_passages.evidence_record_id
                JOIN sources ON sources.id = evidence_records.source_id
                JOIN exposures ON exposures.id = assessment_run_exposure_passages.exposure_id
                JOIN package_instances ON package_instances.id = exposures.package_instance_id
                CROSS JOIN LATERAL (
                    SELECT array_agg(alias.identifier ORDER BY alias.identifier)
                        AS vulnerability_aliases
                    FROM vulnerability_aliases AS alias
                    WHERE alias.vulnerability_record_id = exposures.vulnerability_record_id
                ) AS exposure_metadata
                CROSS JOIN requested
                WHERE assessment_run_exposure_passages.assessment_run_id = %s
                  AND assessment_run_exposure_passages.exposure_id = %s
                  AND sources.identity_key = ANY(%s)
                  AND evidence_passages.kind = ANY(%s)
            )
        """

    @staticmethod
    def _candidate_parameters(
        query: RetrievalQuery, *, space_id: UUID | None = None
    ) -> tuple[object, ...]:
        tail: tuple[object, ...] = (
            query.assessment_run_id,
            query.exposure_id,
            list(query.source_policy.allowed_source_identities),
            list(query.evidence_types),
        )
        if space_id is None:
            return (query.text.strip(), *tail)
        return (query.text.strip(), space_id, *tail)

    @staticmethod
    def _configuration_is_current(
        connection: psycopg.Connection[dict[str, Any]], version: str
    ) -> bool:
        expected = _EXPECTED_CONFIGURATIONS.get(version)
        if expected is None:
            return False
        row = connection.execute(
            """
            SELECT text_search_configuration, ranking_algorithm,
                   passage_construction_version, fusion_algorithm, rrf_rank_constant,
                   full_text_candidate_limit, vector_candidate_limit
            FROM retrieval_configurations WHERE version = %s
            """,
            (version,),
        ).fetchone()
        return row == expected

    @staticmethod
    def _store_space(connection: psycopg.Connection[dict[str, Any]], space: EmbeddingSpace) -> UUID:
        inserted = connection.execute(
            """
            INSERT INTO embedding_spaces (
                id, identity_key, provider, model_artifact, artifact_digest, dimensions,
                retrieval_instruction, normalizer, passage_construction_version
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING RETURNING id
            """,
            (
                uuid4(),
                space.identity,
                space.provider,
                space.model_artifact,
                space.artifact_digest,
                space.dimensions,
                space.retrieval_instruction,
                space.normalizer,
                space.passage_construction_version,
            ),
        ).fetchone()
        if inserted is not None:
            connection.commit()
            return UUID(str(inserted["id"]))
        existing = EvidenceRetriever._stored_space_id(connection, space)
        if existing is None:
            raise ValueError("Embedding Space identity conflicts with stored comparability inputs")
        return existing

    @staticmethod
    def _stored_space_id(
        connection: psycopg.Connection[dict[str, Any]], space: EmbeddingSpace
    ) -> UUID | None:
        row = connection.execute(
            """
            SELECT id, provider, model_artifact, artifact_digest, dimensions,
                   retrieval_instruction, normalizer, passage_construction_version
            FROM embedding_spaces WHERE identity_key = %s
            """,
            (space.identity,),
        ).fetchone()
        if row is None:
            return None
        actual = (
            row["provider"],
            row["model_artifact"],
            row["artifact_digest"],
            row["dimensions"],
            row["retrieval_instruction"],
            row["normalizer"],
            row["passage_construction_version"],
        )
        expected = (
            space.provider,
            space.model_artifact,
            space.artifact_digest,
            space.dimensions,
            space.retrieval_instruction,
            space.normalizer,
            space.passage_construction_version,
        )
        if actual != expected:
            raise ValueError("Stored Embedding Space identity has conflicting inputs")
        return UUID(str(row["id"]))

    @staticmethod
    def _require_complete_index(
        connection: psycopg.Connection[dict[str, Any]],
        query: RetrievalQuery,
        space_id: UUID,
    ) -> None:
        row = connection.execute(
            """
            SELECT count(*) AS passage_count,
                   count(passage_embeddings.passage_id) AS embedding_count
            FROM assessment_run_exposure_passages
            JOIN evidence_passages
              ON evidence_passages.id = assessment_run_exposure_passages.passage_id
            JOIN evidence_records
              ON evidence_records.id = assessment_run_exposure_passages.evidence_record_id
            JOIN sources ON sources.id = evidence_records.source_id
            LEFT JOIN passage_embeddings
              ON passage_embeddings.passage_id = evidence_passages.id
             AND passage_embeddings.embedding_space_id = %s
            WHERE assessment_run_exposure_passages.assessment_run_id = %s
              AND assessment_run_exposure_passages.exposure_id = %s
              AND sources.identity_key = ANY(%s)
              AND evidence_passages.kind = ANY(%s)
            """,
            (
                space_id,
                query.assessment_run_id,
                query.exposure_id,
                list(query.source_policy.allowed_source_identities),
                list(query.evidence_types),
            ),
        ).fetchone()
        assert row is not None
        if row["passage_count"] != row["embedding_count"]:
            raise EmbeddingIndexUnavailable(
                "The requested evidence scope is not fully represented in the configured "
                "Embedding Space. Run a new Assessment after local embedding setup is ready."
            )

    @staticmethod
    def _validate_vector(vector: tuple[float, ...], space: EmbeddingSpace) -> tuple[float, ...]:
        if len(vector) != space.dimensions:
            raise ValueError("Representation dimensions do not match the Embedding Space")
        if any(not math.isfinite(value) for value in vector):
            raise ValueError("Representations must contain only finite values")
        magnitude = math.sqrt(sum(value * value for value in vector))
        if not math.isclose(magnitude, 1.0, rel_tol=1e-6, abs_tol=1e-6):
            raise ValueError("Representations must match the Embedding Space normalizer")
        return vector

    @staticmethod
    def _vector_literal(vector: tuple[float, ...]) -> str:
        return "[" + ",".join(format(value, ".17g") for value in vector) + "]"

    @staticmethod
    def _from_row(row: dict[str, object]) -> RetrievedEvidencePassage:
        def optional_int(value: object) -> int | None:
            return int(str(value)) if value is not None else None

        def optional_float(value: object) -> float | None:
            return float(str(value)) if value is not None else None

        return RetrievedEvidencePassage(
            full_text_rank=optional_int(row["full_text_rank"]),
            full_text_score=optional_float(row["full_text_score"]),
            vector_rank=optional_int(row["vector_rank"]),
            vector_score=optional_float(row["vector_score"]),
            fused_rank=optional_int(row["fused_rank"]),
            fused_score=optional_float(row["fused_score"]),
            passage=RetrievedPassageIdentity(
                id=UUID(str(row["passage_id"])),
                identity=str(row["passage_identity"]),
                kind=str(row["kind"]),
                selector=str(row["selector"]),
                content=str(row["passage_content"]),
            ),
            source=RetrievedSource(
                id=UUID(str(row["source_id"])),
                identity=str(row["source_identity"]),
                authority=str(row["authority"]),
                location=str(row["location"]),
            ),
            capture=RetrievedCapture(
                identity=str(row["capture_identity"]),
                captured_at=cast(datetime, row["captured_at"]),
                content_digest=str(row["content_digest"]),
                payload_identity=str(row["payload_identity"]),
                attribution=str(row["attribution"]),
            ),
            exposure_context=RetrievedExposureContext(
                package_name=str(row["package_name"]),
                package_version=str(row["package_version"]),
                vulnerability_aliases=tuple(
                    str(alias) for alias in cast(list[object], row["vulnerability_aliases"])
                ),
            ),
            evidence_record_id=UUID(str(row["evidence_record_id"])),
        )
