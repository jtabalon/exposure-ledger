"""Metadata-isolated PostgreSQL lexical retrieval for Exposure evidence passages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

LEXICAL_RETRIEVAL_CONFIGURATION_VERSION = "postgres-lexical-v1"
SOURCE_POLICY_VERSION = "explicit-source-allowlist-v1"
_EXPECTED_CONFIGURATION = {
    "text_search_configuration": "simple",
    "ranking_algorithm": "ts_rank_cd-32",
    "passage_construction_version": "source-aware-passage-v1",
}


class RetrievalConfigurationNotCurrent(ValueError):
    """The caller requested a retrieval configuration other than the current one."""


class ExposureRetrievalScopeNotFound(LookupError):
    """The Exposure does not belong to the requested Assessment Run."""


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
    retrieval_configuration_version: str = LEXICAL_RETRIEVAL_CONFIGURATION_VERSION
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
    lexical_rank: int
    lexical_score: float
    passage: RetrievedPassageIdentity
    source: RetrievedSource
    capture: RetrievedCapture
    exposure_context: RetrievedExposureContext
    evidence_record_id: UUID


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    query: RetrievalQuery
    passages: tuple[RetrievedEvidencePassage, ...]


class EvidenceRetriever:
    """Retrieve ranked passages without crossing Exposure or evidence metadata boundaries."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
                available = self._configuration_is_current(
                    connection, LEXICAL_RETRIEVAL_CONFIGURATION_VERSION
                )
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error
        if not available:
            raise RuntimeError("The current lexical retrieval configuration is unavailable.")

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        text = query.text.strip()
        if not text:
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
        if query.retrieval_configuration_version != LEXICAL_RETRIEVAL_CONFIGURATION_VERSION:
            raise RetrievalConfigurationNotCurrent(
                "Only the current lexical retrieval configuration can be queried"
            )

        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            if not self._configuration_is_current(
                connection, query.retrieval_configuration_version
            ):
                raise RetrievalConfigurationNotCurrent(
                    "The requested lexical retrieval configuration is not current"
                )

            belongs_to_run = connection.execute(
                """
                SELECT 1
                FROM assessment_run_exposures
                WHERE assessment_run_id = %s AND exposure_id = %s
                """,
                (query.assessment_run_id, query.exposure_id),
            ).fetchone()
            if belongs_to_run is None:
                raise ExposureRetrievalScopeNotFound(
                    "Exposure does not belong to the requested Assessment Run"
                )

            rows = connection.execute(
                """
                WITH requested AS (
                    SELECT plainto_tsquery('simple'::regconfig, %s) AS query
                ), candidates AS (
                    SELECT evidence_passages.id AS passage_id,
                           evidence_passages.identity_key AS passage_identity,
                           evidence_passages.kind, evidence_passages.selector,
                           evidence_passages.content AS passage_content,
                           evidence_records.id AS evidence_record_id,
                           evidence_records.identity_key AS capture_identity,
                           evidence_records.captured_at,
                           evidence_records.content_digest,
                           evidence_records.payload_identity,
                           evidence_records.attribution,
                           sources.id AS source_id,
                           sources.identity_key AS source_identity,
                           sources.authority, sources.location,
                           package_instances.name AS package_name,
                           package_instances.version AS package_version,
                           exposure_metadata.vulnerability_aliases,
                           (
                               setweight(evidence_passages.search_vector, 'A')
                               || setweight(
                                   to_tsvector(
                                       'simple'::regconfig,
                                       concat_ws(
                                           ' ', evidence_records.payload_identity,
                                           evidence_records.attribution
                                       )
                                   ),
                                   'B'
                               )
                               || setweight(
                                   to_tsvector(
                                       'simple'::regconfig,
                                       concat_ws(
                                           ' ', package_instances.name,
                                           package_instances.version,
                                           array_to_string(
                                               exposure_metadata.vulnerability_aliases, ' '
                                           )
                                       )
                                   ),
                                   'C'
                               )
                               || setweight(
                                   to_tsvector(
                                       'simple'::regconfig,
                                       concat_ws(
                                           ' ', sources.identity_key, sources.authority,
                                           sources.location
                                       )
                                   ),
                                   'D'
                               )
                           ) AS search_document,
                           requested.query
                    FROM assessment_run_exposure_passages
                    JOIN evidence_passages
                      ON evidence_passages.id = assessment_run_exposure_passages.passage_id
                     AND evidence_passages.evidence_record_id =
                         assessment_run_exposure_passages.evidence_record_id
                    JOIN evidence_records
                      ON evidence_records.id = assessment_run_exposure_passages.evidence_record_id
                    JOIN sources ON sources.id = evidence_records.source_id
                    JOIN exposures ON exposures.id = assessment_run_exposure_passages.exposure_id
                    JOIN package_instances ON package_instances.id = exposures.package_instance_id
                    CROSS JOIN LATERAL (
                        SELECT array_agg(alias.identifier ORDER BY alias.identifier)
                            AS vulnerability_aliases
                        FROM vulnerability_aliases AS alias
                        WHERE alias.vulnerability_record_id =
                            exposures.vulnerability_record_id
                    ) AS exposure_metadata
                    CROSS JOIN requested
                    WHERE assessment_run_exposure_passages.assessment_run_id = %s
                      AND assessment_run_exposure_passages.exposure_id = %s
                      AND sources.identity_key = ANY(%s)
                      AND evidence_passages.kind = ANY(%s)
                ), matches AS (
                    SELECT *, ts_rank_cd(search_document, query, 32) AS lexical_score
                    FROM candidates
                    WHERE search_document @@ query
                ), ranked AS (
                    SELECT *, row_number() OVER (
                        ORDER BY lexical_score DESC, capture_identity, passage_identity
                    ) AS lexical_rank
                    FROM matches
                )
                SELECT * FROM ranked
                WHERE lexical_rank <= %s
                ORDER BY lexical_rank
                """,
                (
                    text,
                    query.assessment_run_id,
                    query.exposure_id,
                    list(query.source_policy.allowed_source_identities),
                    list(query.evidence_types),
                    query.limit,
                ),
            ).fetchall()

        return RetrievalResult(
            query=query,
            passages=tuple(self._from_row(row) for row in rows),
        )

    @staticmethod
    def _configuration_is_current(
        connection: psycopg.Connection[dict[str, Any]], version: str
    ) -> bool:
        row = connection.execute(
            """
            SELECT text_search_configuration, ranking_algorithm,
                   passage_construction_version
            FROM retrieval_configurations
            WHERE version = %s
            """,
            (version,),
        ).fetchone()
        return row == _EXPECTED_CONFIGURATION

    @staticmethod
    def _from_row(row: dict[str, object]) -> RetrievedEvidencePassage:
        return RetrievedEvidencePassage(
            lexical_rank=int(str(row["lexical_rank"])),
            lexical_score=float(str(row["lexical_score"])),
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
