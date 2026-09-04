"""PostgreSQL persistence for ranked package-specific Exposures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import (
    AssessmentResult,
    EvidenceRelationship,
    ExposureRanking,
    ExposureSeverity,
    VulnerabilityRecord,
)
from exposure_ledger import EvidenceRecord as DomainEvidenceRecord
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from exposure_ledger_storage.asset_snapshots import PackageInstanceRecord


@dataclass(frozen=True, slots=True)
class VulnerabilityRecordRecord:
    id: UUID
    aliases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceRecord:
    identity: str
    authority: str
    location: str


@dataclass(frozen=True, slots=True)
class EvidencePassageRecord:
    id: UUID
    identity: str
    kind: str
    selector: str
    content: str


@dataclass(frozen=True, slots=True)
class EvidenceRecordRecord:
    id: UUID
    identity: str
    source: SourceRecord
    captured_at: datetime
    content_digest: str
    attribution: str
    aliases: tuple[str, ...]
    payload_identity: str
    content: str
    passages: tuple[EvidencePassageRecord, ...]
    relationship: EvidenceRelationship


@dataclass(frozen=True, slots=True)
class ExposureRecord:
    id: UUID
    assessment_run_id: UUID
    asset_snapshot_id: UUID
    vulnerability_record: VulnerabilityRecordRecord
    package: PackageInstanceRecord
    ranking: ExposureRanking
    rank: int
    selected_for_investigation: bool
    authoritative_conflict: bool
    evidence_records: tuple[EvidenceRecordRecord, ...]


class ExposureRepository:
    """Persist one Assessment Run's deterministic Exposure queue idempotently."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url) as connection:
                connection.execute("SELECT EXISTS (SELECT 1 FROM exposures)")
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error

    def record(
        self,
        *,
        assessment_run_id: UUID,
        asset_snapshot_id: UUID,
        result: AssessmentResult,
    ) -> list[ExposureRecord]:
        if self.is_recorded(
            assessment_run_id,
            asset_snapshot_id=asset_snapshot_id,
        ):
            return self.list_for_assessment(assessment_run_id)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            evidence_by_identity = {
                evidence.identity: evidence for evidence in result.evidence_records
            }
            referenced_evidence = {
                reference.record_identity
                for exposure in result.exposures
                for reference in exposure.evidence
            }
            missing_evidence = referenced_evidence - evidence_by_identity.keys()
            if missing_evidence:
                raise ValueError("Exposure discovery references unavailable Evidence Records")
            evidence_ids: dict[str, UUID] = {}
            passage_ids: dict[str, UUID] = {}
            for identity, domain_evidence in sorted(evidence_by_identity.items()):
                evidence_id, stored_passages = self._persist_immutable_evidence(
                    connection, domain_evidence
                )
                evidence_ids[identity] = evidence_id
                passage_ids.update(stored_passages)
            vulnerability_ids = {
                vulnerability.identity: self._vulnerability_id(connection, vulnerability)
                for vulnerability in result.vulnerability_records
            }
            for exposure in result.exposures:
                package_id = self._package_id(
                    connection,
                    asset_snapshot_id=asset_snapshot_id,
                    name=exposure.package.name,
                    version=exposure.package.version,
                    source=exposure.package.source.as_dict(),
                )
                vulnerability_id = vulnerability_ids[exposure.vulnerability_identity]
                inserted = connection.execute(
                    """
                    INSERT INTO exposures (
                        id, asset_snapshot_id, vulnerability_record_id, package_instance_id
                    ) VALUES (%s, %s, %s, %s)
                    ON CONFLICT (
                        asset_snapshot_id, vulnerability_record_id, package_instance_id
                    ) DO NOTHING
                    RETURNING id
                    """,
                    (uuid4(), asset_snapshot_id, vulnerability_id, package_id),
                ).fetchone()
                if inserted is None:
                    existing = connection.execute(
                        """
                        SELECT id FROM exposures
                        WHERE asset_snapshot_id = %s
                          AND vulnerability_record_id = %s
                          AND package_instance_id = %s
                        """,
                        (asset_snapshot_id, vulnerability_id, package_id),
                    ).fetchone()
                    assert existing is not None
                    exposure_id = UUID(str(existing[0]))
                else:
                    exposure_id = UUID(str(inserted[0]))
                connection.execute(
                    """
                    INSERT INTO assessment_run_exposures (
                        assessment_run_id, exposure_id, rank, selected_for_investigation,
                        severity, direct_dependency, dependency_depth,
                        fixed_version_available, ranking_score, authoritative_conflict
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (assessment_run_id, exposure_id) DO NOTHING
                    """,
                    (
                        assessment_run_id,
                        exposure_id,
                        exposure.rank,
                        exposure.selected_for_investigation,
                        exposure.ranking.severity,
                        exposure.ranking.direct_dependency,
                        exposure.ranking.dependency_depth,
                        exposure.ranking.fixed_version_available,
                        exposure.ranking.score,
                        exposure.authoritative_conflict,
                    ),
                )
                for evidence_reference in exposure.evidence:
                    evidence_id = evidence_ids[evidence_reference.record_identity]
                    connection.execute(
                        """
                        INSERT INTO assessment_run_exposure_evidence (
                            assessment_run_id, exposure_id, evidence_record_id, relationship
                        ) VALUES (%s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            assessment_run_id,
                            exposure_id,
                            evidence_id,
                            evidence_reference.relationship,
                        ),
                    )
                    with connection.cursor() as cursor:
                        cursor.executemany(
                            """
                            INSERT INTO assessment_run_exposure_passages (
                                assessment_run_id, exposure_id, evidence_record_id, passage_id
                            ) VALUES (%s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                            """,
                            [
                                (
                                    assessment_run_id,
                                    exposure_id,
                                    evidence_id,
                                    passage_ids[passage_identity],
                                )
                                for passage_identity in evidence_reference.passage_identities
                            ],
                        )
            connection.execute(
                """
                INSERT INTO exposure_discoveries (
                    assessment_run_id, asset_snapshot_id, exposure_count, completed_at
                ) VALUES (%s, %s, %s, %s)
                ON CONFLICT (assessment_run_id) DO NOTHING
                """,
                (assessment_run_id, asset_snapshot_id, len(result.exposures), datetime.now(UTC)),
            )
        return self.list_for_assessment(assessment_run_id)

    def is_recorded(
        self,
        assessment_run_id: UUID,
        *,
        asset_snapshot_id: UUID,
    ) -> bool:
        with psycopg.connect(self._database_url) as connection:
            row = connection.execute(
                """
                SELECT asset_snapshot_id FROM exposure_discoveries
                WHERE assessment_run_id = %s
                """,
                (assessment_run_id,),
            ).fetchone()
        if row is None:
            return False
        if UUID(str(row[0])) != asset_snapshot_id:
            raise ValueError("Assessment Run Exposure discovery belongs to another Asset Snapshot")
        return True

    def list_for_assessment(self, assessment_run_id: UUID) -> list[ExposureRecord]:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT exposures.id, assessment_run_exposures.assessment_run_id,
                       exposures.asset_snapshot_id, exposures.vulnerability_record_id,
                       package_instances.id AS package_id, package_instances.name,
                       package_instances.version, package_instances.direct,
                       package_instances.source, assessment_run_exposures.rank,
                       assessment_run_exposures.selected_for_investigation,
                       assessment_run_exposures.severity,
                       assessment_run_exposures.direct_dependency,
                       assessment_run_exposures.dependency_depth,
                       assessment_run_exposures.fixed_version_available,
                       assessment_run_exposures.ranking_score,
                       assessment_run_exposures.authoritative_conflict
                FROM assessment_run_exposures
                JOIN exposures ON exposures.id = assessment_run_exposures.exposure_id
                JOIN package_instances
                  ON package_instances.id = exposures.package_instance_id
                WHERE assessment_run_exposures.assessment_run_id = %s
                ORDER BY assessment_run_exposures.rank
                """,
                (assessment_run_id,),
            ).fetchall()
            return [self._from_row(connection, row) for row in rows]

    @staticmethod
    def _persist_immutable_evidence(
        connection: psycopg.Connection[Any], evidence: DomainEvidenceRecord
    ) -> tuple[UUID, dict[str, UUID]]:
        source_inserted = connection.execute(
            """
            INSERT INTO sources (id, identity_key, authority, location)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (identity_key, authority, location) DO NOTHING
            RETURNING id
            """,
            (
                uuid4(),
                evidence.source.identity,
                evidence.source.authority,
                evidence.source.location,
            ),
        ).fetchone()
        if source_inserted is None:
            source_row = connection.execute(
                """
                SELECT id FROM sources
                WHERE identity_key = %s AND authority = %s AND location = %s
                """,
                (evidence.source.identity, evidence.source.authority, evidence.source.location),
            ).fetchone()
            assert source_row is not None
            source_id = UUID(str(source_row[0]))
        else:
            source_id = UUID(str(source_inserted[0]))

        inserted = connection.execute(
            """
            INSERT INTO evidence_records (
                id, identity_key, source_id, captured_at, content_digest, attribution,
                aliases, payload_identity, content
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (identity_key) DO NOTHING
            RETURNING id
            """,
            (
                uuid4(),
                evidence.identity,
                source_id,
                evidence.captured_at,
                evidence.content_digest,
                evidence.attribution,
                list(evidence.aliases),
                evidence.payload_identity,
                evidence.content,
            ),
        ).fetchone()
        if inserted is None:
            existing = connection.execute(
                """
                SELECT id, source_id, content_digest, attribution, aliases,
                       payload_identity, content
                FROM evidence_records WHERE identity_key = %s
                """,
                (evidence.identity,),
            ).fetchone()
            assert existing is not None
            expected = (
                source_id,
                evidence.content_digest,
                evidence.attribution,
                list(evidence.aliases),
                evidence.payload_identity,
                evidence.content,
            )
            actual = (UUID(str(existing[1])), *existing[2:])
            if actual != expected:
                raise ValueError("Evidence identity conflicts with an immutable stored record")
            evidence_id = UUID(str(existing[0]))
        else:
            evidence_id = UUID(str(inserted[0]))

        passage_ids: dict[str, UUID] = {}
        for passage in evidence.passages:
            passage_inserted = connection.execute(
                """
                INSERT INTO evidence_passages (
                    id, evidence_record_id, identity_key, kind, selector, content
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (identity_key) DO NOTHING
                RETURNING id
                """,
                (
                    uuid4(),
                    evidence_id,
                    passage.identity,
                    passage.kind,
                    passage.selector,
                    passage.content,
                ),
            ).fetchone()
            if passage_inserted is None:
                passage_row = connection.execute(
                    """
                    SELECT id, evidence_record_id, kind, selector, content
                    FROM evidence_passages WHERE identity_key = %s
                    """,
                    (passage.identity,),
                ).fetchone()
                assert passage_row is not None
                if (
                    UUID(str(passage_row[1])),
                    str(passage_row[2]),
                    str(passage_row[3]),
                    str(passage_row[4]),
                ) != (evidence_id, passage.kind, passage.selector, passage.content):
                    raise ValueError("Evidence Passage identity conflicts with immutable content")
                passage_id = UUID(str(passage_row[0]))
            else:
                passage_id = UUID(str(passage_inserted[0]))
            passage_ids[passage.identity] = passage_id
        return evidence_id, passage_ids

    @staticmethod
    def _vulnerability_id(
        connection: psycopg.Connection[Any], vulnerability: VulnerabilityRecord
    ) -> UUID:
        rows = connection.execute(
            """
            SELECT DISTINCT vulnerability_record_id
            FROM vulnerability_aliases
            WHERE identifier = ANY(%s)
            """,
            (list(vulnerability.aliases),),
        ).fetchall()
        record_ids = {UUID(str(row[0])) for row in rows}
        if len(record_ids) > 1:
            raise ValueError("OSV aliases conflict with distinct stored Vulnerability Records")
        if record_ids:
            record_id = next(iter(record_ids))
        else:
            inserted = connection.execute(
                """
                INSERT INTO vulnerability_records (id, identity_key)
                VALUES (%s, %s)
                ON CONFLICT (identity_key) DO NOTHING
                RETURNING id
                """,
                (uuid4(), vulnerability.identity),
            ).fetchone()
            if inserted is None:
                existing = connection.execute(
                    "SELECT id FROM vulnerability_records WHERE identity_key = %s",
                    (vulnerability.identity,),
                ).fetchone()
                assert existing is not None
                record_id = UUID(str(existing[0]))
            else:
                record_id = UUID(str(inserted[0]))
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO vulnerability_aliases (identifier, vulnerability_record_id)
                VALUES (%s, %s)
                ON CONFLICT (identifier) DO NOTHING
                """,
                [(alias, record_id) for alias in vulnerability.aliases],
            )
        owners = {
            UUID(str(row[0]))
            for row in connection.execute(
                """
                SELECT DISTINCT vulnerability_record_id
                FROM vulnerability_aliases
                WHERE identifier = ANY(%s)
                """,
                (list(vulnerability.aliases),),
            ).fetchall()
        }
        if owners != {record_id}:
            raise ValueError("OSV aliases conflict with a stored Vulnerability Record")
        return record_id

    @staticmethod
    def _package_id(
        connection: psycopg.Connection[Any],
        *,
        asset_snapshot_id: UUID,
        name: str,
        version: str,
        source: dict[str, str],
    ) -> UUID:
        row = connection.execute(
            """
            SELECT id FROM package_instances
            WHERE asset_snapshot_id = %s AND name = %s AND version = %s
              AND source::jsonb = %s
            """,
            (asset_snapshot_id, name, version, Jsonb(source)),
        ).fetchone()
        if row is None:
            raise ValueError(f"Package {name} {version} is not part of the Asset Snapshot")
        return UUID(str(row[0]))

    @staticmethod
    def _from_row(connection: psycopg.Connection[Any], row: dict[str, Any]) -> ExposureRecord:
        aliases = tuple(
            str(item["identifier"])
            for item in connection.execute(
                """
                SELECT identifier FROM vulnerability_aliases
                WHERE vulnerability_record_id = %s
                ORDER BY identifier
                """,
                (row["vulnerability_record_id"],),
            ).fetchall()
        )
        paths = tuple(
            tuple(str(part) for part in item["path"])
            for item in connection.execute(
                """
                SELECT path FROM dependency_paths
                WHERE package_instance_id = %s
                ORDER BY cardinality(path), path
                """,
                (row["package_id"],),
            ).fetchall()
        )
        evidence_records = ExposureRepository._evidence_records(
            connection,
            assessment_run_id=UUID(str(row["assessment_run_id"])),
            exposure_id=UUID(str(row["id"])),
        )
        return ExposureRecord(
            id=UUID(str(row["id"])),
            assessment_run_id=UUID(str(row["assessment_run_id"])),
            asset_snapshot_id=UUID(str(row["asset_snapshot_id"])),
            vulnerability_record=VulnerabilityRecordRecord(
                id=UUID(str(row["vulnerability_record_id"])), aliases=aliases
            ),
            package=PackageInstanceRecord(
                name=str(row["name"]),
                version=str(row["version"]),
                direct=(bool(row["direct"]) if row["direct"] is not None else None),
                source=json.loads(str(row["source"])),
                dependency_paths=paths if row["direct"] is not None else None,
            ),
            ranking=ExposureRanking(
                severity=ExposureSeverity(str(row["severity"])),
                direct_dependency=(
                    bool(row["direct_dependency"]) if row["direct_dependency"] is not None else None
                ),
                dependency_depth=(
                    int(row["dependency_depth"]) if row["dependency_depth"] is not None else None
                ),
                fixed_version_available=bool(row["fixed_version_available"]),
                score=int(row["ranking_score"]),
            ),
            rank=int(row["rank"]),
            selected_for_investigation=bool(row["selected_for_investigation"]),
            authoritative_conflict=bool(row["authoritative_conflict"]),
            evidence_records=evidence_records,
        )

    @staticmethod
    def _evidence_records(
        connection: psycopg.Connection[Any],
        *,
        assessment_run_id: UUID,
        exposure_id: UUID,
    ) -> tuple[EvidenceRecordRecord, ...]:
        rows = connection.execute(
            """
            SELECT evidence_records.id, evidence_records.identity_key,
                   evidence_records.captured_at, evidence_records.content_digest,
                   evidence_records.attribution, evidence_records.aliases,
                   evidence_records.payload_identity, evidence_records.content,
                   sources.identity_key AS source_identity, sources.authority,
                   sources.location, assessment_run_exposure_evidence.relationship
            FROM assessment_run_exposure_evidence
            JOIN evidence_records
              ON evidence_records.id = assessment_run_exposure_evidence.evidence_record_id
            JOIN sources ON sources.id = evidence_records.source_id
            WHERE assessment_run_exposure_evidence.assessment_run_id = %s
              AND assessment_run_exposure_evidence.exposure_id = %s
            ORDER BY evidence_records.identity_key
            """,
            (assessment_run_id, exposure_id),
        ).fetchall()
        records: list[EvidenceRecordRecord] = []
        for evidence in rows:
            passages = connection.execute(
                """
                SELECT evidence_passages.id, evidence_passages.identity_key,
                       evidence_passages.kind, evidence_passages.selector,
                       evidence_passages.content
                FROM assessment_run_exposure_passages
                JOIN evidence_passages
                  ON evidence_passages.id = assessment_run_exposure_passages.passage_id
                WHERE assessment_run_exposure_passages.assessment_run_id = %s
                  AND assessment_run_exposure_passages.exposure_id = %s
                  AND assessment_run_exposure_passages.evidence_record_id = %s
                ORDER BY
                    CASE evidence_passages.kind
                        WHEN 'publication' THEN 0
                        WHEN 'affected' THEN 1
                        WHEN 'affected_guidance' THEN 1
                        ELSE 2
                    END,
                    evidence_passages.selector,
                    evidence_passages.identity_key
                """,
                (assessment_run_id, exposure_id, evidence["id"]),
            ).fetchall()
            records.append(
                EvidenceRecordRecord(
                    id=UUID(str(evidence["id"])),
                    identity=str(evidence["identity_key"]),
                    source=SourceRecord(
                        identity=str(evidence["source_identity"]),
                        authority=str(evidence["authority"]),
                        location=str(evidence["location"]),
                    ),
                    captured_at=evidence["captured_at"],
                    content_digest=str(evidence["content_digest"]),
                    attribution=str(evidence["attribution"]),
                    aliases=tuple(str(alias) for alias in evidence["aliases"]),
                    payload_identity=str(evidence["payload_identity"]),
                    content=str(evidence["content"]),
                    relationship=EvidenceRelationship(str(evidence["relationship"])),
                    passages=tuple(
                        EvidencePassageRecord(
                            id=UUID(str(passage["id"])),
                            identity=str(passage["identity_key"]),
                            kind=str(passage["kind"]),
                            selector=str(passage["selector"]),
                            content=str(passage["content"]),
                        )
                        for passage in passages
                    ),
                )
            )
        return tuple(records)
