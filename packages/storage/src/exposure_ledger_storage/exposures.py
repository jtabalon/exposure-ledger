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
    ExposureRanking,
    ExposureSeverity,
    VulnerabilityRecord,
)
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from exposure_ledger_storage.asset_snapshots import PackageInstanceRecord


@dataclass(frozen=True, slots=True)
class VulnerabilityRecordRecord:
    id: UUID
    aliases: tuple[str, ...]


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
                        fixed_version_available, ranking_score
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    ),
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
                       assessment_run_exposures.ranking_score
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
        )
