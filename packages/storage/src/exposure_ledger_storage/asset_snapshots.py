"""PostgreSQL persistence for immutable Asset Snapshots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import (
    Architecture,
    AssetSnapshot,
    EnvironmentProfile,
    OperatingSystem,
)
from psycopg.rows import dict_row, tuple_row


@dataclass(frozen=True, slots=True)
class PackageInstanceRecord:
    name: str
    version: str
    direct: bool | None
    source: dict[str, Any]
    dependency_paths: tuple[tuple[str, ...], ...] | None


@dataclass(frozen=True, slots=True)
class AssetSnapshotRecord:
    id: UUID
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    lockfile_digest: str
    environment_profile: EnvironmentProfile
    packages: tuple[PackageInstanceRecord, ...]
    parser_version: str
    captured_at: datetime


class AssetSnapshotRepository:
    """Persist and load immutable Asset Snapshots as one aggregate."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url) as connection:
                connection.execute("SELECT EXISTS (SELECT 1 FROM asset_snapshots)")
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error

    def create(self, snapshot: AssetSnapshot) -> AssetSnapshotRecord:
        environment_id = self._environment_id(snapshot.environment_profile)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            candidate_id = uuid4()
            inserted = connection.execute(
                """
                INSERT INTO asset_snapshots (
                    id, repository, commit_sha, project_root, lockfile_path,
                    lockfile_digest, lockfile_content, project_file_path,
                    project_file_digest, project_file_content, environment_profile_id,
                    parser_version, captured_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (
                    repository, commit_sha, project_root, lockfile_path,
                    lockfile_digest, environment_profile_id
                ) DO NOTHING
                RETURNING id
                """,
                (
                    candidate_id,
                    snapshot.repository,
                    snapshot.commit,
                    snapshot.project_root,
                    snapshot.lockfile_path,
                    snapshot.lockfile_digest,
                    snapshot.lockfile_content,
                    snapshot.project_file.path if snapshot.project_file is not None else None,
                    snapshot.project_file.digest if snapshot.project_file is not None else None,
                    snapshot.project_file.content if snapshot.project_file is not None else None,
                    environment_id,
                    snapshot.parser_version,
                    snapshot.captured_at,
                ),
            ).fetchone()
            if inserted is not None:
                snapshot_id = UUID(str(inserted[0]))
            else:
                existing = connection.execute(
                    """
                    SELECT id FROM asset_snapshots
                    WHERE repository = %s AND commit_sha = %s AND project_root = %s
                      AND lockfile_path = %s AND lockfile_digest = %s
                      AND environment_profile_id = %s
                    """,
                    (
                        snapshot.repository,
                        snapshot.commit,
                        snapshot.project_root,
                        snapshot.lockfile_path,
                        snapshot.lockfile_digest,
                        environment_id,
                    ),
                ).fetchone()
                assert existing is not None
                snapshot_id = UUID(str(existing[0]))
            if inserted is not None:
                for package in snapshot.packages:
                    package_id = uuid4()
                    connection.execute(
                        """
                        INSERT INTO package_instances (
                            id, asset_snapshot_id, name, version, direct, source
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            package_id,
                            snapshot_id,
                            package.name,
                            package.version,
                            package.direct,
                            json.dumps(
                                package.source.as_dict(), sort_keys=True, separators=(",", ":")
                            ),
                        ),
                    )
                    if package.dependency_paths is not None:
                        with connection.cursor() as cursor:
                            cursor.executemany(
                                """
                                INSERT INTO dependency_paths (package_instance_id, path)
                                VALUES (%s, %s)
                                """,
                                [(package_id, list(path)) for path in package.dependency_paths],
                            )
                connection.execute(
                    "UPDATE asset_snapshots SET sealed = true WHERE id = %s",
                    (snapshot_id,),
                )
        record = self.get(snapshot_id)
        assert record is not None
        return record

    def get(self, snapshot_id: UUID) -> AssetSnapshotRecord | None:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                SELECT asset_snapshots.id, asset_snapshots.repository,
                       asset_snapshots.commit_sha, asset_snapshots.project_root,
                       asset_snapshots.lockfile_path, asset_snapshots.lockfile_digest,
                       asset_snapshots.parser_version, asset_snapshots.captured_at,
                       environment_profiles.python_version,
                       environment_profiles.operating_system,
                       environment_profiles.architecture,
                       environment_profiles.selected_extras
                FROM asset_snapshots
                JOIN environment_profiles
                  ON environment_profiles.id = asset_snapshots.environment_profile_id
                WHERE asset_snapshots.id = %s AND asset_snapshots.sealed
                """,
                (snapshot_id,),
            ).fetchone()
            if row is None:
                return None
            package_rows = connection.execute(
                """
                SELECT id, name, version, direct, source
                FROM package_instances
                WHERE asset_snapshot_id = %s
                ORDER BY name, version, source
                """,
                (snapshot_id,),
            ).fetchall()
            packages = []
            for package in package_rows:
                path_rows = connection.execute(
                    """
                    SELECT path
                    FROM dependency_paths
                    WHERE package_instance_id = %s
                    ORDER BY cardinality(path), path
                    """,
                    (package["id"],),
                ).fetchall()
                packages.append(
                    PackageInstanceRecord(
                        name=str(package["name"]),
                        version=str(package["version"]),
                        direct=(bool(package["direct"]) if package["direct"] is not None else None),
                        source=json.loads(str(package["source"])),
                        dependency_paths=(
                            tuple(tuple(item["path"]) for item in path_rows)
                            if package["direct"] is not None
                            else None
                        ),
                    )
                )
            return AssetSnapshotRecord(
                id=UUID(str(row["id"])),
                repository=str(row["repository"]),
                commit=str(row["commit_sha"]).strip(),
                project_root=str(row["project_root"]),
                lockfile_path=str(row["lockfile_path"]),
                lockfile_digest=str(row["lockfile_digest"]),
                environment_profile=EnvironmentProfile(
                    python_version=str(row["python_version"]),
                    operating_system=OperatingSystem(str(row["operating_system"])),
                    architecture=Architecture(str(row["architecture"])),
                    selected_extras=tuple(row["selected_extras"]),
                ),
                packages=tuple(packages),
                parser_version=str(row["parser_version"]),
                captured_at=row["captured_at"],
            )

    def list(self) -> list[AssetSnapshotRecord]:
        with psycopg.connect(self._database_url, row_factory=tuple_row) as connection:
            ids = [
                UUID(str(row[0]))
                for row in connection.execute(
                    """
                    SELECT id FROM asset_snapshots
                    WHERE sealed
                    ORDER BY captured_at DESC, id DESC
                    """
                ).fetchall()
            ]
        return [record for snapshot_id in ids if (record := self.get(snapshot_id)) is not None]

    def _environment_id(self, profile: EnvironmentProfile) -> UUID:
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            candidate_id = uuid4()
            inserted = connection.execute(
                """
                INSERT INTO environment_profiles (
                    id, python_version, operating_system, architecture, selected_extras
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (
                    python_version, operating_system, architecture, selected_extras
                ) DO NOTHING
                RETURNING id
                """,
                (
                    candidate_id,
                    profile.python_version,
                    profile.operating_system,
                    profile.architecture,
                    list(profile.selected_extras),
                ),
            ).fetchone()
            if inserted is not None:
                return UUID(str(inserted[0]))
            existing = connection.execute(
                """
                SELECT id FROM environment_profiles
                WHERE python_version = %s AND operating_system = %s
                  AND architecture = %s AND selected_extras = %s
                """,
                (
                    profile.python_version,
                    profile.operating_system,
                    profile.architecture,
                    list(profile.selected_extras),
                ),
            ).fetchone()
            assert existing is not None
            return UUID(str(existing[0]))
