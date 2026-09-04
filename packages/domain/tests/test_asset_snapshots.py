from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from exposure_ledger import (
    Architecture,
    AssetSnapshotCapture,
    AssetSnapshotRejected,
    CaptureAssetSnapshot,
    EnvironmentProfile,
    OperatingSystem,
    RepositoryArchive,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "uv_repository"


class FixtureArchiveSource:
    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        assert repository == "https://github.com/example/exposure-fixture"
        assert commit == "0123456789abcdef0123456789abcdef01234567"
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in sorted(FIXTURE_ROOT.rglob("*")):
                if path.is_file():
                    archive.write(
                        path, f"exposure-fixture-{commit}/{path.relative_to(FIXTURE_ROOT)}"
                    )
        return RepositoryArchive(content=buffer.getvalue())


def test_supported_uv_repository_produces_a_normalized_asset_snapshot_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    request = CaptureAssetSnapshot(
        repository="https://github.com/Example/Exposure-Fixture.git",
        commit="0123456789ABCDEF0123456789ABCDEF01234567",
        project_root="services/api",
        lockfile_path="services/api/uv.lock",
        environment_profile=EnvironmentProfile(
            python_version="3.12.2",
            operating_system=OperatingSystem.LINUX,
            architecture=Architecture.X86_64,
            selected_extras=("security",),
        ),
    )

    snapshot = AssetSnapshotCapture(
        FixtureArchiveSource(),
        clock=lambda: datetime(2026, 9, 3, 20, 0, tzinfo=UTC),
    ).capture(request)

    assert snapshot.repository == "https://github.com/example/exposure-fixture"
    assert snapshot.commit == "0123456789abcdef0123456789abcdef01234567"
    assert snapshot.project_root == "services/api"
    assert snapshot.lockfile_path == "services/api/uv.lock"
    assert snapshot.lockfile_digest == (
        "sha256:390d60e25c213f27f05ab252c870719ddece955b9af3689a9d77dc546edab685"
    )
    assert snapshot.captured_at == datetime(2026, 9, 3, 20, 0, tzinfo=UTC)
    assert [
        (package.name, package.version, package.direct, package.dependency_paths)
        for package in snapshot.packages
    ] == [
        ("feature-lib", "5.1.0", True, (("demo-app", "feature-lib"),)),
        ("http-x", "2.3.0", True, (("demo-app", "http-x"),)),
        ("leaf-lib", "1.0.0", False, (("demo-app", "http-x", "leaf-lib"),)),
        ("platform-only", "4.0.0", True, (("demo-app", "platform-only"),)),
    ]
    assert not (tmp_path / "REPOSITORY_CONTENT_WAS_EXECUTED").exists()
    assert not (tmp_path / "REPOSITORY_CONTENT_WAS_IMPORTED").exists()


@pytest.mark.parametrize(
    "repository",
    [
        "http://github.com/example/project",
        "https://github.com/example/project/tree/main",
        "https://user@github.com/example/project",
        "https://github.com.evil.test/example/project",
    ],
)
def test_capture_rejects_noncanonical_public_repository_targets(repository: str) -> None:
    with pytest.raises(AssetSnapshotRejected, match="canonical public GitHub repository") as error:
        AssetSnapshotCapture(FixtureArchiveSource()).capture(
            CaptureAssetSnapshot(
                repository=repository,
                commit="0123456789abcdef0123456789abcdef01234567",
                project_root="services/api",
                lockfile_path="services/api/uv.lock",
                environment_profile=EnvironmentProfile(
                    python_version="3.12",
                    operating_system=OperatingSystem.LINUX,
                    architecture=Architecture.X86_64,
                ),
            )
        )

    assert error.value.code == "invalid_repository"
