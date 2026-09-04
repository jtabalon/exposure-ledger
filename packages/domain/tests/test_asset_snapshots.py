from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from stat import S_IFLNK

import pytest
from exposure_ledger import (
    Architecture,
    ArchiveLimits,
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


class BytesArchiveSource:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.archive: RepositoryArchive | None = None

    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        self.archive = RepositoryArchive(content=self.content)
        return self.archive


def capture_request(
    *, lockfile_path: str = "uv.lock", project_root: str = "."
) -> CaptureAssetSnapshot:
    return CaptureAssetSnapshot(
        repository="https://github.com/example/project",
        commit="0123456789abcdef0123456789abcdef01234567",
        project_root=project_root,
        lockfile_path=lockfile_path,
        environment_profile=EnvironmentProfile(
            python_version="3.12.2",
            operating_system=OperatingSystem.LINUX,
            architecture=Architecture.X86_64,
        ),
    )


def archive_bytes(files: dict[str, str], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


def capture_lock(lockfile: str) -> tuple[tuple[str, str, tuple[tuple[str, ...], ...]], ...]:
    content = archive_bytes({"project-root/uv.lock": lockfile})
    snapshot = AssetSnapshotCapture(BytesArchiveSource(content)).capture(capture_request())
    return tuple(
        (package.name, package.version, package.dependency_paths) for package in snapshot.packages
    )


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
        "sha256:9ecd0209306e7e59e67eaf9f4aaed668726f42209685c974ca363345e18d9542"
    )
    assert snapshot.captured_at == datetime(2026, 9, 3, 20, 0, tzinfo=UTC)
    assert "general shell tool" not in snapshot.lockfile_content
    assert "Run setup.py" not in snapshot.lockfile_content
    assert 'tools = ["general_shell", "unrestricted_http"]' in snapshot.lockfile_content
    assert not hasattr(snapshot, "instructions")
    assert not hasattr(snapshot, "tools")
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


def test_capture_closes_the_repository_archive_after_success() -> None:
    source = BytesArchiveSource(
        archive_bytes(
            {
                "project-root/uv.lock": """
version = 1

[[package]]
name = "project"
source = { virtual = "." }
"""
            }
        )
    )

    AssetSnapshotCapture(source).capture(capture_request())

    assert source.archive is not None
    assert source.archive.closed is True


def test_capture_closes_the_repository_archive_after_rejection() -> None:
    source = BytesArchiveSource(archive_bytes({"project-root/uv.lock": "not valid TOML ["}))

    with pytest.raises(AssetSnapshotRejected):
        AssetSnapshotCapture(source).capture(capture_request())

    assert source.archive is not None
    assert source.archive.closed is True


def test_capture_returns_a_typed_rejection_for_corrupted_archive_content() -> None:
    content = archive_bytes({"project-root/uv.lock": "version = 1"})
    corrupted = content.replace(b"version = 1", b"version = 2", 1)
    source = BytesArchiveSource(corrupted)

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(source).capture(capture_request())

    assert error.value.code == "invalid_archive"
    assert source.archive is not None
    assert source.archive.closed is True


def test_capture_returns_a_typed_rejection_for_excessively_nested_toml() -> None:
    nested_value = "[" * 2_000 + "0" + "]" * 2_000
    source = BytesArchiveSource(
        archive_bytes({"project-root/uv.lock": f"version = 1\nvalue = {nested_value}"})
    )

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(source).capture(capture_request())

    assert error.value.code == "invalid_lockfile"
    assert source.archive is not None
    assert source.archive.closed is True


def test_explicit_lockfile_selection_never_merges_other_project_dependencies() -> None:
    first_lock = """
version = 1

[[package]]
name = "first-project"
source = { virtual = "." }
dependencies = [{ name = "first-only" }]

[[package]]
name = "first-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    second_lock = """
version = 1

[[package]]
name = "second-project"
source = { virtual = "." }
dependencies = [{ name = "second-only" }]

[[package]]
name = "second-only"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    source = BytesArchiveSource(
        archive_bytes(
            {
                "project-root/services/first/uv.lock": first_lock,
                "project-root/services/second/uv.lock": second_lock,
            }
        )
    )

    snapshot = AssetSnapshotCapture(source).capture(
        capture_request(
            project_root="services/second",
            lockfile_path="services/second/uv.lock",
        )
    )

    assert [(package.name, package.version) for package in snapshot.packages] == [
        ("second-only", "2.0.0")
    ]


def test_selected_lockfile_rejects_multiple_matching_project_roots() -> None:
    source = BytesArchiveSource(
        archive_bytes(
            {
                "project-root/uv.lock": """
version = 1

[[package]]
name = "first-project"
source = { virtual = "." }

[[package]]
name = "second-project"
source = { editable = "." }
"""
            }
        )
    )

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(source).capture(capture_request())

    assert error.value.code == "ambiguous_project_root"


@pytest.mark.parametrize(
    "repository",
    [
        "http://github.com/example/project",
        "https://github.com/example/project/tree/main",
        "https://user@github.com/example/project",
        "https://github.com.evil.test/example/project",
        "https://github.com:bad/example/project",
        "https://[github.com/example/project",
        "https://github.com/../project",
        "https://github.com/example/..",
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


def test_distinct_same_name_instances_remain_reachable_in_one_dependency_path() -> None:
    packages = capture_lock(
        """
version = 1
requires-python = ">=3.12"

[[package]]
name = "project"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "shared", version = "1.0.0", source = { registry = "https://pypi.org/simple" } },
]

[[package]]
name = "shared"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "shared", version = "2.0.0", source = { git = "https://example.test/shared" } },
]

[[package]]
name = "shared"
version = "2.0.0"
source = { git = "https://example.test/shared" }
"""
    )

    assert packages == (
        ("shared", "1.0.0", (("project", "shared"),)),
        ("shared", "2.0.0", (("project", "shared", "shared"),)),
    )


def test_project_source_paths_are_resolved_relative_to_nested_lockfile() -> None:
    lockfile = """
version = 1

[[package]]
name = "shared-project"
version = "0.1.0"
source = { editable = "../shared" }
dependencies = [{ name = "dependency" }]

[[package]]
name = "dependency"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    content = archive_bytes({"project-root/services/api/uv.lock": lockfile})

    snapshot = AssetSnapshotCapture(BytesArchiveSource(content)).capture(
        capture_request(lockfile_path="services/api/uv.lock", project_root="services/shared")
    )

    assert snapshot.packages[0].dependency_paths == (("shared-project", "dependency"),)


def test_versionless_virtual_project_root_normalizes_its_versioned_dependencies() -> None:
    packages = capture_lock(
        """
version = 1

[[package]]
name = "virtual-project"
source = { virtual = "." }
dependencies = [{ name = "dependency" }]

[[package]]
name = "dependency"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    )

    assert packages == (("dependency", "1.0.0", (("virtual-project", "dependency"),)),)


def test_dependency_path_ceiling_counts_versionless_nodes() -> None:
    content = archive_bytes(
        {
            "project-root/uv.lock": """
version = 1

[[package]]
name = "project"
source = { virtual = "." }
dependencies = [{ name = "virtual-bridge" }]

[[package]]
name = "virtual-bridge"
source = { virtual = "bridge" }
dependencies = [{ name = "dependency" }]

[[package]]
name = "dependency"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
        }
    )

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(
            BytesArchiveSource(content),
            limits=ArchiveLimits(max_dependency_paths=1),
        ).capture(capture_request())

    assert error.value.code == "dependency_graph_too_large"


@pytest.mark.parametrize(
    ("operating_system", "architecture", "machine"),
    [
        (OperatingSystem.LINUX, Architecture.AMD64, "x86_64"),
        (OperatingSystem.LINUX, Architecture.ARM64, "aarch64"),
        (OperatingSystem.MACOS, Architecture.AARCH64, "arm64"),
        (OperatingSystem.WINDOWS, Architecture.X86_64, "AMD64"),
    ],
)
def test_supported_markers_use_exact_python_and_os_machine_values(
    operating_system: OperatingSystem,
    architecture: Architecture,
    machine: str,
) -> None:
    marker = f"python_full_version == '3.13.0rc1' and platform_machine == '{machine}'"
    lockfile = f"""
version = 1

[[package]]
name = "project"
source = {{ virtual = "." }}
dependencies = [
    {{ name = "matched", marker = "{marker}" }},
]

[[package]]
name = "matched"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
"""
    content = archive_bytes({"project-root/uv.lock": lockfile})
    request = CaptureAssetSnapshot(
        repository="https://github.com/example/project",
        commit="0123456789abcdef0123456789abcdef01234567",
        project_root=".",
        lockfile_path="uv.lock",
        environment_profile=EnvironmentProfile(
            python_version="3.13.0rc1",
            operating_system=operating_system,
            architecture=architecture,
        ),
    )

    snapshot = AssetSnapshotCapture(BytesArchiveSource(content)).capture(request)

    assert [package.name for package in snapshot.packages] == ["matched"]


def test_capture_rejects_markers_that_depend_on_unpinned_environment_fields() -> None:
    with pytest.raises(AssetSnapshotRejected) as error:
        capture_lock(
            """
version = 1

[[package]]
name = "project"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "implementation-package", marker = "implementation_name == 'cpython'" },
]

[[package]]
name = "implementation-package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
        )

    assert error.value.code == "unsupported_environment_marker"


def test_capture_returns_a_typed_rejection_for_excessively_nested_markers() -> None:
    marker = "(" * 2_000 + "python_version >= '3.12'" + ")" * 2_000
    content = archive_bytes(
        {
            "project-root/uv.lock": f"""
version = 1

[[package]]
name = "project"
source = {{ virtual = "." }}
dependencies = [{{ name = "dependency", marker = "{marker}" }}]

[[package]]
name = "dependency"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
"""
        }
    )

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(BytesArchiveSource(content)).capture(capture_request())

    assert error.value.code == "environment_marker_too_complex"


@pytest.mark.parametrize(
    ("content", "limits", "code"),
    [
        (
            archive_bytes({"project-root/../escape": "bad"}),
            ArchiveLimits(),
            "unsafe_archive_path",
        ),
        (
            archive_bytes({"first/uv.lock": "version = 1", "second/file": "bad"}),
            ArchiveLimits(),
            "invalid_archive",
        ),
        (
            archive_bytes({"project-root/a": "a", "project-root/uv.lock": "version = 1"}),
            ArchiveLimits(max_file_count=1),
            "archive_too_many_files",
        ),
        (
            archive_bytes({"project-root/uv.lock": "version = 1"}),
            ArchiveLimits(max_compressed_bytes=1),
            "archive_too_large",
        ),
        (
            archive_bytes({"project-root/uv.lock": "version = 1"}),
            ArchiveLimits(max_expanded_bytes=1),
            "archive_too_large",
        ),
        (
            archive_bytes({"project-root/uv.lock": "version = 1"}),
            ArchiveLimits(max_lockfile_bytes=1),
            "lockfile_too_large",
        ),
        (
            archive_bytes({"project-root/uv.lock": "A" * 1_000}, compression=zipfile.ZIP_DEFLATED),
            ArchiveLimits(max_compression_ratio=2),
            "archive_compression_ratio_exceeded",
        ),
    ],
)
def test_capture_rejects_unsafe_or_oversized_archives(
    content: bytes, limits: ArchiveLimits, code: str
) -> None:
    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(BytesArchiveSource(content), limits=limits).capture(capture_request())

    assert error.value.code == code


def test_capture_rejects_archive_links() -> None:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        link = zipfile.ZipInfo("project-root/link")
        link.create_system = 3
        link.external_attr = (S_IFLNK | 0o777) << 16
        archive.writestr(link, "uv.lock")

    with pytest.raises(AssetSnapshotRejected) as error:
        AssetSnapshotCapture(BytesArchiveSource(buffer.getvalue())).capture(capture_request())

    assert error.value.code == "unsafe_archive_link"
