"""Static, no-execution capture of immutable Python Asset Snapshots."""

from __future__ import annotations

import hashlib
import re
import tomllib
import zipfile
from collections import defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.parse import urlsplit

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ASSET_SNAPSHOT_PARSER_VERSION = "uv-lock-v1"
POETRY_LOCK_PARSER_VERSION = "poetry-lock-v1"
REQUIREMENTS_PARSER_VERSION = "requirements-v1"
_COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
_REPOSITORY_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
_QUOTED_MARKER_VALUE_PATTERN = re.compile(r"'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"")
_SUPPORTED_MARKER_VARIABLES = frozenset(
    {
        "extra",
        "os_name",
        "platform_machine",
        "platform_system",
        "python_full_version",
        "python_version",
        "sys_platform",
    }
)
_ALL_MARKER_VARIABLES = _SUPPORTED_MARKER_VARIABLES | {
    "implementation_name",
    "implementation_version",
    "platform_python_implementation",
    "platform_release",
    "platform_version",
}


class OperatingSystem(StrEnum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"


class Architecture(StrEnum):
    AARCH64 = "aarch64"
    ARM64 = "arm64"
    AMD64 = "amd64"
    X86_64 = "x86_64"


@dataclass(frozen=True, slots=True)
class EnvironmentProfile:
    python_version: str
    operating_system: OperatingSystem
    architecture: Architecture
    selected_extras: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            normalized_version = str(Version(self.python_version))
        except InvalidVersion as error:
            raise ValueError("python_version must be a valid Python version") from error
        if len(Version(normalized_version).release) < 2:
            raise ValueError("python_version must include a major and minor version")
        normalized_extras = tuple(
            sorted({canonicalize_name(extra) for extra in self.selected_extras})
        )
        if any(not extra for extra in normalized_extras):
            raise ValueError("selected_extras must contain valid extra names")
        object.__setattr__(self, "python_version", normalized_version)
        object.__setattr__(self, "selected_extras", normalized_extras)


@dataclass(frozen=True, slots=True)
class CaptureAssetSnapshot:
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    environment_profile: EnvironmentProfile


@dataclass(frozen=True, slots=True)
class RepositoryArchive:
    content: bytes


class RepositoryArchiveSource(Protocol):
    def fetch(self, repository: str, commit: str) -> RepositoryArchive: ...


class RepositoryArchiveUnavailable(RuntimeError):
    """The approved public repository archive could not be retrieved."""


@dataclass(frozen=True, slots=True, order=True)
class PackageSource:
    fields: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, str]:
        return dict(self.fields)


@dataclass(frozen=True, slots=True)
class PackageInstance:
    name: str
    version: str
    direct: bool | None
    source: PackageSource
    dependency_paths: tuple[tuple[str, ...], ...] | None


@dataclass(frozen=True, slots=True)
class AssetSnapshot:
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    lockfile_digest: str
    lockfile_content: str = field(repr=False)
    project_file_path: str | None
    project_file_digest: str | None
    project_file_content: str | None = field(repr=False)
    environment_profile: EnvironmentProfile
    packages: tuple[PackageInstance, ...]
    parser_version: str
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_compressed_bytes: int = 10 * 1024 * 1024
    max_expanded_bytes: int = 50 * 1024 * 1024
    max_file_count: int = 5_000
    max_lockfile_bytes: int = 5 * 1024 * 1024
    max_compression_ratio: int = 100
    max_dependency_paths: int = 10_000


class AssetSnapshotRejected(ValueError):
    """A typed, safe rejection at the Asset Snapshot boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _LockedPackage:
    key: tuple[str, str | None, PackageSource]
    name: str
    version: str | None
    source: PackageSource
    data: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _PoetryPackage:
    key: tuple[str, str, PackageSource]
    name: str
    version: str
    source: PackageSource
    data: Mapping[str, Any]


class AssetSnapshotCapture:
    """Capture an archive as immutable dependency data without extracting or executing it."""

    def __init__(
        self,
        archive_source: RepositoryArchiveSource,
        *,
        limits: ArchiveLimits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._archive_source = archive_source
        self._limits = limits or ArchiveLimits()
        self._clock = clock or (lambda: datetime.now(UTC))

    def capture(self, request: CaptureAssetSnapshot) -> AssetSnapshot:
        validated = validate_asset_snapshot_request(request)

        archive = self._archive_source.fetch(validated.repository, validated.commit)
        project_file_path = (
            str(PurePosixPath(validated.project_root) / "pyproject.toml")
            if PurePosixPath(validated.lockfile_path).name == "poetry.lock"
            else None
        )
        if project_file_path == "pyproject.toml" and validated.project_root == ".":
            project_file_path = "pyproject.toml"
        lockfile_bytes, project_file_bytes = _read_snapshot_files_from_archive(
            archive.content,
            lockfile_path=validated.lockfile_path,
            project_file_path=project_file_path,
            limits=self._limits,
        )
        try:
            lockfile_content = lockfile_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssetSnapshotRejected(
                "invalid_lockfile", "selected dependency data must be valid UTF-8 text."
            ) from error

        filename = PurePosixPath(validated.lockfile_path).name
        project_file_content: str | None = None
        if filename == "uv.lock":
            packages = _parse_uv_lock(
                lockfile_content,
                project_root=validated.project_root,
                lockfile_path=validated.lockfile_path,
                environment=validated.environment_profile,
                max_dependency_paths=self._limits.max_dependency_paths,
            )
            parser_version = ASSET_SNAPSHOT_PARSER_VERSION
        elif filename == "poetry.lock":
            assert project_file_bytes is not None
            try:
                project_file_content = project_file_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise AssetSnapshotRejected(
                    "invalid_project_file", "pyproject.toml must be valid UTF-8 text."
                ) from error
            packages = _parse_poetry_lock(
                lockfile_content,
                project_file_content=project_file_content,
                environment=validated.environment_profile,
                max_dependency_paths=self._limits.max_dependency_paths,
            )
            parser_version = POETRY_LOCK_PARSER_VERSION
        else:
            packages = _parse_requirements(
                lockfile_content,
                lockfile_path=validated.lockfile_path,
                environment=validated.environment_profile,
            )
            parser_version = REQUIREMENTS_PARSER_VERSION
        return AssetSnapshot(
            repository=validated.repository,
            commit=validated.commit,
            project_root=validated.project_root,
            lockfile_path=validated.lockfile_path,
            lockfile_digest=f"sha256:{hashlib.sha256(lockfile_bytes).hexdigest()}",
            lockfile_content=lockfile_content,
            project_file_path=project_file_path,
            project_file_digest=(
                f"sha256:{hashlib.sha256(project_file_bytes).hexdigest()}"
                if project_file_bytes is not None
                else None
            ),
            project_file_content=project_file_content,
            environment_profile=validated.environment_profile,
            packages=packages,
            parser_version=parser_version,
            captured_at=self._clock(),
        )


def validate_asset_snapshot_request(request: CaptureAssetSnapshot) -> CaptureAssetSnapshot:
    """Validate and canonicalize an Asset Snapshot request without retrieving content."""
    repository = _canonical_repository(request.repository)
    commit = _immutable_commit(request.commit)
    project_root = _safe_relative_path(request.project_root, allow_root=True)
    lockfile_path = _safe_relative_path(request.lockfile_path, allow_root=False)
    filename = PurePosixPath(lockfile_path).name
    if filename not in {"uv.lock", "poetry.lock", "requirements.txt"} and not (
        filename.startswith("requirements-") and filename.endswith(".txt")
    ):
        raise AssetSnapshotRejected(
            "unsupported_lockfile",
            "Only uv.lock, poetry.lock, requirements.txt, and requirements-*.txt are supported.",
        )
    return CaptureAssetSnapshot(
        repository=repository,
        commit=commit,
        project_root=project_root,
        lockfile_path=lockfile_path,
        environment_profile=request.environment_profile,
    )


def _canonical_repository(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise AssetSnapshotRejected(
            "invalid_repository",
            "repository must identify a canonical public GitHub repository",
        ) from error
    if (
        parsed.scheme != "https"
        or hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AssetSnapshotRejected(
            "invalid_repository",
            "repository must identify a canonical public GitHub repository",
        )
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise AssetSnapshotRejected(
            "invalid_repository",
            "repository must identify a canonical public GitHub repository",
        )
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not all(
        segment and _REPOSITORY_SEGMENT_PATTERN.fullmatch(segment)
        for segment in (owner, repository)
    ):
        raise AssetSnapshotRejected(
            "invalid_repository",
            "repository must identify a canonical public GitHub repository",
        )
    return f"https://github.com/{owner.lower()}/{repository.lower()}"


def _immutable_commit(value: str) -> str:
    if _COMMIT_PATTERN.fullmatch(value) is None:
        raise AssetSnapshotRejected(
            "invalid_commit", "commit must be a complete 40-character Git object ID"
        )
    return value.lower()


def _safe_relative_path(value: str, *, allow_root: bool) -> str:
    if "\\" in value or "\x00" in value:
        raise AssetSnapshotRejected("invalid_repository_path", "repository paths must be safe")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise AssetSnapshotRejected("invalid_repository_path", "repository paths must be safe")
    normalized = str(path)
    if normalized in {"", "."}:
        if allow_root:
            return "."
        raise AssetSnapshotRejected("invalid_repository_path", "repository paths must be safe")
    return normalized.removeprefix("./")


def _read_snapshot_files_from_archive(
    content: bytes,
    *,
    lockfile_path: str,
    project_file_path: str | None,
    limits: ArchiveLimits,
) -> tuple[bytes, bytes | None]:
    if len(content) > limits.max_compressed_bytes:
        raise AssetSnapshotRejected("archive_too_large", "repository archive exceeds size limit")
    try:
        archive = zipfile.ZipFile(BytesIO(content))
    except (zipfile.BadZipFile, OSError) as error:
        raise AssetSnapshotRejected(
            "invalid_archive", "repository archive is not a valid ZIP"
        ) from error

    with archive:
        members = archive.infolist()
        files = [member for member in members if not member.is_dir()]
        if len(files) > limits.max_file_count:
            raise AssetSnapshotRejected(
                "archive_too_many_files", "repository archive has too many files"
            )
        if sum(member.file_size for member in files) > limits.max_expanded_bytes:
            raise AssetSnapshotRejected(
                "archive_too_large", "expanded repository exceeds size limit"
            )

        top_levels: set[str] = set()
        indexed: dict[str, zipfile.ZipInfo] = {}
        for member in members:
            path = PurePosixPath(member.filename)
            if (
                "\\" in member.filename
                or path.is_absolute()
                or not path.parts
                or ".." in path.parts
            ):
                raise AssetSnapshotRejected(
                    "unsafe_archive_path", "repository archive has unsafe paths"
                )
            if _is_symlink(member):
                raise AssetSnapshotRejected(
                    "unsafe_archive_link", "repository archive contains a link"
                )
            if member.flag_bits & 0x1:
                raise AssetSnapshotRejected(
                    "invalid_archive", "encrypted repository files are unsupported"
                )
            if (
                not member.is_dir()
                and member.file_size > 0
                and member.file_size > max(member.compress_size, 1) * limits.max_compression_ratio
            ):
                raise AssetSnapshotRejected(
                    "archive_compression_ratio_exceeded",
                    "repository archive exceeds compression ratio limit",
                )
            top_levels.add(path.parts[0])
            if not member.is_dir():
                relative = str(PurePosixPath(*path.parts[1:]))
                if relative in indexed:
                    raise AssetSnapshotRejected(
                        "invalid_archive", "repository archive contains duplicate paths"
                    )
                indexed[relative] = member

        if len(top_levels) != 1:
            raise AssetSnapshotRejected(
                "invalid_archive", "repository archive must contain one repository root"
            )
        lockfile = indexed.get(lockfile_path)
        if lockfile is None:
            raise AssetSnapshotRejected(
                "lockfile_not_found", f"{lockfile_path} was not found at the selected commit"
            )
        if lockfile.file_size > limits.max_lockfile_bytes:
            raise AssetSnapshotRejected("lockfile_too_large", "dependency data exceeds size limit")
        project_file = indexed.get(project_file_path) if project_file_path is not None else None
        if project_file_path is not None and project_file is None:
            raise AssetSnapshotRejected(
                "project_file_not_found",
                f"{project_file_path} is required to interpret poetry.lock",
            )
        if project_file is not None and project_file.file_size > limits.max_lockfile_bytes:
            raise AssetSnapshotRejected(
                "project_file_too_large", "pyproject.toml exceeds size limit"
            )
        return archive.read(lockfile), archive.read(
            project_file
        ) if project_file is not None else None


def _is_symlink(member: zipfile.ZipInfo) -> bool:
    unix_file_type = (member.external_attr >> 16) & 0o170000
    return unix_file_type == 0o120000


def _parse_uv_lock(
    content: str,
    *,
    project_root: str,
    lockfile_path: str,
    environment: EnvironmentProfile,
    max_dependency_paths: int,
) -> tuple[PackageInstance, ...]:
    try:
        document = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise AssetSnapshotRejected("invalid_lockfile", "uv.lock is not valid TOML") from error
    if document.get("version") != 1:
        raise AssetSnapshotRejected("unsupported_lockfile", "uv.lock format version is unsupported")
    _validate_requires_python(document.get("requires-python"), environment)
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise AssetSnapshotRejected("invalid_lockfile", "uv.lock contains no packages")

    packages = tuple(
        package
        for package in (_locked_package(raw, environment) for raw in raw_packages)
        if package is not None
    )
    lockfile_directory = str(PurePosixPath(lockfile_path).parent)
    roots = [
        package
        for package in packages
        if _package_project_root(package.data, lockfile_directory) == project_root
    ]
    if len(roots) != 1:
        raise AssetSnapshotRejected(
            "ambiguous_project_root",
            "project_root must identify exactly one project in uv.lock",
        )
    root = roots[0]
    available_extras = {
        canonicalize_name(name)
        for name in _mapping(root.data.get("optional-dependencies"), "optional-dependencies")
    }
    unknown_extras = set(environment.selected_extras) - available_extras
    if unknown_extras:
        raise AssetSnapshotRejected(
            "unknown_extra",
            f"selected extras are not defined by the project: {', '.join(sorted(unknown_extras))}",
        )

    by_name: dict[str, list[_LockedPackage]] = defaultdict(list)
    for package in packages:
        by_name[package.name].append(package)
    for candidates in by_name.values():
        candidates.sort(key=lambda package: package.key)

    paths: dict[tuple[str, str | None, PackageSource], set[tuple[str, ...]]] = defaultdict(set)
    queue: deque[
        tuple[
            _LockedPackage,
            tuple[str, ...],
            tuple[tuple[str, str | None, PackageSource], ...],
            frozenset[str],
        ]
    ] = deque()
    for dependency in _dependencies_for(root, frozenset(environment.selected_extras), environment):
        target = _resolve_dependency(dependency, by_name)
        queue.append(
            (
                target,
                (root.name, target.name),
                (root.key, target.key),
                frozenset(_dependency_extras(dependency)),
            )
        )

    total_paths = 0
    expanded: set[tuple[tuple[str, str | None, PackageSource], tuple[str, ...], frozenset[str]]] = (
        set()
    )
    while queue:
        package, path, key_path, active_extras = queue.popleft()
        state = (package.key, path, active_extras)
        if state in expanded:
            continue
        expanded.add(state)
        if package.version is not None and path not in paths[package.key]:
            paths[package.key].add(path)
            total_paths += 1
            if total_paths > max_dependency_paths:
                raise AssetSnapshotRejected(
                    "dependency_graph_too_large", "uv.lock contains too many Dependency Paths"
                )
        for dependency in _dependencies_for(package, active_extras, environment):
            target = _resolve_dependency(dependency, by_name)
            if target.key in key_path:
                continue
            queue.append(
                (
                    target,
                    (*path, target.name),
                    (*key_path, target.key),
                    frozenset(_dependency_extras(dependency)),
                )
            )

    result = []
    for key, package_paths in paths.items():
        name, version, source = key
        assert version is not None
        ordered_paths = tuple(sorted(package_paths, key=lambda path: (len(path), path)))
        result.append(
            PackageInstance(
                name=name,
                version=version,
                direct=any(len(path) == 2 for path in ordered_paths),
                source=source,
                dependency_paths=ordered_paths,
            )
        )
    return tuple(
        sorted(result, key=lambda package: (package.name, package.version, package.source))
    )


def _locked_package(
    raw: object,
    environment: EnvironmentProfile,
) -> _LockedPackage | None:
    data = _mapping(raw, "package")
    raw_name = data.get("name")
    raw_version = data.get("version")
    raw_source = data.get("source")
    if not isinstance(raw_name, str) or (
        raw_version is not None and not isinstance(raw_version, str)
    ):
        raise AssetSnapshotRejected(
            "invalid_lockfile", "every package needs a name and an optional text version"
        )
    source = _package_source(raw_source, "package source")
    resolution_markers = data.get("resolution-markers", [])
    if not isinstance(resolution_markers, list):
        raise AssetSnapshotRejected("invalid_lockfile", "package resolution-markers must be a list")
    if resolution_markers and not any(
        _marker_applies(marker, environment, frozenset()) for marker in resolution_markers
    ):
        return None
    try:
        version = str(Version(raw_version)) if raw_version is not None else None
    except InvalidVersion as error:
        raise AssetSnapshotRejected("invalid_lockfile", "package version is invalid") from error
    name = canonicalize_name(raw_name)
    return _LockedPackage(
        key=(name, version, source), name=name, version=version, source=source, data=data
    )


def _dependencies_for(
    package: _LockedPackage,
    active_extras: frozenset[str],
    environment: EnvironmentProfile,
) -> tuple[Mapping[str, Any], ...]:
    dependencies = list(_dependency_list(package.data.get("dependencies", ())))
    optional: Mapping[str, object] = {
        canonicalize_name(name): dependencies
        for name, dependencies in _mapping(
            package.data.get("optional-dependencies"), "optional-dependencies"
        ).items()
    }
    for extra in sorted(active_extras):
        raw_dependencies = optional.get(extra, ())
        dependencies.extend(_dependency_list(raw_dependencies))
    return tuple(
        dependency
        for dependency in dependencies
        if dependency.get("marker") is None
        or _marker_applies(dependency["marker"], environment, active_extras)
    )


def _dependency_list(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        raise AssetSnapshotRejected("invalid_lockfile", "package dependencies must be a list")
    return tuple(_mapping(item, "dependency") for item in value)


def _resolve_dependency(
    dependency: Mapping[str, Any],
    by_name: Mapping[str, Sequence[_LockedPackage]],
) -> _LockedPackage:
    name = dependency.get("name")
    if not isinstance(name, str):
        raise AssetSnapshotRejected("invalid_lockfile", "dependency name is required")
    candidates = list(by_name.get(canonicalize_name(name), ()))
    version = dependency.get("version")
    if version is not None:
        if not isinstance(version, str):
            raise AssetSnapshotRejected("invalid_lockfile", "dependency version must be text")
        try:
            normalized_version = str(Version(version))
        except InvalidVersion as error:
            raise AssetSnapshotRejected(
                "invalid_lockfile", "dependency version is invalid"
            ) from error
        candidates = [
            candidate for candidate in candidates if candidate.version == normalized_version
        ]
    source = dependency.get("source")
    if source is not None:
        source_key = _package_source(source, "dependency source")
        candidates = [candidate for candidate in candidates if candidate.source == source_key]
    if len(candidates) != 1:
        raise AssetSnapshotRejected(
            "ambiguous_dependency",
            f"dependency {canonicalize_name(name)} does not identify exactly one package",
        )
    return candidates[0]


def _dependency_extras(dependency: Mapping[str, Any]) -> tuple[str, ...]:
    value = dependency.get("extra", [])
    if not isinstance(value, list):
        raise AssetSnapshotRejected("invalid_lockfile", "dependency extras must be a list")
    if not all(isinstance(extra, str) for extra in value):
        raise AssetSnapshotRejected("invalid_lockfile", "dependency extras must be names")
    return tuple(sorted({canonicalize_name(extra) for extra in value}))


def _parse_poetry_lock(
    content: str,
    *,
    project_file_content: str,
    environment: EnvironmentProfile,
    max_dependency_paths: int,
) -> tuple[PackageInstance, ...]:
    lock = _parse_toml(content, "poetry.lock")
    project = _parse_toml(project_file_content, "pyproject.toml")
    metadata = _mapping(lock.get("metadata"), "poetry.lock metadata")
    lock_version = metadata.get("lock-version")
    if lock_version not in {"1.1", "2.0", "2.1"}:
        raise AssetSnapshotRejected(
            "unsupported_lockfile", "poetry.lock format version is unsupported"
        )
    _validate_poetry_python_constraint(metadata.get("python-versions"), environment)

    root_name, root_dependencies = _poetry_root_dependencies(project, environment)
    raw_packages = lock.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise AssetSnapshotRejected("invalid_lockfile", "poetry.lock contains no packages")
    packages = tuple(
        package
        for package in (_poetry_package(raw, environment) for raw in raw_packages)
        if package is not None
    )
    by_name: dict[str, list[_PoetryPackage]] = defaultdict(list)
    for package in packages:
        by_name[package.name].append(package)
    for candidates in by_name.values():
        candidates.sort(key=lambda package: package.key)

    paths: dict[tuple[str, str, PackageSource], set[tuple[str, ...]]] = defaultdict(set)
    queue: deque[
        tuple[
            _PoetryPackage,
            tuple[str, ...],
            tuple[tuple[str, str, PackageSource], ...],
            frozenset[str],
        ]
    ] = deque()
    for name, specification in root_dependencies:
        target = _resolve_poetry_dependency(name, specification, by_name, environment)
        queue.append(
            (
                target,
                (root_name, target.name),
                (target.key,),
                frozenset(_poetry_dependency_extras(specification)),
            )
        )

    total_paths = 0
    while queue:
        package, path, key_path, active_extras = queue.popleft()
        if path in paths[package.key]:
            continue
        paths[package.key].add(path)
        total_paths += 1
        if total_paths > max_dependency_paths:
            raise AssetSnapshotRejected(
                "dependency_graph_too_large", "poetry.lock contains too many Dependency Paths"
            )
        for name, specification in _poetry_dependencies_for(package, active_extras, environment):
            target = _resolve_poetry_dependency(name, specification, by_name, environment)
            if target.key in key_path:
                continue
            queue.append(
                (
                    target,
                    (*path, target.name),
                    (*key_path, target.key),
                    frozenset(_poetry_dependency_extras(specification)),
                )
            )

    result = [
        PackageInstance(
            name=name,
            version=version,
            direct=any(len(path) == 2 for path in package_paths),
            source=source,
            dependency_paths=tuple(sorted(package_paths, key=lambda path: (len(path), path))),
        )
        for (name, version, source), package_paths in paths.items()
    ]
    return tuple(
        sorted(result, key=lambda package: (package.name, package.version, package.source))
    )


def _parse_toml(content: str, label: str) -> Mapping[str, Any]:
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise AssetSnapshotRejected("invalid_lockfile", f"{label} is not valid TOML") from error


def _poetry_root_dependencies(
    project: Mapping[str, Any], environment: EnvironmentProfile
) -> tuple[str, tuple[tuple[str, object], ...]]:
    pep_621 = project.get("project")
    if isinstance(pep_621, dict) and "dependencies" in pep_621:
        return _pep_621_root_dependencies(pep_621, environment)
    tool = project.get("tool", {})
    if not isinstance(tool, dict):
        raise AssetSnapshotRejected("invalid_project_file", "pyproject.toml tool must be a table")
    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        raise AssetSnapshotRejected(
            "unsupported_project_file", "pyproject.toml must contain a tool.poetry project"
        )
    name = poetry.get("name")
    if not isinstance(name, str) or not name:
        raise AssetSnapshotRejected("invalid_project_file", "Poetry project name is required")
    dependencies = _mapping(poetry.get("dependencies"), "Poetry project dependencies")
    _validate_poetry_python_constraint(dependencies.get("python"), environment)
    raw_extras = poetry.get("extras", {})
    extras = _mapping(raw_extras, "Poetry project extras")
    available_extras = {canonicalize_name(extra) for extra in extras}
    unknown_extras = set(environment.selected_extras) - available_extras
    if unknown_extras:
        raise AssetSnapshotRejected(
            "unknown_extra",
            f"selected extras are not defined by the project: {', '.join(sorted(unknown_extras))}",
        )
    enabled_optional: set[str] = set()
    for extra in environment.selected_extras:
        members = extras.get(extra, ())
        if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
            raise AssetSnapshotRejected(
                "invalid_project_file", "Poetry project extras must contain dependency names"
            )
        enabled_optional.update(canonicalize_name(item) for item in members)

    selected: list[tuple[str, object]] = []
    for raw_name, specification in dependencies.items():
        dependency_name = canonicalize_name(raw_name)
        if dependency_name == "python":
            continue
        variants = _poetry_dependency_variants(specification)
        active = tuple(
            variant
            for variant in variants
            if _poetry_dependency_applies(variant, environment)
            and (not bool(variant.get("optional")) or dependency_name in enabled_optional)
        )
        if len(active) > 1:
            raise AssetSnapshotRejected(
                "ambiguous_dependency",
                f"Poetry dependency {dependency_name} has overlapping environment constraints",
            )
        if active:
            selected.append((dependency_name, active[0]))
    return canonicalize_name(name), tuple(selected)


def _pep_621_root_dependencies(
    project: Mapping[str, Any], environment: EnvironmentProfile
) -> tuple[str, tuple[tuple[str, object], ...]]:
    name = project.get("name")
    if not isinstance(name, str) or not name:
        raise AssetSnapshotRejected("invalid_project_file", "project name is required")
    _validate_requires_python(project.get("requires-python"), environment)
    raw_optional = project.get("optional-dependencies", {})
    optional = _mapping(raw_optional, "project optional-dependencies")
    available_extras = {canonicalize_name(extra) for extra in optional}
    unknown_extras = set(environment.selected_extras) - available_extras
    if unknown_extras:
        raise AssetSnapshotRejected(
            "unknown_extra",
            f"selected extras are not defined by the project: {', '.join(sorted(unknown_extras))}",
        )
    raw_dependencies = project.get("dependencies")
    if not isinstance(raw_dependencies, list) or not all(
        isinstance(item, str) for item in raw_dependencies
    ):
        raise AssetSnapshotRejected(
            "invalid_project_file", "project dependencies must contain requirement strings"
        )
    dependency_strings = list(raw_dependencies)
    for extra in environment.selected_extras:
        members = optional.get(extra, ())
        if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
            raise AssetSnapshotRejected(
                "invalid_project_file",
                "project optional-dependencies must contain requirement strings",
            )
        dependency_strings.extend(members)

    dependencies: list[tuple[str, object]] = []
    for value in dependency_strings:
        try:
            requirement = Requirement(value)
        except InvalidRequirement as error:
            raise AssetSnapshotRejected(
                "invalid_project_file", "project contains an invalid dependency requirement"
            ) from error
        if requirement.url is not None:
            raise AssetSnapshotRejected(
                "unsupported_requirement_source", "Poetry project direct URLs are unsupported"
            )
        specification: dict[str, Any] = {
            "version": str(requirement.specifier) or "*",
            "extras": sorted(requirement.extras),
        }
        if requirement.marker is not None:
            specification["markers"] = str(requirement.marker)
        if _poetry_dependency_applies(specification, environment):
            dependencies.append((canonicalize_name(requirement.name), specification))
    return canonicalize_name(name), tuple(dependencies)


def _poetry_package(raw: object, environment: EnvironmentProfile) -> _PoetryPackage | None:
    data = _mapping(raw, "Poetry package")
    raw_name = data.get("name")
    raw_version = data.get("version")
    if not isinstance(raw_name, str) or not isinstance(raw_version, str):
        raise AssetSnapshotRejected(
            "invalid_lockfile", "every Poetry package needs a name and version"
        )
    groups = data.get("groups")
    if groups is not None:
        if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
            raise AssetSnapshotRejected("invalid_lockfile", "Poetry package groups must be names")
        if "main" not in groups:
            return None
    python_versions = data.get("python-versions")
    if python_versions is not None and not _poetry_constraint_applies(
        python_versions, Version(environment.python_version)
    ):
        return None
    marker = data.get("markers", data.get("marker"))
    if marker is not None and not _marker_applies(marker, environment, frozenset()):
        return None
    try:
        version = str(Version(raw_version))
    except InvalidVersion as error:
        raise AssetSnapshotRejected(
            "invalid_lockfile", "Poetry package version is invalid"
        ) from error
    source = _poetry_package_source(data.get("source"))
    name = canonicalize_name(raw_name)
    return _PoetryPackage(
        key=(name, version, source), name=name, version=version, source=source, data=data
    )


def _poetry_package_source(value: object) -> PackageSource:
    if value is None:
        return PackageSource(fields=(("registry", "https://pypi.org/simple"),))
    source = _mapping(value, "Poetry package source")
    source_type = source.get("type")
    url = source.get("url")
    if not isinstance(source_type, str) or not isinstance(url, str) or not url:
        raise AssetSnapshotRejected(
            "invalid_lockfile", "Poetry package source needs text type and URL"
        )
    kind = {
        "legacy": "registry",
        "git": "git",
        "file": "file",
        "directory": "directory",
        "url": "url",
    }.get(source_type)
    if kind is None:
        raise AssetSnapshotRejected(
            "unsupported_package_source", f"Poetry package source type {source_type} is unsupported"
        )
    fields = [(kind, url)]
    for key in ("reference", "resolved_reference"):
        item = source.get(key)
        if item is not None:
            if not isinstance(item, str):
                raise AssetSnapshotRejected(
                    "invalid_lockfile", "Poetry package source references must be text"
                )
            fields.append((key.replace("_", "-"), item))
    return PackageSource(fields=tuple(sorted(fields)))


def _poetry_dependencies_for(
    package: _PoetryPackage,
    active_extras: frozenset[str],
    environment: EnvironmentProfile,
) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    raw_dependencies = package.data.get("dependencies", {})
    dependencies = _mapping(raw_dependencies, "Poetry package dependencies")
    optional_names: set[str] = set()
    raw_extras = package.data.get("extras", {})
    extras = _mapping(raw_extras, "Poetry package extras")
    for extra in active_extras:
        members = extras.get(extra, ())
        if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
            raise AssetSnapshotRejected(
                "invalid_lockfile", "Poetry package extras must contain dependencies"
            )
        optional_names.update(_poetry_extra_dependency_name(item) for item in members)

    selected: list[tuple[str, Mapping[str, Any]]] = []
    for raw_name, specification in dependencies.items():
        name = canonicalize_name(raw_name)
        active = tuple(
            variant
            for variant in _poetry_dependency_variants(specification)
            if _poetry_dependency_applies(variant, environment)
            and (not bool(variant.get("optional")) or name in optional_names)
        )
        if len(active) > 1:
            raise AssetSnapshotRejected(
                "ambiguous_dependency",
                f"Poetry dependency {name} has overlapping environment constraints",
            )
        if active:
            selected.append((name, active[0]))
    return tuple(selected)


def _poetry_dependency_variants(value: object) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, str):
        return ({"version": value},)
    if isinstance(value, dict):
        return (value,)
    if isinstance(value, list):
        if not all(isinstance(item, dict) for item in value):
            raise AssetSnapshotRejected(
                "invalid_lockfile", "Poetry dependency alternatives must be tables"
            )
        return tuple(value)
    raise AssetSnapshotRejected(
        "invalid_lockfile", "Poetry dependency constraint must be text, a table, or a list"
    )


def _poetry_dependency_applies(
    specification: Mapping[str, Any], environment: EnvironmentProfile
) -> bool:
    marker = specification.get("markers")
    if marker is not None and not _marker_applies(marker, environment, frozenset()):
        return False
    python_constraint = specification.get("python")
    if python_constraint is not None and not _poetry_constraint_applies(
        python_constraint, Version(environment.python_version)
    ):
        return False
    platform = specification.get("platform")
    if platform is not None:
        if not isinstance(platform, str):
            raise AssetSnapshotRejected("invalid_lockfile", "Poetry platform must be text")
        expected = {
            OperatingSystem.LINUX: "linux",
            OperatingSystem.MACOS: "darwin",
            OperatingSystem.WINDOWS: "win32",
        }[environment.operating_system]
        if platform != expected:
            return False
    return True


def _resolve_poetry_dependency(
    name: str,
    specification: object,
    by_name: Mapping[str, Sequence[_PoetryPackage]],
    environment: EnvironmentProfile,
) -> _PoetryPackage:
    variants = tuple(
        variant
        for variant in _poetry_dependency_variants(specification)
        if _poetry_dependency_applies(variant, environment)
    )
    if len(variants) != 1:
        raise AssetSnapshotRejected(
            "ambiguous_dependency", f"Poetry dependency {name} is not deterministic"
        )
    version_constraint = variants[0].get("version", "*")
    candidates = [
        candidate
        for candidate in by_name.get(canonicalize_name(name), ())
        if _poetry_constraint_applies(version_constraint, Version(candidate.version))
    ]
    if len(candidates) != 1:
        raise AssetSnapshotRejected(
            "ambiguous_dependency",
            f"Poetry dependency {canonicalize_name(name)} does not identify exactly one package",
        )
    return candidates[0]


def _poetry_dependency_extras(specification: object) -> tuple[str, ...]:
    variants = _poetry_dependency_variants(specification)
    if len(variants) != 1:
        return ()
    extras = variants[0].get("extras", [])
    if not isinstance(extras, list) or not all(isinstance(extra, str) for extra in extras):
        raise AssetSnapshotRejected("invalid_lockfile", "Poetry dependency extras must be names")
    return tuple(sorted({canonicalize_name(extra) for extra in extras}))


def _poetry_extra_dependency_name(value: str) -> str:
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", value)
    if match is None:
        raise AssetSnapshotRejected(
            "invalid_lockfile", "Poetry package extra dependency name is invalid"
        )
    return canonicalize_name(match.group())


def _validate_poetry_python_constraint(value: object, environment: EnvironmentProfile) -> None:
    if value is None:
        return
    if not _poetry_constraint_applies(value, Version(environment.python_version)):
        raise AssetSnapshotRejected(
            "unsupported_environment",
            "Environment Profile does not satisfy Poetry Python constraint",
        )


def _poetry_constraint_applies(value: object, version: Version) -> bool:
    if not isinstance(value, str):
        raise AssetSnapshotRejected("invalid_lockfile", "Poetry version constraint must be text")
    alternatives = [item.strip() for item in value.split("||")]
    try:
        return any(version in _poetry_specifier_set(item) for item in alternatives)
    except (InvalidSpecifier, InvalidVersion, ValueError) as error:
        raise AssetSnapshotRejected(
            "unsupported_version_constraint", f"Poetry version constraint {value!r} is unsupported"
        ) from error


def _poetry_specifier_set(value: str) -> SpecifierSet:
    if value in {"", "*"}:
        return SpecifierSet()
    if value.startswith("^"):
        lower = Version(value[1:])
        release = (*lower.release, 0, 0)
        if release[0] != 0:
            upper = f"{release[0] + 1}.0.0"
        elif release[1] != 0:
            upper = f"0.{release[1] + 1}.0"
        else:
            upper = f"0.0.{release[2] + 1}"
        return SpecifierSet(f">={lower},<{upper}")
    if value.startswith("~") and not value.startswith("~="):
        raw = value[1:]
        lower = Version(raw)
        release = lower.release
        upper = _poetry_tilde_upper_bound(release)
        return SpecifierSet(f">={lower},<{upper}")
    if value.endswith(".*") and not value.startswith(("==", "!=")):
        prefix = Version(value[:-2]).release
        if len(prefix) == 1:
            upper = f"{prefix[0] + 1}.0"
        else:
            upper = ".".join(str(item) for item in (*prefix[:-1], prefix[-1] + 1))
        return SpecifierSet(f">={value[:-2]},<{upper}")
    if re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z]+)*", value):
        return SpecifierSet(f"=={value}")
    normalized = re.sub(r"(?<=[0-9*])\s+(?=[<>!=~])", ",", value)
    return SpecifierSet(normalized)


def _poetry_tilde_upper_bound(release: tuple[int, ...]) -> str:
    if len(release) <= 1:
        return f"{release[0] + 1}.0"
    return f"{release[0]}.{release[1] + 1}"


def _parse_requirements(
    content: str, *, lockfile_path: str, environment: EnvironmentProfile
) -> tuple[PackageInstance, ...]:
    packages: dict[str, PackageInstance] = {}
    for line in _requirements_logical_lines(content):
        without_comment = re.sub(r"\s+#.*$", "", line).strip()
        requirement_text = re.sub(r"\s+--hash=\S+", "", without_comment).strip()
        if not requirement_text:
            continue
        if requirement_text.startswith("-"):
            raise AssetSnapshotRejected(
                "unsupported_requirement_directive",
                "requirements directives, includes, constraints, and editable installs "
                "are unsupported",
            )
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement as error:
            raise AssetSnapshotRejected(
                "invalid_requirements", "requirements data contains an invalid requirement"
            ) from error
        if requirement.url is not None:
            raise AssetSnapshotRejected(
                "unsupported_requirement_source",
                "requirements data must use fully pinned package versions, not direct URLs",
            )
        specifiers = tuple(requirement.specifier)
        if len(specifiers) != 1 or specifiers[0].operator != "==" or "*" in specifiers[0].version:
            raise AssetSnapshotRejected(
                "unpinned_requirement",
                f"requirement {canonicalize_name(requirement.name)} must pin exactly one "
                "version with ==",
            )
        try:
            version = str(Version(specifiers[0].version))
        except InvalidVersion as error:
            raise AssetSnapshotRejected(
                "invalid_requirements", "requirements data contains an invalid pinned version"
            ) from error
        if requirement.marker is not None and not _marker_applies(
            str(requirement.marker), environment, frozenset(environment.selected_extras)
        ):
            continue
        name = canonicalize_name(requirement.name)
        package = PackageInstance(
            name=name,
            version=version,
            direct=None,
            source=PackageSource(fields=(("manifest", lockfile_path),)),
            dependency_paths=None,
        )
        existing = packages.get(name)
        if existing is not None and existing != package:
            raise AssetSnapshotRejected(
                "ambiguous_dependency",
                f"requirements data selects multiple versions of {name} for the "
                "Environment Profile",
            )
        packages[name] = package
    if not packages:
        raise AssetSnapshotRejected(
            "invalid_requirements", "requirements data contains no applicable pinned packages"
        )
    return tuple(sorted(packages.values(), key=lambda package: (package.name, package.version)))


def _requirements_logical_lines(content: str) -> tuple[str, ...]:
    logical_lines: list[str] = []
    pending = ""
    for physical_line in content.splitlines():
        stripped = physical_line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        pending += stripped
        logical_lines.append(pending)
        pending = ""
    if pending:
        raise AssetSnapshotRejected(
            "invalid_requirements", "requirements data ends with an incomplete line continuation"
        )
    return tuple(logical_lines)


def _marker_applies(
    value: object,
    environment: EnvironmentProfile,
    active_extras: frozenset[str],
) -> bool:
    if not isinstance(value, str):
        raise AssetSnapshotRejected("invalid_lockfile", "environment marker must be text")
    unquoted = _QUOTED_MARKER_VALUE_PATTERN.sub("", value)
    unsupported = {
        variable
        for variable in _ALL_MARKER_VARIABLES - _SUPPORTED_MARKER_VARIABLES
        if re.search(rf"\b{re.escape(variable)}\b", unquoted)
    }
    if unsupported:
        raise AssetSnapshotRejected(
            "unsupported_environment_marker",
            "uv.lock marker depends on fields not pinned by the Environment Profile: "
            + ", ".join(sorted(unsupported)),
        )
    try:
        marker = Marker(value)
        extras = active_extras or frozenset({""})
        return any(marker.evaluate(_marker_environment(environment, extra)) for extra in extras)
    except (InvalidMarker, KeyError) as error:
        raise AssetSnapshotRejected(
            "unsupported_environment_marker", "uv.lock contains an unsupported environment marker"
        ) from error


def _marker_environment(environment: EnvironmentProfile, extra: str) -> dict[str, str]:
    python = Version(environment.python_version)
    release = (*python.release, 0, 0)
    python_full_version = str(python)
    python_version = ".".join(str(part) for part in release[:2])
    os_values = {
        OperatingSystem.LINUX: ("posix", "linux", "Linux"),
        OperatingSystem.MACOS: ("posix", "darwin", "Darwin"),
        OperatingSystem.WINDOWS: ("nt", "win32", "Windows"),
    }
    os_name, sys_platform, platform_system = os_values[environment.operating_system]
    architecture_family = {
        Architecture.AMD64: "x86_64",
        Architecture.X86_64: "x86_64",
        Architecture.AARCH64: "arm64",
        Architecture.ARM64: "arm64",
    }[environment.architecture]
    platform_machine = {
        OperatingSystem.LINUX: {
            "x86_64": "x86_64",
            "arm64": "aarch64",
        },
        OperatingSystem.MACOS: {
            "x86_64": "x86_64",
            "arm64": "arm64",
        },
        OperatingSystem.WINDOWS: {
            "x86_64": "AMD64",
            "arm64": "ARM64",
        },
    }[environment.operating_system][architecture_family]
    return {
        "os_name": os_name,
        "platform_machine": platform_machine,
        "platform_system": platform_system,
        "python_full_version": python_full_version,
        "python_version": python_version,
        "sys_platform": sys_platform,
        "extra": extra,
    }


def _validate_requires_python(value: object, environment: EnvironmentProfile) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise AssetSnapshotRejected("invalid_lockfile", "requires-python must be text")
    try:
        supported = Version(environment.python_version) in SpecifierSet(value)
    except (InvalidSpecifier, InvalidVersion) as error:
        raise AssetSnapshotRejected("invalid_lockfile", "requires-python is invalid") from error
    if not supported:
        raise AssetSnapshotRejected(
            "unsupported_environment", "Environment Profile does not satisfy requires-python"
        )


def _package_project_root(package: Mapping[str, Any], lockfile_directory: str) -> str | None:
    source = _mapping(package.get("source"), "package source")
    root = source.get("editable", source.get("virtual"))
    if not isinstance(root, str):
        return None
    return _resolve_repository_path(lockfile_directory, root)


def _resolve_repository_path(base: str, relative: str) -> str:
    if "\\" in relative or "\x00" in relative:
        raise AssetSnapshotRejected("invalid_lockfile", "package source path is unsafe")
    path = PurePosixPath(relative)
    if path.is_absolute():
        raise AssetSnapshotRejected("invalid_lockfile", "package source path is unsafe")
    resolved = [] if base == "." else list(PurePosixPath(base).parts)
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise AssetSnapshotRejected("invalid_lockfile", "package source path is unsafe")
            resolved.pop()
        else:
            resolved.append(part)
    return "/".join(resolved) or "."


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if value is None and label == "optional-dependencies":
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AssetSnapshotRejected("invalid_lockfile", f"{label} must be a table")
    return value


def _package_source(value: object, label: str) -> PackageSource:
    source = _mapping(value, label)
    if not source or not all(isinstance(item, str) and item for item in source.values()):
        raise AssetSnapshotRejected("invalid_lockfile", f"{label} must contain text values")
    return PackageSource(fields=tuple(sorted(source.items())))
