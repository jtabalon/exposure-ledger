"""Static, no-execution capture of immutable ``uv.lock`` Asset Snapshots."""

from __future__ import annotations

import hashlib
import json
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
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ASSET_SNAPSHOT_PARSER_VERSION = "uv-lock-v1"
_COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
_REPOSITORY_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")


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


@dataclass(frozen=True, slots=True)
class PackageInstance:
    name: str
    version: str
    direct: bool
    source: str
    dependency_paths: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class AssetSnapshot:
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    lockfile_digest: str
    lockfile_content: str = field(repr=False)
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
    key: tuple[str, str, str]
    name: str
    version: str
    source: str
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
        repository = _canonical_repository(request.repository)
        commit = _immutable_commit(request.commit)
        project_root = _safe_relative_path(request.project_root, allow_root=True)
        lockfile_path = _safe_relative_path(request.lockfile_path, allow_root=False)
        if PurePosixPath(lockfile_path).name != "uv.lock":
            raise AssetSnapshotRejected("unsupported_lockfile", "Only uv.lock is supported.")

        archive = self._archive_source.fetch(repository, commit)
        lockfile_bytes = _read_lockfile_from_archive(
            archive.content,
            lockfile_path=lockfile_path,
            limits=self._limits,
        )
        try:
            lockfile_content = lockfile_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssetSnapshotRejected(
                "invalid_lockfile", "uv.lock must be valid UTF-8 text."
            ) from error

        packages = _parse_uv_lock(
            lockfile_content,
            project_root=project_root,
            environment=request.environment_profile,
            max_dependency_paths=self._limits.max_dependency_paths,
        )
        return AssetSnapshot(
            repository=repository,
            commit=commit,
            project_root=project_root,
            lockfile_path=lockfile_path,
            lockfile_digest=f"sha256:{hashlib.sha256(lockfile_bytes).hexdigest()}",
            lockfile_content=lockfile_content,
            environment_profile=request.environment_profile,
            packages=packages,
            parser_version=ASSET_SNAPSHOT_PARSER_VERSION,
            captured_at=self._clock(),
        )


def _canonical_repository(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
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


def _read_lockfile_from_archive(
    content: bytes,
    *,
    lockfile_path: str,
    limits: ArchiveLimits,
) -> bytes:
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
            raise AssetSnapshotRejected("lockfile_too_large", "uv.lock exceeds size limit")
        return archive.read(lockfile)


def _is_symlink(member: zipfile.ZipInfo) -> bool:
    unix_file_type = (member.external_attr >> 16) & 0o170000
    return unix_file_type == 0o120000


def _parse_uv_lock(
    content: str,
    *,
    project_root: str,
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
    roots = [package for package in packages if _package_project_root(package.data) == project_root]
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

    paths: dict[tuple[str, str, str], set[tuple[str, ...]]] = defaultdict(set)
    sources: dict[tuple[str, str, str], str] = {}
    queue: deque[tuple[_LockedPackage, tuple[str, ...], frozenset[str]]] = deque()
    for dependency in _dependencies_for(root, frozenset(environment.selected_extras), environment):
        target = _resolve_dependency(dependency, by_name, environment)
        queue.append(
            (
                target,
                (root.name, target.name),
                frozenset(_dependency_extras(dependency)),
            )
        )

    total_paths = 0
    expanded: set[tuple[tuple[str, str, str], tuple[str, ...], frozenset[str]]] = set()
    while queue:
        package, path, active_extras = queue.popleft()
        state = (package.key, path, active_extras)
        if state in expanded:
            continue
        expanded.add(state)
        if path not in paths[package.key]:
            paths[package.key].add(path)
            total_paths += 1
            if total_paths > max_dependency_paths:
                raise AssetSnapshotRejected(
                    "dependency_graph_too_large", "uv.lock contains too many Dependency Paths"
                )
        sources[package.key] = package.source
        for dependency in _dependencies_for(package, active_extras, environment):
            target = _resolve_dependency(dependency, by_name, environment)
            if target.name in path:
                continue
            queue.append(
                (
                    target,
                    (*path, target.name),
                    frozenset(_dependency_extras(dependency)),
                )
            )

    result = []
    for key, package_paths in paths.items():
        name, version, _ = key
        ordered_paths = tuple(sorted(package_paths, key=lambda path: (len(path), path)))
        result.append(
            PackageInstance(
                name=name,
                version=version,
                direct=any(len(path) == 2 for path in ordered_paths),
                source=sources[key],
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
    if not isinstance(raw_name, str) or not isinstance(raw_version, str):
        raise AssetSnapshotRejected("invalid_lockfile", "every package needs a name and version")
    source_mapping = _mapping(raw_source, "package source")
    resolution_markers = data.get("resolution-markers", [])
    if not isinstance(resolution_markers, list):
        raise AssetSnapshotRejected("invalid_lockfile", "package resolution-markers must be a list")
    if resolution_markers and not any(
        _marker_applies(marker, environment, frozenset()) for marker in resolution_markers
    ):
        return None
    try:
        version = str(Version(raw_version))
    except InvalidVersion as error:
        raise AssetSnapshotRejected("invalid_lockfile", "package version is invalid") from error
    name = canonicalize_name(raw_name)
    source = json.dumps(source_mapping, sort_keys=True, separators=(",", ":"))
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
    environment: EnvironmentProfile,
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
        source_key = json.dumps(
            _mapping(source, "dependency source"), sort_keys=True, separators=(",", ":")
        )
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


def _marker_applies(
    value: object,
    environment: EnvironmentProfile,
    active_extras: frozenset[str],
) -> bool:
    if not isinstance(value, str):
        raise AssetSnapshotRejected("invalid_lockfile", "environment marker must be text")
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
    release = (*python.release, 0, 0, 0)
    python_full_version = ".".join(str(part) for part in release[:3])
    python_version = ".".join(str(part) for part in release[:2])
    os_values = {
        OperatingSystem.LINUX: ("posix", "linux", "Linux"),
        OperatingSystem.MACOS: ("posix", "darwin", "Darwin"),
        OperatingSystem.WINDOWS: ("nt", "win32", "Windows"),
    }
    os_name, sys_platform, platform_system = os_values[environment.operating_system]
    return {
        "implementation_name": "cpython",
        "implementation_version": python_full_version,
        "os_name": os_name,
        "platform_machine": environment.architecture,
        "platform_python_implementation": "CPython",
        "platform_release": "",
        "platform_system": platform_system,
        "platform_version": "",
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


def _package_project_root(package: Mapping[str, Any]) -> str | None:
    source = _mapping(package.get("source"), "package source")
    root = source.get("editable", source.get("virtual"))
    if not isinstance(root, str):
        return None
    return _safe_relative_path(root, allow_root=True)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if value is None and label == "optional-dependencies":
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AssetSnapshotRejected("invalid_lockfile", f"{label} must be a table")
    return value
