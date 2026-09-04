from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from exposure_ledger import (
    Architecture,
    AssetSnapshot,
    EnvironmentProfile,
    ExposureDiscovery,
    OperatingSystem,
    OsvBatchResponse,
    OsvPackageQuery,
    PackageInstance,
    PackageSource,
)


class CapturedOsvSource:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.queries: tuple[OsvPackageQuery, ...] = ()

    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        self.queries = queries
        return OsvBatchResponse.capture(self.response, expected_results=len(queries))


def snapshot_with(*packages: PackageInstance) -> AssetSnapshot:
    return AssetSnapshot(
        repository="https://github.com/example/project",
        commit="0123456789abcdef0123456789abcdef01234567",
        project_root=".",
        lockfile_path="uv.lock",
        lockfile_digest="sha256:fixture",
        lockfile_content="version = 1",
        environment_profile=EnvironmentProfile(
            python_version="3.12.2",
            operating_system=OperatingSystem.LINUX,
            architecture=Architecture.X86_64,
        ),
        packages=tuple(packages),
        parser_version="uv-lock-v1",
        captured_at=datetime(2026, 9, 3, 20, 0, tzinfo=UTC),
    )


def pypi_package(
    name: str,
    version: str,
    *,
    direct: bool = True,
    path: tuple[str, ...] | None = None,
) -> PackageInstance:
    normalized_path = path or ("project", name)
    return PackageInstance(
        name=name,
        version=version,
        direct=direct,
        source=PackageSource((("registry", "https://pypi.org/simple"),)),
        dependency_paths=(normalized_path,),
    )


def git_package(name: str, version: str) -> PackageInstance:
    return PackageInstance(
        name=name,
        version=version,
        direct=True,
        source=PackageSource((("git", "https://github.com/example/package"),)),
        dependency_paths=(("project", name),),
    )


def test_discovery_normalizes_pypi_identity_and_matches_an_affected_ecosystem_range() -> None:
    source = CapturedOsvSource(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "aliases": ["CVE-2026-1000"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "Django"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "4.0"},
                                                {"fixed": "4.2.1"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )

    result = ExposureDiscovery(source).discover(snapshot_with(pypi_package("Django", "4.2")))

    assert source.queries == (OsvPackageQuery(name="django", version="4.2"),)
    assert len(result.vulnerability_records) == 1
    assert result.vulnerability_records[0].aliases == (
        "CVE-2026-1000",
        "GHSA-AAAA-BBBB-CCCC",
    )
    assert len(result.exposures) == 1
    exposure = result.exposures[0]
    assert exposure.package.name == "django"
    assert exposure.package.version == "4.2"
    assert exposure.rank == 1
    assert exposure.selected_for_investigation is True
    assert exposure.ranking.severity == "high"
    assert exposure.ranking.direct_dependency is True
    assert exposure.ranking.dependency_depth == 1
    assert exposure.ranking.fixed_version_available is True


def test_discovery_coalesces_aliases_and_duplicate_responses_across_affected_packages() -> None:
    first = {
        "id": "GHSA-1111-2222-3333",
        "aliases": ["CVE-2026-2000"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "alpha_pkg"},
                "versions": ["1.0"],
            }
        ],
    }
    second = {
        "id": "PYSEC-2026-20",
        "aliases": ["CVE-2026-2000"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "beta-pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "2.0"}],
                    }
                ],
            }
        ],
    }
    source = CapturedOsvSource(
        {
            "results": [
                {"vulns": [first, first]},
                {"vulns": [second]},
            ]
        }
    )

    result = ExposureDiscovery(source).discover(
        snapshot_with(
            pypi_package("alpha.pkg", "1.0"),
            pypi_package("Beta_Pkg", "2.0", direct=False, path=("project", "mid", "beta")),
        )
    )

    assert source.queries == (
        OsvPackageQuery(name="alpha-pkg", version="1.0"),
        OsvPackageQuery(name="beta-pkg", version="2.0"),
    )
    assert [record.aliases for record in result.vulnerability_records] == [
        ("CVE-2026-2000", "GHSA-1111-2222-3333", "PYSEC-2026-20")
    ]
    assert {(item.package.name, item.package.version) for item in result.exposures} == {
        ("alpha-pkg", "1.0"),
        ("beta-pkg", "2.0"),
    }
    assert len(result.exposures) == 2


@pytest.mark.parametrize(
    ("version", "events", "expected"),
    [
        ("1.0", [{"introduced": "1.0"}, {"fixed": "2.0"}], True),
        ("2.0", [{"introduced": "1.0"}, {"fixed": "2.0"}], False),
        ("2.0", [{"introduced": "1.0"}, {"last_affected": "2.0"}], True),
        ("2.0.post1", [{"introduced": "1.0"}, {"last_affected": "2.0"}], False),
        ("1.9", [{"introduced": "0"}, {"limit": "2.0"}], True),
        ("2.0", [{"introduced": "0"}, {"limit": "2.0"}], False),
        ("99.0", [{"introduced": "0"}, {"limit": "*"}], True),
        (
            "3.5",
            [
                {"introduced": "1.0"},
                {"fixed": "2.0"},
                {"introduced": "3.0"},
                {"fixed": "4.0"},
            ],
            True,
        ),
    ],
)
def test_discovery_applies_osv_ecosystem_range_boundaries_deterministically(
    version: str,
    events: list[dict[str, str]],
    expected: bool,
) -> None:
    source = CapturedOsvSource(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-30",
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "range-pkg"},
                                    "ranges": [{"type": "ECOSYSTEM", "events": events}],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )

    result = ExposureDiscovery(source).discover(snapshot_with(pypi_package("range-pkg", version)))

    assert bool(result.exposures) is expected


def test_discovery_does_not_merge_distinct_vulnerabilities_for_one_package() -> None:
    source = CapturedOsvSource(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-AAAA-AAAA-AAAA",
                            "aliases": ["CVE-2026-3000"],
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "shared"},
                                    "versions": ["1.0"],
                                }
                            ],
                        },
                        {
                            "id": "GHSA-BBBB-BBBB-BBBB",
                            "aliases": ["CVE-2026-3001"],
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "shared"},
                                    "versions": ["1.0"],
                                }
                            ],
                        },
                    ]
                }
            ]
        }
    )

    result = ExposureDiscovery(source).discover(snapshot_with(pypi_package("shared", "1.0")))

    assert [record.aliases for record in result.vulnerability_records] == [
        ("CVE-2026-3000", "GHSA-AAAA-AAAA-AAAA"),
        ("CVE-2026-3001", "GHSA-BBBB-BBBB-BBBB"),
    ]
    assert len(result.exposures) == 2


def test_discovery_queries_only_normalized_pypi_package_instances() -> None:
    source = CapturedOsvSource({"results": [{}]})

    result = ExposureDiscovery(source).discover(
        snapshot_with(git_package("source-only", "1.0"), pypi_package("PyPI_Pkg", "2.0"))
    )

    assert source.queries == (OsvPackageQuery(name="pypi-pkg", version="2.0"),)
    assert result.exposures == ()


def test_discovery_ranks_inspectable_signals_and_selects_only_the_top_five() -> None:
    severities = ["CRITICAL", "HIGH", "HIGH", "MODERATE", "LOW", "UNKNOWN"]
    names = ["alpha", "beta", "charlie", "delta", "epsilon", "zeta"]
    results: list[dict[str, Any]] = []
    for index, (name, severity) in enumerate(zip(names, severities, strict=True)):
        events = [{"introduced": "0"}]
        if index < 2:
            events.append({"fixed": "2.0"})
        results.append(
            {
                "vulns": [
                    {
                        "id": f"PYSEC-2026-{index + 100}",
                        "database_specific": {"severity": severity},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": name},
                                "ranges": [{"type": "ECOSYSTEM", "events": events}],
                            }
                        ],
                    }
                ]
            }
        )
    source = CapturedOsvSource({"results": results})

    result = ExposureDiscovery(source).discover(
        snapshot_with(*(pypi_package(name, "1.0") for name in reversed(names)))
    )

    assert [item.package.name for item in result.exposures] == names
    assert [item.rank for item in result.exposures] == [1, 2, 3, 4, 5, 6]
    assert [item.ranking.score for item in result.exposures] == [79, 69, 59, 49, 39, 29]
    assert [item.selected_for_investigation for item in result.exposures] == [
        True,
        True,
        True,
        True,
        True,
        False,
    ]


def test_ranking_reports_a_fix_only_when_it_is_newer_than_the_installed_version() -> None:
    source = CapturedOsvSource(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-999",
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "reintroduced"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "1.0"},
                                                {"fixed": "2.0"},
                                                {"introduced": "3.0"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )

    result = ExposureDiscovery(source).discover(snapshot_with(pypi_package("reintroduced", "3.5")))

    assert result.exposures[0].ranking.fixed_version_available is False


def test_discovery_applies_a_pypi_wildcard_record_to_each_matching_package() -> None:
    wildcard = {
        "id": "PYSEC-2026-1000",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "*"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}],
                    }
                ],
            }
        ],
    }
    source = CapturedOsvSource({"results": [{"vulns": [wildcard]}, {"vulns": [wildcard]}]})

    result = ExposureDiscovery(source).discover(
        snapshot_with(pypi_package("first", "1.0"), pypi_package("second", "2.0"))
    )

    assert [exposure.package.name for exposure in result.exposures] == ["first", "second"]
    assert len(result.vulnerability_records) == 1


def test_ranking_ignores_fixes_from_disjoint_and_git_ranges() -> None:
    source = CapturedOsvSource(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "PYSEC-2026-1001",
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "multi-range"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "1.0"}],
                                        },
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "3.0"},
                                                {"fixed": "4.0"},
                                            ],
                                        },
                                        {
                                            "type": "GIT",
                                            "repo": "https://github.com/example/multi-range",
                                            "events": [
                                                {"introduced": "a" * 40},
                                                {"fixed": "b" * 40},
                                            ],
                                        },
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )

    result = ExposureDiscovery(source).discover(snapshot_with(pypi_package("multi-range", "2.0")))

    assert result.exposures[0].ranking.fixed_version_available is False
