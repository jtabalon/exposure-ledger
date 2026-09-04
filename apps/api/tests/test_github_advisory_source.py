from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from exposure_ledger import (
    GitHubAdvisorySourceUnavailable,
    GitHubAdvisoryTarget,
)
from exposure_ledger_worker.github_advisories import GitHubAdvisoryApiSource


def _target() -> GitHubAdvisoryTarget:
    return GitHubAdvisoryTarget(
        owner="acme",
        repository="demo",
        advisory_id="GHSA-2345-6789-CFGH",
        derived_from_evidence="sha256:osv-capture",
    )


def _payload() -> dict[str, object]:
    return {
        "ghsa_id": "GHSA-2345-6789-CFGH",
        "cve_id": "CVE-2026-5000",
        "url": _target().api_url,
        "html_url": _target().publication_url,
        "summary": "Demo advisory",
        "description": "Upgrade demo-pkg.",
        "published_at": "2026-09-01T12:00:00Z",
        "updated_at": "2026-09-03T12:00:00Z",
        "withdrawn_at": None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "demo-pkg"},
                "vulnerable_version_range": ">= 1.0, < 1.4.2",
                "patched_versions": "1.4.2",
            }
        ],
    }


def test_github_advisory_source_retrieves_only_the_approved_target() -> None:
    requests: list[httpx.Request] = []
    content = json.dumps(_payload(), separators=(",", ":"), sort_keys=True)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=content.encode())

    records = GitHubAdvisoryApiSource(
        transport=httpx.MockTransport(handler),
        capture_clock=lambda: datetime(2026, 9, 4, 9, 0, tzinfo=UTC),
    ).retrieve((_target(),))

    assert len(records) == 1
    assert records[0].content == content
    assert records[0].captured_at == datetime(2026, 9, 4, 9, 0, tzinfo=UTC)
    assert [str(request.url) for request in requests] == [_target().api_url]
    assert requests[0].method == "GET"
    assert requests[0].headers["accept"] == "application/vnd.github+json"
    assert requests[0].headers["x-github-api-version"] == "2026-03-10"
    assert "authorization" not in requests[0].headers


def test_github_advisory_source_rejects_redirects_without_following_links() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://example.test/advisory"})

    source = GitHubAdvisoryApiSource(transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubAdvisorySourceUnavailable, match="redirects are not accepted"):
        source.retrieve((_target(),))

    assert len(requests) == 1


def test_github_advisory_source_reports_unavailable_responses() -> None:
    source = GitHubAdvisoryApiSource(
        transport=httpx.MockTransport(lambda request: httpx.Response(503))
    )

    with pytest.raises(GitHubAdvisorySourceUnavailable, match="unsuccessful response"):
        source.retrieve((_target(),))


def test_github_advisory_source_rejects_non_public_dns_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )

    with pytest.raises(GitHubAdvisorySourceUnavailable, match="non-public"):
        GitHubAdvisoryApiSource().retrieve((_target(),))
