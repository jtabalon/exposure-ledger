from __future__ import annotations

import json

import httpx
import pytest
from exposure_ledger import OsvPackageQuery, OsvSourceUnavailable
from exposure_ledger_worker.osv import OsvApiSource


def test_osv_source_batch_queries_versions_and_hydrates_full_records() -> None:
    requests: list[httpx.Request] = []
    full_record = {
        "id": "PYSEC-2026-50",
        "aliases": ["CVE-2026-5000"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                "versions": ["1.0"],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/querybatch":
            assert json.loads(request.content) == {
                "queries": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                        "version": "1.0",
                    }
                ]
            }
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "PYSEC-2026-50"}]}]},
            )
        assert request.url.path == "/v1/vulns/PYSEC-2026-50"
        return httpx.Response(200, json=full_record)

    source = OsvApiSource(transport=httpx.MockTransport(handler))

    response = source.query_batch((OsvPackageQuery(name="demo-pkg", version="1.0"),))

    assert response == {"results": [{"vulns": [full_record]}]}
    assert [request.method for request in requests] == ["POST", "GET"]
    assert all(request.url.host == "api.osv.dev" for request in requests)


def test_osv_source_rejects_non_public_dns_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )

    with pytest.raises(OsvSourceUnavailable, match="non-public"):
        OsvApiSource().query_batch((OsvPackageQuery(name="demo-pkg", version="1.0"),))


def test_osv_source_rejects_redirects() -> None:
    source = OsvApiSource(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                302,
                headers={"location": "https://example.test/redirected"},
            )
        )
    )

    with pytest.raises(OsvSourceUnavailable, match="redirects are not accepted"):
        source.query_batch((OsvPackageQuery(name="demo-pkg", version="1.0"),))
