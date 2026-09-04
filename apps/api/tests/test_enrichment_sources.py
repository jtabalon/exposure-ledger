from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from exposure_ledger import (
    EpssResponseRejected,
    EpssSourceUnavailable,
    KevResponseRejected,
    KevSourceUnavailable,
)
from exposure_ledger_worker import enrichment as enrichment_module
from exposure_ledger_worker.enrichment import CisaKevApiSource, FirstEpssApiSource


def test_kev_source_captures_the_exact_catalog_response() -> None:
    content = (
        '{"catalogVersion":"2026.09.03","dateReleased":"2026-09-03T10:15:30Z",'
        '"count":1,"vulnerabilities":[{"cveID":"CVE-2026-5000"}]}'
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=content.encode())

    catalog = CisaKevApiSource(
        transport=httpx.MockTransport(handler),
        capture_clock=lambda: datetime(2026, 9, 3, 10, 16, tzinfo=UTC),
    ).catalog()

    assert requests[0].url == (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    assert catalog.observed_at == datetime(2026, 9, 3, 10, 15, 30, tzinfo=UTC)
    assert catalog.evidence_record.content == content
    assert catalog.evidence_record.captured_at == datetime(2026, 9, 3, 10, 16, tzinfo=UTC)


def test_epss_source_queries_only_the_requested_cves_and_captures_the_response() -> None:
    content = (
        '{"status":"OK","status-code":200,"total":1,"offset":0,"limit":100,"data":['
        '{"cve":"CVE-2026-5000","epss":"0.125000000",'
        '"percentile":"0.910000000","date":"2026-09-03"}]}'
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=content.encode())

    response = FirstEpssApiSource(
        transport=httpx.MockTransport(handler),
        capture_clock=lambda: datetime(2026, 9, 3, 11, 0, tzinfo=UTC),
    ).query(("CVE-2026-5000", "CVE-2026-6000"))

    assert requests[0].url.host == "api.first.org"
    assert requests[0].url.path == "/data/v1/epss"
    assert requests[0].url.params["cve"] == "CVE-2026-5000,CVE-2026-6000"
    assert requests[0].url.params["limit"] == "100"
    assert response.evidence_record.content == content
    assert response.scores[0].cve_id == "CVE-2026-5000"


@pytest.mark.parametrize(
    ("source", "error"),
    [
        (
            CisaKevApiSource(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, content=b"not-json")
                )
            ),
            KevResponseRejected,
        ),
        (
            FirstEpssApiSource(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, content=b"not-json")
                )
            ),
            EpssResponseRejected,
        ),
    ],
)
def test_sources_distinguish_malformed_responses_from_unavailability(source, error) -> None:
    with pytest.raises(error):
        if isinstance(source, CisaKevApiSource):
            source.catalog()
        else:
            source.query(("CVE-2026-5000",))


@pytest.mark.parametrize(
    ("source", "error"),
    [
        (
            CisaKevApiSource(transport=httpx.MockTransport(lambda request: httpx.Response(503))),
            KevSourceUnavailable,
        ),
        (
            FirstEpssApiSource(transport=httpx.MockTransport(lambda request: httpx.Response(503))),
            EpssSourceUnavailable,
        ),
    ],
)
def test_sources_report_upstream_failures_as_unavailable(source, error) -> None:
    with pytest.raises(error):
        if isinstance(source, CisaKevApiSource):
            source.catalog()
        else:
            source.query(("CVE-2026-5000",))


@pytest.mark.parametrize(
    "source",
    [
        CisaKevApiSource(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302,
                    headers={"location": "https://example.test/redirected"},
                )
            )
        ),
        FirstEpssApiSource(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302,
                    headers={"location": "https://example.test/redirected"},
                )
            )
        ),
    ],
)
def test_sources_reject_redirects(source) -> None:
    with pytest.raises((KevSourceUnavailable, EpssSourceUnavailable), match="unavailable"):
        if isinstance(source, CisaKevApiSource):
            source.catalog()
        else:
            source.query(("CVE-2026-5000",))


def test_sources_reject_non_public_dns_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )

    with pytest.raises(KevSourceUnavailable, match="unavailable"):
        CisaKevApiSource().catalog()


def test_sources_enforce_response_size_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enrichment_module, "_KEV_MAX_RESPONSE_BYTES", 4)
    source = CisaKevApiSource(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"12345"))
    )

    with pytest.raises(KevSourceUnavailable, match="unavailable"):
        source.catalog()


def test_sources_enforce_one_time_budget() -> None:
    now = [0.0]

    def handler(request: httpx.Request) -> httpx.Response:
        now[0] = 21.0
        return httpx.Response(200, content=b"{}")

    source = FirstEpssApiSource(
        timeout_seconds=20,
        transport=httpx.MockTransport(handler),
        clock=lambda: now[0],
    )

    with pytest.raises(EpssSourceUnavailable, match="unavailable"):
        source.query(("CVE-2026-5000",))
