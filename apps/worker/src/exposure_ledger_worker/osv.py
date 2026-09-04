"""Narrow worker adapter for the fixed public OSV API origin."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpcore
import httpx
from exposure_ledger import OsvBatchResponse, OsvPackageQuery, OsvSourceUnavailable

_OSV_ORIGIN = "https://api.osv.dev"
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_PAGES = 20
_MAX_QUERIES = 1_000
_MAX_VULNERABILITIES = 3_000


class OsvApiSource:
    """Batch-query PyPI versions and hydrate the returned OSV records."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] | None = None,
        capture_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._timeout = httpx.Timeout(timeout_seconds)
        self._transport = transport
        self._clock = clock or time.monotonic
        self._capture_clock = capture_clock or (lambda: datetime.now(UTC))

    def query_batch(self, queries: tuple[OsvPackageQuery, ...]) -> OsvBatchResponse:
        if not queries:
            return OsvBatchResponse(results=())
        if len(queries) > _MAX_QUERIES:
            raise OsvSourceUnavailable("The OSV package batch exceeds the query limit.")
        deadline = self._clock() + self._timeout_seconds
        transport = self._transport
        if transport is None:
            address = _public_osv_address(f"{_OSV_ORIGIN}/v1/querybatch")
            _remaining_time(deadline, self._clock)
            transport = _PinnedOsvTransport(address)
        vulnerability_ids: list[set[str]] = [set() for _ in queries]
        pending: list[tuple[int, OsvPackageQuery, str | None]] = [
            (index, query, None) for index, query in enumerate(queries)
        ]
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=self._timeout,
                trust_env=False,
                headers={"User-Agent": "Exposure-Ledger/0.1"},
                transport=transport,
            ) as client:
                for _ in range(_MAX_PAGES):
                    if not pending:
                        break
                    response_payload, _ = _request_json(
                        client,
                        "POST",
                        f"{_OSV_ORIGIN}/v1/querybatch",
                        json_body={
                            "queries": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": query.name},
                                    "version": query.version,
                                    **({"page_token": token} if token else {}),
                                }
                                for _, query, token in pending
                            ]
                        },
                        deadline=deadline,
                        clock=self._clock,
                    )
                    page_results = response_payload.get("results")
                    if not isinstance(page_results, Sequence) or isinstance(
                        page_results, (str, bytes)
                    ):
                        raise OsvSourceUnavailable("OSV returned an invalid batch response.")
                    if len(page_results) != len(pending):
                        raise OsvSourceUnavailable("OSV returned a misaligned batch response.")
                    next_pending: list[tuple[int, OsvPackageQuery, str | None]] = []
                    for (index, query, _), result in zip(pending, page_results, strict=True):
                        if not isinstance(result, Mapping):
                            raise OsvSourceUnavailable("OSV returned an invalid query result.")
                        vulns = result.get("vulns", [])
                        if not isinstance(vulns, Sequence) or isinstance(vulns, (str, bytes)):
                            raise OsvSourceUnavailable(
                                "OSV returned an invalid vulnerability list."
                            )
                        for vulnerability in vulns:
                            if isinstance(vulnerability, Mapping):
                                identifier = vulnerability.get("id")
                                if isinstance(identifier, str) and identifier:
                                    vulnerability_ids[index].add(identifier)
                        token = result.get("next_page_token")
                        if isinstance(token, str) and token:
                            next_pending.append((index, query, token))
                    pending = next_pending
                    if len(set[str]().union(*vulnerability_ids)) > _MAX_VULNERABILITIES:
                        raise OsvSourceUnavailable(
                            "The OSV package batch exceeds the vulnerability limit."
                        )
                if pending:
                    raise OsvSourceUnavailable("OSV pagination exceeded the bounded page limit.")

                records: dict[str, dict[str, Any]] = {}
                captured_contents: dict[str, str] = {}
                for identifier in sorted(set[str]().union(*vulnerability_ids)):
                    record, captured_content = _request_json(
                        client,
                        "GET",
                        f"{_OSV_ORIGIN}/v1/vulns/{quote(identifier, safe='')}",
                        deadline=deadline,
                        clock=self._clock,
                    )
                    if record.get("id") != identifier:
                        raise OsvSourceUnavailable(
                            "OSV returned a vulnerability record with a mismatched identifier."
                        )
                    records[identifier] = record
                    captured_contents[identifier] = captured_content
        except httpx.HTTPError as error:
            raise OsvSourceUnavailable("The public OSV API could not be retrieved.") from error

        payload = {
            "results": [
                {"vulns": [records[identifier] for identifier in sorted(identifiers)]}
                for identifiers in vulnerability_ids
            ]
        }
        return OsvBatchResponse.capture(
            payload,
            expected_results=len(queries),
            captured_at=self._capture_clock(),
            captured_contents=captured_contents,
        )


def _request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    json_body: dict[str, object] | None = None,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[str, Any], str]:
    timeout_seconds = _remaining_time(deadline, clock)
    with client.stream(
        method,
        url,
        json=json_body,
        headers={"Accept": "application/json"},
        timeout=timeout_seconds,
    ) as response:
        _remaining_time(deadline, clock)
        if response.is_redirect:
            raise OsvSourceUnavailable("OSV redirects are not accepted.")
        if response.status_code != 200:
            raise OsvSourceUnavailable("The public OSV API returned an unsuccessful response.")
        content = bytearray()
        for chunk in response.iter_bytes():
            _remaining_time(deadline, clock)
            content.extend(chunk)
            if len(content) > _MAX_RESPONSE_BYTES:
                raise OsvSourceUnavailable("The public OSV response exceeds the size limit.")
    try:
        captured_content = content.decode("utf-8")
        payload = json.loads(captured_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OsvSourceUnavailable("The public OSV API returned invalid JSON.") from error
    if not isinstance(payload, dict):
        raise OsvSourceUnavailable("The public OSV API returned an invalid JSON object.")
    return payload, captured_content


def _remaining_time(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise OsvSourceUnavailable("The public OSV lookup exceeded its time budget.")
    return remaining


class _PinnedOsvNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, address: str) -> None:
        self._address = address
        self._backend = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if host != "api.osv.dev" or port != 443:
            raise httpcore.ConnectError("OSV egress target is not allowed.")
        return self._backend.connect_tcp(
            self._address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("Unix sockets are not permitted for OSV retrieval.")


class _PinnedOsvTransport(httpx.HTTPTransport):
    def __init__(self, address: str) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=_PinnedOsvNetworkBackend(address),
        )


def _public_osv_address(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.osv.dev"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise OsvSourceUnavailable("OSV egress target is not allowed.")
    try:
        addresses = {
            ipaddress.ip_address(sockaddr[0])
            for _, _, _, _, sockaddr in socket.getaddrinfo(
                "api.osv.dev", 443, type=socket.SOCK_STREAM
            )
        }
    except (OSError, ValueError) as error:
        raise OsvSourceUnavailable("OSV egress target could not be validated.") from error
    if not addresses or any(not address.is_global for address in addresses):
        raise OsvSourceUnavailable("OSV egress resolved to a non-public address.")
    return str(min(addresses, key=lambda address: (address.version, str(address))))
