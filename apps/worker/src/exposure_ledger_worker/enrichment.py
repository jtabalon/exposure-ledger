"""Narrow worker adapters for the fixed public CISA KEV and FIRST EPSS origins."""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpcore
import httpx
from exposure_ledger import (
    CISA_KEV_CATALOG_URL,
    FIRST_EPSS_API_URL,
    CapturedJsonRejected,
    CapturedSourcePayload,
    CisaKevCatalog,
    EpssResponseRejected,
    EpssSourceUnavailable,
    FirstEpssResponse,
    KevResponseRejected,
    KevSourceUnavailable,
    load_captured_json,
)

_CISA_HOST = "www.cisa.gov"
_FIRST_HOST = "api.first.org"
_KEV_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_EPSS_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_EPSS_MAX_CVES = 100


class CisaKevApiSource:
    """Retrieve the complete JSON KEV catalog from its fixed CISA origin."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] | None = None,
        capture_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._clock = clock or time.monotonic
        self._capture_clock = capture_clock or (lambda: datetime.now(UTC))

    def catalog(self) -> CisaKevCatalog:
        try:
            content = _request_content(
                CISA_KEV_CATALOG_URL,
                host=_CISA_HOST,
                maximum_bytes=_KEV_MAX_RESPONSE_BYTES,
                timeout_seconds=self._timeout_seconds,
                transport=self._transport,
                clock=self._clock,
            )
        except (httpx.HTTPError, _PublicSourceUnavailable) as error:
            raise KevSourceUnavailable("The public CISA KEV Source is unavailable.") from error
        except CapturedJsonRejected as error:
            raise KevResponseRejected(str(error)) from error
        payload = _captured_json_object(
            content,
            provider="CISA KEV",
            rejection=KevResponseRejected,
        )
        try:
            return CisaKevCatalog.capture(
                payload,
                capture=CapturedSourcePayload(
                    content=content,
                    captured_at=self._capture_clock(),
                ),
            )
        except KevResponseRejected:
            raise
        except ValueError as error:
            raise KevResponseRejected(str(error)) from error


class FirstEpssApiSource:
    """Retrieve current EPSS observations for one bounded batch of CVEs."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] | None = None,
        capture_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._clock = clock or time.monotonic
        self._capture_clock = capture_clock or (lambda: datetime.now(UTC))

    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        normalized = tuple(sorted({identifier.strip().upper() for identifier in cve_ids}))
        if not normalized or len(normalized) > _EPSS_MAX_CVES or len(",".join(normalized)) > 2_000:
            raise EpssSourceUnavailable("The FIRST EPSS CVE batch exceeds the query limit.")
        parameters = {"cve": ",".join(normalized), "limit": str(_EPSS_MAX_CVES)}
        try:
            content = _request_content(
                FIRST_EPSS_API_URL,
                host=_FIRST_HOST,
                maximum_bytes=_EPSS_MAX_RESPONSE_BYTES,
                timeout_seconds=self._timeout_seconds,
                transport=self._transport,
                clock=self._clock,
                params=parameters,
            )
        except (httpx.HTTPError, _PublicSourceUnavailable) as error:
            raise EpssSourceUnavailable("The public FIRST EPSS Source is unavailable.") from error
        except CapturedJsonRejected as error:
            raise EpssResponseRejected(str(error)) from error
        payload = _captured_json_object(
            content,
            provider="FIRST EPSS",
            rejection=EpssResponseRejected,
        )
        try:
            return FirstEpssResponse.capture(
                payload,
                cve_ids=normalized,
                capture=CapturedSourcePayload(
                    content=content,
                    captured_at=self._capture_clock(),
                ),
            )
        except EpssResponseRejected:
            raise
        except ValueError as error:
            raise EpssResponseRejected(str(error)) from error


class _PublicSourceUnavailable(RuntimeError):
    pass


def _request_content(
    url: str,
    *,
    host: str,
    maximum_bytes: int,
    timeout_seconds: float,
    transport: httpx.BaseTransport | None,
    clock: Callable[[], float],
    params: Mapping[str, str] | None = None,
) -> str:
    deadline = clock() + timeout_seconds
    selected_transport = transport
    if selected_transport is None:
        selected_transport = _PinnedHttpsTransport(host, _public_address(host))
    with (
        httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds),
            trust_env=False,
            headers={"User-Agent": "Exposure-Ledger/0.1", "Accept": "application/json"},
            transport=selected_transport,
        ) as client,
        client.stream(
            "GET",
            url,
            params=params,
            timeout=_remaining_time(deadline, clock),
        ) as response,
    ):
        _remaining_time(deadline, clock)
        if response.is_redirect:
            raise _PublicSourceUnavailable("Public Source redirects are not accepted.")
        if response.status_code != 200:
            raise _PublicSourceUnavailable("Public Source returned an unsuccessful response.")
        captured = bytearray()
        for chunk in response.iter_bytes():
            _remaining_time(deadline, clock)
            captured.extend(chunk)
            if len(captured) > maximum_bytes:
                raise _PublicSourceUnavailable("Public Source response exceeds the size limit.")
    try:
        return captured.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CapturedJsonRejected("Captured content must be valid UTF-8 JSON") from error


def _captured_json_object(
    content: str,
    *,
    provider: str,
    rejection: type[KevResponseRejected] | type[EpssResponseRejected],
) -> dict[str, Any]:
    try:
        payload = load_captured_json(content)
    except CapturedJsonRejected as error:
        message = str(error).replace("Captured content", f"Captured {provider} content")
        raise rejection(message) from error
    if not isinstance(payload, dict):
        raise rejection(f"Captured {provider} content must be a JSON object")
    return payload


def _remaining_time(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise _PublicSourceUnavailable("Public Source lookup exceeded its time budget.")
    return remaining


class _PinnedHttpsNetworkBackend(httpcore.NetworkBackend):
    def __init__(self, host: str, address: str) -> None:
        self._host = host
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
        if host != self._host or port != 443:
            raise httpcore.ConnectError("Public Source egress target is not allowed.")
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
        raise httpcore.ConnectError("Unix sockets are not permitted for public Source retrieval.")


class _PinnedHttpsTransport(httpx.HTTPTransport):
    def __init__(self, host: str, address: str) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=_PinnedHttpsNetworkBackend(host, address),
        )


def _public_address(host: str) -> str:
    try:
        addresses = {
            ipaddress.ip_address(sockaddr[0])
            for _, _, _, _, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as error:
        message = "Public Source egress target could not be validated."
        raise _PublicSourceUnavailable(message) from error
    if not addresses or any(not address.is_global for address in addresses):
        raise _PublicSourceUnavailable("Public Source egress resolved to a non-public address.")
    return str(min(addresses, key=lambda address: (address.version, str(address))))
