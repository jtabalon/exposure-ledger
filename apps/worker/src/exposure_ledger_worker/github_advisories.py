"""Target-scoped worker adapter for GitHub repository security advisories."""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx
from exposure_ledger import (
    CapturedJsonRejected,
    CapturedSourcePayload,
    EvidenceRecord,
    GitHubAdvisorySourceUnavailable,
    GitHubAdvisoryTarget,
    GitHubRepositoryAdvisoryAdapter,
    load_captured_json,
)

_MAX_ADVISORIES = 20
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class GitHubAdvisoryApiSource:
    """Retrieve approved first-party advisories under one aggregate budget."""

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

    def retrieve(self, targets: tuple[GitHubAdvisoryTarget, ...]) -> tuple[EvidenceRecord, ...]:
        if not targets:
            return ()
        if len(targets) > _MAX_ADVISORIES:
            raise GitHubAdvisorySourceUnavailable(
                "GitHub advisory retrieval exceeds the target limit."
            )
        deadline = self._clock() + self._timeout_seconds
        for target in targets:
            _validate_api_target(target.api_url, target)
        transport = self._transport
        if transport is None:
            address = _public_github_address(targets[0].api_url, targets[0])
            _remaining_time(deadline, self._clock)
            transport = _PinnedGitHubTransport(address)

        records: list[EvidenceRecord] = []
        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=self._timeout,
                trust_env=False,
                headers={"User-Agent": "Exposure-Ledger/0.1"},
                transport=transport,
            ) as client:
                for target in targets:
                    payload, content = _request_json(
                        client,
                        target.api_url,
                        deadline=deadline,
                        clock=self._clock,
                    )
                    records.append(
                        GitHubRepositoryAdvisoryAdapter(target).capture(
                            payload,
                            capture=CapturedSourcePayload(
                                content=content,
                                captured_at=self._capture_clock(),
                            ),
                        )
                    )
        except httpx.HTTPError as error:
            raise GitHubAdvisorySourceUnavailable(
                "The GitHub repository advisory source could not be retrieved."
            ) from error
        return tuple(records)


def _request_json(
    client: httpx.Client,
    url: str,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[str, Any], str]:
    with client.stream(
        "GET",
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        timeout=_remaining_time(deadline, clock),
    ) as response:
        _remaining_time(deadline, clock)
        if response.is_redirect:
            raise GitHubAdvisorySourceUnavailable("GitHub advisory redirects are not accepted.")
        if response.status_code != 200:
            raise GitHubAdvisorySourceUnavailable(
                "The GitHub advisory API returned an unsuccessful response."
            )
        content = bytearray()
        for chunk in response.iter_bytes():
            _remaining_time(deadline, clock)
            content.extend(chunk)
            if len(content) > _MAX_RESPONSE_BYTES:
                raise GitHubAdvisorySourceUnavailable(
                    "The GitHub advisory response exceeds the size limit."
                )
    try:
        captured_content = content.decode("utf-8")
        payload = load_captured_json(captured_content)
    except (UnicodeDecodeError, CapturedJsonRejected) as error:
        raise GitHubAdvisorySourceUnavailable(
            "The GitHub advisory API returned invalid JSON."
        ) from error
    if not isinstance(payload, dict):
        raise GitHubAdvisorySourceUnavailable(
            "The GitHub advisory API returned an invalid JSON object."
        )
    return payload, captured_content


def _remaining_time(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if remaining <= 0:
        raise GitHubAdvisorySourceUnavailable("GitHub advisory retrieval exceeded its time budget.")
    return remaining


class _PinnedGitHubNetworkBackend(httpcore.NetworkBackend):
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
        if host != "api.github.com" or port != 443:
            raise httpcore.ConnectError("GitHub advisory egress target is not allowed.")
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
        raise httpcore.ConnectError("Unix sockets are not permitted for GitHub advisory retrieval.")


class _PinnedGitHubTransport(httpx.HTTPTransport):
    def __init__(self, address: str) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=_PinnedGitHubNetworkBackend(address),
        )


def _public_github_address(url: str, target: GitHubAdvisoryTarget) -> str:
    _validate_api_target(url, target)
    try:
        addresses = {
            ipaddress.ip_address(sockaddr[0])
            for _, _, _, _, sockaddr in socket.getaddrinfo(
                "api.github.com", 443, type=socket.SOCK_STREAM
            )
        }
    except (OSError, ValueError) as error:
        raise GitHubAdvisorySourceUnavailable(
            "GitHub advisory egress target could not be validated."
        ) from error
    if not addresses or any(not address.is_global for address in addresses):
        raise GitHubAdvisorySourceUnavailable(
            "GitHub advisory egress resolved to a non-public address."
        )
    return str(min(addresses, key=lambda address: (address.version, str(address))))


def _validate_api_target(url: str, target: GitHubAdvisoryTarget) -> None:
    parsed = urlsplit(url)
    if (
        url != target.api_url
        or parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/repos/")
    ):
        raise GitHubAdvisorySourceUnavailable("GitHub advisory egress target is not allowed.")
