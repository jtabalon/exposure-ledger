"""Narrow worker HTTP adapter for immutable public GitHub repository archives."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpcore
import httpx
from exposure_ledger import RepositoryArchive, RepositoryArchiveUnavailable


class GitHubArchiveSource:
    """Fetch one commit archive from the fixed public codeload origin."""

    def __init__(self, *, max_bytes: int, timeout_seconds: float = 15.0) -> None:
        self._max_bytes = max_bytes
        self._timeout = httpx.Timeout(timeout_seconds)

    def fetch(self, repository: str, commit: str) -> RepositoryArchive:
        path = urlsplit(repository).path.strip("/")
        url = f"https://codeload.github.com/{path}/zip/{commit}"
        address = _public_codeload_address(url)
        try:
            with (
                httpx.Client(
                    follow_redirects=False,
                    timeout=self._timeout,
                    trust_env=False,
                    headers={"User-Agent": "Exposure-Ledger/0.1"},
                    transport=_PinnedHTTPTransport(address),
                ) as client,
                client.stream("GET", url, headers={"Accept": "application/zip"}) as response,
            ):
                if response.is_redirect:
                    raise RepositoryArchiveUnavailable(
                        "repository_redirect_rejected",
                        "GitHub archive redirects are not accepted.",
                    )
                if response.status_code != 200:
                    raise RepositoryArchiveUnavailable(
                        "repository_unavailable",
                        "The public repository or immutable commit was not available.",
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > self._max_bytes:
                        raise RepositoryArchiveUnavailable(
                            "archive_too_large",
                            "The public repository archive exceeds the download limit.",
                        )
        except httpx.HTTPError as error:
            raise RepositoryArchiveUnavailable(
                "repository_unavailable", "The public repository archive could not be retrieved."
            ) from error
        return RepositoryArchive(content=bytes(content))


class _PinnedNetworkBackend(httpcore.NetworkBackend):
    """Connect the approved hostname to the exact address that passed validation."""

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
        if host != "codeload.github.com" or port != 443:
            raise httpcore.ConnectError("Repository archive egress target is not allowed.")
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
        raise httpcore.ConnectError("Unix sockets are not permitted for repository retrieval.")


class _PinnedHTTPTransport(httpx.HTTPTransport):
    def __init__(self, address: str) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=_PinnedNetworkBackend(address),
        )


def _public_codeload_address(url: str) -> str:
    """Validate the fixed archive origin and return one public address to pin."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "codeload.github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RepositoryArchiveUnavailable(
            "repository_target_rejected",
            "Repository archive egress target is not allowed.",
        )
    try:
        addresses = {
            ipaddress.ip_address(sockaddr[0])
            for _, _, _, _, sockaddr in socket.getaddrinfo(
                "codeload.github.com", 443, type=socket.SOCK_STREAM
            )
        }
    except (OSError, ValueError) as error:
        raise RepositoryArchiveUnavailable(
            "repository_address_unavailable",
            "Repository archive egress target could not be validated.",
        ) from error
    if not addresses or any(not address.is_global for address in addresses):
        raise RepositoryArchiveUnavailable(
            "repository_address_rejected",
            "Repository archive egress resolved to a non-public address.",
        )
    return str(min(addresses, key=lambda address: (address.version, str(address))))
