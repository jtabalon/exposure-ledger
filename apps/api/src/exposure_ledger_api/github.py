"""Narrow HTTP adapter for immutable public GitHub repository archives."""

from __future__ import annotations

from urllib.parse import urlsplit

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
        try:
            with httpx.stream(
                "GET",
                url,
                follow_redirects=False,
                timeout=self._timeout,
                headers={
                    "Accept": "application/zip",
                    "User-Agent": "Exposure-Ledger/0.1",
                },
            ) as response:
                if response.is_redirect:
                    raise RepositoryArchiveUnavailable("GitHub archive redirects are not accepted.")
                if response.status_code != 200:
                    raise RepositoryArchiveUnavailable(
                        "The public repository or immutable commit was not available."
                    )
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > self._max_bytes:
                        raise RepositoryArchiveUnavailable(
                            "The public repository archive exceeds the download limit."
                        )
        except httpx.HTTPError as error:
            raise RepositoryArchiveUnavailable(
                "The public repository archive could not be retrieved."
            ) from error
        return RepositoryArchive(content=bytes(content))
