from __future__ import annotations

import socket

import httpx
import pytest
from exposure_ledger import RepositoryArchiveUnavailable
from exposure_ledger_worker import repository_archives
from exposure_ledger_worker.repository_archives import GitHubArchiveSource, _public_codeload_address


def test_codeload_egress_rejects_non_public_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )

    with pytest.raises(RepositoryArchiveUnavailable, match="non-public") as error:
        _public_codeload_address(
            "https://codeload.github.com/example/project/zip/"
            "0123456789abcdef0123456789abcdef01234567"
        )

    assert error.value.code == "repository_address_rejected"


def test_codeload_egress_accepts_only_fixed_https_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.10", 443))
        ],
    )

    assert (
        _public_codeload_address(
            "https://codeload.github.com/example/project/zip/"
            "0123456789abcdef0123456789abcdef01234567"
        )
        == "140.82.112.10"
    )
    with pytest.raises(RepositoryArchiveUnavailable, match="not allowed"):
        _public_codeload_address(
            "https://codeload.github.com.evil.test/example/project/zip/"
            "0123456789abcdef0123456789abcdef01234567"
        )


def test_codeload_redirect_is_a_typed_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_archives,
        "_public_codeload_address",
        lambda url: "140.82.112.10",
    )
    monkeypatch.setattr(
        repository_archives,
        "_PinnedHTTPTransport",
        lambda address: httpx.MockTransport(
            lambda request: httpx.Response(
                302,
                headers={"location": "https://example.test/expanded-target"},
                request=request,
            )
        ),
    )

    with pytest.raises(RepositoryArchiveUnavailable) as error:
        GitHubArchiveSource(max_bytes=1024).fetch(
            "https://github.com/example/project",
            "0123456789abcdef0123456789abcdef01234567",
        )

    assert error.value.code == "repository_redirect_rejected"
