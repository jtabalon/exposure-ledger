from __future__ import annotations

import socket

import pytest
from exposure_ledger import RepositoryArchiveUnavailable
from exposure_ledger_worker.repository_archives import _public_codeload_address


def test_codeload_egress_rejects_non_public_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )

    with pytest.raises(RepositoryArchiveUnavailable, match="non-public"):
        _public_codeload_address(
            "https://codeload.github.com/example/project/zip/"
            "0123456789abcdef0123456789abcdef01234567"
        )


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
