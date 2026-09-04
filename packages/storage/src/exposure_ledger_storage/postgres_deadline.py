"""Shared PostgreSQL deadline enforcement for bounded Investigation operations."""

from __future__ import annotations

from ipaddress import ip_address
from os import environ
from time import monotonic
from typing import Any

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

_LIBPQ_MINIMUM_CONNECT_TIMEOUT_SECONDS = 2


def deadline_after(timeout_seconds: float) -> float:
    if timeout_seconds <= 0:
        raise TimeoutError("Investigation wall-time budget exhausted")
    return monotonic() + timeout_seconds


def connect_with_deadline(
    database_url: str, deadline_monotonic: float | None
) -> psycopg.Connection[Any]:
    if deadline_monotonic is None:
        return psycopg.connect(database_url, row_factory=dict_row)

    parameters = conninfo_to_dict(database_url)
    if parameters.get("service") or environ.get("PGSERVICE"):
        raise ValueError("Bounded Investigation database access does not allow PGSERVICE")
    if any(
        len(str(parameters.get(key, "")).split(",")) > 1 for key in ("host", "hostaddr", "port")
    ):
        raise ValueError(
            "Bounded Investigation database access requires one explicit PostgreSQL host"
        )
    host = str(parameters.get("host", "")).strip()
    hostaddr = str(parameters.get("hostaddr", "")).strip()
    if not host and not hostaddr:
        raise ValueError(
            "Bounded Investigation database access requires an explicit PostgreSQL host"
        )

    connection_host: str
    connection_hostaddr: str | None
    if hostaddr:
        try:
            ip_address(hostaddr)
        except ValueError as error:
            raise ValueError(
                "Bounded Investigation database access requires one explicit PostgreSQL address"
            ) from error
        connection_host = host or hostaddr
        connection_hostaddr = hostaddr
    elif host.startswith("/"):
        if environ.get("PGHOSTADDR"):
            raise ValueError("Bounded Investigation Unix-socket access does not allow PGHOSTADDR")
        connection_host = host
        connection_hostaddr = None
    else:
        address = "127.0.0.1" if host == "localhost" else host
        try:
            ip_address(address)
        except ValueError as error:
            raise ValueError(
                "Bounded Investigation database access requires one explicit PostgreSQL address"
            ) from error
        connection_host = host
        connection_hostaddr = address

    remaining_seconds = deadline_monotonic - monotonic()
    if remaining_seconds < _LIBPQ_MINIMUM_CONNECT_TIMEOUT_SECONDS:
        raise TimeoutError("Insufficient wall-time budget for a PostgreSQL connection")
    connect_timeout = max(
        _LIBPQ_MINIMUM_CONNECT_TIMEOUT_SECONDS,
        int(remaining_seconds),
    )
    try:
        if connection_hostaddr is None:
            return psycopg.connect(
                database_url,
                row_factory=dict_row,
                connect_timeout=connect_timeout,
                host=connection_host,
            )
        return psycopg.connect(
            database_url,
            row_factory=dict_row,
            connect_timeout=connect_timeout,
            host=connection_host,
            hostaddr=connection_hostaddr,
        )
    except psycopg.errors.ConnectionTimeout as error:
        raise TimeoutError(
            "PostgreSQL connection exceeded the Investigation wall-time budget"
        ) from error


def set_statement_deadline(
    connection: psycopg.Connection[Any], deadline_monotonic: float | None
) -> None:
    if deadline_monotonic is None:
        return
    remaining_ms = int((deadline_monotonic - monotonic()) * 1000)
    if remaining_ms <= 0:
        raise TimeoutError("Investigation wall-time budget exhausted")
    connection.execute(
        "SELECT set_config('statement_timeout', %s, true)",
        (f"{remaining_ms}ms",),
    )
