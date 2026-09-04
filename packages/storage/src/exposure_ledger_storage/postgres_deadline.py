"""Shared PostgreSQL deadline enforcement for bounded Investigation operations."""

from __future__ import annotations

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
    if "service" in parameters or any(
        len(str(parameters.get(key, "")).split(",")) > 1 for key in ("host", "hostaddr")
    ):
        raise ValueError(
            "Bounded Investigation database access requires one explicit PostgreSQL host"
        )
    remaining_seconds = deadline_monotonic - monotonic()
    if remaining_seconds < _LIBPQ_MINIMUM_CONNECT_TIMEOUT_SECONDS:
        raise TimeoutError("Insufficient wall-time budget for a PostgreSQL connection")
    return psycopg.connect(
        database_url,
        row_factory=dict_row,
        connect_timeout=max(
            _LIBPQ_MINIMUM_CONNECT_TIMEOUT_SECONDS,
            int(remaining_seconds),
        ),
    )


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
