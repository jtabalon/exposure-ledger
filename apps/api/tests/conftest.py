from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from exposure_ledger_storage import apply_migrations
from psycopg import sql


@pytest.fixture
def database_url() -> Iterator[str]:
    database_name = f"exposure_ledger_test_{uuid4().hex}"
    admin_url = os.environ.get(
        "EXPOSURE_LEDGER_TEST_ADMIN_URL",
        "postgresql://exposure_ledger:local-development-only@localhost:5432/postgres",
    )

    try:
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
    except psycopg.OperationalError as error:
        pytest.fail(
            "PostgreSQL is required for API integration tests. Start it with `make infra-up`. "
            f"Connection failed: {error}"
        )

    try:
        test_database_url = (
            f"postgresql://exposure_ledger:local-development-only@localhost:5432/{database_name}"
        )
        apply_migrations(test_database_url)
        yield test_database_url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database_name))
            )
