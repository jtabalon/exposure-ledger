"""Shared PostgreSQL configuration primitives."""

DEFAULT_DATABASE_URL = (
    "postgresql://exposure_ledger:local-development-only@localhost:5432/exposure_ledger"
)


def normalize_database_url(value: str) -> str:
    normalized = value.replace("postgresql+psycopg://", "postgresql://", 1)
    if not normalized.startswith(("postgresql://", "postgres://")):
        raise ValueError("DATABASE_URL must use PostgreSQL")
    return normalized
