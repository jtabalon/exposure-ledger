"""Command-line entry point for database migrations."""

import logging

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from exposure_ledger_storage.configuration import (
    DEFAULT_DATABASE_URL,
    normalize_database_url,
)
from exposure_ledger_storage.migrations import apply_migrations


class MigrationSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = DEFAULT_DATABASE_URL

    @field_validator("database_url")
    @classmethod
    def require_postgresql(cls, value: str) -> str:
        return normalize_database_url(value)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = MigrationSettings()
    try:
        apply_migrations(settings.database_url)
    except Exception:
        logging.exception(
            "Database migration failed. Check DATABASE_URL and start PostgreSQL with "
            "`make infra-up`."
        )
        raise
    logging.info("Exposure Ledger database migrations are current")


if __name__ == "__main__":
    main()
