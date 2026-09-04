"""Validated API configuration."""

from exposure_ledger_storage import DEFAULT_DATABASE_URL, normalize_database_url
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = DEFAULT_DATABASE_URL
    event_poll_seconds: float = Field(default=0.25, gt=0, le=10)

    @field_validator("database_url")
    @classmethod
    def require_postgresql(cls, value: str) -> str:
        return normalize_database_url(value)
