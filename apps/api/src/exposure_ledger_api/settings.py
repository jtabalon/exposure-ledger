"""Validated API configuration."""

from exposure_ledger_storage import DEFAULT_DATABASE_URL, normalize_database_url
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = DEFAULT_DATABASE_URL
    event_poll_seconds: float = Field(default=0.25, gt=0, le=10)
    enable_local_dispositions: bool = Field(
        default=False,
        validation_alias="EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS",
    )
    local_operator: str = Field(
        default="Local AppSec operator",
        min_length=1,
        max_length=200,
        validation_alias="EXPOSURE_LEDGER_LOCAL_OPERATOR",
    )

    @field_validator("database_url")
    @classmethod
    def require_postgresql(cls, value: str) -> str:
        return normalize_database_url(value)

    @field_validator("local_operator")
    @classmethod
    def require_local_operator(cls, value: str) -> str:
        operator = value.strip()
        if not operator:
            raise ValueError("Local Disposition operator must not be blank")
        return operator
