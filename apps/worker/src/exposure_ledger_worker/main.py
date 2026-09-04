"""Worker process for durable Assessment Runs."""

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Event, Thread
from uuid import UUID

from exposure_ledger_storage import (
    DEFAULT_DATABASE_URL,
    AssessmentMode,
    AssessmentRunRepository,
    AssessmentScenario,
    normalize_database_url,
)
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = DEFAULT_DATABASE_URL
    worker_poll_seconds: float = Field(default=0.5, gt=0, le=30)
    worker_lease_seconds: float = Field(default=30, ge=1, le=3600)

    @field_validator("database_url")
    @classmethod
    def require_postgresql(cls, value: str) -> str:
        return normalize_database_url(value)


@contextmanager
def maintain_claim(
    repository: AssessmentRunRepository,
    *,
    assessment_run_id: UUID,
    claim_id: UUID,
    lease_seconds: float,
) -> Iterator[None]:
    """Renew a worker claim until the bounded unit of work finishes."""
    stopped = Event()

    def heartbeat() -> None:
        interval = max(lease_seconds / 3, 0.1)
        while not stopped.wait(interval):
            try:
                if not repository.renew_claim(assessment_run_id, claim_id=claim_id):
                    logger.warning("Assessment Run %s claim was lost", assessment_run_id)
                    return
            except Exception:
                logger.exception("Assessment Run %s claim renewal failed", assessment_run_id)

    thread = Thread(target=heartbeat, name=f"assessment-heartbeat-{assessment_run_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join()


def process_next_assessment(*, database_url: str, stale_after_seconds: float = 30) -> bool:
    """Advance one queued Assessment Run, returning whether work was claimed."""
    repository = AssessmentRunRepository(database_url)
    assessment_run = repository.claim_next(stale_after_seconds=stale_after_seconds)
    if assessment_run is None:
        return False
    if assessment_run.claim_id is None:
        raise RuntimeError(f"Assessment Run {assessment_run.id} was claimed without an owner token")

    try:
        with maintain_claim(
            repository,
            assessment_run_id=assessment_run.id,
            claim_id=assessment_run.claim_id,
            lease_seconds=stale_after_seconds,
        ):
            if (
                assessment_run.mode == AssessmentMode.SYNTHETIC
                and assessment_run.scenario == AssessmentScenario.WORKER_FAILURE
            ):
                repository.fail(
                    assessment_run.id,
                    claim_id=assessment_run.claim_id,
                    code="synthetic_worker_failure",
                    message="Synthetic worker failure requested for contract verification.",
                )
                return True
            if assessment_run.mode == AssessmentMode.SYNTHETIC:
                repository.complete_synthetic(
                    assessment_run.id,
                    claim_id=assessment_run.claim_id,
                )
            else:
                repository.complete_repository(
                    assessment_run.id,
                    claim_id=assessment_run.claim_id,
                )
    except Exception:
        logger.exception("Assessment Run %s failed", assessment_run.id)
        repository.fail(
            assessment_run.id,
            claim_id=assessment_run.claim_id,
            code="worker_execution_failed",
            message="The Assessment worker could not complete this run.",
        )
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = WorkerSettings()
    repository = AssessmentRunRepository(settings.database_url)
    repository.check_ready()
    logger.info("Exposure Ledger worker ready")

    try:
        while True:
            if not process_next_assessment(
                database_url=settings.database_url,
                stale_after_seconds=settings.worker_lease_seconds,
            ):
                time.sleep(settings.worker_poll_seconds)
    except KeyboardInterrupt:
        logger.info("Exposure Ledger worker stopped")


if __name__ == "__main__":
    main()
