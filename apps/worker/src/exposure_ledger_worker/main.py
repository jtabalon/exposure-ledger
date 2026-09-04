"""Worker process for durable Assessment Runs."""

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Event, Thread
from uuid import UUID

from exposure_ledger import (
    CISA_KEV_CATALOG_URL,
    FIRST_EPSS_API_URL,
    ArchiveLimits,
    AssessmentOperation,
    AssessmentRequest,
    AssetSnapshotCapture,
    AssetSnapshotRejected,
    AuthorizationStatus,
    CisaKevCatalog,
    CisaKevSource,
    CyberPolicy,
    EpssSource,
    EpssSourceUnavailable,
    ExposureDiscovery,
    ExposureEnricher,
    FirstEpssResponse,
    FirstPartyAdvisoryCollector,
    FirstPartyAdvisorySource,
    GitHubAdvisoryResponseRejected,
    GitHubAdvisorySourceUnavailable,
    KevSourceUnavailable,
    OsvResponseRejected,
    OsvSource,
    OsvSourceUnavailable,
    PolicyDecision,
    PolicyResult,
    RepositoryArchiveSource,
    RepositoryArchiveUnavailable,
    derive_assessment_advisory_targets,
)
from exposure_ledger_storage import (
    DEFAULT_DATABASE_URL,
    AssessmentMode,
    AssessmentRunRepository,
    AssessmentScenario,
    AssetSnapshotRepository,
    EmbeddingIndexUnavailable,
    EmbeddingProvider,
    EmbeddingProviderUnavailable,
    EvidenceRetriever,
    ExposureRepository,
    OllamaEmbeddingProvider,
    normalize_database_url,
)
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from exposure_ledger_worker.enrichment import CisaKevApiSource, FirstEpssApiSource
from exposure_ledger_worker.github_advisories import GitHubAdvisoryApiSource
from exposure_ledger_worker.osv import OsvApiSource
from exposure_ledger_worker.repository_archives import GitHubArchiveSource

logger = logging.getLogger(__name__)


class _PolicyGatedKevSource:
    def __init__(
        self,
        repository: AssessmentRunRepository,
        assessment_run_id: UUID,
        source: CisaKevSource,
    ) -> None:
        self._repository = repository
        self._assessment_run_id = assessment_run_id
        self._source = source

    def catalog(self) -> CisaKevCatalog:
        decision = _public_source_decision(
            AssessmentOperation.PUBLIC_CISA_KEV_LOOKUP,
            CISA_KEV_CATALOG_URL,
        )
        self._repository.record_tool_policy_decision(self._assessment_run_id, decision)
        if decision.result is not PolicyResult.ALLOWED:
            raise KevSourceUnavailable("CISA KEV Source access was blocked by policy.")
        return self._source.catalog()


class _PolicyGatedEpssSource:
    def __init__(
        self,
        repository: AssessmentRunRepository,
        assessment_run_id: UUID,
        source: EpssSource,
    ) -> None:
        self._repository = repository
        self._assessment_run_id = assessment_run_id
        self._source = source

    def query(self, cve_ids: tuple[str, ...]) -> FirstEpssResponse:
        decision = _public_source_decision(
            AssessmentOperation.PUBLIC_FIRST_EPSS_LOOKUP,
            FIRST_EPSS_API_URL,
        )
        self._repository.record_tool_policy_decision(self._assessment_run_id, decision)
        if decision.result is not PolicyResult.ALLOWED:
            raise EpssSourceUnavailable("FIRST EPSS Source access was blocked by policy.")
        return self._source.query(cve_ids)


def _public_source_decision(
    operation: AssessmentOperation,
    target_scope: str,
) -> PolicyDecision:
    return CyberPolicy.decide(
        AssessmentRequest(
            operation=operation,
            target_scope=target_scope,
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )


def _index_evidence_or_fail(
    *,
    repository: AssessmentRunRepository,
    assessment_run_id: UUID,
    claim_id: UUID,
    database_url: str,
    embedding_provider: EmbeddingProvider,
) -> bool:
    retriever = EvidenceRetriever(database_url, embedding_provider=embedding_provider)
    readiness = embedding_provider.check_readiness()
    retriever.record_embedding_readiness(readiness)
    if readiness.space is None:
        error = EmbeddingProviderUnavailable(readiness)
    else:
        decision = CyberPolicy.decide(
            AssessmentRequest(
                operation=AssessmentOperation.EMBED_RETRIEVED_EVIDENCE,
                target_scope=(
                    f"assessment:{assessment_run_id};embedding-space:{readiness.space.identity}"
                ),
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
            )
        )
        repository.record_retrieved_content_policy_decision(assessment_run_id, decision)
        if decision.result is not PolicyResult.ALLOWED:
            repository.fail(
                assessment_run_id,
                claim_id=claim_id,
                code="embedding_content_policy_blocked",
                message=decision.reason,
            )
            return False
        try:
            retriever.index_assessment(assessment_run_id, space=readiness.space)
            return True
        except EmbeddingProviderUnavailable as caught:
            error = caught
        except (EmbeddingIndexUnavailable, ValueError) as caught:
            repository.fail(
                assessment_run_id,
                claim_id=claim_id,
                code="embedding_index_failed",
                message=str(caught),
            )
            return False

    detail = error.readiness.message
    if error.readiness.setup is not None:
        detail = f"{detail} {error.readiness.setup}"
    repository.fail(
        assessment_run_id,
        claim_id=claim_id,
        code=error.readiness.code or "embedding_provider_unavailable",
        message=detail,
    )
    return False


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = DEFAULT_DATABASE_URL
    worker_poll_seconds: float = Field(default=0.5, gt=0, le=30)
    worker_lease_seconds: float = Field(default=30, ge=1, le=3600)
    embedding_health_seconds: float = Field(default=10, gt=0, le=20)
    ollama_base_url: str = "http://localhost:11434"
    embedding_model: str = "qwen3-embedding:0.6b"

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


@contextmanager
def maintain_embedding_readiness(
    retriever: EvidenceRetriever,
    provider: EmbeddingProvider,
    *,
    interval_seconds: float,
) -> Iterator[None]:
    """Refresh worker-owned embedding health while long Assessments are running."""
    stopped = Event()

    def observe() -> None:
        try:
            retriever.record_embedding_readiness(provider.check_readiness())
        except Exception:
            logger.exception("Local embedding readiness observation failed")

    def heartbeat() -> None:
        while not stopped.wait(interval_seconds):
            observe()

    observe()
    thread = Thread(target=heartbeat, name="embedding-readiness-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join()


def process_next_assessment(
    *,
    database_url: str,
    stale_after_seconds: float = 30,
    archive_source: RepositoryArchiveSource | None = None,
    osv_source: OsvSource | None = None,
    kev_source: CisaKevSource | None = None,
    epss_source: EpssSource | None = None,
    advisory_source: FirstPartyAdvisorySource | None = None,
    embedding_provider: EmbeddingProvider | None = None,
) -> bool:
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
                capture_request = repository.get_capture_request(assessment_run.id)
                if capture_request is None:
                    raise RuntimeError("Repository Assessment Run has no capture request")
                tool_decision = CyberPolicy.decide(
                    AssessmentRequest(
                        operation=AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT,
                        target_scope=(f"{capture_request.repository}@{capture_request.commit}"),
                        authorization_scope="local operator",
                        authorization_status=AuthorizationStatus.CONFIRMED,
                    )
                )
                repository.record_tool_policy_decision(assessment_run.id, tool_decision)
                if tool_decision.result is not PolicyResult.ALLOWED:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code="repository_fetch_policy_blocked",
                        message=tool_decision.reason,
                    )
                    return True
                limits = ArchiveLimits()
                source = archive_source or GitHubArchiveSource(
                    max_bytes=limits.max_compressed_bytes
                )
                try:
                    captured = AssetSnapshotCapture(source, limits=limits).capture(capture_request)
                    snapshot = AssetSnapshotRepository(database_url).create(captured)
                except AssetSnapshotRejected as error:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code=error.code,
                        message=str(error),
                    )
                    return True
                except RepositoryArchiveUnavailable as error:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code=error.code,
                        message=str(error),
                    )
                    return True
                exposure_repository = ExposureRepository(database_url)
                if exposure_repository.is_recorded(
                    assessment_run.id,
                    asset_snapshot_id=snapshot.id,
                ):
                    if embedding_provider is not None and not _index_evidence_or_fail(
                        repository=repository,
                        assessment_run_id=assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        database_url=database_url,
                        embedding_provider=embedding_provider,
                    ):
                        return True
                    repository.complete_repository(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        asset_snapshot_id=snapshot.id,
                    )
                    return True
                osv_decision = CyberPolicy.decide(
                    AssessmentRequest(
                        operation=AssessmentOperation.PUBLIC_OSV_LOOKUP,
                        target_scope="https://api.osv.dev/v1",
                        authorization_scope="local operator",
                        authorization_status=AuthorizationStatus.CONFIRMED,
                    )
                )
                repository.record_tool_policy_decision(assessment_run.id, osv_decision)
                if osv_decision.result is not PolicyResult.ALLOWED:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code="osv_lookup_policy_blocked",
                        message=osv_decision.reason,
                    )
                    return True
                try:
                    discovered = ExposureDiscovery(osv_source or OsvApiSource()).discover(
                        snapshot.as_domain()
                    )
                    result = ExposureEnricher(
                        kev_source=_PolicyGatedKevSource(
                            repository,
                            assessment_run.id,
                            kev_source or CisaKevApiSource(),
                        ),
                        epss_source=_PolicyGatedEpssSource(
                            repository,
                            assessment_run.id,
                            epss_source or FirstEpssApiSource(),
                        ),
                    ).enrich(discovered)
                    advisory_targets = derive_assessment_advisory_targets(result)
                    for target in advisory_targets:
                        advisory_decision = _public_source_decision(
                            AssessmentOperation.PUBLIC_FIRST_PARTY_ADVISORY_LOOKUP,
                            target.api_url,
                        )
                        repository.record_tool_policy_decision(assessment_run.id, advisory_decision)
                        if advisory_decision.result is not PolicyResult.ALLOWED:
                            exposure_repository.record(
                                assessment_run_id=assessment_run.id,
                                asset_snapshot_id=snapshot.id,
                                result=result,
                            )
                            repository.fail(
                                assessment_run.id,
                                claim_id=assessment_run.claim_id,
                                code="first_party_advisory_policy_blocked",
                                message=advisory_decision.reason,
                            )
                            return True
                    if advisory_targets:
                        try:
                            result = FirstPartyAdvisoryCollector(
                                advisory_source or GitHubAdvisoryApiSource()
                            ).collect(result)
                        except GitHubAdvisorySourceUnavailable as error:
                            exposure_repository.record(
                                assessment_run_id=assessment_run.id,
                                asset_snapshot_id=snapshot.id,
                                result=result,
                            )
                            repository.fail(
                                assessment_run.id,
                                claim_id=assessment_run.claim_id,
                                code="first_party_advisory_unavailable",
                                message=str(error),
                            )
                            return True
                        except GitHubAdvisoryResponseRejected as error:
                            exposure_repository.record(
                                assessment_run_id=assessment_run.id,
                                asset_snapshot_id=snapshot.id,
                                result=result,
                            )
                            repository.fail(
                                assessment_run.id,
                                claim_id=assessment_run.claim_id,
                                code="invalid_first_party_advisory",
                                message=str(error),
                            )
                            return True
                    exposure_repository.record(
                        assessment_run_id=assessment_run.id,
                        asset_snapshot_id=snapshot.id,
                        result=result,
                    )
                    if embedding_provider is not None and not _index_evidence_or_fail(
                        repository=repository,
                        assessment_run_id=assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        database_url=database_url,
                        embedding_provider=embedding_provider,
                    ):
                        return True
                except OsvSourceUnavailable as error:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code="osv_unavailable",
                        message=str(error),
                    )
                    return True
                except OsvResponseRejected as error:
                    repository.fail(
                        assessment_run.id,
                        claim_id=assessment_run.claim_id,
                        code="invalid_osv_response",
                        message=str(error),
                    )
                    return True
                repository.complete_repository(
                    assessment_run.id,
                    claim_id=assessment_run.claim_id,
                    asset_snapshot_id=snapshot.id,
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
    embedding_provider = OllamaEmbeddingProvider(
        base_url=settings.ollama_base_url,
        model_artifact=settings.embedding_model,
    )
    readiness_repository = EvidenceRetriever(
        settings.database_url,
        embedding_provider=embedding_provider,
    )
    logger.info("Exposure Ledger worker ready")

    try:
        with maintain_embedding_readiness(
            readiness_repository,
            embedding_provider,
            interval_seconds=settings.embedding_health_seconds,
        ):
            while True:
                if not process_next_assessment(
                    database_url=settings.database_url,
                    stale_after_seconds=settings.worker_lease_seconds,
                    embedding_provider=embedding_provider,
                ):
                    time.sleep(settings.worker_poll_seconds)
    except KeyboardInterrupt:
        logger.info("Exposure Ledger worker stopped")


if __name__ == "__main__":
    main()
