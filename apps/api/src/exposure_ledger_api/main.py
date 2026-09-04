"""FastAPI application entry point."""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from exposure_ledger import (
    ActionLevel,
    Architecture,
    AssessmentOperation,
    AssessmentRequest,
    AssetSnapshotRejected,
    AssistanceClass,
    AuthorizationStatus,
    CaptureAssetSnapshot,
    CyberPolicy,
    EnvironmentProfile,
    ExposureRanking,
    ExposureSeverity,
    OperatingSystem,
    PolicyResult,
    validate_asset_snapshot_request,
)
from exposure_ledger_storage import (
    AssessmentEvent,
    AssessmentMode,
    AssessmentRun,
    AssessmentRunRepository,
    AssessmentScenario,
    AssessmentStatus,
    AssetSnapshotRecord,
    AssetSnapshotRepository,
    EvidencePassageRecord,
    EvidenceRecordRecord,
    ExposureRecord,
    ExposureRepository,
    PackageInstanceRecord,
    PolicyDecisionRecord,
)
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from exposure_ledger_api.settings import Settings

APP_VERSION = "0.1.0"


def _to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: Literal["exposure-ledger-api"]
    version: str
    inference_mode: Literal["local"]


class AssessmentPolicyContext(ApiModel):
    model_config = ConfigDict(extra="forbid")

    operation_chain: list[str] = Field(default_factory=list)


class CreateSyntheticAssessmentRunRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["synthetic"]
    scenario: AssessmentScenario = AssessmentScenario.COMPLETE
    policy_context: AssessmentPolicyContext = Field(default_factory=AssessmentPolicyContext)


class PolicyDecisionResponse(ApiModel):
    id: UUID
    assessment_run_id: UUID | None
    standard_version: str
    assistance_class: AssistanceClass
    action_level: ActionLevel
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str
    created_at: datetime
    enforcement_point: str

    @classmethod
    def from_record(cls, record: PolicyDecisionRecord) -> "PolicyDecisionResponse":
        return cls.model_validate(record, from_attributes=True)


class AssessmentRunResponse(ApiModel):
    id: UUID
    mode: AssessmentMode
    scenario: AssessmentScenario
    label: str
    synthetic: bool
    status: AssessmentStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    asset_snapshot_id: UUID | None
    policy_decision: PolicyDecisionResponse

    @classmethod
    def from_record(
        cls,
        record: AssessmentRun,
        policy_decision: PolicyDecisionRecord,
    ) -> "AssessmentRunResponse":
        return cls.model_validate(
            {
                **asdict(record),
                "policy_decision": PolicyDecisionResponse.from_record(policy_decision),
            }
        )


class AssessmentRunListResponse(ApiModel):
    items: list[AssessmentRunResponse]


class PolicyDecisionListResponse(ApiModel):
    items: list[PolicyDecisionResponse]


class EnvironmentProfileRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    python_version: str
    operating_system: OperatingSystem
    architecture: Architecture
    selected_extras: list[str] = Field(default_factory=list)


class CreateRepositoryAssessmentRunRequest(ApiModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["repository"]
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    environment_profile: EnvironmentProfileRequest
    policy_context: AssessmentPolicyContext = Field(default_factory=AssessmentPolicyContext)


CreateAssessmentRunRequest = Annotated[
    CreateSyntheticAssessmentRunRequest | CreateRepositoryAssessmentRunRequest,
    Field(discriminator="mode"),
]


class EnvironmentProfileResponse(ApiModel):
    python_version: str
    operating_system: OperatingSystem
    architecture: Architecture
    selected_extras: list[str]

    @classmethod
    def from_domain(cls, profile: EnvironmentProfile) -> "EnvironmentProfileResponse":
        return cls(
            python_version=profile.python_version,
            operating_system=profile.operating_system,
            architecture=profile.architecture,
            selected_extras=list(profile.selected_extras),
        )


class PackageInstanceResponse(ApiModel):
    name: str
    version: str
    direct: bool | None
    source: dict[str, object]
    dependency_paths: list[list[str]] | None

    @classmethod
    def from_record(cls, package: PackageInstanceRecord) -> "PackageInstanceResponse":
        return cls(
            name=package.name,
            version=package.version,
            direct=package.direct,
            source=package.source,
            dependency_paths=(
                [list(path) for path in package.dependency_paths]
                if package.dependency_paths is not None
                else None
            ),
        )


class AssetSnapshotResponse(ApiModel):
    id: UUID
    repository: str
    commit: str
    project_root: str
    lockfile_path: str
    lockfile_digest: str
    environment_profile: EnvironmentProfileResponse
    packages: list[PackageInstanceResponse]
    parser_version: str
    captured_at: datetime

    @classmethod
    def from_record(cls, snapshot: AssetSnapshotRecord) -> "AssetSnapshotResponse":
        return cls(
            id=snapshot.id,
            repository=snapshot.repository,
            commit=snapshot.commit,
            project_root=snapshot.project_root,
            lockfile_path=snapshot.lockfile_path,
            lockfile_digest=snapshot.lockfile_digest,
            environment_profile=EnvironmentProfileResponse.from_domain(
                snapshot.environment_profile
            ),
            packages=[PackageInstanceResponse.from_record(item) for item in snapshot.packages],
            parser_version=snapshot.parser_version,
            captured_at=snapshot.captured_at,
        )


class AssetSnapshotListResponse(ApiModel):
    items: list[AssetSnapshotResponse]


class VulnerabilityRecordResponse(ApiModel):
    id: UUID
    aliases: list[str]


class ExposureRankingResponse(ApiModel):
    severity: ExposureSeverity
    direct_dependency: bool | None
    dependency_depth: int | None
    fixed_version_available: bool
    score: int

    @classmethod
    def from_domain(cls, ranking: ExposureRanking) -> "ExposureRankingResponse":
        return cls.model_validate(ranking, from_attributes=True)


class SourceResponse(ApiModel):
    identity: str
    authority: str
    location: str


class EvidencePassageResponse(ApiModel):
    id: UUID
    identity: str
    kind: str
    selector: str
    content: str

    @classmethod
    def from_record(cls, passage: EvidencePassageRecord) -> "EvidencePassageResponse":
        return cls.model_validate(passage, from_attributes=True)


class EvidenceRecordResponse(ApiModel):
    id: UUID
    identity: str
    source: SourceResponse
    captured_at: datetime
    content_digest: str
    attribution: str
    aliases: list[str]
    payload_identity: str
    content: str
    passages: list[EvidencePassageResponse]

    @classmethod
    def from_record(cls, evidence: EvidenceRecordRecord) -> "EvidenceRecordResponse":
        return cls(
            id=evidence.id,
            identity=evidence.identity,
            source=SourceResponse.model_validate(evidence.source, from_attributes=True),
            captured_at=evidence.captured_at,
            content_digest=evidence.content_digest,
            attribution=evidence.attribution,
            aliases=list(evidence.aliases),
            payload_identity=evidence.payload_identity,
            content=evidence.content,
            passages=[EvidencePassageResponse.from_record(item) for item in evidence.passages],
        )


class ExposureResponse(ApiModel):
    id: UUID
    assessment_run_id: UUID
    asset_snapshot_id: UUID
    vulnerability_record: VulnerabilityRecordResponse
    package: PackageInstanceResponse
    ranking: ExposureRankingResponse
    rank: int
    selected_for_investigation: bool
    evidence_records: list[EvidenceRecordResponse]

    @classmethod
    def from_record(cls, exposure: ExposureRecord) -> "ExposureResponse":
        return cls(
            id=exposure.id,
            assessment_run_id=exposure.assessment_run_id,
            asset_snapshot_id=exposure.asset_snapshot_id,
            vulnerability_record=VulnerabilityRecordResponse(
                id=exposure.vulnerability_record.id,
                aliases=list(exposure.vulnerability_record.aliases),
            ),
            package=PackageInstanceResponse.from_record(exposure.package),
            ranking=ExposureRankingResponse.from_domain(exposure.ranking),
            rank=exposure.rank,
            selected_for_investigation=exposure.selected_for_investigation,
            evidence_records=[
                EvidenceRecordResponse.from_record(item) for item in exposure.evidence_records
            ],
        )


class ExposureListResponse(ApiModel):
    items: list[ExposureResponse]


def _not_found(assessment_run_id: UUID) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "code": "assessment_run_not_found",
            "message": f"Assessment Run {assessment_run_id} was not found.",
        },
    )


def _assessment_response(
    repository: AssessmentRunRepository,
    assessment_run: AssessmentRun,
) -> AssessmentRunResponse:
    policy_decision = repository.get_policy_decision(assessment_run.id)
    if policy_decision is None:
        raise RuntimeError(f"Assessment Run {assessment_run.id} has no request Policy Decision.")
    return AssessmentRunResponse.from_record(assessment_run, policy_decision)


def _encode_sse(event: AssessmentEvent) -> str:
    body = {
        "assessmentRunId": str(event.assessment_run_id),
        "sequence": event.sequence,
        "type": event.event_type,
        "occurredAt": event.occurred_at.isoformat(),
        **event.payload,
    }
    return (
        f"id: {event.sequence}\n"
        f"event: {event.event_type}\n"
        f"data: {json.dumps(body, separators=(',', ':'))}\n\n"
    )


def create_app(
    settings: Settings | None = None,
) -> FastAPI:
    configured_settings = settings or Settings()
    repository = AssessmentRunRepository(configured_settings.database_url)
    snapshot_repository = AssetSnapshotRepository(configured_settings.database_url)
    exposure_repository = ExposureRepository(configured_settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        repository.check_ready()
        snapshot_repository.check_ready()
        exposure_repository.check_ready()
        yield

    application = FastAPI(
        title="Exposure Ledger API",
        summary="Evidence-led software exposure investigations",
        version=APP_VERSION,
        lifespan=lifespan,
    )

    @application.exception_handler(RequestValidationError)
    async def typed_request_validation(
        request: Request,
        error: RequestValidationError,
    ) -> Response:
        body = error.body
        selection_error_fields = {
            str(item["loc"][-1])
            for item in error.errors()
            if item.get("loc")
            and item["loc"][-1] in {"projectRoot", "lockfilePath", "project_root", "lockfile_path"}
        }
        if isinstance(body, dict) and body.get("mode") == "repository" and selection_error_fields:
            raw_context = body.get("policyContext", body.get("policy_context", {}))
            raw_chain = (
                raw_context.get("operationChain", raw_context.get("operation_chain", []))
                if isinstance(raw_context, dict)
                else []
            )
            operation_chain = (
                tuple(raw_chain)
                if isinstance(raw_chain, list)
                and all(isinstance(operation, str) for operation in raw_chain)
                else ("unrecognized_operation",)
            )
            raw_repository = body.get("repository")
            raw_commit = body.get("commit")
            target_scope = (
                f"{raw_repository}@{raw_commit}"
                if isinstance(raw_repository, str) and isinstance(raw_commit, str)
                else None
            )
            decision = CyberPolicy.decide(
                AssessmentRequest(
                    operation=AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT,
                    target_scope=target_scope,
                    authorization_scope="local operator",
                    authorization_status=AuthorizationStatus.UNCERTAIN,
                    operation_chain=operation_chain,
                )
            )
            repository.record_policy_decision(
                replace(
                    decision,
                    result=PolicyResult.BLOCKED,
                    reason=(
                        "Asset Snapshot project and lockfile selection is materially uncertain; "
                        "the Assessment request is blocked."
                    ),
                )
            )
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                content={
                    "detail": {
                        "code": "asset_snapshot_selection_required",
                        "message": (
                            "Select exactly one project root and one supported lockfile before "
                            "capturing an Asset Snapshot."
                        ),
                    }
                },
            )
        return await request_validation_exception_handler(request, error)

    @application.get("/health", response_model=HealthResponse, tags=["operations"])
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="exposure-ledger-api",
            version=APP_VERSION,
            inference_mode="local",
        )

    @application.get(
        "/api/v1/asset-snapshots",
        response_model=AssetSnapshotListResponse,
        response_model_by_alias=True,
        tags=["asset-snapshots"],
    )
    def list_asset_snapshots() -> AssetSnapshotListResponse:
        return AssetSnapshotListResponse(
            items=[AssetSnapshotResponse.from_record(item) for item in snapshot_repository.list()]
        )

    @application.get(
        "/api/v1/asset-snapshots/{snapshot_id}",
        response_model=AssetSnapshotResponse,
        response_model_by_alias=True,
        tags=["asset-snapshots"],
    )
    def get_asset_snapshot(snapshot_id: UUID) -> AssetSnapshotResponse:
        snapshot = snapshot_repository.get(snapshot_id)
        if snapshot is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "asset_snapshot_not_found",
                    "message": f"Asset Snapshot {snapshot_id} was not found.",
                },
            )
        return AssetSnapshotResponse.from_record(snapshot)

    @application.post(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunResponse,
        response_model_by_alias=True,
        status_code=status.HTTP_201_CREATED,
        tags=["assessment-runs"],
    )
    def create_assessment_run(request: CreateAssessmentRunRequest) -> AssessmentRunResponse:
        context = request.policy_context
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            operation = AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT
            target_scope = f"{request.repository}@{request.commit}"
        else:
            operation = AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT
            target_scope = "bundled synthetic fixture"
        decision = CyberPolicy.decide(
            AssessmentRequest(
                operation=operation,
                target_scope=target_scope,
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
                operation_chain=tuple(context.operation_chain),
            )
        )
        if decision.result is not PolicyResult.ALLOWED:
            policy_record = repository.record_policy_decision(decision)
            response = PolicyDecisionResponse.from_record(policy_record)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": f"assessment_policy_{decision.result}",
                    "message": decision.reason,
                    "policyDecision": response.model_dump(mode="json", by_alias=True),
                },
            )
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            try:
                profile = EnvironmentProfile(
                    python_version=request.environment_profile.python_version,
                    operating_system=request.environment_profile.operating_system,
                    architecture=request.environment_profile.architecture,
                    selected_extras=tuple(request.environment_profile.selected_extras),
                )
                capture_request = validate_asset_snapshot_request(
                    CaptureAssetSnapshot(
                        repository=request.repository,
                        commit=request.commit,
                        project_root=request.project_root,
                        lockfile_path=request.lockfile_path,
                        environment_profile=profile,
                    )
                )
            except AssetSnapshotRejected as error:
                repository.record_policy_decision(
                    replace(
                        decision,
                        result=PolicyResult.BLOCKED,
                        reason=(
                            f"Target scope is invalid; the Assessment request is blocked: {error}"
                        ),
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={"code": error.code, "message": str(error)},
                ) from error
            except ValueError as error:
                repository.record_policy_decision(
                    replace(
                        decision,
                        result=PolicyResult.BLOCKED,
                        reason=(
                            "Environment Profile is invalid; the Assessment request is blocked: "
                            f"{error}"
                        ),
                    )
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail={"code": "invalid_environment_profile", "message": str(error)},
                ) from error
            target_scope = f"{capture_request.repository}@{capture_request.commit}"
            decision = CyberPolicy.decide(
                AssessmentRequest(
                    operation=operation,
                    target_scope=target_scope,
                    authorization_scope="local operator",
                    authorization_status=AuthorizationStatus.CONFIRMED,
                    operation_chain=tuple(context.operation_chain),
                )
            )
        if isinstance(request, CreateRepositoryAssessmentRunRequest):
            assessment_run = repository.create_repository(
                capture_request=capture_request,
                label=(
                    f"{capture_request.repository.removeprefix('https://github.com/')}"
                    f"@{capture_request.commit[:12]}"
                ),
                policy_decision=decision,
            )
        else:
            assessment_run = repository.create_synthetic(
                scenario=request.scenario,
                policy_decision=decision,
            )
        return _assessment_response(repository, assessment_run)

    @application.get(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunListResponse,
        response_model_by_alias=True,
        tags=["assessment-runs"],
    )
    def list_assessment_runs() -> AssessmentRunListResponse:
        return AssessmentRunListResponse(
            items=[_assessment_response(repository, item) for item in repository.list_runs()]
        )

    @application.get(
        "/api/v1/policy-decisions",
        response_model=PolicyDecisionListResponse,
        response_model_by_alias=True,
        tags=["policy-decisions"],
    )
    def list_policy_decisions() -> PolicyDecisionListResponse:
        return PolicyDecisionListResponse(
            items=[
                PolicyDecisionResponse.from_record(item)
                for item in repository.list_policy_decisions()
            ]
        )

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}",
        response_model=AssessmentRunResponse,
        response_model_by_alias=True,
        tags=["assessment-runs"],
    )
    def get_assessment_run(assessment_run_id: UUID) -> AssessmentRunResponse:
        assessment_run = repository.get(assessment_run_id)
        if assessment_run is None:
            raise _not_found(assessment_run_id)
        return _assessment_response(repository, assessment_run)

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/exposures",
        response_model=ExposureListResponse,
        response_model_by_alias=True,
        tags=["exposures"],
    )
    def list_assessment_exposures(assessment_run_id: UUID) -> ExposureListResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)
        return ExposureListResponse(
            items=[
                ExposureResponse.from_record(item)
                for item in exposure_repository.list_for_assessment(assessment_run_id)
            ]
        )

    @application.get(
        "/api/v1/assessment-runs/{assessment_run_id}/events",
        response_class=StreamingResponse,
        tags=["assessment-runs"],
        responses={200: {"content": {"text/event-stream": {}}}},
    )
    async def stream_assessment_events(
        assessment_run_id: UUID,
        request: Request,
        after: Annotated[int | None, Query(ge=0)] = None,
        follow: bool = True,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        if repository.get(assessment_run_id) is None:
            raise _not_found(assessment_run_id)

        cursor = after if after is not None else _parse_last_event_id(last_event_id)

        async def event_stream() -> AsyncIterator[str]:
            current = cursor
            while True:
                events = repository.list_events(assessment_run_id, after=current)
                for event in events:
                    current = event.sequence
                    yield _encode_sse(event)

                assessment_run = repository.get(assessment_run_id)
                finished = assessment_run is None or assessment_run.status in {
                    AssessmentStatus.COMPLETED,
                    AssessmentStatus.FAILED,
                }
                if not follow or finished or await request.is_disconnected():
                    break
                await asyncio.sleep(configured_settings.event_poll_seconds)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    return application


def _parse_last_event_id(value: str | None) -> int:
    if value is None:
        return 0
    try:
        parsed = int(value)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_event_cursor",
                "message": "Last-Event-ID must be a non-negative integer.",
            },
        ) from error
    if parsed < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_event_cursor",
                "message": "Last-Event-ID must be a non-negative integer.",
            },
        )
    return parsed


app = create_app()
