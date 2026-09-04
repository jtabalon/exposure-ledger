"""FastAPI application entry point."""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from exposure_ledger_storage import (
    AssessmentEvent,
    AssessmentMode,
    AssessmentRun,
    AssessmentRunRepository,
    AssessmentScenario,
    AssessmentStatus,
)
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

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


class CreateAssessmentRunRequest(ApiModel):
    mode: Literal["synthetic"]
    scenario: AssessmentScenario = AssessmentScenario.COMPLETE


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

    @classmethod
    def from_record(cls, record: AssessmentRun) -> "AssessmentRunResponse":
        return cls.model_validate(record, from_attributes=True)


class AssessmentRunListResponse(ApiModel):
    items: list[AssessmentRunResponse]


def _not_found(assessment_run_id: UUID) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "code": "assessment_run_not_found",
            "message": f"Assessment Run {assessment_run_id} was not found.",
        },
    )


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


def create_app(settings: Settings | None = None) -> FastAPI:
    configured_settings = settings or Settings()
    repository = AssessmentRunRepository(configured_settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        repository.check_ready()
        yield

    application = FastAPI(
        title="Exposure Ledger API",
        summary="Evidence-led software exposure investigations",
        version=APP_VERSION,
        lifespan=lifespan,
    )

    @application.get("/health", response_model=HealthResponse, tags=["operations"])
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="exposure-ledger-api",
            version=APP_VERSION,
            inference_mode="local",
        )

    @application.post(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunResponse,
        response_model_by_alias=True,
        status_code=status.HTTP_201_CREATED,
        tags=["assessment-runs"],
    )
    def create_assessment_run(request: CreateAssessmentRunRequest) -> AssessmentRunResponse:
        return AssessmentRunResponse.from_record(
            repository.create_synthetic(scenario=request.scenario)
        )

    @application.get(
        "/api/v1/assessment-runs",
        response_model=AssessmentRunListResponse,
        response_model_by_alias=True,
        tags=["assessment-runs"],
    )
    def list_assessment_runs() -> AssessmentRunListResponse:
        return AssessmentRunListResponse(
            items=[AssessmentRunResponse.from_record(item) for item in repository.list_runs()]
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
        return AssessmentRunResponse.from_record(assessment_run)

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
