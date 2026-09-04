"""Durable Assessment Run records and ordered progress events."""

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, cast
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import (
    ActionLevel,
    Architecture,
    AssistanceClass,
    CaptureAssetSnapshot,
    EnvironmentProfile,
    InvestigationEvent,
    OperatingSystem,
    PolicyDecision,
    PolicyResult,
)
from psycopg.rows import class_row, tuple_row
from psycopg.types.json import Jsonb

_ASSESSMENT_RUN_SELECT = """
    SELECT id, mode, scenario, label, synthetic, status, created_at, started_at,
           completed_at, error_code, error_message, claimed_at, claim_id, asset_snapshot_id
    FROM assessment_runs
"""

_POLICY_DECISION_SELECT = """
    SELECT id, assessment_run_id, standard_version, assistance_class, action_level,
           target_scope, authorization_scope, result, rule_version, reason, created_at,
           enforcement_point
    FROM policy_decisions
"""


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentMode(StrEnum):
    SYNTHETIC = "synthetic"
    REPOSITORY = "repository"


class AssessmentScenario(StrEnum):
    COMPLETE = "complete"
    WORKER_FAILURE = "worker_failure"


class AssessmentEventType(StrEnum):
    QUEUED = "assessment.queued"
    STARTED = "assessment.started"
    RESUMED = "assessment.resumed"
    SYNTHETIC_PROGRESS = "assessment.synthetic_progress"
    ASSET_SNAPSHOT_CAPTURED = "assessment.asset_snapshot_captured"
    COMPLETED = "assessment.completed"
    FAILED = "assessment.failed"
    INVESTIGATION_PROGRESS = "investigation.progress"


@dataclass(frozen=True, slots=True)
class AssessmentRun:
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
    claimed_at: datetime | None
    claim_id: UUID | None
    asset_snapshot_id: UUID | None


@dataclass(frozen=True, slots=True)
class AssessmentEvent:
    assessment_run_id: UUID
    sequence: int
    event_type: AssessmentEventType
    payload: dict[str, Any]
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyDecisionRecord:
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


class AssessmentRunRepository:
    """Persist Assessment request decisions, Runs, and event streams in PostgreSQL."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def check_ready(self) -> None:
        try:
            with psycopg.connect(self._database_url) as connection:
                connection.execute(
                    "SELECT EXISTS (SELECT 1 FROM assessment_runs), "
                    "EXISTS (SELECT 1 FROM policy_decisions)"
                )
        except psycopg.Error as error:
            raise RuntimeError(
                "PostgreSQL is unavailable or not migrated. "
                "Check DATABASE_URL, then run `make infra-up migrate`."
            ) from error

    def create_synthetic(
        self,
        *,
        policy_decision: PolicyDecision,
        scenario: AssessmentScenario = AssessmentScenario.COMPLETE,
    ) -> AssessmentRun:
        return self._create(
            mode=AssessmentMode.SYNTHETIC,
            scenario=scenario,
            label="Synthetic Assessment Run",
            synthetic=True,
            asset_snapshot_id=None,
            policy_decision=policy_decision,
        )

    def create_repository(
        self,
        *,
        capture_request: CaptureAssetSnapshot,
        label: str,
        policy_decision: PolicyDecision,
    ) -> AssessmentRun:
        return self._create(
            mode=AssessmentMode.REPOSITORY,
            scenario=AssessmentScenario.COMPLETE,
            label=label,
            synthetic=False,
            asset_snapshot_id=None,
            policy_decision=policy_decision,
            capture_request=capture_request,
        )

    def _create(
        self,
        *,
        mode: AssessmentMode,
        scenario: AssessmentScenario,
        label: str,
        synthetic: bool,
        asset_snapshot_id: UUID | None,
        policy_decision: PolicyDecision,
        capture_request: CaptureAssetSnapshot | None = None,
    ) -> AssessmentRun:
        if policy_decision.result is not PolicyResult.ALLOWED:
            raise ValueError("Only an allowed Policy Decision can create an Assessment Run.")
        assessment_run = AssessmentRun(
            id=uuid4(),
            mode=mode,
            scenario=scenario,
            label=label,
            synthetic=synthetic,
            status=AssessmentStatus.QUEUED,
            created_at=datetime.now(UTC),
            started_at=None,
            completed_at=None,
            error_code=None,
            error_message=None,
            claimed_at=None,
            claim_id=None,
            asset_snapshot_id=asset_snapshot_id,
        )
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            connection.execute(
                """
                INSERT INTO assessment_runs (
                    id, mode, scenario, label, synthetic, status, created_at,
                    asset_snapshot_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    assessment_run.id,
                    assessment_run.mode,
                    assessment_run.scenario,
                    assessment_run.label,
                    assessment_run.synthetic,
                    assessment_run.status,
                    assessment_run.created_at,
                    assessment_run.asset_snapshot_id,
                ),
            )
            self._insert_event(
                connection,
                assessment_run.id,
                sequence=1,
                event_type=AssessmentEventType.QUEUED,
                payload={
                    "status": AssessmentStatus.QUEUED,
                    "message": f"{assessment_run.label} queued.",
                },
                occurred_at=assessment_run.created_at,
            )
            self._insert_policy_decision(
                connection,
                policy_decision,
                assessment_run_id=assessment_run.id,
                created_at=assessment_run.created_at,
                enforcement_point="request",
            )
            if capture_request is not None:
                profile = capture_request.environment_profile
                connection.execute(
                    """
                    INSERT INTO asset_capture_requests (
                        assessment_run_id, repository, commit_sha, project_root,
                        lockfile_path, python_version, operating_system,
                        architecture, selected_extras
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        assessment_run.id,
                        capture_request.repository,
                        capture_request.commit,
                        capture_request.project_root,
                        capture_request.lockfile_path,
                        profile.python_version,
                        profile.operating_system,
                        profile.architecture,
                        list(profile.selected_extras),
                    ),
                )
        return assessment_run

    def record_policy_decision(self, decision: PolicyDecision) -> PolicyDecisionRecord:
        created_at = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            decision_id, created_at = self._insert_policy_decision(
                connection,
                decision,
                assessment_run_id=None,
                created_at=created_at,
                enforcement_point="request",
            )
        return PolicyDecisionRecord(
            id=decision_id,
            assessment_run_id=None,
            standard_version=decision.standard_version,
            assistance_class=decision.assistance_class,
            action_level=decision.action_level,
            target_scope=decision.target_scope,
            authorization_scope=decision.authorization_scope,
            result=decision.result,
            rule_version=decision.rule_version,
            reason=decision.reason,
            created_at=created_at,
            enforcement_point="request",
        )

    def record_tool_policy_decision(
        self, assessment_run_id: UUID, decision: PolicyDecision
    ) -> PolicyDecisionRecord:
        created_at = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            decision_id, created_at = self._insert_policy_decision(
                connection,
                decision,
                assessment_run_id=assessment_run_id,
                created_at=created_at,
                enforcement_point="tool_call",
                idempotency_key=_policy_idempotency_key("tool_call", decision),
            )
        return PolicyDecisionRecord(
            id=decision_id,
            assessment_run_id=assessment_run_id,
            standard_version=decision.standard_version,
            assistance_class=decision.assistance_class,
            action_level=decision.action_level,
            target_scope=decision.target_scope,
            authorization_scope=decision.authorization_scope,
            result=decision.result,
            rule_version=decision.rule_version,
            reason=decision.reason,
            created_at=created_at,
            enforcement_point="tool_call",
        )

    def record_retrieved_content_policy_decision(
        self, assessment_run_id: UUID, decision: PolicyDecision
    ) -> PolicyDecisionRecord:
        """Record policy enforcement before untrusted evidence enters a local model."""
        created_at = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            decision_id, created_at = self._insert_policy_decision(
                connection,
                decision,
                assessment_run_id=assessment_run_id,
                created_at=created_at,
                enforcement_point="retrieved_content",
                idempotency_key=_policy_idempotency_key("retrieved_content", decision),
            )
        return PolicyDecisionRecord(
            id=decision_id,
            assessment_run_id=assessment_run_id,
            standard_version=decision.standard_version,
            assistance_class=decision.assistance_class,
            action_level=decision.action_level,
            target_scope=decision.target_scope,
            authorization_scope=decision.authorization_scope,
            result=decision.result,
            rule_version=decision.rule_version,
            reason=decision.reason,
            created_at=created_at,
            enforcement_point="retrieved_content",
        )

    def get_policy_decision(self, assessment_run_id: UUID) -> PolicyDecisionRecord | None:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(PolicyDecisionRecord),
        ) as connection:
            return connection.execute(
                f"{_POLICY_DECISION_SELECT} WHERE assessment_run_id = %s "
                "AND enforcement_point = 'request' "
                "ORDER BY created_at DESC, id DESC LIMIT 1",
                (assessment_run_id,),
            ).fetchone()

    def list_policy_decisions(self) -> list[PolicyDecisionRecord]:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(PolicyDecisionRecord),
        ) as connection:
            return list(
                connection.execute(
                    f"{_POLICY_DECISION_SELECT} ORDER BY created_at DESC, id DESC"
                ).fetchall()
            )

    def get(self, assessment_run_id: UUID) -> AssessmentRun | None:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(AssessmentRun),
        ) as connection:
            return connection.execute(
                f"{_ASSESSMENT_RUN_SELECT} WHERE id = %s",
                (assessment_run_id,),
            ).fetchone()

    def get_capture_request(self, assessment_run_id: UUID) -> CaptureAssetSnapshot | None:
        with psycopg.connect(self._database_url, row_factory=tuple_row) as connection:
            row = connection.execute(
                """
                SELECT repository, commit_sha, project_root, lockfile_path,
                       python_version, operating_system, architecture, selected_extras
                FROM asset_capture_requests
                WHERE assessment_run_id = %s
                """,
                (assessment_run_id,),
            ).fetchone()
        if row is None:
            return None
        return CaptureAssetSnapshot(
            repository=str(row[0]),
            commit=str(row[1]).strip(),
            project_root=str(row[2]),
            lockfile_path=str(row[3]),
            environment_profile=EnvironmentProfile(
                python_version=str(row[4]),
                operating_system=OperatingSystem(str(row[5])),
                architecture=Architecture(str(row[6])),
                selected_extras=tuple(row[7]),
            ),
        )

    def list_runs(self) -> list[AssessmentRun]:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(AssessmentRun),
        ) as connection:
            return list(
                connection.execute(
                    f"{_ASSESSMENT_RUN_SELECT} ORDER BY created_at DESC, id DESC"
                ).fetchall()
            )

    def list_events(self, assessment_run_id: UUID, *, after: int) -> list[AssessmentEvent]:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(AssessmentEvent),
        ) as connection:
            return list(
                connection.execute(
                    """
                    SELECT assessment_run_id, sequence, event_type, payload, occurred_at
                    FROM assessment_events
                    WHERE assessment_run_id = %s AND sequence > %s
                    ORDER BY sequence
                    """,
                    (assessment_run_id, after),
                ).fetchall()
            )

    def record_investigation_progress(
        self,
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
        operation_id: UUID,
        exposure_id: UUID,
        event: InvestigationEvent,
    ) -> InvestigationEvent | None:
        """Append one fenced graph-stage event exactly once for an Investigation operation."""
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            if not self._owns_claim(connection, assessment_run_id, claim_id=claim_id):
                return None
            idempotency_key = f"investigation:{operation_id}:stage:{event.stage}"
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=AssessmentEventType.INVESTIGATION_PROGRESS,
                payload={
                    "status": AssessmentStatus.RUNNING,
                    "operationId": str(operation_id),
                    "exposureId": str(exposure_id),
                    "stage": event.stage,
                    "mode": event.mode,
                    "message": event.detail,
                },
                occurred_at=event.occurred_at,
                idempotency_key=idempotency_key,
            )
            row = connection.execute(
                """
                SELECT occurred_at FROM assessment_events
                WHERE assessment_run_id = %s AND idempotency_key = %s
                """,
                (assessment_run_id, idempotency_key),
            ).fetchone()
            assert row is not None
            return replace(event, occurred_at=cast(datetime, row[0]))

    def claim_next(self, *, stale_after_seconds: float) -> AssessmentRun | None:
        claimed_at = datetime.now(UTC)
        claim_id = uuid4()
        with (
            psycopg.connect(
                self._database_url,
                row_factory=class_row(AssessmentRun),
            ) as connection,
            connection.transaction(),
        ):
            assessment_run = connection.execute(
                f"""
                {_ASSESSMENT_RUN_SELECT}
                WHERE EXISTS (
                    SELECT 1
                    FROM policy_decisions
                    WHERE policy_decisions.assessment_run_id = assessment_runs.id
                      AND policy_decisions.result = 'allowed'
                      AND policy_decisions.enforcement_point = 'request'
                )
                  AND (
                      status = 'queued'
                      OR (
                          status = 'running'
                          AND COALESCE(claimed_at, started_at) <= %s
                      )
                  )
                ORDER BY CASE status WHEN 'queued' THEN 0 ELSE 1 END, created_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                (claimed_at - timedelta(seconds=stale_after_seconds),),
            ).fetchone()
            if assessment_run is None:
                return None
            resumed = assessment_run.status == AssessmentStatus.RUNNING
            connection.execute(
                """
                UPDATE assessment_runs
                SET status = 'running',
                    started_at = COALESCE(started_at, %s),
                    claimed_at = %s,
                    claim_id = %s
                WHERE id = %s
                """,
                (claimed_at, claimed_at, claim_id, assessment_run.id),
            )
            self._insert_event(
                connection,
                assessment_run.id,
                sequence=self._next_sequence(connection, assessment_run.id),
                event_type=(
                    AssessmentEventType.RESUMED if resumed else AssessmentEventType.STARTED
                ),
                payload={
                    "status": AssessmentStatus.RUNNING,
                    "message": (
                        f"{assessment_run.label} resumed after an interrupted worker."
                        if resumed
                        else f"{assessment_run.label} started."
                    ),
                },
                occurred_at=claimed_at,
            )
            return AssessmentRun(
                id=assessment_run.id,
                mode=assessment_run.mode,
                scenario=assessment_run.scenario,
                label=assessment_run.label,
                synthetic=assessment_run.synthetic,
                status=AssessmentStatus.RUNNING,
                created_at=assessment_run.created_at,
                started_at=assessment_run.started_at or claimed_at,
                completed_at=None,
                error_code=None,
                error_message=None,
                claimed_at=claimed_at,
                claim_id=claim_id,
                asset_snapshot_id=assessment_run.asset_snapshot_id,
            )

    def complete_synthetic(self, assessment_run_id: UUID, *, claim_id: UUID) -> bool:
        return self._complete(
            assessment_run_id,
            claim_id=claim_id,
            progress_event=AssessmentEventType.SYNTHETIC_PROGRESS,
            progress_message="Synthetic dependency evaluation completed.",
            completed_message="Synthetic Assessment Run completed.",
        )

    def complete_repository(
        self,
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
        asset_snapshot_id: UUID,
    ) -> bool:
        return self._complete(
            assessment_run_id,
            claim_id=claim_id,
            progress_event=AssessmentEventType.ASSET_SNAPSHOT_CAPTURED,
            progress_message="Immutable Asset Snapshot captured and normalized.",
            completed_message="Repository Assessment Run completed.",
            asset_snapshot_id=asset_snapshot_id,
        )

    def record_asset_snapshot(
        self,
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
        asset_snapshot_id: UUID,
    ) -> bool:
        """Persist a completed Asset Snapshot so reclaimed work does not fetch it again."""
        with psycopg.connect(self._database_url) as connection:
            result = connection.execute(
                """
                UPDATE assessment_runs
                SET asset_snapshot_id = %s
                WHERE id = %s AND status = 'running' AND claim_id = %s
                  AND (asset_snapshot_id IS NULL OR asset_snapshot_id = %s)
                """,
                (asset_snapshot_id, assessment_run_id, claim_id, asset_snapshot_id),
            )
            return result.rowcount == 1

    def _complete(
        self,
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
        progress_event: AssessmentEventType,
        progress_message: str,
        completed_message: str,
        asset_snapshot_id: UUID | None = None,
    ) -> bool:
        now = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            if not self._owns_claim(connection, assessment_run_id, claim_id=claim_id):
                return False
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=progress_event,
                payload={
                    "status": AssessmentStatus.RUNNING,
                    "message": progress_message,
                    "progress": 75,
                },
                occurred_at=now,
            )
            connection.execute(
                """
                UPDATE assessment_runs
                SET status = 'completed', completed_at = %s,
                    claimed_at = NULL, claim_id = NULL,
                    asset_snapshot_id = COALESCE(%s, asset_snapshot_id)
                WHERE id = %s AND status = 'running' AND claim_id = %s
                """,
                (now, asset_snapshot_id, assessment_run_id, claim_id),
            )
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=AssessmentEventType.COMPLETED,
                payload={
                    "status": AssessmentStatus.COMPLETED,
                    "message": completed_message,
                    "progress": 100,
                },
                occurred_at=now,
            )
        return True

    def renew_claim(self, assessment_run_id: UUID, *, claim_id: UUID) -> bool:
        """Keep an owned Assessment Run from being reclaimed while work is active."""
        with psycopg.connect(self._database_url) as connection:
            result = connection.execute(
                """
                UPDATE assessment_runs
                SET claimed_at = %s
                WHERE id = %s AND status = 'running' AND claim_id = %s
                """,
                (datetime.now(UTC), assessment_run_id, claim_id),
            )
            return result.rowcount == 1

    def fail(
        self,
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
        code: str,
        message: str,
    ) -> bool:
        now = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            if not self._owns_claim(connection, assessment_run_id, claim_id=claim_id):
                return False
            connection.execute(
                """
                    UPDATE assessment_runs
                SET status = 'failed', completed_at = %s,
                    error_code = %s, error_message = %s,
                    claimed_at = NULL, claim_id = NULL
                WHERE id = %s AND status = 'running' AND claim_id = %s
                """,
                (now, code, message, assessment_run_id, claim_id),
            )
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=AssessmentEventType.FAILED,
                payload={
                    "status": AssessmentStatus.FAILED,
                    "code": code,
                    "message": message,
                },
                occurred_at=now,
            )
        return True

    @staticmethod
    def _insert_policy_decision(
        connection: psycopg.Connection[Any],
        decision: PolicyDecision,
        *,
        assessment_run_id: UUID | None,
        created_at: datetime,
        enforcement_point: str,
        idempotency_key: str | None = None,
    ) -> tuple[UUID, datetime]:
        decision_id = uuid4()
        row = connection.execute(
            """
            INSERT INTO policy_decisions (
                id, assessment_run_id, standard_version, assistance_class, action_level,
                target_scope, authorization_scope, result, rule_version, reason, created_at,
                enforcement_point, idempotency_key
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (assessment_run_id, idempotency_key) DO NOTHING
            RETURNING id, created_at
            """,
            (
                decision_id,
                assessment_run_id,
                decision.standard_version,
                decision.assistance_class,
                decision.action_level,
                decision.target_scope,
                decision.authorization_scope,
                decision.result,
                decision.rule_version,
                decision.reason,
                created_at,
                enforcement_point,
                idempotency_key,
            ),
        ).fetchone()
        if row is None:
            assert idempotency_key is not None
            row = connection.execute(
                """
                SELECT id, created_at FROM policy_decisions
                WHERE assessment_run_id = %s AND idempotency_key = %s
                """,
                (assessment_run_id, idempotency_key),
            ).fetchone()
        assert row is not None
        return UUID(str(row[0])), cast(datetime, row[1])

    @staticmethod
    def _owns_claim(
        connection: psycopg.Connection[Any],
        assessment_run_id: UUID,
        *,
        claim_id: UUID,
    ) -> bool:
        with connection.cursor(row_factory=tuple_row) as cursor:
            return (
                cursor.execute(
                    """
                    SELECT 1
                    FROM assessment_runs
                    WHERE id = %s AND status = 'running' AND claim_id = %s
                    FOR UPDATE
                    """,
                    (assessment_run_id, claim_id),
                ).fetchone()
                is not None
            )

    @staticmethod
    def _next_sequence(connection: psycopg.Connection[Any], assessment_run_id: UUID) -> int:
        with connection.cursor(row_factory=tuple_row) as cursor:
            row = cursor.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1
                FROM assessment_events
                WHERE assessment_run_id = %s
                """,
                (assessment_run_id,),
            ).fetchone()
        assert row is not None
        return int(row[0])

    @staticmethod
    def _insert_event(
        connection: psycopg.Connection[Any],
        assessment_run_id: UUID,
        *,
        sequence: int,
        event_type: AssessmentEventType,
        payload: dict[str, Any],
        occurred_at: datetime,
        idempotency_key: str | None = None,
    ) -> bool:
        result = connection.execute(
            """
            INSERT INTO assessment_events (
                assessment_run_id, sequence, event_type, payload, occurred_at, idempotency_key
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (assessment_run_id, idempotency_key) DO NOTHING
            """,
            (
                assessment_run_id,
                sequence,
                event_type,
                Jsonb(payload),
                occurred_at,
                idempotency_key,
            ),
        )
        return result.rowcount == 1


def _policy_idempotency_key(enforcement_point: str, decision: PolicyDecision) -> str:
    encoded = json.dumps(
        (
            enforcement_point,
            decision.standard_version,
            decision.rule_version,
            decision.assistance_class,
            decision.action_level,
            decision.target_scope or "",
            decision.authorization_scope or "",
            decision.result,
            decision.reason,
        ),
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
