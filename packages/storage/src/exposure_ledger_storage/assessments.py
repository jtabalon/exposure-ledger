"""Durable Assessment Run records and ordered progress events."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

import psycopg
from exposure_ledger import ActionLevel, AssistanceClass, PolicyDecision, PolicyResult
from psycopg.rows import class_row, tuple_row
from psycopg.types.json import Jsonb

_ASSESSMENT_RUN_SELECT = """
    SELECT id, mode, scenario, label, synthetic, status, created_at, started_at,
           completed_at, error_code, error_message, claimed_at, claim_id
    FROM assessment_runs
"""

_POLICY_DECISION_SELECT = """
    SELECT id, assessment_run_id, standard_version, assistance_class, action_level,
           target_scope, authorization_scope, result, rule_version, reason, created_at
    FROM policy_decisions
"""


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssessmentMode(StrEnum):
    SYNTHETIC = "synthetic"


class AssessmentScenario(StrEnum):
    COMPLETE = "complete"
    WORKER_FAILURE = "worker_failure"


class AssessmentEventType(StrEnum):
    QUEUED = "assessment.queued"
    STARTED = "assessment.started"
    RESUMED = "assessment.resumed"
    SYNTHETIC_PROGRESS = "assessment.synthetic_progress"
    COMPLETED = "assessment.completed"
    FAILED = "assessment.failed"


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
    assistance_class: AssistanceClass | None
    action_level: ActionLevel | None
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str
    created_at: datetime


class AssessmentRunRepository:
    """Persist Assessment Runs and their event streams in PostgreSQL."""

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
        if policy_decision.result is not PolicyResult.ALLOWED:
            raise ValueError("Only an allowed Policy Decision can create an Assessment Run.")
        assessment_run = AssessmentRun(
            id=uuid4(),
            mode=AssessmentMode.SYNTHETIC,
            scenario=scenario,
            label="Synthetic Assessment Run",
            synthetic=True,
            status=AssessmentStatus.QUEUED,
            created_at=datetime.now(UTC),
            started_at=None,
            completed_at=None,
            error_code=None,
            error_message=None,
            claimed_at=None,
            claim_id=None,
        )
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            connection.execute(
                """
                INSERT INTO assessment_runs (
                    id, mode, scenario, label, synthetic, status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    assessment_run.id,
                    assessment_run.mode,
                    assessment_run.scenario,
                    assessment_run.label,
                    assessment_run.synthetic,
                    assessment_run.status,
                    assessment_run.created_at,
                ),
            )
            self._insert_event(
                connection,
                assessment_run.id,
                sequence=1,
                event_type=AssessmentEventType.QUEUED,
                payload={
                    "status": AssessmentStatus.QUEUED,
                    "message": "Synthetic Assessment Run queued.",
                },
                occurred_at=assessment_run.created_at,
            )
            self._insert_policy_decision(
                connection,
                policy_decision,
                assessment_run_id=assessment_run.id,
                created_at=assessment_run.created_at,
            )
        return assessment_run

    def record_policy_decision(self, decision: PolicyDecision) -> PolicyDecisionRecord:
        created_at = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            decision_id = self._insert_policy_decision(
                connection,
                decision,
                assessment_run_id=None,
                created_at=created_at,
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
        )

    def get_policy_decision(self, assessment_run_id: UUID) -> PolicyDecisionRecord | None:
        with psycopg.connect(
            self._database_url,
            row_factory=class_row(PolicyDecisionRecord),
        ) as connection:
            return connection.execute(
                f"{_POLICY_DECISION_SELECT} WHERE assessment_run_id = %s "
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
                        "Synthetic Assessment Run resumed after an interrupted worker."
                        if resumed
                        else "Synthetic Assessment Run started."
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
            )

    def complete_synthetic(self, assessment_run_id: UUID, *, claim_id: UUID) -> bool:
        now = datetime.now(UTC)
        with psycopg.connect(self._database_url) as connection, connection.transaction():
            if not self._owns_claim(connection, assessment_run_id, claim_id=claim_id):
                return False
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=AssessmentEventType.SYNTHETIC_PROGRESS,
                payload={
                    "status": AssessmentStatus.RUNNING,
                    "message": "Synthetic dependency evaluation completed.",
                    "progress": 75,
                },
                occurred_at=now,
            )
            connection.execute(
                """
                UPDATE assessment_runs
                SET status = 'completed', completed_at = %s,
                    claimed_at = NULL, claim_id = NULL
                WHERE id = %s AND status = 'running' AND claim_id = %s
                """,
                (now, assessment_run_id, claim_id),
            )
            self._insert_event(
                connection,
                assessment_run_id,
                sequence=self._next_sequence(connection, assessment_run_id),
                event_type=AssessmentEventType.COMPLETED,
                payload={
                    "status": AssessmentStatus.COMPLETED,
                    "message": "Synthetic Assessment Run completed.",
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
    ) -> UUID:
        decision_id = uuid4()
        connection.execute(
            """
            INSERT INTO policy_decisions (
                id, assessment_run_id, standard_version, assistance_class, action_level,
                target_scope, authorization_scope, result, rule_version, reason, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
            ),
        )
        return decision_id

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
    ) -> None:
        connection.execute(
            """
            INSERT INTO assessment_events (
                assessment_run_id, sequence, event_type, payload, occurred_at
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (assessment_run_id, sequence, event_type, Jsonb(payload), occurred_at),
        )
