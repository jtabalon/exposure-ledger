"""Small, ordered PostgreSQL migration runner for the local-first deployment."""

from collections.abc import Sequence

import psycopg

MIGRATIONS: Sequence[tuple[int, str]] = (
    (
        1,
        """
        CREATE TABLE assessment_runs (
            id uuid PRIMARY KEY,
            mode text NOT NULL CHECK (mode IN ('synthetic')),
            label text NOT NULL,
            synthetic boolean NOT NULL,
            status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
            created_at timestamptz NOT NULL,
            started_at timestamptz,
            completed_at timestamptz,
            error_code text,
            error_message text
        );

        CREATE INDEX assessment_runs_status_created_at_idx
            ON assessment_runs (status, created_at);

        CREATE TABLE assessment_events (
            assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id) ON DELETE CASCADE,
            sequence bigint NOT NULL CHECK (sequence > 0),
            event_type text NOT NULL,
            payload jsonb NOT NULL,
            occurred_at timestamptz NOT NULL,
            PRIMARY KEY (assessment_run_id, sequence)
        );
        """,
    ),
    (
        2,
        """
        ALTER TABLE assessment_runs
            ADD COLUMN scenario text NOT NULL DEFAULT 'complete'
            CHECK (scenario IN ('complete', 'worker_failure'));
        """,
    ),
    (
        3,
        """
        ALTER TABLE assessment_runs
            ADD COLUMN claimed_at timestamptz,
            ADD COLUMN claim_id uuid;

        UPDATE assessment_runs
        SET claimed_at = started_at
        WHERE status = 'running';
        """,
    ),
    (
        4,
        """
        CREATE TABLE policy_decisions (
            id uuid PRIMARY KEY,
            assessment_run_id uuid UNIQUE REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            standard_version text NOT NULL,
            assistance_class text CHECK (assistance_class IN ('C0', 'C1', 'C2', 'C3')),
            action_level text CHECK (action_level IN ('A0', 'A1', 'A2', 'A3', 'A4')),
            target_scope text,
            authorization_scope text,
            result text NOT NULL CHECK (result IN ('allowed', 'restricted', 'blocked')),
            rule_version text NOT NULL,
            reason text NOT NULL,
            created_at timestamptz NOT NULL
        );

        CREATE INDEX policy_decisions_created_at_idx
            ON policy_decisions (created_at DESC, id DESC);

        INSERT INTO policy_decisions (
            id, assessment_run_id, standard_version, assistance_class, action_level,
            target_scope, authorization_scope, result, rule_version, reason, created_at
        )
        SELECT gen_random_uuid(), id, '0.1', NULL, NULL, NULL,
               NULL, 'blocked', 'assessment-request-v1',
               'Legacy Assessment Run predates request-gate classification and is blocked.', now()
        FROM assessment_runs;

        INSERT INTO assessment_events (
            assessment_run_id, sequence, event_type, payload, occurred_at
        )
        SELECT assessment_runs.id,
               COALESCE(MAX(assessment_events.sequence), 0) + 1,
               'assessment.failed',
               jsonb_build_object(
                   'status', 'failed',
                   'code', 'policy_gate_unavailable',
                   'message',
                   'Legacy Assessment Run predates request-gate classification and cannot run.'
               ),
               now()
        FROM assessment_runs
        LEFT JOIN assessment_events
          ON assessment_events.assessment_run_id = assessment_runs.id
        WHERE assessment_runs.status IN ('queued', 'running')
        GROUP BY assessment_runs.id;

        UPDATE assessment_runs
        SET status = 'failed',
            completed_at = now(),
            error_code = 'policy_gate_unavailable',
            error_message =
                'Legacy Assessment Run predates request-gate classification and cannot run.',
            claimed_at = NULL,
            claim_id = NULL
        WHERE status IN ('queued', 'running');

        CREATE FUNCTION reject_policy_decision_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Policy Decisions are append-only';
        END;
        $$;

        CREATE TRIGGER policy_decisions_are_append_only
        BEFORE UPDATE OR DELETE ON policy_decisions
        FOR EACH ROW EXECUTE FUNCTION reject_policy_decision_mutation();
        """,
    ),
)


def apply_migrations(database_url: str) -> None:
    """Apply every pending schema migration exactly once."""
    with psycopg.connect(database_url) as connection, connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(887301492)")
        connection.execute(
            """
                CREATE TABLE IF NOT EXISTS exposure_ledger_schema_migrations (
                    version integer PRIMARY KEY,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )
                """
        )
        applied = {
            row[0]
            for row in connection.execute(
                "SELECT version FROM exposure_ledger_schema_migrations"
            ).fetchall()
        }
        for version, statement in MIGRATIONS:
            if version in applied:
                continue
            connection.execute(statement)
            connection.execute(
                "INSERT INTO exposure_ledger_schema_migrations (version) VALUES (%s)",
                (version,),
            )
