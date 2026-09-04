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
