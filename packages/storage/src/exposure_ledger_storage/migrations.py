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
            assistance_class text NOT NULL CHECK (assistance_class IN ('C0', 'C1', 'C2', 'C3')),
            action_level text NOT NULL CHECK (action_level IN ('A0', 'A1', 'A2', 'A3', 'A4')),
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
        SELECT gen_random_uuid(), id, '0.1', 'C3', 'A4', NULL,
               NULL, 'blocked', 'assessment-request-v1',
               'Legacy Assessment Run predates request-gate classification; it is ' ||
               'conservatively classified C3/A4 and blocked.',
               now()
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
    (
        5,
        """
        CREATE TABLE environment_profiles (
            id uuid PRIMARY KEY,
            python_version text NOT NULL,
            operating_system text NOT NULL
                CHECK (operating_system IN ('linux', 'macos', 'windows')),
            architecture text NOT NULL
                CHECK (architecture IN ('aarch64', 'arm64', 'amd64', 'x86_64')),
            selected_extras text[] NOT NULL,
            UNIQUE (python_version, operating_system, architecture, selected_extras)
        );

        CREATE TABLE asset_snapshots (
            id uuid PRIMARY KEY,
            repository text NOT NULL,
            commit_sha char(40) NOT NULL,
            project_root text NOT NULL,
            lockfile_path text NOT NULL,
            lockfile_digest text NOT NULL,
            lockfile_content text NOT NULL,
            environment_profile_id uuid NOT NULL
                REFERENCES environment_profiles(id) ON DELETE RESTRICT,
            parser_version text NOT NULL,
            captured_at timestamptz NOT NULL,
            UNIQUE (
                repository, commit_sha, project_root, lockfile_path,
                lockfile_digest, environment_profile_id
            )
        );

        CREATE INDEX asset_snapshots_captured_at_idx
            ON asset_snapshots (captured_at DESC, id DESC);

        CREATE TABLE package_instances (
            id uuid PRIMARY KEY,
            asset_snapshot_id uuid NOT NULL REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            name text NOT NULL,
            version text NOT NULL,
            direct boolean NOT NULL,
            source text NOT NULL,
            UNIQUE (asset_snapshot_id, name, version, source)
        );

        CREATE TABLE dependency_paths (
            package_instance_id uuid NOT NULL REFERENCES package_instances(id) ON DELETE RESTRICT,
            path text[] NOT NULL CHECK (cardinality(path) >= 2),
            PRIMARY KEY (package_instance_id, path)
        );

        CREATE FUNCTION reject_asset_snapshot_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Asset Snapshot records are immutable';
        END;
        $$;

        CREATE TRIGGER environment_profiles_are_immutable
        BEFORE UPDATE OR DELETE ON environment_profiles
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        CREATE TRIGGER asset_snapshots_are_immutable
        BEFORE UPDATE OR DELETE ON asset_snapshots
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        CREATE TRIGGER package_instances_are_immutable
        BEFORE UPDATE OR DELETE ON package_instances
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        CREATE TRIGGER dependency_paths_are_immutable
        BEFORE UPDATE OR DELETE ON dependency_paths
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        ALTER TABLE assessment_runs
            DROP CONSTRAINT assessment_runs_mode_check,
            ADD COLUMN asset_snapshot_id uuid
                REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            ADD CONSTRAINT assessment_runs_mode_check
                CHECK (mode IN ('synthetic', 'repository')),
            ADD CONSTRAINT assessment_runs_asset_snapshot_check
                CHECK (
                    (mode = 'synthetic' AND synthetic AND asset_snapshot_id IS NULL)
                    OR
                    (mode = 'repository' AND NOT synthetic AND asset_snapshot_id IS NOT NULL)
                );
        """,
    ),
    (
        6,
        """
        DROP TRIGGER asset_snapshots_are_immutable ON asset_snapshots;

        ALTER TABLE asset_snapshots
            ADD COLUMN sealed boolean NOT NULL DEFAULT false;

        UPDATE asset_snapshots SET sealed = true;

        CREATE FUNCTION protect_asset_snapshot_package_membership()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM asset_snapshots
                WHERE id = NEW.asset_snapshot_id AND sealed
            ) THEN
                RAISE EXCEPTION 'Asset Snapshot membership is immutable';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE FUNCTION protect_asset_snapshot_path_membership()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM package_instances
                JOIN asset_snapshots
                  ON asset_snapshots.id = package_instances.asset_snapshot_id
                WHERE package_instances.id = NEW.package_instance_id
                  AND asset_snapshots.sealed
            ) THEN
                RAISE EXCEPTION 'Asset Snapshot membership is immutable';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE FUNCTION allow_only_asset_snapshot_seal()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF OLD.sealed = false AND NEW.sealed = true
               AND ROW(OLD.id, OLD.repository, OLD.commit_sha, OLD.project_root,
                       OLD.lockfile_path, OLD.lockfile_digest, OLD.lockfile_content,
                       OLD.environment_profile_id, OLD.parser_version, OLD.captured_at)
                   IS NOT DISTINCT FROM
                   ROW(NEW.id, NEW.repository, NEW.commit_sha, NEW.project_root,
                       NEW.lockfile_path, NEW.lockfile_digest, NEW.lockfile_content,
                       NEW.environment_profile_id, NEW.parser_version, NEW.captured_at)
            THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'Asset Snapshot records are immutable';
        END;
        $$;

        CREATE TRIGGER asset_snapshots_allow_only_seal
        BEFORE UPDATE ON asset_snapshots
        FOR EACH ROW EXECUTE FUNCTION allow_only_asset_snapshot_seal();

        CREATE TRIGGER asset_snapshots_cannot_be_deleted
        BEFORE DELETE ON asset_snapshots
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        CREATE TRIGGER sealed_asset_snapshot_packages_reject_inserts
        BEFORE INSERT ON package_instances
        FOR EACH ROW EXECUTE FUNCTION protect_asset_snapshot_package_membership();

        CREATE TRIGGER sealed_asset_snapshot_paths_reject_inserts
        BEFORE INSERT ON dependency_paths
        FOR EACH ROW EXECUTE FUNCTION protect_asset_snapshot_path_membership();

        ALTER TABLE assessment_runs
            DROP CONSTRAINT assessment_runs_asset_snapshot_check,
            ADD CONSTRAINT assessment_runs_asset_snapshot_check
                CHECK (
                    (mode = 'synthetic' AND synthetic AND asset_snapshot_id IS NULL)
                    OR
                    (mode = 'repository' AND NOT synthetic
                     AND (status != 'completed' OR asset_snapshot_id IS NOT NULL))
                );

        CREATE TABLE asset_capture_requests (
            assessment_run_id uuid PRIMARY KEY
                REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            repository text NOT NULL,
            commit_sha char(40) NOT NULL,
            project_root text NOT NULL,
            lockfile_path text NOT NULL,
            python_version text NOT NULL,
            operating_system text NOT NULL
                CHECK (operating_system IN ('linux', 'macos', 'windows')),
            architecture text NOT NULL
                CHECK (architecture IN ('aarch64', 'arm64', 'amd64', 'x86_64')),
            selected_extras text[] NOT NULL
        );

        CREATE TRIGGER asset_capture_requests_are_immutable
        BEFORE UPDATE OR DELETE ON asset_capture_requests
        FOR EACH ROW EXECUTE FUNCTION reject_asset_snapshot_mutation();

        ALTER TABLE policy_decisions
            DROP CONSTRAINT policy_decisions_assessment_run_id_key,
            ADD COLUMN enforcement_point text NOT NULL DEFAULT 'request'
                CHECK (enforcement_point IN ('request', 'tool_call'));

        CREATE UNIQUE INDEX policy_decisions_one_request_per_run_idx
            ON policy_decisions (assessment_run_id)
            WHERE enforcement_point = 'request' AND assessment_run_id IS NOT NULL;
        """,
    ),
    (
        7,
        """
        CREATE TABLE vulnerability_records (
            id uuid PRIMARY KEY,
            identity_key text NOT NULL UNIQUE
        );

        CREATE TABLE vulnerability_aliases (
            identifier text PRIMARY KEY,
            vulnerability_record_id uuid NOT NULL
                REFERENCES vulnerability_records(id) ON DELETE RESTRICT
        );

        CREATE INDEX vulnerability_aliases_record_idx
            ON vulnerability_aliases (vulnerability_record_id, identifier);

        CREATE TABLE exposures (
            id uuid PRIMARY KEY,
            asset_snapshot_id uuid NOT NULL
                REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            vulnerability_record_id uuid NOT NULL
                REFERENCES vulnerability_records(id) ON DELETE RESTRICT,
            package_instance_id uuid NOT NULL
                REFERENCES package_instances(id) ON DELETE RESTRICT,
            UNIQUE (asset_snapshot_id, vulnerability_record_id, package_instance_id)
        );

        CREATE TABLE assessment_run_exposures (
            assessment_run_id uuid NOT NULL
                REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            exposure_id uuid NOT NULL REFERENCES exposures(id) ON DELETE RESTRICT,
            rank integer NOT NULL CHECK (rank > 0),
            selected_for_investigation boolean NOT NULL,
            severity text NOT NULL
                CHECK (severity IN ('critical', 'high', 'moderate', 'low', 'unknown')),
            direct_dependency boolean NOT NULL,
            dependency_depth integer NOT NULL CHECK (dependency_depth >= 0),
            fixed_version_available boolean NOT NULL,
            ranking_score integer NOT NULL CHECK (ranking_score >= 0),
            PRIMARY KEY (assessment_run_id, exposure_id),
            UNIQUE (assessment_run_id, rank)
        );

        CREATE FUNCTION reject_exposure_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Exposure discovery records are immutable';
        END;
        $$;

        CREATE TRIGGER vulnerability_records_cannot_be_changed
        BEFORE UPDATE OR DELETE ON vulnerability_records
        FOR EACH ROW EXECUTE FUNCTION reject_exposure_mutation();

        CREATE TRIGGER vulnerability_aliases_cannot_be_changed
        BEFORE UPDATE OR DELETE ON vulnerability_aliases
        FOR EACH ROW EXECUTE FUNCTION reject_exposure_mutation();

        CREATE TRIGGER exposures_cannot_be_changed
        BEFORE UPDATE OR DELETE ON exposures
        FOR EACH ROW EXECUTE FUNCTION reject_exposure_mutation();

        CREATE TRIGGER assessment_run_exposures_cannot_be_changed
        BEFORE UPDATE OR DELETE ON assessment_run_exposures
        FOR EACH ROW EXECUTE FUNCTION reject_exposure_mutation();
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
