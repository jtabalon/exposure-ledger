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
        ALTER TABLE package_instances
            ALTER COLUMN direct DROP NOT NULL;

        ALTER TABLE asset_snapshots
            ADD COLUMN project_file_path text,
            ADD COLUMN project_file_digest text,
            ADD COLUMN project_file_content text,
            ADD CONSTRAINT asset_snapshots_project_file_check
                CHECK (
                    (project_file_path IS NULL
                     AND project_file_digest IS NULL
                     AND project_file_content IS NULL)
                    OR
                    (project_file_path IS NOT NULL
                     AND project_file_digest IS NOT NULL
                     AND project_file_content IS NOT NULL)
                );

        CREATE OR REPLACE FUNCTION allow_only_asset_snapshot_seal()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF OLD.sealed = false AND NEW.sealed = true
               AND ROW(OLD.id, OLD.repository, OLD.commit_sha, OLD.project_root,
                       OLD.lockfile_path, OLD.lockfile_digest, OLD.lockfile_content,
                       OLD.project_file_path, OLD.project_file_digest,
                       OLD.project_file_content, OLD.environment_profile_id,
                       OLD.parser_version, OLD.captured_at)
                   IS NOT DISTINCT FROM
                   ROW(NEW.id, NEW.repository, NEW.commit_sha, NEW.project_root,
                       NEW.lockfile_path, NEW.lockfile_digest, NEW.lockfile_content,
                       NEW.project_file_path, NEW.project_file_digest,
                       NEW.project_file_content, NEW.environment_profile_id,
                       NEW.parser_version, NEW.captured_at)
            THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'Asset Snapshot records are immutable';
        END;
        $$;
        """,
    ),
    (
        8,
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

        ALTER TABLE package_instances
            ADD CONSTRAINT package_instances_id_snapshot_key
            UNIQUE (id, asset_snapshot_id);

        CREATE TABLE exposures (
            id uuid PRIMARY KEY,
            asset_snapshot_id uuid NOT NULL
                REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            vulnerability_record_id uuid NOT NULL
                REFERENCES vulnerability_records(id) ON DELETE RESTRICT,
            package_instance_id uuid NOT NULL,
            FOREIGN KEY (package_instance_id, asset_snapshot_id)
                REFERENCES package_instances(id, asset_snapshot_id) ON DELETE RESTRICT,
            UNIQUE (asset_snapshot_id, vulnerability_record_id, package_instance_id)
        );

        CREATE TABLE assessment_run_exposures (
            assessment_run_id uuid NOT NULL
                REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            exposure_id uuid NOT NULL REFERENCES exposures(id) ON DELETE RESTRICT,
            rank integer NOT NULL CHECK (rank > 0),
            selected_for_investigation boolean NOT NULL
                CHECK (NOT selected_for_investigation OR rank <= 5),
            severity text NOT NULL
                CHECK (severity IN ('critical', 'high', 'moderate', 'low', 'unknown')),
            direct_dependency boolean,
            dependency_depth integer CHECK (
                dependency_depth IS NULL OR dependency_depth >= 0
            ),
            fixed_version_available boolean NOT NULL,
            ranking_score integer NOT NULL CHECK (ranking_score >= 0),
            PRIMARY KEY (assessment_run_id, exposure_id),
            UNIQUE (assessment_run_id, rank)
        );

        CREATE TABLE exposure_discoveries (
            assessment_run_id uuid PRIMARY KEY
                REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            asset_snapshot_id uuid NOT NULL
                REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            exposure_count integer NOT NULL CHECK (exposure_count >= 0),
            completed_at timestamptz NOT NULL
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

        CREATE TRIGGER exposure_discoveries_cannot_be_changed
        BEFORE UPDATE OR DELETE ON exposure_discoveries
        FOR EACH ROW EXECUTE FUNCTION reject_exposure_mutation();
        """,
    ),
    (
        9,
        """
        CREATE TABLE sources (
            id uuid PRIMARY KEY,
            identity_key text NOT NULL,
            authority text NOT NULL,
            location text NOT NULL,
            UNIQUE (identity_key, authority, location)
        );

        CREATE TABLE evidence_records (
            id uuid PRIMARY KEY,
            identity_key text NOT NULL UNIQUE,
            source_id uuid NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
            captured_at timestamptz NOT NULL,
            content_digest text NOT NULL CHECK (content_digest LIKE 'sha256:%'),
            attribution text NOT NULL,
            aliases text[] NOT NULL,
            payload_identity text NOT NULL,
            content text NOT NULL,
            UNIQUE (source_id, payload_identity, content_digest)
        );

        CREATE TABLE evidence_passages (
            id uuid PRIMARY KEY,
            evidence_record_id uuid NOT NULL
                REFERENCES evidence_records(id) ON DELETE RESTRICT,
            identity_key text NOT NULL UNIQUE,
            kind text NOT NULL,
            selector text NOT NULL,
            content text NOT NULL,
            UNIQUE (id, evidence_record_id)
        );

        CREATE TABLE assessment_run_exposure_evidence (
            assessment_run_id uuid NOT NULL,
            exposure_id uuid NOT NULL,
            evidence_record_id uuid NOT NULL
                REFERENCES evidence_records(id) ON DELETE RESTRICT,
            PRIMARY KEY (assessment_run_id, exposure_id, evidence_record_id),
            FOREIGN KEY (assessment_run_id, exposure_id)
                REFERENCES assessment_run_exposures(assessment_run_id, exposure_id)
                ON DELETE RESTRICT
        );

        CREATE TABLE assessment_run_exposure_passages (
            assessment_run_id uuid NOT NULL,
            exposure_id uuid NOT NULL,
            evidence_record_id uuid NOT NULL,
            passage_id uuid NOT NULL,
            PRIMARY KEY (assessment_run_id, exposure_id, passage_id),
            FOREIGN KEY (assessment_run_id, exposure_id, evidence_record_id)
                REFERENCES assessment_run_exposure_evidence(
                    assessment_run_id, exposure_id, evidence_record_id
                ) ON DELETE RESTRICT,
            FOREIGN KEY (passage_id, evidence_record_id)
                REFERENCES evidence_passages(id, evidence_record_id) ON DELETE RESTRICT
        );

        CREATE FUNCTION reject_evidence_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Evidence Records are immutable';
        END;
        $$;

        CREATE TRIGGER sources_cannot_be_changed
        BEFORE UPDATE OR DELETE ON sources
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

        CREATE TRIGGER evidence_records_cannot_be_changed
        BEFORE UPDATE OR DELETE ON evidence_records
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

        CREATE TRIGGER evidence_passages_cannot_be_changed
        BEFORE UPDATE OR DELETE ON evidence_passages
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

        CREATE TRIGGER assessment_run_exposure_evidence_cannot_be_changed
        BEFORE UPDATE OR DELETE ON assessment_run_exposure_evidence
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();

        CREATE TRIGGER assessment_run_exposure_passages_cannot_be_changed
        BEFORE UPDATE OR DELETE ON assessment_run_exposure_passages
        FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation();
        """,
    ),
    (
        10,
        """
        CREATE TABLE retrieval_configurations (
            version text PRIMARY KEY,
            text_search_configuration text NOT NULL,
            ranking_algorithm text NOT NULL,
            passage_construction_version text NOT NULL
        );

        INSERT INTO retrieval_configurations (
            version, text_search_configuration, ranking_algorithm,
            passage_construction_version
        ) VALUES (
            'postgres-lexical-v1', 'simple', 'ts_rank_cd-32', 'source-aware-passage-v1'
        );

        ALTER TABLE evidence_passages
            ADD COLUMN search_vector tsvector
            GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, content)) STORED;

        CREATE INDEX evidence_passages_search_vector_idx
            ON evidence_passages USING gin (search_vector);

        CREATE FUNCTION reject_retrieval_configuration_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Retrieval configurations are immutable';
        END;
        $$;

        CREATE TRIGGER retrieval_configurations_cannot_be_changed
        BEFORE UPDATE OR DELETE ON retrieval_configurations
        FOR EACH ROW EXECUTE FUNCTION reject_retrieval_configuration_mutation();
        """,
    ),
    (
        11,
        """
        ALTER TABLE assessment_run_exposures
            ADD COLUMN kev_state text NOT NULL DEFAULT 'not_collected'
                CHECK (kev_state IN (
                    'available', 'stale', 'missing', 'malformed',
                    'unavailable', 'not_collected'
                )),
            ADD COLUMN kev_listed boolean,
            ADD COLUMN kev_observed_at timestamptz,
            ADD COLUMN kev_detail text,
            ADD COLUMN epss_state text NOT NULL DEFAULT 'not_collected'
                CHECK (epss_state IN (
                    'available', 'stale', 'missing', 'malformed',
                    'unavailable', 'not_collected'
                )),
            ADD COLUMN epss_score numeric(10, 9)
                CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)),
            ADD COLUMN epss_percentile numeric(10, 9)
                CHECK (
                    epss_percentile IS NULL
                    OR (epss_percentile >= 0 AND epss_percentile <= 1)
                ),
            ADD COLUMN epss_observed_at timestamptz,
            ADD COLUMN epss_detail text,
            ADD CONSTRAINT assessment_run_exposures_kev_signal_check CHECK (
                (kev_state IN ('available', 'stale')
                 AND kev_listed IS NOT NULL AND kev_observed_at IS NOT NULL)
                OR
                (kev_state NOT IN ('available', 'stale')
                 AND kev_listed IS NULL AND kev_observed_at IS NULL)
            ),
            ADD CONSTRAINT assessment_run_exposures_epss_signal_check CHECK (
                (epss_state IN ('available', 'stale')
                 AND epss_score IS NOT NULL AND epss_percentile IS NOT NULL
                 AND epss_observed_at IS NOT NULL)
                OR
                (epss_state NOT IN ('available', 'stale')
                 AND epss_score IS NULL AND epss_percentile IS NULL
                 AND epss_observed_at IS NULL)
            );
        """,
    ),
    (
        12,
        """
        ALTER TABLE assessment_run_exposures
            ADD COLUMN authoritative_conflict boolean NOT NULL DEFAULT false;

        ALTER TABLE assessment_run_exposure_evidence
            ADD COLUMN relationship text NOT NULL DEFAULT 'supports'
                CHECK (relationship IN ('supports', 'contradicts', 'contextual'));
        """,
    ),
    (
        13,
        """
        CREATE EXTENSION IF NOT EXISTS vector;

        ALTER TABLE retrieval_configurations
            ADD COLUMN fusion_algorithm text NOT NULL DEFAULT 'none',
            ADD COLUMN rrf_rank_constant integer NOT NULL DEFAULT 60
                CHECK (rrf_rank_constant > 0),
            ADD COLUMN full_text_candidate_limit integer NOT NULL DEFAULT 100
                CHECK (full_text_candidate_limit > 0),
            ADD COLUMN vector_candidate_limit integer NOT NULL DEFAULT 100
                CHECK (vector_candidate_limit > 0);

        INSERT INTO retrieval_configurations (
            version, text_search_configuration, ranking_algorithm,
            passage_construction_version, fusion_algorithm, rrf_rank_constant,
            full_text_candidate_limit, vector_candidate_limit
        ) VALUES (
            'postgres-hybrid-rrf-v1', 'simple', 'ts_rank_cd-32',
            'source-aware-passage-v1', 'reciprocal-rank-fusion-v1', 60, 100, 100
        );

        CREATE TABLE embedding_spaces (
            id uuid PRIMARY KEY,
            identity_key text NOT NULL UNIQUE CHECK (identity_key LIKE 'sha256:%'),
            provider text NOT NULL,
            model_artifact text NOT NULL,
            artifact_digest text NOT NULL CHECK (artifact_digest LIKE 'sha256:%'),
            dimensions integer NOT NULL CHECK (dimensions > 0),
            retrieval_instruction text NOT NULL,
            normalizer text NOT NULL,
            passage_construction_version text NOT NULL,
            UNIQUE (
                provider, model_artifact, artifact_digest, dimensions,
                retrieval_instruction, normalizer, passage_construction_version
            )
        );

        CREATE TABLE passage_embeddings (
            passage_id uuid NOT NULL REFERENCES evidence_passages(id) ON DELETE RESTRICT,
            embedding_space_id uuid NOT NULL REFERENCES embedding_spaces(id) ON DELETE RESTRICT,
            representation vector NOT NULL,
            PRIMARY KEY (passage_id, embedding_space_id)
        );

        CREATE INDEX passage_embeddings_space_idx
            ON passage_embeddings (embedding_space_id, passage_id);

        CREATE FUNCTION validate_embedding_dimensions()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            expected_dimensions integer;
        BEGIN
            SELECT dimensions INTO expected_dimensions
            FROM embedding_spaces WHERE id = NEW.embedding_space_id;
            IF vector_dims(NEW.representation) <> expected_dimensions THEN
                RAISE EXCEPTION 'Representation dimensions do not match the Embedding Space';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER passage_embeddings_validate_dimensions
        BEFORE INSERT ON passage_embeddings
        FOR EACH ROW EXECUTE FUNCTION validate_embedding_dimensions();

        CREATE FUNCTION reject_embedding_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Embedding Spaces and representations are immutable';
        END;
        $$;

        CREATE TRIGGER embedding_spaces_cannot_be_changed
        BEFORE UPDATE OR DELETE ON embedding_spaces
        FOR EACH ROW EXECUTE FUNCTION reject_embedding_mutation();

        CREATE TRIGGER passage_embeddings_cannot_be_changed
        BEFORE UPDATE OR DELETE ON passage_embeddings
        FOR EACH ROW EXECUTE FUNCTION reject_embedding_mutation();
        """,
    ),
    (
        14,
        """
        ALTER TABLE policy_decisions
            DROP CONSTRAINT policy_decisions_enforcement_point_check,
            ADD CONSTRAINT policy_decisions_enforcement_point_check
                CHECK (enforcement_point IN ('request', 'tool_call', 'retrieved_content'));

        CREATE TABLE embedding_provider_observations (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            observed_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL CHECK (status IN ('ready', 'unavailable')),
            code text,
            message text NOT NULL,
            setup text,
            embedding_space_id uuid REFERENCES embedding_spaces(id) ON DELETE RESTRICT,
            CHECK (
                (status = 'ready' AND code IS NULL AND setup IS NULL
                    AND embedding_space_id IS NOT NULL)
                OR
                (status = 'unavailable' AND code IS NOT NULL
                    AND embedding_space_id IS NULL)
            )
        );

        CREATE TABLE retrieval_query_embeddings (
            assessment_run_id uuid NOT NULL
                REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            exposure_id uuid NOT NULL REFERENCES exposures(id) ON DELETE RESTRICT,
            query_digest text NOT NULL CHECK (query_digest LIKE 'sha256:%'),
            query_text text NOT NULL,
            embedding_space_id uuid NOT NULL REFERENCES embedding_spaces(id) ON DELETE RESTRICT,
            representation vector NOT NULL,
            PRIMARY KEY (
                assessment_run_id, exposure_id, query_digest, embedding_space_id
            )
        );

        CREATE TRIGGER retrieval_query_embeddings_validate_dimensions
        BEFORE INSERT ON retrieval_query_embeddings
        FOR EACH ROW EXECUTE FUNCTION validate_embedding_dimensions();

        CREATE TRIGGER retrieval_query_embeddings_cannot_be_changed
        BEFORE UPDATE OR DELETE ON retrieval_query_embeddings
        FOR EACH ROW EXECUTE FUNCTION reject_embedding_mutation();
        """,
    ),
    (
        15,
        """
        ALTER TABLE policy_decisions
            DROP CONSTRAINT policy_decisions_enforcement_point_check,
            ADD CONSTRAINT policy_decisions_enforcement_point_check
                CHECK (enforcement_point IN (
                    'request', 'tool_call', 'retrieved_content', 'structured_output'
                ));

        ALTER TABLE evidence_records ADD COLUMN source_adapter_version text;
        UPDATE evidence_records
        SET source_adapter_version = CASE sources.identity_key
            WHEN 'osv' THEN 'osv-v1'
            WHEN 'cisa-kev' THEN 'cisa-kev-v1'
            WHEN 'first-epss' THEN 'first-epss-v1'
            WHEN 'github_repository_security_advisory'
                THEN 'github-repository-advisory-v1'
            ELSE 'legacy-source-adapter-v1'
        END
        FROM sources
        WHERE sources.id = evidence_records.source_id;
        ALTER TABLE evidence_records ALTER COLUMN source_adapter_version SET NOT NULL;

        CREATE TABLE investigations (
            id uuid PRIMARY KEY,
            exposure_id uuid NOT NULL UNIQUE REFERENCES exposures(id) ON DELETE RESTRICT,
            created_at timestamptz NOT NULL
        );

        CREATE TABLE generation_provider_observations (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            observed_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL CHECK (status IN ('ready', 'unavailable')),
            code text,
            message text NOT NULL,
            setup text,
            provider text,
            model_artifact text,
            artifact_digest text CHECK (
                artifact_digest IS NULL OR artifact_digest LIKE 'sha256:%'
            ),
            CHECK (
                (status = 'ready' AND code IS NULL AND setup IS NULL
                    AND provider IS NOT NULL AND model_artifact IS NOT NULL
                    AND artifact_digest IS NOT NULL)
                OR
                (status = 'unavailable' AND code IS NOT NULL
                    AND provider IS NULL AND model_artifact IS NULL
                    AND artifact_digest IS NULL)
            )
        );

        CREATE TABLE investigation_revisions (
            id uuid PRIMARY KEY,
            investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE RESTRICT,
            revision_number integer NOT NULL CHECK (revision_number > 0),
            assessment_run_id uuid NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            exposure_id uuid NOT NULL REFERENCES exposures(id) ON DELETE RESTRICT,
            asset_snapshot_id uuid NOT NULL REFERENCES asset_snapshots(id) ON DELETE RESTRICT,
            status text NOT NULL CHECK (status IN ('complete', 'incomplete')),
            stopping_condition text NOT NULL CHECK (stopping_condition IN (
                'completed', 'wall_time_budget_exhausted',
                'graph_transition_budget_exhausted', 'tool_call_budget_exhausted',
                'generation_model_call_budget_exhausted',
                'generation_provider_unavailable', 'generation_runtime_unavailable',
                'generation_model_not_installed', 'generation_model_not_current',
                'generation_cloud_model_rejected', 'generation_provider_invalid_response',
                'generation_prompt_not_current', 'generation_artifact_changed',
                'generation_invalid_structured_output', 'structured_output_policy_blocked'
            )),
            CHECK ((status = 'complete') = (stopping_condition = 'completed')),
            material_claims_supported boolean NOT NULL,
            authoritative_conflict boolean,
            validation_issues text[] NOT NULL,
            retrieval_query text NOT NULL,
            retrieved_passages jsonb NOT NULL,
            recommendation text NOT NULL CHECK (recommendation IN (
                'urgent_remediation', 'planned_remediation', 'monitor',
                'no_remediation_indicated', 'more_evidence_required'
            )),
            recommendation_accepted boolean NOT NULL,
            recommendation_reason text NOT NULL,
            recommendation_summary text NOT NULL,
            recommendation_reasons text[] NOT NULL,
            recommendation_limitations text[] NOT NULL,
            output_policy_decision_id uuid NOT NULL UNIQUE
                REFERENCES policy_decisions(id) ON DELETE RESTRICT,
            events jsonb NOT NULL,
            measurements jsonb NOT NULL,
            application_release text NOT NULL,
            graph_version text NOT NULL,
            prompt_version text NOT NULL,
            policy_version text NOT NULL,
            parser_version text NOT NULL,
            retrieval_configuration_version text NOT NULL,
            source_policy_version text NOT NULL,
            source_adapter_versions text[] NOT NULL,
            generation_provider text NOT NULL,
            generation_model_artifact text NOT NULL,
            generation_artifact_digest text NOT NULL
                CHECK (generation_artifact_digest LIKE 'sha256:%'),
            embedding_space_identity text NOT NULL
                REFERENCES embedding_spaces(identity_key) ON DELETE RESTRICT,
            sealed boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL,
            UNIQUE (investigation_id, revision_number)
        );

        CREATE INDEX investigation_revisions_assessment_idx
            ON investigation_revisions (assessment_run_id, created_at DESC, id DESC);

        CREATE TABLE investigation_revision_evidence (
            revision_id uuid NOT NULL
                REFERENCES investigation_revisions(id) ON DELETE RESTRICT,
            evidence_record_id uuid NOT NULL REFERENCES evidence_records(id) ON DELETE RESTRICT,
            content_digest text NOT NULL CHECK (content_digest LIKE 'sha256:%'),
            available_passage_identities text[] NOT NULL,
            retrieved_passage_identities text[] NOT NULL,
            PRIMARY KEY (revision_id, evidence_record_id)
        );

        CREATE TABLE claims (
            id uuid PRIMARY KEY,
            revision_id uuid NOT NULL
                REFERENCES investigation_revisions(id) ON DELETE RESTRICT,
            identity_key text NOT NULL,
            ordinal integer NOT NULL CHECK (ordinal > 0),
            kind text NOT NULL CHECK (kind IN ('fact', 'inference')),
            claim_text text NOT NULL,
            material boolean NOT NULL,
            limitation text,
            supported boolean NOT NULL,
            UNIQUE (revision_id, identity_key),
            UNIQUE (revision_id, ordinal)
        );

        CREATE TABLE claim_evidence_relationships (
            claim_id uuid NOT NULL REFERENCES claims(id) ON DELETE RESTRICT,
            evidence_record_id uuid NOT NULL REFERENCES evidence_records(id) ON DELETE RESTRICT,
            relationship text NOT NULL
                CHECK (relationship IN ('supports', 'contradicts', 'contextual')),
            passage_identities text[] NOT NULL,
            PRIMARY KEY (claim_id, evidence_record_id, relationship)
        );

        CREATE FUNCTION reject_investigation_history_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'Investigation history is immutable';
        END;
        $$;

        CREATE TRIGGER investigations_cannot_be_changed
        BEFORE UPDATE OR DELETE ON investigations
        FOR EACH ROW EXECUTE FUNCTION reject_investigation_history_mutation();

        CREATE FUNCTION allow_only_investigation_revision_seal()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT OLD.sealed AND NEW.sealed
               AND (to_jsonb(NEW) - 'sealed') = (to_jsonb(OLD) - 'sealed') THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'Investigation history is immutable';
        END;
        $$;

        CREATE FUNCTION protect_investigation_revision_children()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            revision_is_sealed boolean;
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'Investigation history is immutable';
            END IF;
            IF TG_TABLE_NAME = 'claim_evidence_relationships' THEN
                SELECT investigation_revisions.sealed INTO revision_is_sealed
                FROM claims
                JOIN investigation_revisions
                  ON investigation_revisions.id = claims.revision_id
                WHERE claims.id = NEW.claim_id;
            ELSE
                SELECT sealed INTO revision_is_sealed
                FROM investigation_revisions WHERE id = NEW.revision_id;
            END IF;
            IF revision_is_sealed OR revision_is_sealed IS NULL THEN
                RAISE EXCEPTION 'Investigation history is immutable';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE FUNCTION require_investigation_revision_sealed()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            revision_is_sealed boolean;
        BEGIN
            SELECT sealed INTO revision_is_sealed
            FROM investigation_revisions WHERE id = NEW.id;
            IF NOT revision_is_sealed THEN
                RAISE EXCEPTION 'Investigation Revision must be sealed atomically';
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER investigation_revisions_allow_only_seal
        BEFORE UPDATE OR DELETE ON investigation_revisions
        FOR EACH ROW EXECUTE FUNCTION allow_only_investigation_revision_seal();

        CREATE CONSTRAINT TRIGGER investigation_revisions_require_seal
        AFTER INSERT ON investigation_revisions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION require_investigation_revision_sealed();

        CREATE TRIGGER investigation_revision_evidence_cannot_be_changed
        BEFORE INSERT OR UPDATE OR DELETE ON investigation_revision_evidence
        FOR EACH ROW EXECUTE FUNCTION protect_investigation_revision_children();

        CREATE TRIGGER claims_cannot_be_changed
        BEFORE INSERT OR UPDATE OR DELETE ON claims
        FOR EACH ROW EXECUTE FUNCTION protect_investigation_revision_children();

        CREATE TRIGGER claim_evidence_relationships_cannot_be_changed
        BEFORE INSERT OR UPDATE OR DELETE ON claim_evidence_relationships
        FOR EACH ROW EXECUTE FUNCTION protect_investigation_revision_children();
        """,
    ),
    (
        16,
        """
        ALTER TABLE investigation_revisions
            DROP CONSTRAINT investigation_revisions_stopping_condition_check,
            ADD CONSTRAINT investigation_revisions_stopping_condition_check
                CHECK (stopping_condition IN (
                    'completed', 'wall_time_budget_exhausted',
                    'graph_transition_budget_exhausted', 'tool_call_budget_exhausted',
                    'generation_model_call_budget_exhausted',
                    'generation_provider_unavailable', 'generation_runtime_unavailable',
                    'generation_model_not_installed', 'generation_model_not_current',
                    'generation_cloud_model_rejected', 'generation_provider_invalid_response',
                    'generation_prompt_not_current', 'generation_artifact_changed',
                    'generation_invalid_structured_output', 'structured_output_policy_blocked',
                    'follow_up_invalid', 'follow_up_policy_blocked',
                    'follow_up_unavailable', 'follow_up_limit_reached'
                )),
            ADD COLUMN stopping_reason text,
            ADD COLUMN evidence_gap jsonb,
            ADD COLUMN follow_up jsonb,
            ADD COLUMN follow_up_policy_decision_id uuid UNIQUE
                REFERENCES policy_decisions(id) ON DELETE RESTRICT;

        ALTER TABLE investigation_revisions
            ADD CONSTRAINT investigation_revisions_stopping_reason_check
                CHECK (
                    (status = 'complete' AND stopping_reason IS NULL)
                    OR
                    (status = 'incomplete' AND stopping_reason IS NOT NULL
                     AND length(trim(stopping_reason)) > 0)
                ) NOT VALID,
            ADD CONSTRAINT investigation_revisions_follow_up_check
                CHECK (
                    (follow_up IS NULL) = (follow_up_policy_decision_id IS NULL)
                );
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
