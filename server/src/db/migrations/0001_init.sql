-- Tawny cutover schema. Applied as one simple-query script by the migrator.
-- Runtime values never go through this file.

CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    name text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    email text NOT NULL,
    name text,
    role text NOT NULL CHECK (role IN ('admin', 'viewer')),
    password_hash text,
    github_id text UNIQUE,
    created_at timestamptz NOT NULL,
    disabled_at timestamptz,
    UNIQUE (tenant_id, email)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    secret_hash bytea NOT NULL,
    csrf_secret bytea NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE oauth_states (
    state text PRIMARY KEY,
    pkce_verifier text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE agents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    hostname text NOT NULL,
    operating_system text NOT NULL CHECK (operating_system IN ('windows', 'macos', 'linux')),
    os_version text NOT NULL,
    agent_version text NOT NULL,
    architecture text NOT NULL CHECK (architecture IN ('x64', 'arm64')),
    public_ip text,
    enrolled_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz,
    status text NOT NULL CHECK (status IN ('online', 'stale', 'offline', 'unknown', 'revoked')),
    tags text[] NOT NULL DEFAULT '{}',
    credential_version integer NOT NULL DEFAULT 1,
    revoked_at timestamptz,
    last_telemetry_sequence bigint NOT NULL DEFAULT 0,
    last_telemetry_batch_id uuid,
    last_clock_skew_seconds integer NOT NULL DEFAULT 0,
    last_ingest_event_count integer NOT NULL DEFAULT 0,
    device_public_key text
);

CREATE INDEX agents_tenant_idx ON agents (tenant_id, hostname);

CREATE TABLE telemetry_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    received_at timestamptz NOT NULL,
    client_event_id uuid,
    batch_id uuid,
    sequence_number bigint,
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    confidence text NOT NULL DEFAULT 'agent_reported',
    payload_digest text,
    payload jsonb NOT NULL,
    PRIMARY KEY (received_at, id)
) PARTITION BY RANGE (received_at);

CREATE TABLE telemetry_events_default PARTITION OF telemetry_events DEFAULT;

CREATE INDEX telemetry_events_agent_idx ON telemetry_events (tenant_id, agent_id, received_at DESC);
CREATE INDEX telemetry_events_id_idx ON telemetry_events (id);

-- Dedupe cannot be a unique key on the partitioned table: PostgreSQL requires
-- that unique constraints include the partition column.
CREATE TABLE telemetry_dedupe (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    client_event_id uuid NOT NULL,
    received_at timestamptz NOT NULL,
    event_id bigint NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, client_event_id)
);

CREATE TABLE alert_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    format text NOT NULL CHECK (format IN ('tawny_predicate', 'sigma', 'ioc', 'sequence', 'yara', 'package_exposure')),
    external_id text,
    description text,
    event_type text,
    severity text NOT NULL,
    operator text NOT NULL,
    payload_path text,
    match_value text,
    source_definition text,
    compiled_expression_json jsonb,
    is_enabled boolean NOT NULL DEFAULT true,
    mitre_techniques text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX alert_rules_tenant_idx ON alert_rules (tenant_id, format, name);

CREATE TABLE alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    alert_rule_id uuid NOT NULL REFERENCES alert_rules (id),
    agent_id uuid NOT NULL REFERENCES agents (id),
    telemetry_event_id bigint NOT NULL,
    telemetry_received_at timestamptz NOT NULL,
    severity text NOT NULL,
    status text NOT NULL DEFAULT 'open',
    slack_notification_status text NOT NULL DEFAULT 'not_configured',
    slack_notified_at timestamptz,
    slack_notification_error text,
    sentinel_notification_status text NOT NULL DEFAULT 'not_configured',
    sentinel_notified_at timestamptz,
    sentinel_notification_error text,
    soc_notification_status text NOT NULL DEFAULT 'not_configured',
    soc_notified_at timestamptz,
    soc_notification_error text,
    title text NOT NULL,
    description text,
    enrichment_json jsonb,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (telemetry_received_at, telemetry_event_id)
        REFERENCES telemetry_events (received_at, id)
        ON DELETE NO ACTION
);

CREATE INDEX alerts_tenant_id_idx ON alerts (tenant_id, id);
CREATE INDEX alerts_tenant_created_idx ON alerts (tenant_id, created_at DESC);
CREATE INDEX alerts_event_idx ON alerts (telemetry_event_id);

CREATE TABLE response_actions (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents (id),
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    action_type text NOT NULL CHECK (action_type IN ('kill_process', 'isolate_host', 'release_host')),
    status text NOT NULL,
    requested_by_user_id uuid,
    requested_at timestamptz NOT NULL,
    dispatched_at timestamptz,
    completed_at timestamptz,
    expires_at timestamptz,
    received_at timestamptz,
    payload_json jsonb NOT NULL,
    payload_hash text,
    result_json jsonb,
    execution_token_hash text,
    idempotency_key text,
    UNIQUE (tenant_id, agent_id, idempotency_key)
);

CREATE INDEX response_actions_agent_idx ON response_actions (agent_id, requested_at DESC);

CREATE TABLE suppression_rules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    reason text,
    scope text NOT NULL,
    alert_rule_id uuid REFERENCES alert_rules (id),
    agent_id uuid REFERENCES agents (id),
    payload_path text,
    operator text NOT NULL,
    match_value text,
    is_enabled boolean NOT NULL DEFAULT true,
    created_by_user_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz,
    suppressed_count integer NOT NULL DEFAULT 0,
    last_suppressed_at timestamptz
);

CREATE TABLE threat_intel_feeds (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    kind text NOT NULL,
    url text NOT NULL,
    auth_header_name text,
    auth_header_value_encrypted text,
    default_severity text NOT NULL,
    is_enabled boolean NOT NULL DEFAULT true,
    interval_minutes integer NOT NULL DEFAULT 60,
    status text NOT NULL DEFAULT 'never_run',
    last_run_at timestamptz,
    last_success_at timestamptz,
    last_imported_count integer NOT NULL DEFAULT 0,
    last_skipped_count integer NOT NULL DEFAULT 0,
    last_error text,
    etag text,
    created_by_user_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE reputation_cache (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    provider text NOT NULL,
    indicator_kind text NOT NULL,
    indicator_value text NOT NULL,
    verdict text NOT NULL,
    score integer,
    detail_json jsonb NOT NULL,
    fetched_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, provider, indicator_kind, indicator_value)
);

CREATE TABLE saved_hunts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    description text,
    query text NOT NULL,
    created_by_user_id uuid,
    is_scheduled boolean NOT NULL DEFAULT false,
    schedule_cron text,
    alert_on_match boolean NOT NULL DEFAULT false,
    alert_severity text NOT NULL DEFAULT 'medium',
    mitre_techniques text[] NOT NULL DEFAULT '{}',
    last_run_at timestamptz,
    last_match_count integer,
    is_shared boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE hunt_runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    saved_hunt_id uuid NOT NULL REFERENCES saved_hunts (id) ON DELETE CASCADE,
    triggered_by_user_id uuid,
    status text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    match_count integer NOT NULL DEFAULT 0,
    alerts_created integer NOT NULL DEFAULT 0,
    error_message text
);

CREATE TABLE hunt_cursors (
    hunt_id uuid PRIMARY KEY REFERENCES saved_hunts (id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL,
    last_event_id bigint NOT NULL DEFAULT 0
);

CREATE TABLE api_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    token_prefix text NOT NULL,
    created_by_user_id uuid,
    role text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE TABLE enrollment_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    used_by_agent_id uuid,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    user_id uuid,
    action text NOT NULL,
    target text,
    metadata_json jsonb,
    occurred_at timestamptz NOT NULL,
    prev_hash bytea,
    hash bytea NOT NULL
);

CREATE TABLE agent_releases (
    version text NOT NULL,
    platform text NOT NULL,
    download_url text NOT NULL,
    sha256 text NOT NULL,
    released_at timestamptz NOT NULL,
    is_latest boolean NOT NULL DEFAULT false,
    PRIMARY KEY (platform, version)
);

CREATE TABLE jobs (
    name text PRIMARY KEY,
    schedule text NOT NULL,
    last_started_at timestamptz,
    last_finished_at timestamptz,
    last_status text,
    last_error text
);

CREATE TABLE work_queue (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind text NOT NULL,
    tenant_id uuid,
    payload jsonb NOT NULL,
    run_after timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX work_queue_ready_idx ON work_queue (run_after, id);

CREATE TABLE sequence_state (
    tenant_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    step integer NOT NULL,
    last_event_id bigint NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, rule_id, agent_id)
);

INSERT INTO tenants (id, slug, name, created_at)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default', now());

INSERT INTO jobs (name, schedule) VALUES
    ('mark-stale-agents', 'every 1 minute'),
    ('purge-old-events', 'daily 02:00'),
    ('backup-telemetry', 'daily 03:00'),
    ('check-agent-releases', 'hourly'),
    ('scheduled-hunts', 'every 5 minutes'),
    ('threat-intel-feeds', 'every 10 minutes'),
    ('reputation-enrichment', 'every 5 minutes');

-- Row level security. Missing tawny.tenant_id matches nothing.
-- Table owner is subject to these policies when the owner is not a superuser
-- and FORCE ROW LEVEL SECURITY is set. The app role must not own the tables
-- and must not have BYPASSRLS. Jobs use a separate BYPASSRLS role.

CREATE OR REPLACE FUNCTION tawny_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('tawny.tenant_id', true), '')::uuid
$$;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users', 'sessions', 'agents', 'telemetry_events', 'telemetry_dedupe',
        'alert_rules', 'alerts', 'response_actions', 'suppression_rules',
        'threat_intel_feeds', 'reputation_cache', 'saved_hunts', 'hunt_runs',
        'hunt_cursors', 'api_tokens', 'enrollment_tokens', 'audit_log',
        'sequence_state', 'work_queue'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = tawny_current_tenant()) WITH CHECK (tenant_id = tawny_current_tenant())',
            t);
    END LOOP;
END $$;

-- work_queue rows with a null tenant_id are job-global. The policy above
-- hides them from the app role, which is what we want. The jobs role bypasses RLS.

REVOKE ALL ON audit_log FROM PUBLIC;
