-- AI Security Reasoning tables. Applied as one simple-query script by the migrator.
-- These tables store behaviour observations, persistent security findings,
-- investigation state, and model invocation telemetry.

CREATE TABLE security_observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    agent_id uuid REFERENCES agents (id),
    hostname text,
    observation_type text NOT NULL,
    behaviour_fingerprint text,
    features jsonb NOT NULL DEFAULT '{}',
    observables jsonb NOT NULL DEFAULT '{}',
    source_event_ids bigint[] NOT NULL DEFAULT '{}',
    source_alert_ids bigint[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    processed_at timestamptz,
    processing_status text NOT NULL DEFAULT 'pending' CHECK (processing_status IN ('pending', 'processing', 'completed', 'failed', 'skipped')),
    processing_error text
);

CREATE INDEX security_observations_tenant_idx ON security_observations (tenant_id, created_at DESC);
CREATE INDEX security_observations_fingerprint_idx ON security_observations (tenant_id, behaviour_fingerprint);
CREATE INDEX security_observations_status_idx ON security_observations (tenant_id, processing_status, created_at DESC);

CREATE TABLE security_findings (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    behaviour_fingerprint text NOT NULL,
    classification text NOT NULL CHECK (classification IN ('malicious', 'suspicious', 'benign', 'unknown')),
    confidence real NOT NULL DEFAULT 0.0,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    attack_techniques text[] NOT NULL DEFAULT '{}',
    required_features jsonb NOT NULL DEFAULT '{}',
    supporting_features jsonb NOT NULL DEFAULT '{}',
    recommended_actions jsonb NOT NULL DEFAULT '[]',
    source text NOT NULL DEFAULT 'llm_investigation' CHECK (source IN ('llm_investigation', 'analyst', 'import', 'compiled_detector')),
    model text,
    model_version text,
    policy_version text,
    trust_level text NOT NULL DEFAULT 'candidate' CHECK (trust_level IN ('candidate', 'validated', 'trusted', 'deterministic')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz,
    occurrences integer NOT NULL DEFAULT 1,
    validation_count integer NOT NULL DEFAULT 0,
    false_positive_count integer NOT NULL DEFAULT 0,
    finding_version integer NOT NULL DEFAULT 1
);

CREATE INDEX security_findings_tenant_idx ON security_findings (tenant_id, last_seen_at DESC);
CREATE INDEX security_findings_fingerprint_idx ON security_findings (tenant_id, behaviour_fingerprint);
CREATE INDEX security_findings_trust_idx ON security_findings (tenant_id, trust_level, status);

CREATE TABLE security_investigations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    observation_id uuid NOT NULL REFERENCES security_observations (id),
    finding_id uuid REFERENCES security_findings (id),
    status text NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'failed', 'cancelled')),
    hypotheses jsonb NOT NULL DEFAULT '[]',
    evidence jsonb NOT NULL DEFAULT '[]',
    tool_calls jsonb NOT NULL DEFAULT '[]',
    related_findings jsonb NOT NULL DEFAULT '[]',
    intermediate_confidence real,
    final_confidence real,
    verdict text,
    severity text,
    attack_techniques text[] NOT NULL DEFAULT '{}',
    recommended_actions jsonb NOT NULL DEFAULT '[]',
    rationale text,
    model text,
    model_version text,
    provider text,
    policy_version text,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    error_message text
);

CREATE INDEX security_investigations_tenant_idx ON security_investigations (tenant_id, started_at DESC);
CREATE INDEX security_investigations_observation_idx ON security_investigations (observation_id);
CREATE INDEX security_investigations_finding_idx ON security_investigations (finding_id);

CREATE TABLE security_model_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    investigation_id uuid REFERENCES security_investigations (id),
    provider text NOT NULL,
    model text NOT NULL,
    model_version text,
    prompt_template_version text,
    tokens_input integer,
    tokens_output integer,
    latency_ms integer,
    cost_usd real,
    tools_available text[] NOT NULL DEFAULT '{}',
    tools_called text[] NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'error', 'timeout', 'refused')),
    error_message text,
    created_at timestamptz NOT NULL
);

CREATE INDEX security_model_runs_tenant_idx ON security_model_runs (tenant_id, created_at DESC);
CREATE INDEX security_model_runs_investigation_idx ON security_model_runs (investigation_id);

-- Row level security for AI reasoning tables
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'security_observations', 'security_findings', 'security_investigations', 'security_model_runs'
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
